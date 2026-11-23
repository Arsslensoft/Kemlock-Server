//! `PolicyRepo` on a real `SqlStore`, and the membership facts the Require SSO check reads, which
//! come from the space tables and the policies together.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, and PostgreSQL and
//! MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, memory, unique_email, user};
use kemlock_app::Actor;
use kemlock_app::policies::{PolicyRepo, StoredPolicies};
use kemlock_app::ports::{Clock, UserRepo};
use kemlock_app::spaces::{
    AcceptInvitation, CreateSpace, CreateSpaceInput, InviteInput, InviteMember, NewCollection,
};
use kemlock_app::sso::{MembershipFacts, SpaceMembership, SpaceRole as SsoRole};
use kemlock_domain::policies::{MasterPasswordPolicy, SpacePolicies, TimeoutAction};
use kemlock_domain::spaces::{CollectionId, CustomPermissions, SEALED_KEY_LEN, SpaceRole};
use kemlock_domain::{DeviceId, SpaceId, UserId};
use kemlock_store_sql::SqlStore;
use time::OffsetDateTime;
use time::macros::datetime;

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        datetime!(2026-06-01 12:00:00 UTC)
    }
}

const SET_AT: OffsetDateTime = datetime!(2026-06-02 08:09:10 UTC);

fn busy() -> SpacePolicies {
    SpacePolicies {
        require_sso: true,
        two_step: true,
        master_password: Some(MasterPasswordPolicy {
            min_length: Some(14),
            min_complexity: Some(3),
            require_upper: true,
            require_lower: false,
            require_numbers: true,
            require_special: false,
            enforce_on_login: true,
        }),
        single_space: true,
        disable_export: true,
        disable_send: true,
        always_show_email: true,
        session_timeout_minutes: Some(30),
        session_timeout_action: Some(TimeoutAction::LogOut),
        no_pin_unlock: true,
        central_ownership: true,
        no_card_items: true,
    }
}

async fn account(store: &SqlStore, prefix: &str) -> (UserId, String) {
    let email = unique_email(prefix);
    let account = user(&email);
    UserRepo::insert(store, &account)
        .await
        .expect("the account is stored");
    (account.id, email)
}

fn actor(user: UserId) -> Actor {
    Actor {
        user,
        device: DeviceId::random(),
        admin: false,
    }
}

fn sealed_key(fill: u8) -> Vec<u8> {
    let mut key = vec![fill; SEALED_KEY_LEN];
    key[0] = 1;
    key
}

async fn make_space(store: &SqlStore, owner: UserId) -> SpaceId {
    let space = SpaceId::random();
    CreateSpace {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner),
        CreateSpaceInput {
            id: space,
            name: vec![1; 40],
            sealed_space_key: sealed_key(2),
            collection: NewCollection {
                id: CollectionId::random(),
                name: vec![3; 40],
                sealed_key: sealed_key(4),
            },
        },
    )
    .await
    .expect("the space is made");
    space
}

async fn a_space_without_policies_has_everything_off(store: &SqlStore) {
    let stored = PolicyRepo::space_policies(store, SpaceId::random())
        .await
        .expect("read");
    assert_eq!(stored, StoredPolicies::default());
    assert!(!stored.policies.any());
    assert_eq!(stored.updated_at, None);
}

async fn typed_settings_round_trip_and_a_second_put_replaces_them(store: &SqlStore) {
    let (admin, _) = account(store, "policy-admin").await;
    let space = SpaceId::random();

    PolicyRepo::put_space_policies(store, space, &busy(), admin, SET_AT)
        .await
        .expect("stored");
    let stored = PolicyRepo::space_policies(store, space)
        .await
        .expect("read");
    assert_eq!(stored.policies, busy());
    assert_eq!(stored.updated_at, Some(SET_AT));
    assert_eq!(stored.updated_by, Some(admin));

    // Turning things off clears them, master password rules and timeout included.
    let relaxed = SpacePolicies {
        two_step: true,
        ..SpacePolicies::default()
    };
    let later = SET_AT + time::Duration::hours(1);
    PolicyRepo::put_space_policies(store, space, &relaxed, admin, later)
        .await
        .expect("replaced");
    let stored = PolicyRepo::space_policies(store, space)
        .await
        .expect("read");
    assert_eq!(stored.policies, relaxed);
    assert_eq!(stored.updated_at, Some(later));

    // The same values again are fine (MySQL counts that as no row changed).
    PolicyRepo::put_space_policies(store, space, &relaxed, admin, later)
        .await
        .expect("the same again");
}

async fn empty_master_password_rules_stay_on(store: &SqlStore) {
    let (admin, _) = account(store, "policy-admin").await;
    let space = SpaceId::random();
    let on = SpacePolicies {
        master_password: Some(MasterPasswordPolicy::default()),
        ..SpacePolicies::default()
    };
    PolicyRepo::put_space_policies(store, space, &on, admin, SET_AT)
        .await
        .expect("stored");
    assert_eq!(
        PolicyRepo::space_policies(store, space)
            .await
            .expect("read")
            .policies,
        on
    );
}

async fn several_spaces_at_once(store: &SqlStore) {
    let (admin, _) = account(store, "policy-admin").await;
    let (a, b, none) = (SpaceId::random(), SpaceId::random(), SpaceId::random());
    PolicyRepo::put_space_policies(store, a, &busy(), admin, SET_AT)
        .await
        .expect("stored");
    let only_sso = SpacePolicies {
        require_sso: true,
        ..SpacePolicies::default()
    };
    PolicyRepo::put_space_policies(store, b, &only_sso, admin, SET_AT)
        .await
        .expect("stored");

    let found = PolicyRepo::policies_of_spaces(store, &[a, b, none])
        .await
        .expect("read");
    assert_eq!(found.len(), 2);
    assert_eq!(found.get(&a), Some(&busy()));
    assert_eq!(found.get(&b), Some(&only_sso));
    assert!(!found.contains_key(&none));
    assert!(
        PolicyRepo::policies_of_spaces(store, &[])
            .await
            .expect("empty")
            .is_empty()
    );
}

async fn membership_facts_come_from_members_and_policies(store: &SqlStore) {
    let (owner, _) = account(store, "facts-owner").await;
    let (member, member_email) = account(store, "facts-member").await;
    let (loner, _) = account(store, "facts-loner").await;
    let strict = make_space(store, owner).await;
    let lax = make_space(store, owner).await;
    PolicyRepo::put_space_policies(
        store,
        strict,
        &SpacePolicies {
            require_sso: true,
            ..SpacePolicies::default()
        },
        owner,
        SET_AT,
    )
    .await
    .expect("stored");

    // The owner is in both, as an owner.
    let mut owners = MembershipFacts::spaces_of(store, owner)
        .await
        .expect("read");
    owners.sort_by_key(|m| m.space);
    let mut expected = vec![
        SpaceMembership {
            space: strict,
            role: SsoRole::Owner,
            require_sso: true,
        },
        SpaceMembership {
            space: lax,
            role: SsoRole::Owner,
            require_sso: false,
        },
    ];
    expected.sort_by_key(|m| m.space);
    assert_eq!(owners, expected);

    // An invitation is not membership; accepting it is.
    InviteMember {
        spaces: store.clone(),
        users: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner),
        strict,
        InviteInput {
            email: member_email,
            role: SpaceRole::Custom,
            custom: CustomPermissions::NONE,
            grants: Vec::new(),
        },
    )
    .await
    .expect("invited");
    assert_eq!(
        MembershipFacts::spaces_of(store, member).await,
        Ok(Vec::new())
    );
    AcceptInvitation {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(&actor(member), strict)
    .await
    .expect("accepted");
    assert_eq!(
        MembershipFacts::spaces_of(store, member).await,
        Ok(vec![SpaceMembership {
            space: strict,
            // A Custom member counts as an ordinary member for Require SSO.
            role: SsoRole::Member,
            require_sso: true,
        }])
    );

    assert_eq!(
        MembershipFacts::spaces_of(store, loner).await,
        Ok(Vec::new())
    );
}

/// `SpaceRepo`'s Require SSO calls and `PolicyRepo` are two ways at the one table.
async fn the_narrow_require_sso_calls_use_the_general_policies(store: &SqlStore) {
    use kemlock_app::spaces::SpaceRepo;

    let (admin, _) = account(store, "narrow-admin").await;
    let space = SpaceId::random();
    let two_step = SpacePolicies {
        two_step: true,
        ..SpacePolicies::default()
    };
    PolicyRepo::put_space_policies(store, space, &two_step, admin, SET_AT)
        .await
        .expect("stored");

    // Setting it by the narrow call shows in the general policies and leaves the rest alone.
    SpaceRepo::set_require_sso(store, space, true)
        .await
        .expect("set");
    let stored = PolicyRepo::space_policies(store, space)
        .await
        .expect("read")
        .policies;
    assert!(stored.require_sso && stored.two_step);
    assert!(
        PolicyRepo::policy_require_sso(store, space)
            .await
            .expect("read")
    );

    // Setting it by the general policies shows in the narrow read.
    PolicyRepo::put_space_policies(store, space, &two_step, admin, SET_AT)
        .await
        .expect("stored");
    assert!(
        SpaceRepo::require_sso_of(store, &[space])
            .await
            .expect("read")
            .is_empty()
    );
    PolicyRepo::set_policy_require_sso(store, space, true, admin, SET_AT)
        .await
        .expect("set");
    assert_eq!(
        SpaceRepo::require_sso_of(store, &[space])
            .await
            .expect("read"),
        vec![space]
    );

    // A space with no policies yet gets a row, made by no one in particular.
    let fresh = SpaceId::random();
    SpaceRepo::set_require_sso(store, fresh, true)
        .await
        .expect("set");
    let row = PolicyRepo::space_policies(store, fresh)
        .await
        .expect("read");
    assert!(row.policies.require_sso);
    assert_eq!(row.updated_by, None);
    assert!(row.updated_at.is_some());
}

async fn run_all(store: &SqlStore) {
    a_space_without_policies_has_everything_off(store).await;
    typed_settings_round_trip_and_a_second_put_replaces_them(store).await;
    empty_master_password_rules_stay_on(store).await;
    several_spaces_at_once(store).await;
    membership_facts_come_from_members_and_policies(store).await;
    the_narrow_require_sso_calls_use_the_general_policies(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}

/// What `space_policies` held when the merge migration runs: copied into `space_policy_settings`,
/// the table then gone.
#[tokio::test]
async fn the_merge_migration_copies_the_old_policies_and_drops_their_table() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let url = common::file_url(&dir.path().join("db.sqlite3"));
    let store = SqlStore::connect(&url).await.expect("a new database");
    let (admin, _) = account(&store, "merge-admin").await;
    let (both, only_old_on, only_old_off) =
        (SpaceId::random(), SpaceId::random(), SpaceId::random());
    // A space with a general row that has Require SSO off while the old table has it on.
    let two_step = SpacePolicies {
        two_step: true,
        ..SpacePolicies::default()
    };
    PolicyRepo::put_space_policies(&store, both, &two_step, admin, SET_AT)
        .await
        .expect("stored");
    store.close().await.expect("closed");

    // Put the old table and its rows back, and forget the migration that dropped it.
    let db = sea_orm::Database::connect(&url)
        .await
        .expect("a raw connection");
    for sql in [
        "CREATE TABLE space_policies (space_id uuid NOT NULL PRIMARY KEY, require_sso boolean NOT NULL)".to_owned(),
        format!("INSERT INTO space_policies VALUES (X'{}', 1)", both.0.simple()),
        format!("INSERT INTO space_policies VALUES (X'{}', 1)", only_old_on.0.simple()),
        format!("INSERT INTO space_policies VALUES (X'{}', 0)", only_old_off.0.simple()),
        "DELETE FROM seaql_migrations WHERE version = 'm20261124_010001_merge_space_policies'"
            .to_owned(),
    ] {
        sea_orm::ConnectionTrait::execute_unprepared(&db, &sql)
            .await
            .expect("the old state is put back");
    }
    db.close().await.expect("closed");

    let store = SqlStore::connect(&url).await.expect("the migration runs");
    let read = |space| PolicyRepo::space_policies(&store, space);
    // The general row stays as it was, with Require SSO on as the old table had it.
    let kept = read(both).await.expect("read").policies;
    assert!(kept.require_sso && kept.two_step);
    // A space only the old table knew gets a row with just that policy.
    let copied = read(only_old_on).await.expect("read");
    assert_eq!(
        copied.policies,
        SpacePolicies {
            require_sso: true,
            ..SpacePolicies::default()
        }
    );
    assert!(copied.updated_at.is_some());
    assert!(!read(only_old_off).await.expect("read").policies.require_sso);
    store.close().await.expect("closed");

    let db = sea_orm::Database::connect(&url)
        .await
        .expect("a raw connection");
    let left = sea_orm::ConnectionTrait::query_all_raw(
        &db,
        sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE name = 'space_policies'",
        ),
    )
    .await
    .expect("a query");
    assert!(left.is_empty(), "the old table is dropped");
    db.close().await.expect("closed");
}
