//! The admin ports: the event log with its filters and pages, accounts and their flags,
//! invitations, settings, the requests queue and spaces, and erasing an account.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, SQLite in a file, and
//! PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set. A
//! database kept between runs holds other rows, so every check names rows of its own.

mod common;

use common::{draft, external, file, memory, put, unique_email, user};
use kemlock_app::admin::{
    AdminEvent, AdminEventRepo, AdminSpaceRepo, AdminUserRepo, ComplianceRepo, ComplianceRequest,
    EventFilter, Invite, InviteRepo, RequestKind, RequestStatus, SettingsRepo, UserQuery,
};
use kemlock_app::ports::{
    ItemStore, StoreError, TwoFactor, TwoFactorMethod, TwoFactorRepo, UserRepo,
};
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{CustomPermissions, Member, MemberState, Space, SpaceRole};
use kemlock_domain::{DeviceId, Email, ItemId, Owner, SpaceId, User, UserId};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

fn unique(prefix: &str) -> String {
    format!("{prefix}.{}", Uuid::new_v4().simple())
}

async fn account(store: &SqlStore, prefix: &str) -> User {
    let account = user(&unique_email(prefix));
    UserRepo::insert(store, &account).await.expect("insert");
    account
}

fn event(actor: Option<UserId>, action: &str, target: &str, at: OffsetDateTime) -> AdminEvent {
    AdminEvent {
        actor,
        device: Some(DeviceId::random()),
        action: action.to_owned(),
        target: Some(target.to_owned()),
        ip: Some("203.0.113.0/24".to_owned()),
        at,
    }
}

async fn events_scenario(store: &SqlStore) {
    let admin = account(store, "ev-admin").await;
    let other = account(store, "ev-other").await;
    let action = unique("admin.user.disable");
    let other_action = unique("space.change");
    for i in 0..5 {
        store
            .record_admin_event(event(
                Some(admin.id),
                &action,
                &format!("user:{i}"),
                T0 + Duration::minutes(i),
            ))
            .await
            .expect("record");
    }
    store
        .record_admin_event(event(
            Some(other.id),
            &other_action,
            "space:xyz",
            T0 + Duration::minutes(10),
        ))
        .await
        .expect("record");

    // Newest first, the actor's email attached, the truncated address kept.
    let by_admin = EventFilter {
        actor: Some(admin.id),
        ..EventFilter::default()
    };
    let page = store
        .query_events(&by_admin, None, 100)
        .await
        .expect("query");
    assert_eq!(page.events.len(), 5);
    assert_eq!(page.next, None);
    assert_eq!(page.events[0].target.as_deref(), Some("user:4"));
    assert_eq!(page.events[4].target.as_deref(), Some("user:0"));
    assert_eq!(
        page.events[0].actor_email.as_deref(),
        Some(admin.email.as_str())
    );
    assert_eq!(page.events[0].ip.as_deref(), Some("203.0.113.0/24"));

    // Pages follow the cursor without repeating or skipping.
    let first = store
        .query_events(&by_admin, None, 2)
        .await
        .expect("page 1");
    assert_eq!(first.events.len(), 2);
    let second = store
        .query_events(&by_admin, first.next.as_ref(), 2)
        .await
        .expect("page 2");
    let third = store
        .query_events(&by_admin, second.next.as_ref(), 2)
        .await
        .expect("page 3");
    let targets: Vec<_> = first
        .events
        .iter()
        .chain(&second.events)
        .chain(&third.events)
        .map(|e| e.target.clone().expect("a target"))
        .collect();
    assert_eq!(targets, ["user:4", "user:3", "user:2", "user:1", "user:0"]);
    assert_eq!(third.next, None);

    // Action: exact, or a prefix with a star. Target: contains. Time: from and to.
    let exact = EventFilter {
        action: Some(action.clone()),
        ..EventFilter::default()
    };
    assert_eq!(
        store
            .query_events(&exact, None, 100)
            .await
            .expect("q")
            .events
            .len(),
        5
    );
    let prefix = EventFilter {
        action: Some("space.change.*".to_owned()),
        actor: Some(other.id),
        ..EventFilter::default()
    };
    assert_eq!(
        store
            .query_events(&prefix, None, 100)
            .await
            .expect("q")
            .events
            .len(),
        1
    );
    let target = EventFilter {
        action: Some(action.clone()),
        target: Some("user:3".to_owned()),
        ..EventFilter::default()
    };
    assert_eq!(
        store
            .query_events(&target, None, 100)
            .await
            .expect("q")
            .events
            .len(),
        1
    );
    let window = EventFilter {
        action: Some(action.clone()),
        from: Some(T0 + Duration::minutes(1)),
        to: Some(T0 + Duration::minutes(3)),
        ..EventFilter::default()
    };
    assert_eq!(
        store
            .query_events(&window, None, 100)
            .await
            .expect("q")
            .events
            .len(),
        3
    );

    // Counting and retention by time.
    assert!(
        store
            .count_events_since(T0 + Duration::minutes(10))
            .await
            .expect("count")
            >= 1
    );
    let purged = store
        .purge_events_before(T0 + Duration::minutes(3))
        .await
        .expect("purge");
    assert!(purged >= 3, "{purged}");
    let left = store
        .query_events(&by_admin, None, 100)
        .await
        .expect("query");
    assert_eq!(left.events.len(), 2);
}

async fn users_scenario(store: &SqlStore) {
    let prefix = unique("ulist").replace('.', "-");
    let mut ada = user(&format!("{prefix}-ada@example.org"));
    ada.role = kemlock_domain::Role::Admin;
    ada.name = Some("Ada Lovelace".to_owned());
    UserRepo::insert(store, &ada).await.expect("insert");
    let bob = user(&format!("{prefix}-bob@example.org"));
    UserRepo::insert(store, &bob).await.expect("insert");
    TwoFactorRepo::put(
        store,
        &TwoFactor {
            user: ada.id,
            method: TwoFactorMethod::Totp,
            sealed_secret: vec![1; 40],
            enabled: true,
            created_at: T0,
        },
    )
    .await
    .expect("two-step");
    let device = common::device(ada.id, "Pixel", T0);
    kemlock_app::ports::DeviceRepo::upsert(store, &device)
        .await
        .expect("device");

    let all = store
        .list_users(&UserQuery {
            search: Some(prefix.to_uppercase()),
            limit: 10,
            offset: 0,
        })
        .await
        .expect("list");
    assert_eq!(all.total, 2);
    let first = &all.users[0];
    assert_eq!(first.id, ada.id, "ordered by email");
    assert!(first.two_step);
    assert_eq!(first.devices, 1);
    assert_eq!(first.last_seen_at, Some(T0));
    assert_eq!(first.role, kemlock_domain::Role::Admin);
    assert!(!all.users[1].two_step);
    assert_eq!(all.users[1].devices, 0);
    assert!(!first.erasure_pending && !all.users[1].erasure_pending);

    // An account on the erasure schedule says so, and cancelling it clears the flag.
    kemlock_app::privacy::AccountEraser::schedule_erasure(
        store,
        bob.id,
        T0,
        T0 + Duration::days(30),
    )
    .await
    .expect("scheduled");
    let waiting = store.user_row(bob.id).await.expect("row").expect("bob");
    assert!(waiting.erasure_pending);
    let listed = store
        .list_users(&UserQuery {
            search: Some(prefix.to_uppercase()),
            limit: 10,
            offset: 0,
        })
        .await
        .expect("list");
    assert!(
        !listed.users[0].erasure_pending,
        "ada is not on the schedule"
    );
    assert!(listed.users[1].erasure_pending);
    assert!(
        store
            .cancel_pending_erasure(bob.id)
            .await
            .expect("cancelled")
    );
    let cleared = store.user_row(bob.id).await.expect("row").expect("bob");
    assert!(!cleared.erasure_pending);

    // The name is searched too, and a page is a slice.
    let by_name = store
        .list_users(&UserQuery {
            search: Some("lovelace".to_owned()),
            limit: 10,
            offset: 0,
        })
        .await
        .expect("list");
    assert!(by_name.users.iter().any(|u| u.id == ada.id));
    let paged = store
        .list_users(&UserQuery {
            search: Some(prefix.clone()),
            limit: 1,
            offset: 1,
        })
        .await
        .expect("list");
    assert_eq!(paged.total, 2);
    assert_eq!(paged.users.len(), 1);
    assert_eq!(paged.users[0].id, bob.id);

    // Disable and enable; an account that isn't there is NotFound.
    assert!(!store.is_disabled(bob.id).await.expect("flag"));
    assert!(
        !UserRepo::account_disabled(store, bob.id)
            .await
            .expect("flag")
    );
    store
        .set_disabled(bob.id, Some((T0, ada.id)))
        .await
        .expect("disable");
    store
        .set_disabled(bob.id, Some((T0, ada.id)))
        .await
        .expect("disable again");
    assert!(store.is_disabled(bob.id).await.expect("flag"));
    // The sign-in paths ask the user port, which sees the same flag.
    assert!(
        UserRepo::account_disabled(store, bob.id)
            .await
            .expect("flag")
    );
    let row = store.user_row(bob.id).await.expect("row").expect("there");
    assert_eq!(row.disabled_at, Some(T0));
    store.set_disabled(bob.id, None).await.expect("enable");
    assert!(!store.is_disabled(bob.id).await.expect("flag"));
    assert!(
        !UserRepo::account_disabled(store, bob.id)
            .await
            .expect("flag")
    );
    assert_eq!(
        store
            .set_disabled(UserId::random(), Some((T0, ada.id)))
            .await,
        Err(StoreError::NotFound)
    );
    assert_eq!(store.user_row(UserId::random()).await, Ok(None));

    assert!(
        store
            .admins()
            .await
            .expect("admins")
            .iter()
            .any(|a| a.id == ada.id)
    );
    let counts = store.user_counts().await.expect("counts");
    assert!(counts.users >= 2 && counts.admins >= 1 && counts.devices >= 1);
}

async fn invites_scenario(store: &SqlStore) {
    let admin = account(store, "inv-admin").await;
    let email = Email::parse(&unique_email("invitee")).expect("email");
    let invite = Invite {
        id: Uuid::new_v4(),
        email: email.clone(),
        invited_by: admin.id,
        token_hash: [7; 32],
        created_at: T0,
        expires_at: T0 + Duration::days(7),
        last_sent_at: T0,
        sent: 1,
        accepted_at: None,
    };
    store.insert_invite(&invite).await.expect("insert");
    let again = Invite {
        id: Uuid::new_v4(),
        token_hash: [8; 32],
        ..invite.clone()
    };
    assert_eq!(
        store.insert_invite(&again).await,
        Err(StoreError::Duplicate)
    );

    assert_eq!(store.invite(invite.id).await, Ok(Some(invite.clone())));
    assert_eq!(
        store.invite_by_token([7; 32]).await,
        Ok(Some(invite.clone()))
    );
    assert_eq!(store.invite_by_token([9; 32]).await, Ok(None));
    assert!(store.invites().await.expect("list").contains(&invite));
    assert!(
        store
            .pending_invites(T0 + Duration::days(1))
            .await
            .expect("count")
            >= 1
    );

    // A resend replaces the hash and the dates.
    let resent = Invite {
        token_hash: [8; 32],
        expires_at: T0 + Duration::days(14),
        sent: 2,
        ..invite.clone()
    };
    store.update_invite(&resent).await.expect("update");
    assert_eq!(store.invite_by_token([7; 32]).await, Ok(None));
    assert_eq!(store.invite(invite.id).await, Ok(Some(resent)));

    store.remove_invite(invite.id).await.expect("remove");
    assert_eq!(store.invite(invite.id).await, Ok(None));
}

async fn settings_scenario(store: &SqlStore) {
    let prefix = format!("{}.", unique("setting"));
    let key = |name: &str| format!("{prefix}{name}");
    store.put_setting(&key("a"), "1").await.expect("put");
    store.put_setting(&key("b"), "two").await.expect("put");
    store.put_setting(&key("a"), "one").await.expect("replace");
    assert_eq!(
        store.settings_with_prefix(&prefix).await.expect("list"),
        vec![(key("a"), "one".to_owned()), (key("b"), "two".to_owned())]
    );
    store.delete_setting(&key("a")).await.expect("delete");
    store.delete_setting(&key("never")).await.expect("delete");
    assert_eq!(
        store.settings_with_prefix(&prefix).await.expect("list"),
        vec![(key("b"), "two".to_owned())]
    );
}

fn request(kind: RequestKind, due: OffsetDateTime) -> ComplianceRequest {
    ComplianceRequest {
        id: Uuid::new_v4(),
        kind,
        requester: unique_email("requester"),
        user: None,
        received_at: T0,
        due_at: due,
        extended: false,
        status: RequestStatus::Open,
        note: Some("by letter".to_owned()),
        closed_at: None,
        handled_by: None,
    }
}

async fn compliance_scenario(store: &SqlStore) {
    let soon = request(RequestKind::Access, T0 + Duration::days(10));
    let late = request(RequestKind::Erasure, T0 + Duration::days(45));
    store
        .insert_compliance_request(&late)
        .await
        .expect("insert");
    store
        .insert_compliance_request(&soon)
        .await
        .expect("insert");

    assert_eq!(
        store.compliance_request(soon.id).await,
        Ok(Some(soon.clone()))
    );
    let open = store.compliance_requests(true).await.expect("queue");
    let ours: Vec<_> = open
        .iter()
        .filter(|r| r.id == soon.id || r.id == late.id)
        .map(|r| r.id)
        .collect();
    assert_eq!(ours, [soon.id, late.id], "soonest due first");

    let counts = store
        .compliance_counts(T0 + Duration::days(20))
        .await
        .expect("counts");
    assert!(counts.open >= 2 && counts.overdue >= 1);

    let closed = ComplianceRequest {
        status: RequestStatus::Done,
        closed_at: Some(T0 + Duration::days(2)),
        handled_by: Some(UserId::random()),
        ..soon.clone()
    };
    store
        .update_compliance_request(&closed)
        .await
        .expect("update");
    assert_eq!(
        store.compliance_request(soon.id).await,
        Ok(Some(closed.clone()))
    );
    let open = store.compliance_requests(true).await.expect("queue");
    assert!(!open.iter().any(|r| r.id == soon.id));
    let every = store.compliance_requests(false).await.expect("all");
    assert!(every.iter().any(|r| r.id == soon.id));
}

fn space(id: SpaceId) -> Space {
    Space {
        id,
        name: vec![1; 40],
        key_version: 1,
        keys_pending_since: None,
        created_at: T0,
        updated_at: T0,
    }
}

fn member(space: SpaceId, user: UserId, role: SpaceRole, state: MemberState) -> Member {
    Member {
        state,
        ..Member::invited(space, user, role, CustomPermissions::NONE, user, T0)
    }
}

async fn spaces_scenario(store: &SqlStore) {
    let owner = account(store, "sp-owner").await;
    let second = account(store, "sp-second").await;
    let pending = account(store, "sp-pending").await;
    let id = SpaceId::random();
    SpaceRepo::create(
        store,
        SpaceChanges {
            space: Some(space(id)),
            members: vec![
                member(id, owner.id, SpaceRole::Owner, MemberState::Confirmed),
                member(id, second.id, SpaceRole::Member, MemberState::Confirmed),
                member(id, pending.id, SpaceRole::Member, MemberState::Invited),
            ],
            ..SpaceChanges::new(id)
        },
    )
    .await
    .expect("create");
    put(store, draft(ItemId::random(), Owner::Space(id), None, 1)).await;

    let row = store.space_row(id).await.expect("row").expect("there");
    assert_eq!(row.members, 3);
    assert_eq!(row.confirmed, 2);
    assert_eq!(row.owners.len(), 1);
    assert_eq!(row.owners[0].user, owner.id);
    assert_eq!(row.owners[0].email, owner.email.as_str());
    assert_eq!(row.live_items, 1);
    assert_eq!(store.space_row(SpaceId::random()).await, Ok(None));

    let page = store.list_spaces(500, 0).await.expect("list");
    assert!(page.total >= 1);
    assert!(page.spaces.iter().any(|s| s.id == id));
    assert!(store.live_items().await.expect("items") >= 1);

    // Only the sole confirmed owner owns a space alone.
    assert_eq!(
        store.sole_owned_spaces(owner.id).await.expect("owned"),
        vec![id]
    );
    assert!(
        store
            .sole_owned_spaces(second.id)
            .await
            .expect("owned")
            .is_empty()
    );
}

async fn erase_scenario(store: &SqlStore) {
    let doomed = account(store, "erase").await;
    let keeper = account(store, "keeper").await;
    let item = ItemId::random();
    put(store, draft(item, Owner::User(doomed.id), None, 1)).await;
    let kept = ItemId::random();
    put(store, draft(kept, Owner::User(keeper.id), None, 1)).await;
    let device = common::device(doomed.id, "Pixel", T0);
    kemlock_app::ports::DeviceRepo::upsert(store, &device)
        .await
        .expect("device");
    TwoFactorRepo::put(
        store,
        &TwoFactor {
            user: doomed.id,
            method: TwoFactorMethod::Totp,
            sealed_secret: vec![1; 40],
            enabled: true,
            created_at: T0,
        },
    )
    .await
    .expect("two-step");
    store
        .set_disabled(doomed.id, Some((T0, keeper.id)))
        .await
        .expect("disable");
    let space_id = SpaceId::random();
    SpaceRepo::create(
        store,
        SpaceChanges {
            space: Some(space(space_id)),
            members: vec![
                member(
                    space_id,
                    keeper.id,
                    SpaceRole::Owner,
                    MemberState::Confirmed,
                ),
                member(
                    space_id,
                    doomed.id,
                    SpaceRole::Member,
                    MemberState::Confirmed,
                ),
            ],
            ..SpaceChanges::new(space_id)
        },
    )
    .await
    .expect("space");

    store.erase_user(doomed.id).await.expect("erase");

    assert_eq!(UserRepo::by_id(store, doomed.id).await, Ok(None));
    assert_eq!(ItemStore::get(store, item).await, Ok(None));
    assert!(ItemStore::get(store, kept).await.expect("get").is_some());
    assert_eq!(
        kemlock_app::ports::DeviceRepo::get(store, device.id).await,
        Ok(None)
    );
    assert!(
        TwoFactorRepo::list(store, doomed.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(!store.is_disabled(doomed.id).await.expect("flag"));
    let state = SpaceRepo::load(store, space_id)
        .await
        .expect("load")
        .expect("there");
    assert_eq!(state.members.len(), 1, "the member row went");
    assert_eq!(
        store.erase_user(doomed.id).await,
        Err(StoreError::NotFound),
        "a second erase finds nobody"
    );
    // The other account is untouched.
    assert!(
        UserRepo::by_id(store, keeper.id)
            .await
            .expect("get")
            .is_some()
    );
}

async fn run_all(store: &SqlStore) {
    events_scenario(store).await;
    users_scenario(store).await;
    invites_scenario(store).await;
    settings_scenario(store).await;
    compliance_scenario(store).await;
    spaces_scenario(store).await;
    erase_scenario(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    run_all(&store).await;
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

#[tokio::test]
async fn events_written_before_the_admin_migration_have_no_address() {
    // The plain event log writes no address; the console reads it back as none.
    use kemlock_app::ports::{Event, EventLog};
    let store = memory().await;
    let actor = account(&store, "plain").await;
    EventLog::record(
        &store,
        Event {
            actor: Some(actor.id),
            device: None,
            action: "auth.sign_in",
            target: None,
            at: T0,
        },
    )
    .await
    .expect("record");
    let page = store
        .query_events(
            &EventFilter {
                actor: Some(actor.id),
                ..EventFilter::default()
            },
            None,
            10,
        )
        .await
        .expect("query");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].ip, None);
    assert_eq!(page.events[0].action, "auth.sign_in");
}
