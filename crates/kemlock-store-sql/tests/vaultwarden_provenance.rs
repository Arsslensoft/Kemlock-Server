//! The move from Vaultwarden writes only what an import made. A snapshot is data a person chose,
//! so it can name any id: these tests name the ids of accounts, spaces, devices and items this
//! server already has, and check that nothing of them changes, while an import over its own
//! earlier copy still does.

mod common;

use common::{draft, kind, memory, unique_email, user};
use kemlock_app::Actor;
use kemlock_app::b64url;
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::ports::{Clock, DeviceRepo, ItemStore, TwoFactorRepo, UserRepo};
use kemlock_app::spaces::{CreateSpace, CreateSpaceInput, NewCollection, SpaceRepo};
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::spaces::{CollectionId, SEALED_KEY_LEN, SpaceRole};
use kemlock_domain::{AccountMode, DeviceId, ItemId, Owner, Role, SpaceId, UserId};
use kemlock_store_sql::{ImportFiles, ImportFilesFuture, ImportOptions, SqlImportSink, SqlStore};
use kemlock_vaultwarden::mapping::{
    BitwardenAccount, FileCopy, FileKind, MappedAccount, MappedAttachment, MappedImport, MappedItem,
};
use kemlock_vaultwarden::schema;
use kemlock_vaultwarden::settings::MappedSettings;
use kemlock_vaultwarden::snapshot::{Cell, Table};
use kemlock_vaultwarden::{ApplyReport, apply};
use serde_json::json;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

const NOW: OffsetDateTime = datetime!(2026-06-01 12:00:00 UTC);

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        NOW
    }
}

/// File storage that remembers what it was asked to keep.
#[derive(Debug, Default)]
struct Files(Mutex<Vec<String>>);

impl ImportFiles for Files {
    fn put<'a>(&'a self, key: &'a str, _bytes: Vec<u8>) -> ImportFilesFuture<'a> {
        Box::pin(async move {
            self.0.lock().expect("a lock").push(key.to_owned());
            Ok(())
        })
    }

    fn delete<'a>(&'a self, _key: &'a str) -> ImportFilesFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn account(id: UserId, email: &str, name: &str) -> MappedAccount {
    MappedAccount {
        id,
        email: email.to_owned(),
        name: name.to_owned(),
        mode: AccountMode::Compatible,
        role: Role::User,
        created_at: NOW,
        updated_at: NOW,
        bitwarden: BitwardenAccount {
            enabled: true,
            verified_at: None,
            last_verifying_at: None,
            login_verify_count: 0,
            email_new: None,
            email_new_token: None,
            password_hash: vec![9; 32],
            salt: vec![8; 16],
            password_iterations: 600_000,
            password_hint: None,
            akey: "2.attacker|key|mac".to_owned(),
            private_key: Some("2.attacker|private|mac".to_owned()),
            public_key: Some("MIIBattacker".to_owned()),
            totp_secret: None,
            totp_recover: None,
            security_stamp: Uuid::new_v4().to_string(),
            stamp_exception: None,
            equivalent_domains: "[]".to_owned(),
            excluded_globals: "[]".to_owned(),
            client_kdf_type: 0,
            client_kdf_iter: 600_000,
            client_kdf_memory: None,
            client_kdf_parallelism: None,
            api_key: None,
            avatar_color: None,
            external_id: None,
            key_id: None,
        },
    }
}

fn text(value: impl ToString) -> Cell {
    Cell::Text(value.to_string())
}

/// A `devices` row of a Vaultwarden database with a refresh token the snapshot's author knows.
fn devices(rows: &[(Uuid, UserId)]) -> Table {
    let token = b64url::encode(&[7u8; 32]);
    Table::from_rows(
        &schema::DEVICES,
        rows.iter()
            .map(|(device, user)| {
                vec![
                    text(device),
                    text("2024-01-01 00:00:00"),
                    text("2024-05-01 00:00:00"),
                    text(user.0),
                    text("Planted"),
                    Cell::Int(0),
                    Cell::Null,
                    Cell::Null,
                    text(&token),
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                ]
            })
            .collect(),
    )
}

/// An authenticator setup whose secret the snapshot's author knows.
fn twofactor(rows: &[UserId]) -> Table {
    Table::from_rows(
        &schema::TWOFACTOR,
        rows.iter()
            .map(|user| {
                vec![
                    text(Uuid::new_v4()),
                    text(user.0),
                    Cell::Int(0),
                    Cell::Int(1),
                    text("JBSWY3DPEHPK3PXP"),
                    Cell::Int(0),
                ]
            })
            .collect(),
    )
}

fn organizations(rows: &[(SpaceId, &str)]) -> Table {
    Table::from_rows(
        &schema::ORGANIZATIONS,
        rows.iter()
            .map(|(space, name)| {
                vec![
                    text(space.0),
                    text(name),
                    text("billing@example.org"),
                    text("2.orgpriv|iv|mac"),
                    text("orgpub"),
                ]
            })
            .collect(),
    )
}

/// An owner's confirmed membership.
fn memberships(rows: &[(SpaceId, UserId)]) -> Table {
    Table::from_rows(
        &schema::USERS_ORGANIZATIONS,
        rows.iter()
            .map(|(space, user)| {
                vec![
                    text(Uuid::new_v4()),
                    text(user.0),
                    text(space.0),
                    Cell::Null,
                    Cell::Int(0),
                    text("2.key|iv|mac"),
                    Cell::Int(2),
                    Cell::Int(0),
                    Cell::Null,
                    Cell::Null,
                ]
            })
            .collect(),
    )
}

async fn pass(store: &SqlStore, mapped: &MappedImport, adopt: bool) -> ApplyReport {
    pass_with(store, mapped, adopt, Arc::new(Files::default())).await
}

async fn pass_with(
    store: &SqlStore,
    mapped: &MappedImport,
    adopt: bool,
    files: Arc<Files>,
) -> ApplyReport {
    let dest = tempfile::tempdir().expect("a temp dir");
    let mut options = ImportOptions::new(dest.path(), files, NOW);
    options.adopt_existing = adopt;
    let mut sink = SqlImportSink::begin(store, ServerSeal::new(&[7u8; 32]), options)
        .await
        .expect("a pass opens");
    apply(mapped, &[], &mut sink)
        .await
        .expect("the pass applies")
}

async fn native(store: &SqlStore, prefix: &str) -> UserId {
    let account = user(&unique_email(prefix));
    UserRepo::insert(store, &account).await.expect("stored");
    account.id
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

const SPACE_NAME: [u8; 40] = [1; 40];

/// A space of this server's own, made by `owner`, with its first collection.
async fn native_space(store: &SqlStore, owner: UserId) -> (SpaceId, CollectionId) {
    native_space_with_id(store, owner, SpaceId::random()).await
}

async fn native_space_with_id(
    store: &SqlStore,
    owner: UserId,
    space: SpaceId,
) -> (SpaceId, CollectionId) {
    let collection = CollectionId::random();
    CreateSpace {
        spaces: store.clone(),
        events: store.clone(),
        clock: FixedClock,
    }
    .execute(
        &actor(owner),
        CreateSpaceInput {
            id: space,
            name: SPACE_NAME.to_vec(),
            sealed_space_key: sealed_key(2),
            collection: NewCollection {
                id: collection,
                name: vec![3; 40],
                sealed_key: sealed_key(4),
            },
        },
    )
    .await
    .expect("the space is made");
    (space, collection)
}

/// A cipher of the Bitwarden API, as the import stores it.
fn cipher(id: ItemId, owner: Owner, updated_at: OffsetDateTime) -> MappedItem {
    MappedItem {
        id,
        owner,
        kind: kind("login"),
        format: kemlock_domain::ItemFormat::Bw,
        atype: 1,
        json: json!({"name": "2.name|iv|mac"}),
        created_at: updated_at,
        updated_at,
    }
}

fn refused(report: &ApplyReport, kind: &str) -> Vec<String> {
    report.refused.get(kind).cloned().unwrap_or_default()
}

#[tokio::test]
async fn a_snapshot_cannot_rewrite_accounts_or_spaces_that_already_exist() {
    let store = memory().await;
    // Two accounts of this server: one the snapshot lists as a user, one it only points at.
    let listed = native(&store, "listed").await;
    let pointed_at = native(&store, "pointed-at").await;
    let attacker = native(&store, "attacker").await;
    let (space, _) = native_space(&store, listed).await;
    let before = UserRepo::by_id(&store, listed)
        .await
        .expect("a read")
        .expect("the account");

    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(listed, "owned@example.org", "Owned"));
    mapped.carried = vec![
        devices(&[(Uuid::new_v4(), listed), (Uuid::new_v4(), pointed_at)]),
        organizations(&[(space, "Hijacked")]),
        memberships(&[(space, attacker)]),
        twofactor(&[listed, pointed_at]),
    ];
    let report = pass(&store, &mapped, false).await;

    // Everything it named is reported as left alone.
    assert_eq!(refused(&report, "user"), vec![listed.0.to_string()]);
    assert_eq!(refused(&report, "space"), vec![space.0.to_string()]);
    assert_eq!(report.accounts, 0, "no account was written");
    assert_eq!(refused(&report, "devices").len(), 2);
    assert_eq!(refused(&report, "twofactor").len(), 2);
    assert_eq!(refused(&report, "users_organizations").len(), 1);

    // The listed account keeps its email, name and stamp, and has no Bitwarden record.
    let after = UserRepo::by_id(&store, listed)
        .await
        .expect("a read")
        .expect("the account");
    assert_eq!(after.email, before.email);
    assert_eq!(after.name, before.name);
    assert_eq!(after.security_stamp, before.security_stamp);
    assert_eq!(after.mode, before.mode);
    assert!(
        BwAccountRepo::get(&store, listed)
            .await
            .expect("a read")
            .is_none()
    );

    // No device and no refresh token was planted, and no second step was replaced or added.
    for victim in [listed, pointed_at] {
        assert!(
            DeviceRepo::list(&store, victim)
                .await
                .expect("a read")
                .is_empty()
        );
        assert!(
            TwoFactorRepo::list(&store, victim)
                .await
                .expect("a read")
                .is_empty()
        );
    }

    // The space keeps its name and its members: the attacker is not one of them.
    let state = SpaceRepo::load(&store, space)
        .await
        .expect("a read")
        .expect("the space");
    assert_eq!(state.space.name, SPACE_NAME.to_vec());
    assert!(state.members.iter().all(|m| m.user != attacker));
    assert!(
        state
            .members
            .iter()
            .any(|m| m.user == listed && m.role == SpaceRole::Owner)
    );
}

/// A `collections` row of a Vaultwarden database.
fn collections(rows: &[(CollectionId, SpaceId)]) -> Table {
    Table::from_rows(
        &schema::COLLECTIONS,
        rows.iter()
            .map(|(collection, space)| {
                vec![
                    text(collection.0),
                    text(space.0),
                    text("2.name|iv|mac"),
                    Cell::Null,
                ]
            })
            .collect(),
    )
}

#[tokio::test]
async fn a_collection_of_another_space_is_not_moved_into_an_imported_one() {
    let store = memory().await;
    let owner = native(&store, "collection-owner").await;
    let (native_space, native_collection) = native_space(&store, owner).await;

    // An organization the import makes, listing the id of a collection the other space holds.
    let imported_space = SpaceId::random();
    let own_collection = CollectionId::random();
    let mapped = MappedImport {
        carried: vec![
            organizations(&[(imported_space, "Imported")]),
            collections(&[
                (native_collection, imported_space),
                (own_collection, imported_space),
            ]),
        ],
        ..Default::default()
    };
    let report = pass(&store, &mapped, false).await;
    assert_eq!(
        refused(&report, "collections"),
        vec![format!("{}", native_collection.0)]
    );
    let state = SpaceRepo::load(&store, native_space)
        .await
        .expect("a read")
        .expect("the space");
    assert!(
        state.collections.iter().any(|c| c.id == native_collection),
        "the collection stayed in its own space"
    );
    let imported = SpaceRepo::load(&store, imported_space)
        .await
        .expect("a read")
        .expect("the imported space");
    assert!(
        imported
            .collections
            .iter()
            .all(|c| c.id != native_collection)
    );
    assert!(imported.collections.iter().any(|c| c.id == own_collection));

    // Listing a collection under the other space itself is refused as well, space and all.
    let under_native = MappedImport {
        carried: vec![collections(&[(CollectionId::random(), native_space)])],
        ..Default::default()
    };
    let report = pass(&store, &under_native, false).await;
    assert_eq!(refused(&report, "collections").len(), 1);
}

#[tokio::test]
async fn a_move_may_run_again_over_its_own_earlier_copy() {
    let store = memory().await;
    let user = UserId::random();
    let space = SpaceId::random();
    let device = Uuid::new_v4();

    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(user, &unique_email("moved"), "Moved"));
    mapped.carried = vec![
        devices(&[(device, user)]),
        organizations(&[(space, "Family")]),
        memberships(&[(space, user)]),
        twofactor(&[user]),
    ];
    let first = pass(&store, &mapped, false).await;
    assert!(first.refused.is_empty(), "{:?}", first.refused);
    assert_eq!(first.accounts, 1);
    assert_eq!(
        DeviceRepo::list(&store, user).await.expect("a read").len(),
        1
    );
    assert_eq!(
        TwoFactorRepo::list(&store, user)
            .await
            .expect("a read")
            .len(),
        1
    );

    // Run again with the account renamed and the space renamed: the import's own rows change.
    let mut again = mapped.clone();
    again.accounts[0].name = "Renamed".to_owned();
    again.carried[1] = organizations(&[(space, "Renamed family")]);
    let second = pass(&store, &again, false).await;
    assert!(second.refused.is_empty(), "{:?}", second.refused);
    assert_eq!(
        UserRepo::by_id(&store, user)
            .await
            .expect("a read")
            .expect("the account")
            .name
            .as_deref(),
        Some("Renamed")
    );
    let state = SpaceRepo::load(&store, space)
        .await
        .expect("a read")
        .expect("the space");
    assert_eq!(state.space.name, b"Renamed family".to_vec());

    // A pass that carries only a device and a two-step setup for the account, as a second pass
    // of a two-pass copy does, is still the import's.
    let delta = MappedImport {
        carried: vec![devices(&[(Uuid::new_v4(), user)]), twofactor(&[user])],
        ..Default::default()
    };
    let third = pass(&store, &delta, false).await;
    assert!(third.refused.is_empty(), "{:?}", third.refused);
    assert_eq!(
        DeviceRepo::list(&store, user).await.expect("a read").len(),
        2
    );
}

#[tokio::test]
async fn an_operator_can_adopt_what_is_there_and_it_is_the_imports_from_then_on() {
    let store = memory().await;
    let existing = native(&store, "adopted").await;
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(existing, "adopted@example.org", "Adopted"));

    let refused_first = pass(&store, &mapped, false).await;
    assert_eq!(
        refused(&refused_first, "user"),
        vec![existing.0.to_string()]
    );

    let adopted = pass(&store, &mapped, true).await;
    assert!(adopted.refused.is_empty(), "{:?}", adopted.refused);
    assert_eq!(adopted.accounts, 1);
    let user = UserRepo::by_id(&store, existing)
        .await
        .expect("a read")
        .expect("the account");
    assert_eq!(user.email.as_str(), "adopted@example.org");
    assert!(
        BwAccountRepo::get(&store, existing)
            .await
            .expect("a read")
            .is_some()
    );

    // Adopting recorded it, so an ordinary rerun accepts it.
    let rerun = pass(&store, &mapped, false).await;
    assert!(rerun.refused.is_empty(), "{:?}", rerun.refused);
}

#[tokio::test]
async fn config_json_can_only_set_the_names_of_the_settings_list() {
    let store = memory().await;
    store
        .put_setting("migration.status", "kept")
        .await
        .expect("a setting");
    let mut mapped = MappedImport::default();
    let mut settings = MappedSettings::default();
    for (name, value) in [
        ("signups_allowed", json!(false)),
        ("smtp_port", json!(465)),
        ("smtp_port_typo", json!(1)),
        ("trash_days", json!("a month")),
        ("migration.status", json!("overwritten")),
        ("setting.smtp_host", json!("evil.example.org")),
        ("smtp_password", json!("hunter2")),
        ("domain", json!("https://vault.example.org")),
    ] {
        settings.values.insert(name.to_owned(), value);
    }
    mapped.settings = settings;
    let report = pass(&store, &mapped, false).await;

    // Kept under the key the settings code reads, so they take effect.
    assert_eq!(report.settings, 2);
    assert_eq!(
        store
            .setting("setting.signups_allowed")
            .await
            .expect("a read")
            .as_deref(),
        Some("false")
    );
    assert_eq!(
        store
            .setting("setting.smtp_port")
            .await
            .expect("a read")
            .as_deref(),
        Some("465")
    );
    // Not the bare name, not a name the list lacks, not a secret, not a value it would refuse.
    for other in [
        "signups_allowed",
        "setting.smtp_port_typo",
        "setting.trash_days",
        "setting.setting.smtp_host",
        "setting.smtp_password",
        "setting.domain",
        "smtp_password",
        "domain",
    ] {
        assert_eq!(store.setting(other).await.expect("a read"), None, "{other}");
    }
    assert_eq!(
        store
            .setting("migration.status")
            .await
            .expect("a read")
            .as_deref(),
        Some("kept")
    );
    assert_eq!(refused(&report, "setting").len(), 6);
}

#[tokio::test]
async fn items_attachments_and_files_of_another_owner_are_not_touched() {
    let store = memory().await;
    let victim = native(&store, "owner-of-items").await;
    let item = ItemId::random();
    let stored = common::put(&store, draft(item, Owner::User(victim), None, 1)).await;

    // The snapshot claims the victim's item for a new account, and an attachment on it.
    let thief = UserId::random();
    let attachment_dir = tempfile::tempdir().expect("a temp dir");
    let file = attachment_dir.path().join("payload");
    std::fs::write(&file, b"payload").expect("a file");
    let storage_key = format!("attachments/{}/att0000000000001", item.0);
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(thief, &unique_email("thief"), "Thief"));
    mapped.items.push(MappedItem {
        id: item,
        owner: Owner::User(thief),
        kind: kind("login"),
        format: kemlock_domain::ItemFormat::Bw,
        atype: 1,
        json: json!({"name": "2.stolen|iv|mac"}),
        created_at: NOW,
        updated_at: NOW,
    });
    mapped.attachments.push(MappedAttachment {
        id: "att0000000000001".to_owned(),
        item,
        file_name: "2.name|iv|mac".to_owned(),
        size: 7,
        key: None,
        storage_key: storage_key.clone(),
        file_found: true,
    });
    mapped.files.push(FileCopy {
        kind: FileKind::Attachment,
        from: file,
        storage_key,
        size: 7,
    });
    let files = Arc::new(Files::default());
    let report = pass_with(&store, &mapped, false, files.clone()).await;

    assert_eq!(refused(&report, "item"), vec![item.0.to_string()]);
    assert_eq!(report.items, 0);
    assert_eq!(
        report.attachments, 0,
        "the attachment is on an item that isn't the import's"
    );
    assert_eq!(refused(&report, "file").len(), 1);
    assert!(
        files.0.lock().expect("a lock").is_empty(),
        "no file was stored"
    );

    // The victim's item is as it was: same owner, same revision, same bytes.
    let after = ItemStore::get(&store, item)
        .await
        .expect("a read")
        .expect("the item");
    assert_eq!(after.owner, Owner::User(victim));
    assert_eq!(after.revision, stored.revision);
    assert_eq!(after.ciphertext, stored.ciphertext);
}

#[tokio::test]
async fn an_id_a_pass_only_names_is_not_marked_as_the_imports() {
    let store = memory().await;
    let owner = native(&store, "late-owner").await;
    let space = SpaceId::random();

    // A cipher of an organization whose row never comes: the import writes it for that owner,
    // but the space is not created and so is not recorded as the import's.
    let user = UserId::random();
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(user, &unique_email("member"), "Member"));
    mapped
        .items
        .push(cipher(ItemId::random(), Owner::Space(space), NOW));
    let first = pass(&store, &mapped, false).await;
    assert!(first.refused.is_empty(), "{:?}", first.refused);
    assert_eq!(first.items, 1);

    // A real space is made under that id later (legacy space ids are deterministic) ...
    let (made, _) = native_space_with_id(&store, owner, space).await;
    assert_eq!(made, space);
    // ... and a later move can't rename it or add members.
    let later = MappedImport {
        carried: vec![
            organizations(&[(space, "Hijacked")]),
            memberships(&[(space, user)]),
        ],
        ..Default::default()
    };
    let report = pass(&store, &later, false).await;
    assert_eq!(refused(&report, "space"), vec![space.0.to_string()]);
    let state = SpaceRepo::load(&store, space)
        .await
        .expect("a read")
        .expect("the space");
    assert_eq!(state.space.name, SPACE_NAME.to_vec());
    assert!(state.members.iter().all(|m| m.user != user));
}

#[tokio::test]
async fn an_account_and_a_space_never_share_an_id() {
    let store = memory().await;
    let owner = native(&store, "owner").await;
    let (space, _) = native_space(&store, owner).await;

    // A snapshot that gives a user the id of a space of this server, and a space the id of one
    // of its accounts: neither is created, and neither side's rows change.
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(UserId(space.0), &unique_email("clash"), "Clash"));
    mapped.carried = vec![organizations(&[(SpaceId(owner.0), "Clash")])];
    let report = pass(&store, &mapped, false).await;

    assert_eq!(refused(&report, "user"), vec![space.0.to_string()]);
    assert_eq!(refused(&report, "space"), vec![owner.0.to_string()]);
    assert!(
        UserRepo::by_id(&store, UserId(space.0))
            .await
            .expect("a read")
            .is_none()
    );
    assert!(
        SpaceRepo::load(&store, SpaceId(owner.0))
            .await
            .expect("a read")
            .is_none()
    );
}

#[tokio::test]
async fn an_address_another_account_holds_leaves_that_account_out_and_not_the_pass_failed() {
    let store = memory().await;
    let holder = user(&unique_email("holder"));
    UserRepo::insert(&store, &holder).await.expect("stored");

    let fine = UserId::random();
    let clash = UserId::random();
    let twin = UserId::random();
    let shared = unique_email("shared");
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(clash, holder.email.as_str(), "Clash"));
    mapped
        .accounts
        .push(account(fine, &unique_email("fine"), "Fine"));
    // Two accounts of the snapshot with one address: the first is written, the second is left out.
    let mut first = account(twin, &shared, "Twin");
    first.id = UserId(Uuid::from_u128(1));
    mapped.accounts.push(first);
    mapped.accounts.push(account(twin, &shared, "Other twin"));
    let report = pass(&store, &mapped, false).await;

    assert!(
        refused(&report, "user").contains(&clash.0.to_string()),
        "{:?}",
        report.refused
    );
    assert!(
        UserRepo::by_id(&store, fine)
            .await
            .expect("a read")
            .is_some()
    );
    assert!(
        UserRepo::by_id(&store, clash)
            .await
            .expect("a read")
            .is_none()
    );
    assert_eq!(
        UserRepo::by_id(&store, holder.id)
            .await
            .expect("a read")
            .expect("the holder")
            .email,
        holder.email
    );
    assert_eq!(refused(&report, "user").len(), 2);
}

/// An `event` row of a Vaultwarden database from the day before NOW.
fn events(rows: &[(Option<UserId>, Option<UserId>)]) -> Table {
    Table::from_rows(
        &schema::EVENT,
        rows.iter()
            .map(|(actor, subject)| {
                vec![
                    text(Uuid::new_v4()),
                    Cell::Int(1000),
                    subject.map_or(Cell::Null, |u| text(u.0)),
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                    actor.map_or(Cell::Null, |u| text(u.0)),
                    Cell::Int(0),
                    Cell::Null,
                    text("2026-05-31 12:00:00"),
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                    Cell::Null,
                ]
            })
            .collect(),
    )
}

#[tokio::test]
async fn events_of_a_deleted_vaultwarden_user_are_kept_but_not_those_naming_this_servers_users() {
    use kemlock_app::admin::{AdminEventRepo, EventFilter};

    let store = memory().await;
    let native_user = native(&store, "named-in-events").await;
    let moved = UserId::random();
    let gone = UserId::random();

    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(moved, &unique_email("moved"), "Moved"));
    mapped.carried = vec![events(&[
        // Done by a user of the snapshot, and by one Vaultwarden has since deleted.
        (Some(moved), None),
        (Some(gone), Some(gone)),
        // Naming one of this server's own users, as the actor or as the subject.
        (Some(native_user), None),
        (Some(moved), Some(native_user)),
    ])];
    let report = pass(&store, &mapped, false).await;

    assert_eq!(refused(&report, "event").len(), 2, "{:?}", report.refused);
    let kept = store
        .query_events(
            &EventFilter {
                action: Some("vw-event-*".to_owned()),
                ..EventFilter::default()
            },
            None,
            10,
        )
        .await
        .expect("events");
    assert_eq!(kept.events.len(), 2);
}

#[tokio::test]
async fn a_second_pass_cannot_delete_rows_that_hang_off_what_the_import_does_not_own() {
    use kemlock_vaultwarden::Deletion;

    let store = memory().await;
    let owner = native(&store, "grant-owner").await;
    let (space, collection) = native_space(&store, owner).await;
    let item = ItemId::random();
    common::put(&store, draft(item, Owner::User(owner), None, 1)).await;
    let before = SpaceRepo::load(&store, space)
        .await
        .expect("a read")
        .expect("the space");

    let key = |parts: &[String]| parts.to_vec();
    let deletions = vec![
        Deletion {
            table: "ciphers_collections",
            key: key(&[item.0.to_string(), collection.0.to_string()]),
        },
        Deletion {
            table: "users_collections",
            key: key(&[owner.0.to_string(), collection.0.to_string()]),
        },
        Deletion {
            table: "collections_groups",
            key: key(&[collection.0.to_string(), Uuid::new_v4().to_string()]),
        },
        Deletion {
            table: "collections",
            key: key(&[collection.0.to_string()]),
        },
        Deletion {
            table: "ciphers",
            key: key(&[item.0.to_string()]),
        },
    ];
    let dest = tempfile::tempdir().expect("a temp dir");
    let mut sink = SqlImportSink::begin(
        &store,
        ServerSeal::new(&[7u8; 32]),
        ImportOptions::new(dest.path(), Arc::new(Files::default()), NOW),
    )
    .await
    .expect("a pass opens");
    let report = apply(&MappedImport::default(), &deletions, &mut sink)
        .await
        .expect("the pass applies");

    for table in [
        "ciphers_collections",
        "users_collections",
        "collections_groups",
        "collections",
        "ciphers",
    ] {
        assert_eq!(
            refused(&report, table).len(),
            1,
            "{table}: {:?}",
            report.refused
        );
    }
    let after = SpaceRepo::load(&store, space)
        .await
        .expect("a read")
        .expect("the space");
    assert_eq!(after.collections.len(), before.collections.len());
    assert_eq!(after.grants.len(), before.grants.len());
    let kept = ItemStore::get(&store, item)
        .await
        .expect("a read")
        .expect("the item");
    assert!(
        kept.deleted_at.is_none(),
        "the item was not turned into a tombstone"
    );
}

#[tokio::test]
async fn an_account_the_api_changed_since_is_not_rolled_back_by_a_rerun() {
    let store = memory().await;
    let user = UserId::random();
    let device = Uuid::new_v4();
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(user, &unique_email("moved"), "Moved"));
    mapped.carried = vec![devices(&[(device, user)]), twofactor(&[user])];
    let first = pass(&store, &mapped, false).await;
    assert!(first.refused.is_empty(), "{:?}", first.refused);

    // The person changes their account here, and removes the planted-looking device.
    let mut changed = UserRepo::by_id(&store, user)
        .await
        .expect("a read")
        .expect("the account");
    changed.name = Some("Changed here".to_owned());
    changed.updated_at = NOW + time::Duration::hours(1);
    UserRepo::update(&store, &changed).await.expect("updated");
    DeviceRepo::remove(&store, DeviceId(device))
        .await
        .expect("removed");

    // A later pass over the same snapshot leaves it all as it is now.
    let rerun = pass(&store, &mapped, false).await;
    assert_eq!(refused(&rerun, "user-changed"), vec![user.0.to_string()]);
    assert_eq!(rerun.accounts, 0);
    let after = UserRepo::by_id(&store, user)
        .await
        .expect("a read")
        .expect("the account");
    assert_eq!(after.name.as_deref(), Some("Changed here"));
    assert!(
        DeviceRepo::list(&store, user)
            .await
            .expect("a read")
            .is_empty()
    );

    // An operator who means it adopts, and the snapshot wins again.
    let adopted = pass(&store, &mapped, true).await;
    assert!(adopted.refused.is_empty(), "{:?}", adopted.refused);
    assert_eq!(
        UserRepo::by_id(&store, user)
            .await
            .expect("a read")
            .expect("the account")
            .name
            .as_deref(),
        Some("Moved")
    );
    assert_eq!(
        DeviceRepo::list(&store, user).await.expect("a read").len(),
        1
    );

    // The vault moving on (any change to the Bitwarden record's revision) counts too.
    BwAccountRepo::touch(&store, user, 9_999_999_999_999)
        .await
        .expect("touched");
    let again = pass(&store, &mapped, false).await;
    assert_eq!(refused(&again, "user-changed"), vec![user.0.to_string()]);
}

#[tokio::test]
async fn an_item_the_api_revised_after_the_source_is_not_overwritten() {
    let store = memory().await;
    let user = UserId::random();
    let item = ItemId::random();
    let mut mapped = MappedImport::default();
    mapped
        .accounts
        .push(account(user, &unique_email("vault"), "Vault"));
    mapped.items.push(cipher(item, Owner::User(user), NOW));
    let first = pass(&store, &mapped, false).await;
    assert_eq!(first.items, 1);

    // A newer revision made here.
    let newer = kemlock_domain::ItemDraft {
        updated_at: NOW + time::Duration::hours(1),
        ..draft(item, Owner::User(user), Some(1), 2)
    };
    let stored = common::put(&store, newer).await;

    let rerun = pass(&store, &mapped, false).await;
    assert_eq!(refused(&rerun, "item"), vec![item.0.to_string()]);
    assert_eq!(rerun.items, 0);
    let after = ItemStore::get(&store, item)
        .await
        .expect("a read")
        .expect("the item");
    assert_eq!(after.revision, stored.revision);
    assert_eq!(after.ciphertext, stored.ciphertext);
}
