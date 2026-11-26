//! Erasure reaches federated peers on SQL: a home that erases an account queues the erasure for
//! each replica of its vault, in the erasing transaction, and a replica deletes its copy (items,
//! offer, settings, a copied account) when its home says so.

mod common;

use common::{MADE_AT, draft, memory, put, unique_email, user};
use kemlock_app::dedup::TagStore;
use kemlock_app::ports::{DeviceRepo, ItemStore, ServerInfo, UserRepo};
use kemlock_app::privacy::{AccountEraser, PrivacyLog};
use kemlock_domain::{
    DedupTag, DeviceId, DeviceKind, ItemId, Owner, Revision, ServerId, TagSet, User, UserId,
};
use kemlock_federation::eventsync::{EventSync, LogEntry};
use kemlock_federation::extra::{
    ErasureOutbox, FedAdminRepo, MemberApply, MemberStore, StoredOffer, VaultErasure,
};
use kemlock_federation::home::VaultFederation;
use kemlock_federation::members::{MemberAccount, MemberDevice};
use kemlock_federation::message::OfferState;
use kemlock_federation::ports::{PeerRepo, VaultRepo};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;

async fn account_with_items(store: &SqlStore, name: &str, items: usize) -> (User, Vec<ItemId>) {
    let account = user(&unique_email(name));
    UserRepo::insert(store, &account).await.expect("account");
    let mut ids = Vec::new();
    for _ in 0..items {
        let id = ItemId::random();
        put(store, draft(id, Owner::User(account.id), None, 1)).await;
        ids.push(id);
    }
    (account, ids)
}

async fn events_named(store: &SqlStore, action: &str) -> usize {
    PrivacyLog::events_between(
        store,
        datetime!(2000-01-01 0:00 UTC),
        datetime!(2100-01-01 0:00 UTC),
    )
    .await
    .expect("events")
    .iter()
    .filter(|e| e.action == action)
    .count()
}

#[tokio::test]
async fn erasing_an_account_queues_the_erasure_for_each_replica_of_a_vault_it_is_the_home_of() {
    let store = memory().await;
    let me = ServerInfo::server_id(&store);
    let (ada, _) = account_with_items(&store, "ada", 2).await;
    let (bob, _) = account_with_items(&store, "bob", 1).await;
    let (kim, _) = account_with_items(&store, "kim", 1).await;
    let (first, second) = (ServerId::random(), ServerId::random());
    let elsewhere = ServerId::random();
    // Ada's vault is federated with two replicas and this server as its home; Bob's has another
    // home (this server holds a copy); Kim's never leaves.
    store
        .put_vault(&VaultFederation::federated(
            Owner::User(ada.id),
            me,
            vec![first, second],
        ))
        .await
        .expect("settings");
    store
        .put_vault(&VaultFederation::federated(
            Owner::User(bob.id),
            elsewhere,
            vec![me],
        ))
        .await
        .expect("settings");
    store
        .put_vault(&VaultFederation::local(Owner::User(kim.id), me))
        .await
        .expect("settings");

    for account in [&ada, &bob, &kim] {
        AccountEraser::erase_user(&store, account)
            .await
            .expect("the erasure works");
    }

    for peer in [first, second] {
        let pending = store.pending_erasures(peer).await.expect("pending");
        assert_eq!(pending.len(), 1, "{peer}");
        assert_eq!(pending[0].vault, Owner::User(ada.id));
        assert_eq!(pending[0].peer, peer);
    }
    assert!(
        store
            .pending_erasures(elsewhere)
            .await
            .expect("pending")
            .is_empty(),
        "a vault another server is the home of is that server's to tell"
    );
    assert!(
        store
            .pending_erasures(me)
            .await
            .expect("pending")
            .is_empty(),
        "nor is a local vault told to anyone"
    );
    // The vault's settings went with it, so only the queue remembers who holds a copy.
    assert_eq!(store.get_vault(Owner::User(ada.id)).await, Ok(None));

    // A peer that acknowledges is done, once, and the others still wait.
    ErasureOutbox::complete_erasure(&store, first, Owner::User(ada.id))
        .await
        .expect("completed");
    ErasureOutbox::complete_erasure(&store, first, Owner::User(ada.id))
        .await
        .expect("completed again");
    assert!(
        store
            .pending_erasures(first)
            .await
            .expect("pending")
            .is_empty()
    );
    assert_eq!(
        store.pending_erasures(second).await.expect("pending").len(),
        1
    );
    assert_eq!(
        events_named(&store, "federation.erasure_forwarded").await,
        1,
        "logged once, for the acknowledgement that mattered"
    );
}

#[tokio::test]
async fn removing_a_peer_drops_what_it_was_still_to_be_told() {
    let store = memory().await;
    let me = ServerInfo::server_id(&store);
    let (ada, _) = account_with_items(&store, "ada", 1).await;
    let peer = ServerId::random();
    store
        .put_vault(&VaultFederation::federated(
            Owner::User(ada.id),
            me,
            vec![peer],
        ))
        .await
        .expect("settings");
    AccountEraser::erase_user(&store, &ada)
        .await
        .expect("the erasure works");
    assert_eq!(
        store.pending_erasures(peer).await.expect("pending").len(),
        1
    );

    store.remove_peer(peer).await.expect("removed");

    assert!(
        store
            .pending_erasures(peer)
            .await
            .expect("pending")
            .is_empty()
    );
}

#[tokio::test]
async fn a_replica_deletes_its_copy_of_an_erased_vault_and_the_copied_account() {
    let store = memory().await;
    let me = ServerInfo::server_id(&store);
    let home = ServerId::random();
    let owner = UserId::random();
    let vault = Owner::User(owner);
    // The account lives here only as a copy of the home's, with a device and some items.
    let template = user(&unique_email("ada"));
    let copy = MemberAccount {
        id: owner,
        email: template.email.as_str().to_owned(),
        name: template.name.clone(),
        mode: template.mode,
        kdf: template.kdf.clone(),
        wrapped_root_key: template.wrapped_root_key.clone(),
        public_bundle: template.public_bundle.clone(),
        bundle_signature: template.bundle_signature.clone(),
        sealed_private_keys: template.sealed_private_keys.clone(),
        key_version: template.key_version,
        created_at: MADE_AT.unix_timestamp(),
        updated_at: MADE_AT.unix_timestamp(),
        devices: vec![MemberDevice {
            id: DeviceId::random(),
            name: "Pixel".to_owned(),
            kind: DeviceKind::KemlockAndroid,
            dpop_jkt: Some("jkt".to_owned()),
            created_at: MADE_AT.unix_timestamp(),
        }],
    };
    assert_eq!(
        store.apply_member_account(vault, home, &copy).await,
        Ok(MemberApply::Applied)
    );
    let first = ItemId::random();
    let second = ItemId::random();
    put(&store, draft(first, vault, None, 1)).await;
    put(&store, draft(second, vault, None, 1)).await;
    store
        .put_vault(&VaultFederation::federated(vault, home, vec![me]))
        .await
        .expect("settings");
    store
        .put_offer(&StoredOffer {
            vault,
            home,
            epoch: 1,
            replicas: vec![me],
            state: OfferState::Accepted,
            received_at: 1_800_000_000,
        })
        .await
        .expect("offer");
    // Another account's vault on this server must survive.
    let (other, other_items) = account_with_items(&store, "bob", 1).await;

    let erased = VaultErasure::erase_vault(&store, vault)
        .await
        .expect("the copy is erased");

    assert_eq!(erased.items, 2);
    assert_eq!(erased.accounts, 1);
    assert_eq!(ItemStore::get(&store, first).await, Ok(None));
    assert_eq!(ItemStore::get(&store, second).await, Ok(None));
    assert_eq!(store.get_vault(vault).await, Ok(None));
    assert_eq!(store.offer(vault).await, Ok(None));
    assert_eq!(UserRepo::by_id(&store, owner).await, Ok(None));
    assert_eq!(DeviceRepo::list(&store, owner).await, Ok(Vec::new()));
    assert!(!store.is_replica_account(owner).await.expect("a read"));
    assert!(
        UserRepo::by_id(&store, other.id)
            .await
            .expect("a read")
            .is_some()
    );
    assert!(
        ItemStore::get(&store, other_items[0])
            .await
            .expect("a read")
            .is_some()
    );
    assert_eq!(events_named(&store, "federation.vault_erased").await, 1);
}

#[tokio::test]
async fn a_replica_never_erases_an_account_that_lives_on_it() {
    let store = memory().await;
    let (ada, items) = account_with_items(&store, "ada", 2).await;

    // Asked to erase the vault of an account that is this server's own (no copy marker), it
    // refuses and deletes nothing: a peer that became the vault's home (an admin here accepted a
    // promotion) can't wipe a local user's items with an Erase.
    // The refusal is the one the replica turns into an answer the home takes as final.
    let refused = VaultErasure::erase_vault(&store, Owner::User(ada.id)).await;
    assert_eq!(refused, Err(kemlock_app::ports::StoreError::Duplicate));

    for item in &items {
        assert!(
            ItemStore::get(&store, *item)
                .await
                .expect("a read")
                .is_some(),
            "the item stays"
        );
    }
    assert!(
        UserRepo::by_id(&store, ada.id)
            .await
            .expect("a read")
            .is_some(),
        "the account row stays"
    );
}

/// The number of rows in `table`, read through a connection of its own.
async fn rows_in(url: &str, table: &str) -> i64 {
    let db = sea_orm::Database::connect(url)
        .await
        .expect("a raw connection");
    let row = sea_orm::ConnectionTrait::query_one_raw(
        &db,
        sea_orm::Statement::from_string(
            sea_orm::DbBackend::Sqlite,
            format!("SELECT COUNT(*) AS n FROM {table}"),
        ),
    )
    .await
    .expect("a query")
    .expect("a count row");
    let count: i64 = row.try_get("", "n").expect("a count");
    db.close().await.expect("closed");
    count
}

fn log_entry(n: u8) -> LogEntry {
    let mut id = [0u8; 16];
    id[15] = n;
    LogEntry {
        id,
        at_ms: 1_800_000_000_000 + u64::from(n),
        actor: None,
        device: None,
        action: "login".to_owned(),
        target: None,
    }
}

#[tokio::test]
async fn erasing_a_replica_vault_clears_its_event_log_tags_and_matching_switch() {
    let (store, dir) = common::file().await;
    let url = common::file_url(&dir.path().join("kemlock.db"));
    let peer = ServerId::random();
    let (ada, ada_items) = account_with_items(&store, "ada", 1).await;
    let (bob, bob_items) = account_with_items(&store, "bob", 1).await;
    let (vault, other) = (Owner::User(ada.id), Owner::User(bob.id));
    let tags = TagSet::new(1, [DedupTag([7; 32])]).expect("a small set");
    for (owner, by, item, n) in [
        (vault, ada.id, ada_items[0], 1),
        (other, bob.id, bob_items[0], 2),
    ] {
        EventSync::store_peer_events(&store, peer, owner, &[log_entry(n)])
            .await
            .expect("an event is kept");
        TagStore::set_matching(&store, owner, true, by, MADE_AT)
            .await
            .expect("matching is on");
        assert!(
            TagStore::put_tags(&store, owner, item, Revision(1), &tags)
                .await
                .expect("tags are stored")
        );
    }
    for table in ["peer_events", "item_tags", "dedup_owners"] {
        assert_eq!(rows_in(&url, table).await, 2, "{table} before");
    }

    VaultErasure::erase_vault(&store, vault)
        .await
        .expect("the vault is erased");

    // Only the other vault's row is left in each table.
    for table in ["peer_events", "item_tags", "dedup_owners"] {
        assert_eq!(rows_in(&url, table).await, 1, "{table} after");
    }
    assert!(
        EventSync::peer_events(&store, vault, 10)
            .await
            .expect("a read")
            .is_empty()
    );
    assert!(
        !TagStore::settings(&store, vault)
            .await
            .expect("settings")
            .enabled
    );
    assert_eq!(
        EventSync::peer_events(&store, other, 10)
            .await
            .expect("a read")
            .len(),
        1
    );
}

fn copy_of(id: UserId, email: &str) -> MemberAccount {
    let template = user(email);
    MemberAccount {
        id,
        email: template.email.as_str().to_owned(),
        name: template.name.clone(),
        mode: template.mode,
        kdf: template.kdf.clone(),
        wrapped_root_key: template.wrapped_root_key.clone(),
        public_bundle: template.public_bundle.clone(),
        bundle_signature: template.bundle_signature.clone(),
        sealed_private_keys: template.sealed_private_keys.clone(),
        key_version: template.key_version,
        created_at: MADE_AT.unix_timestamp(),
        updated_at: MADE_AT.unix_timestamp(),
        devices: Vec::new(),
    }
}

#[tokio::test]
async fn a_copied_account_follows_the_home_it_came_from_and_no_other() {
    let store = memory().await;
    let first_home = ServerId::random();
    let other_home = ServerId::random();
    let space = Owner::Space(kemlock_domain::SpaceId::random());
    let id = UserId::random();
    let email = unique_email("ada");
    let mut copy = copy_of(id, &email);
    assert_eq!(
        store.apply_member_account(space, first_home, &copy).await,
        Ok(MemberApply::Applied)
    );

    // Another server's home record can't replace the copy: not its keys, not its devices.
    let mut takeover = copy.clone();
    takeover.wrapped_root_key = vec![0xEE; 100];
    takeover.devices = vec![MemberDevice {
        id: DeviceId::random(),
        name: "Thief".to_owned(),
        kind: DeviceKind::KemlockAndroid,
        dpop_jkt: Some("thief-jkt".to_owned()),
        created_at: MADE_AT.unix_timestamp(),
    }];
    assert_eq!(
        store
            .apply_member_account(space, other_home, &takeover)
            .await,
        Ok(MemberApply::Refused)
    );
    let kept = UserRepo::by_id(&store, id)
        .await
        .expect("a read")
        .expect("the copy");
    assert_eq!(kept.wrapped_root_key, copy.wrapped_root_key);
    assert!(
        DeviceRepo::list(&store, id)
            .await
            .expect("devices")
            .is_empty()
    );

    // The home it came from still updates it.
    copy.wrapped_root_key = vec![0x11; 100];
    assert_eq!(
        store.apply_member_account(space, first_home, &copy).await,
        Ok(MemberApply::Applied)
    );
}

#[tokio::test]
async fn a_copied_account_cannot_take_a_device_of_another_account() {
    let store = memory().await;
    let home = ServerId::random();
    // Bob lives on this server, with a device.
    let (bob, _) = account_with_items(&store, "bob", 0).await;
    let device = kemlock_domain::Device {
        id: DeviceId::random(),
        user: bob.id,
        name: "Bob's phone".to_owned(),
        kind: DeviceKind::KemlockAndroid,
        dpop_jkt: Some("bob-jkt".to_owned()),
        created_at: MADE_AT,
        last_seen_at: MADE_AT,
    };
    DeviceRepo::upsert(&store, &device).await.expect("a device");

    // A home publishes an account that lists Bob's device id with its own key.
    let mut copy = copy_of(UserId::random(), &unique_email("eve"));
    copy.devices = vec![MemberDevice {
        id: device.id,
        name: "Mine".to_owned(),
        kind: DeviceKind::KemlockAndroid,
        dpop_jkt: Some("eve-jkt".to_owned()),
        created_at: MADE_AT.unix_timestamp(),
    }];
    store
        .apply_member_account(Owner::Space(kemlock_domain::SpaceId::random()), home, &copy)
        .await
        .expect("the account itself is taken");

    let held = DeviceRepo::get(&store, device.id)
        .await
        .expect("a read")
        .expect("the device");
    assert_eq!(held.user, bob.id, "the device stays Bob's");
    assert_eq!(held.dpop_jkt.as_deref(), Some("bob-jkt"));
    assert!(
        DeviceRepo::list(&store, copy.id)
            .await
            .expect("devices")
            .is_empty()
    );
}

#[tokio::test]
async fn the_home_of_a_personal_vault_speaks_for_its_account_not_the_home_of_a_space() {
    let store = memory().await;
    let me = ServerInfo::server_id(&store);
    let (space_home, personal_home) = (ServerId::random(), ServerId::random());
    let space = Owner::Space(kemlock_domain::SpaceId::random());
    let victim = UserId::random();
    let personal = Owner::User(victim);
    let email = unique_email("victim");

    // Before this server federates the victim's vault, a space home may create the copy.
    let mut forged = copy_of(victim, &email);
    forged.public_bundle = vec![0xAA; 50];
    assert_eq!(
        store.apply_member_account(space, space_home, &forged).await,
        Ok(MemberApply::Applied)
    );

    // Then the victim's own home offers the vault and this server accepts it. From now on the
    // space home can't touch the copy, and the personal home replaces what the space home made.
    store
        .put_vault(&VaultFederation::federated(
            personal,
            personal_home,
            vec![me],
        ))
        .await
        .expect("settings");
    let mut hostile = forged.clone();
    hostile.wrapped_root_key = vec![0xEE; 90];
    assert_eq!(
        store
            .apply_member_account(space, space_home, &hostile)
            .await,
        Ok(MemberApply::Refused)
    );
    let real = copy_of(victim, &email);
    assert_eq!(
        store
            .apply_member_account(personal, personal_home, &real)
            .await,
        Ok(MemberApply::Applied)
    );
    let kept = UserRepo::by_id(&store, victim)
        .await
        .expect("a read")
        .expect("the copy");
    assert_eq!(kept.public_bundle, real.public_bundle);
    // And it is the personal home's now: the space home is still refused.
    assert_eq!(
        store.apply_member_account(space, space_home, &forged).await,
        Ok(MemberApply::Refused)
    );

    // A space home can't create a copy of an account whose personal vault is federated here.
    let other = UserId::random();
    store
        .put_vault(&VaultFederation::federated(
            Owner::User(other),
            personal_home,
            vec![me],
        ))
        .await
        .expect("settings");
    assert_eq!(
        store
            .apply_member_account(space, space_home, &copy_of(other, &unique_email("o")))
            .await,
        Ok(MemberApply::Refused)
    );
}
