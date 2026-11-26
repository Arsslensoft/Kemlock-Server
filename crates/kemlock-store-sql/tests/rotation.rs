//! Rotating the root key: `RotationStore`, staging and the one-transaction install.
//!
//! Each scenario runs on every backend that is available, as `recovery_kits.rs` does: in-memory
//! SQLite, SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{draft, external, file, memory, put, unique_email, user};
use kemlock_app::ports::{ItemStore, UserRepo};
use kemlock_app::recovery_kit::RecoveryKitRepo;
use kemlock_app::rotation::{Install, InstallRequest, RotationError, RotationStore, StagedItem};
use kemlock_domain::{DeviceId, ItemId, Owner, RecoveryKit, Revision, User};
use kemlock_store_sql::SqlStore;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

const T0: OffsetDateTime = datetime!(2026-12-02 10:00:00 UTC);
const ROTATION: [u8; 16] = [7; 16];

fn request() -> InstallRequest {
    InstallRequest {
        rotation: ROTATION,
        from_version: 1,
        to_version: 2,
        public_bundle: vec![8; 3621],
        bundle_signature: vec![9; 3373],
        sealed_private_keys: vec![10; 189],
        sealed_previous_private_keys: vec![11; 189],
        wrapped_root_key: Some(vec![12; 92]),
        kit: None,
        drop_kit: true,
        device_copy: None,
        passkeys: Vec::new(),
        drop_passkeys: Vec::new(),
        emergency: Vec::new(),
        drop_emergency: Vec::new(),
        recovery: Vec::new(),
        drop_recovery: Vec::new(),
        sends: Vec::new(),
        spaces_handled: false,
    }
}

fn install_of(before: &User, request: InstallRequest) -> Install {
    let after = User {
        public_bundle: request.public_bundle.clone(),
        bundle_signature: request.bundle_signature.clone(),
        sealed_private_keys: request.sealed_private_keys.clone(),
        wrapped_root_key: request.wrapped_root_key.clone().unwrap_or_default(),
        key_version: request.to_version,
        security_stamp: Uuid::new_v4(),
        updated_at: T0,
        ..before.clone()
    };
    Install {
        request,
        before: before.clone(),
        after,
        device: DeviceId::random(),
        now: T0,
        staged_since: T0 - time::Duration::hours(2),
    }
}

async fn account(store: &SqlStore) -> User {
    let account = user(&unique_email("rotation"));
    UserRepo::insert(store, &account)
        .await
        .expect("insert user");
    account
}

fn staged(id: ItemId, base: u64) -> StagedItem {
    StagedItem {
        id,
        base_revision: Revision(base),
        ciphertext: vec![0x77; 60],
        item_key: vec![0x66; 60],
    }
}

async fn rotation(store: &SqlStore) {
    let sam = account(store).await;
    let owner = Owner::User(sam.id);
    let (a, b) = (ItemId::random(), ItemId::random());
    put(store, draft(a, owner, None, 1)).await;
    put(store, draft(b, owner, None, 1)).await;
    let kit = RecoveryKit {
        kit_id: "AAAAAAAA".to_owned(),
        wrapped_key: vec![1; 92],
        key_version: 1,
        created_at: T0,
    };
    store
        .insert_recovery_kit(sam.id, &kit)
        .await
        .expect("insert kit");

    // The holdings are what the plan shows.
    let holdings = RotationStore::holdings(store, sam.id)
        .await
        .expect("holdings");
    assert_eq!(holdings.kit.as_deref(), Some("AAAAAAAA"));
    assert_eq!(holdings.live_items.len(), 2);
    assert_eq!(holdings.spaces, 0);

    // An install that stages one of two items is refused, and writes nothing at all.
    assert_eq!(
        RotationStore::stage(
            store,
            sam.id,
            ROTATION,
            vec![staged(a, 1)],
            T0,
            T0 - time::Duration::hours(2)
        )
        .await,
        Ok(1)
    );
    let refused = RotationStore::install(store, install_of(&sam, request())).await;
    assert!(
        matches!(refused, Err(RotationError::Incomplete(_))),
        "{refused:?}"
    );
    assert_eq!(
        UserRepo::by_id(store, sam.id)
            .await
            .expect("read")
            .expect("account")
            .key_version,
        1
    );
    assert_eq!(
        ItemStore::get(store, a)
            .await
            .expect("read")
            .expect("item")
            .revision,
        Revision(1)
    );
    assert_eq!(
        store.recovery_kit(sam.id).await,
        Ok(Some(kit.clone())),
        "the kit is still there"
    );

    // Staging the rest and installing writes everything.
    assert_eq!(
        RotationStore::stage(
            store,
            sam.id,
            ROTATION,
            vec![staged(a, 1), staged(b, 1)],
            T0,
            T0 - time::Duration::hours(2)
        )
        .await,
        Ok(2)
    );
    let change = RotationStore::install(store, install_of(&sam, request()))
        .await
        .expect("the install");
    assert!(
        change.is_some(),
        "the last item written names the change to nudge devices with"
    );
    let after = UserRepo::by_id(store, sam.id)
        .await
        .expect("read")
        .expect("account");
    assert_eq!(after.key_version, 2);
    assert_eq!(after.public_bundle, vec![8; 3621]);
    assert_eq!(after.wrapped_root_key, vec![12; 92]);
    assert_ne!(after.security_stamp, sam.security_stamp);
    for id in [a, b] {
        let item = ItemStore::get(store, id)
            .await
            .expect("read")
            .expect("item");
        assert_eq!(item.revision, Revision(2));
        assert_eq!(item.key_version, 2);
        assert_eq!(item.ciphertext, Some(vec![0x77; 60]));
    }
    assert_eq!(
        store.recovery_kit(sam.id).await,
        Ok(None),
        "the old kit is gone"
    );
    let previous = RotationStore::previous_keys(store, sam.id)
        .await
        .expect("read")
        .expect("the previous keys are kept");
    assert_eq!((previous.key_version, previous.sealed), (1, vec![11; 189]));
    assert_eq!(
        RotationStore::clear_previous_keys(store, sam.id).await,
        Ok(true)
    );
    assert_eq!(
        RotationStore::clear_previous_keys(store, sam.id).await,
        Ok(false)
    );

    // The staged rows are gone: installing again finds nothing staged and the items live.
    let again = RotationStore::install(
        store,
        install_of(
            &after,
            InstallRequest {
                from_version: 2,
                to_version: 3,
                ..request()
            },
        ),
    )
    .await;
    assert!(
        matches!(again, Err(RotationError::Incomplete(_))),
        "{again:?}"
    );
}

async fn a_stale_account_row_writes_nothing(store: &SqlStore) {
    let sam = account(store).await;
    let id = ItemId::random();
    put(store, draft(id, Owner::User(sam.id), None, 1)).await;
    RotationStore::stage(
        store,
        sam.id,
        ROTATION,
        vec![staged(id, 1)],
        T0,
        T0 - time::Duration::hours(2),
    )
    .await
    .expect("stage");
    // The account was written since it was read.
    let mut changed = sam.clone();
    changed.updated_at = datetime!(2026-12-01 00:00:00 UTC);
    UserRepo::update(store, &changed).await.expect("write");
    let result = RotationStore::install(store, install_of(&sam, request())).await;
    assert_eq!(result, Err(RotationError::AccountChanged));
    assert_eq!(
        ItemStore::get(store, id)
            .await
            .expect("read")
            .expect("item")
            .revision,
        Revision(1)
    );
}

async fn staging_is_per_attempt_and_can_be_abandoned(store: &SqlStore) {
    let sam = account(store).await;
    let owner = Owner::User(sam.id);
    let id = ItemId::random();
    put(store, draft(id, owner, None, 1)).await;
    let since = T0 - time::Duration::hours(2);
    assert_eq!(
        RotationStore::stage(store, sam.id, ROTATION, vec![staged(id, 1)], T0, since).await,
        Ok(1)
    );
    // A second attempt discards the first's rows.
    assert_eq!(
        RotationStore::stage(store, sam.id, [8; 16], vec![], T0, since).await,
        Ok(0)
    );
    // Staging the same item twice leaves one row.
    assert_eq!(
        RotationStore::stage(store, sam.id, [8; 16], vec![staged(id, 1)], T0, since).await,
        Ok(1)
    );
    assert_eq!(
        RotationStore::stage(store, sam.id, [8; 16], vec![staged(id, 1)], T0, since).await,
        Ok(1)
    );
    RotationStore::discard(store, sam.id)
        .await
        .expect("discard");
    assert_eq!(
        RotationStore::stage(store, sam.id, [8; 16], vec![], T0, since).await,
        Ok(0)
    );
    // Rows that ran out are ignored and removed.
    assert_eq!(
        RotationStore::stage(
            store,
            sam.id,
            [8; 16],
            vec![staged(id, 1)],
            T0 - time::Duration::hours(3),
            since
        )
        .await,
        Ok(1)
    );
    assert_eq!(
        RotationStore::stage(store, sam.id, [8; 16], vec![], T0, since).await,
        Ok(0)
    );
}

async fn all(store: &SqlStore) {
    rotation(store).await;
    a_stale_account_row_writes_nothing(store).await;
    staging_is_per_attempt_and_can_be_abandoned(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    all(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        all(&store).await;
    }
}
