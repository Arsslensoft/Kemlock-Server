//! Rotating the root key: `RotationStore`, staging and the one-transaction install.
//!
//! Each scenario runs on every backend that is available, as `recovery_kits.rs` does: in-memory
//! SQLite, SQLite in a file, and PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` /
//! `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{draft, external, file, memory, put, unique_email, user};
use kemlock_app::devices::{ApprovalRepo, KeyCopyRepo};
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::passkeys::PasskeyRepo;
use kemlock_app::ports::{DeviceRepo, ItemStore, StoreError, UserRepo};
use kemlock_app::recovery_kit::RecoveryKitRepo;
use kemlock_app::rotation::{Install, InstallRequest, RotationError, RotationStore, StagedItem};
use kemlock_app::sends::SendRepo;
use kemlock_domain::DeviceKind;
use kemlock_domain::sends::{SendId, SendKind, SendRecord};
use kemlock_domain::unlock::{
    ApprovalId, ApprovalState, AuthRequest, DeviceKeyCopy, EmergencyGrant, EmergencyKind,
    EmergencyState, GrantId, KeyProtection, SEALED_BOX_OVERHEAD,
};
use kemlock_domain::{
    DeviceId, Email, ItemId, Owner, Passkey, PasskeyId, PrfWrap, RecoveryKit, Revision, User,
};
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
        signature: None,
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
    let installed = RotationStore::install(store, install_of(&sam, request()))
        .await
        .expect("the install");
    assert!(
        installed.change.is_some(),
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
    // An account in no space has nothing to sign a rekey with: the old keys are not kept.
    assert_eq!(RotationStore::previous_keys(store, sam.id).await, Ok(None));
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

async fn wraps_written_through_the_repos_are_all_seen_and_replaced(store: &SqlStore) {
    let sam = account(store).await;
    // A device copy, a passkey with a PRF wrap and a kit, each written the way the routes write
    // them (each under the account's lock), are what the install must find and replace.
    let phone = common::device(sam.id, "phone", T0);
    DeviceRepo::upsert(store, &phone).await.expect("device");
    store
        .put_key_copy(&DeviceKeyCopy {
            device: phone.id,
            wrapped_key: vec![1; 80],
            protection: KeyProtection::WebCrypto,
            created_at: T0,
            updated_at: T0,
        })
        .await
        .expect("copy");
    let passkey = Passkey {
        id: PasskeyId::random(),
        user: sam.id,
        credential_id: vec![9; 24],
        name: "key".to_owned(),
        credential: vec![8; 32],
        prf_wrap: Some(PrfWrap {
            wrapped_key: vec![2; 92],
            key_version: 1,
        }),
        created_at: T0,
        last_used_at: None,
    };
    PasskeyRepo::insert_passkey(store, &passkey)
        .await
        .expect("passkey");
    let held = RotationStore::holdings(store, sam.id)
        .await
        .expect("holdings");
    assert_eq!(held.device_copies, vec![phone.id]);
    assert_eq!(held.passkeys.len(), 1);

    // Not naming the passkey is refused; naming it replaces its wrap and the device copy goes.
    let refused = RotationStore::install(store, install_of(&sam, request())).await;
    assert!(
        matches!(refused, Err(RotationError::Incomplete(_))),
        "{refused:?}"
    );
    assert!(store.key_copy(phone.id).await.expect("read").is_some());
    let named = InstallRequest {
        passkeys: vec![(passkey.id, vec![3; 92])],
        ..request()
    };
    RotationStore::install(store, install_of(&sam, named))
        .await
        .expect("the install");
    assert_eq!(store.key_copy(phone.id).await, Ok(None));
    let after = PasskeyRepo::passkeys_of(store, sam.id).await.expect("read");
    let wrap = after[0].prf_wrap.clone().expect("a wrap");
    assert_eq!((wrap.wrapped_key, wrap.key_version), (vec![3; 92], 2));
}

async fn an_approval_that_holds_the_old_root_key_does_not_survive_the_install(store: &SqlStore) {
    let sam = account(store).await;
    let answered = AuthRequest {
        id: ApprovalId::random(),
        user: sam.id,
        device: DeviceId::random(),
        device_name: "Firefox on Linux".to_owned(),
        device_kind: DeviceKind::KemlockWeb,
        public_key: vec![7; 1600],
        jkt: "jkt".to_owned(),
        ip: "203.0.113.0/24".to_owned(),
        state: ApprovalState::Approved,
        sealed_key: Some(vec![5; 1700]),
        answered_at: Some(T0),
        created_at: T0,
        expires_at: T0 + time::Duration::minutes(15),
    };
    let waiting = AuthRequest {
        id: ApprovalId::random(),
        state: ApprovalState::Pending,
        sealed_key: None,
        answered_at: None,
        ..answered.clone()
    };
    for request in [&answered, &waiting] {
        ApprovalRepo::insert_request(store, request)
            .await
            .expect("insert request");
    }
    RotationStore::install(store, install_of(&sam, request()))
        .await
        .expect("the install");
    assert_eq!(ApprovalRepo::request(store, answered.id).await, Ok(None));
    // A request that holds nothing is left as it was.
    assert!(
        ApprovalRepo::request(store, waiting.id)
            .await
            .expect("read")
            .is_some()
    );
}

async fn a_grant_that_names_the_account_as_contact_goes_back_to_waiting(store: &SqlStore) {
    let grantor = account(store).await;
    let sam = account(store).await;
    let mut grant = EmergencyGrant::invite(
        GrantId::random(),
        grantor.id,
        Email::parse(sam.email.as_str()).expect("email"),
        EmergencyKind::View,
        7,
        T0,
    )
    .expect("a grant");
    grant.accept(sam.id, T0).expect("accepted");
    grant
        .confirm(vec![3; SEALED_BOX_OVERHEAD + 64], T0)
        .expect("confirmed");
    EmergencyRepo::insert_grant(store, &grant)
        .await
        .expect("grant");

    let held = RotationStore::holdings(store, sam.id)
        .await
        .expect("holdings");
    assert_eq!(held.as_contact, vec![(grant.id, EmergencyState::Confirmed)]);
    assert!(
        held.emergency.is_empty(),
        "the account holds no box of its own for it"
    );

    let installed = RotationStore::install(store, install_of(&sam, request()))
        .await
        .expect("the install");
    assert_eq!(
        installed.reset_grantors,
        vec![grantor.id],
        "the install names the grantor to tell"
    );
    // The grantor's box was sealed to the keys the account no longer has: the grantor confirms
    // again, to the new bundle.
    let after = EmergencyRepo::grant(store, grant.id)
        .await
        .expect("read")
        .expect("the grant");
    assert_eq!(after.state, EmergencyState::Accepted);
    assert_eq!(after.sealed_key, None);
    assert_eq!(after.grantee, Some(sam.id));
}

async fn a_vault_that_takes_signed_writes_only_installs_no_unsigned_item(store: &SqlStore) {
    let sam = account(store).await;
    let owner = Owner::User(sam.id);
    let id = ItemId::random();
    put(store, draft(id, owner, None, 1)).await;
    ItemStore::require_signed_writes(store, owner, T0)
        .await
        .expect("the owner asked");
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
    // The staged item carries no signature: nothing is installed, the account stays as it was.
    let result = RotationStore::install(store, install_of(&sam, request())).await;
    assert_eq!(
        result,
        Err(RotationError::App(kemlock_app::AppError::Item(
            kemlock_domain::ItemError::SignatureRequired
        )))
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
        ItemStore::get(store, id)
            .await
            .expect("read")
            .expect("item")
            .revision,
        Revision(1)
    );
    // An item that isn't signed-only is installed as before.
    ItemStore::clear_signed_writes(store, owner)
        .await
        .expect("cleared");
    RotationStore::install(store, install_of(&sam, request()))
        .await
        .expect("the install");
}

/// A wrap written while an install runs, on every backend (on PostgreSQL and MySQL the two really
/// take row locks; on SQLite the one writer connection orders them). Whichever goes first, the
/// outcome is one of two consistent states, never a hang, a lost write or a wrap of the old key:
///
/// - the writer committed first: the install reads the wrap under the account's lock, finds a
///   wrap its request does not name, and is refused (`Incomplete`) with nothing written; the
///   client reads the plan again, names the wrap, and the second install replaces it;
/// - the install committed first: the writer waited for its commit, read the account's new key
///   version under the lock, and was refused (`StaleKeyVersion`) with nothing written.
///
/// The rounds run on accounts of their own, so a database that holds earlier runs is fine.
async fn a_wrap_written_while_the_install_runs_is_replaced_or_refused(store: &SqlStore) {
    for round in 0..6 {
        let sam = account(store).await;
        let passkey = Passkey {
            id: PasskeyId::random(),
            user: sam.id,
            credential_id: Uuid::new_v4().as_bytes().to_vec(),
            name: format!("racing {round}"),
            credential: vec![8; 32],
            prf_wrap: Some(PrfWrap {
                wrapped_key: vec![2; 92],
                key_version: 1,
            }),
            created_at: T0,
            last_used_at: None,
        };
        let (written, installed) = tokio::join!(
            PasskeyRepo::insert_passkey(store, &passkey),
            RotationStore::install(store, install_of(&sam, request())),
        );

        let account_after = UserRepo::by_id(store, sam.id)
            .await
            .expect("read")
            .expect("account");
        let held = PasskeyRepo::passkeys_of(store, sam.id)
            .await
            .expect("read");

        match installed {
            Err(RotationError::Incomplete(_)) => {
                written.expect("the writer committed first");
                assert_eq!(account_after.key_version, 1, "round {round}: nothing written");
                assert_eq!(account_after.public_bundle, sam.public_bundle);
                assert_eq!(account_after.security_stamp, sam.security_stamp);
                assert_eq!(held.len(), 1, "round {round}");
                let wrap = held[0].prf_wrap.clone().expect("a wrap");
                assert_eq!((wrap.wrapped_key, wrap.key_version), (vec![2; 92], 1));
                // Reading the plan again and naming the wrap installs, and replaces it.
                let named = InstallRequest {
                    passkeys: vec![(passkey.id, vec![3; 92])],
                    ..request()
                };
                RotationStore::install(store, install_of(&sam, named))
                    .await
                    .expect("the install that names the wrap");
                let held = PasskeyRepo::passkeys_of(store, sam.id)
                    .await
                    .expect("read");
                let wrap = held[0].prf_wrap.clone().expect("a wrap");
                assert_eq!(
                    (wrap.wrapped_key, wrap.key_version),
                    (vec![3; 92], 2),
                    "round {round}: no wrap of the old key is left"
                );
            }
            Ok(_) => {
                assert_eq!(account_after.key_version, 2, "round {round}");
                assert_ne!(account_after.security_stamp, sam.security_stamp);
                // The writer waited for the install and met the new key version: refused, and
                // no wrap of the old key is left.
                assert_eq!(
                    written,
                    Err(StoreError::StaleKeyVersion { current: 2 }),
                    "round {round}"
                );
                assert!(held.is_empty(), "round {round}: the refused passkey was not kept");
            }
            Err(other) => panic!("round {round}: the install failed another way: {other:?}"),
        }
    }
}

/// After an install, a wrap for the old key version is refused whichever way it is written, and
/// one for the new version is kept.
async fn a_wrap_for_the_old_key_version_is_refused_after_the_install(store: &SqlStore) {
    let sam = account(store).await;
    RotationStore::install(store, install_of(&sam, request()))
        .await
        .expect("the install");
    let stale = StoreError::StaleKeyVersion { current: 2 };

    let passkey = |version: u32| Passkey {
        id: PasskeyId::random(),
        user: sam.id,
        credential_id: Uuid::new_v4().as_bytes().to_vec(),
        name: "key".to_owned(),
        credential: vec![8; 32],
        prf_wrap: Some(PrfWrap {
            wrapped_key: vec![2; 92],
            key_version: version,
        }),
        created_at: T0,
        last_used_at: None,
    };
    assert_eq!(
        PasskeyRepo::insert_passkey(store, &passkey(1)).await,
        Err(stale.clone())
    );
    let current = passkey(2);
    PasskeyRepo::insert_passkey(store, &current)
        .await
        .expect("a wrap for the current version");
    let old = PrfWrap {
        wrapped_key: vec![5; 92],
        key_version: 1,
    };
    assert_eq!(
        PasskeyRepo::set_passkey_wrap(store, sam.id, current.id, Some(&old)).await,
        Err(stale.clone())
    );
    let held = PasskeyRepo::passkeys_of(store, sam.id).await.expect("read");
    assert_eq!(held.len(), 1, "only the passkey of the current version");
    assert_eq!(held[0].prf_wrap, current.prf_wrap);

    let kit = |version: u32| RecoveryKit {
        kit_id: "AAAAAAAA".to_owned(),
        wrapped_key: vec![1; 92],
        key_version: version,
        created_at: T0,
    };
    assert_eq!(
        store.insert_recovery_kit(sam.id, &kit(1)).await,
        Err(stale.clone())
    );
    assert_eq!(store.recovery_kit(sam.id).await, Ok(None));
    assert_eq!(store.insert_recovery_kit(sam.id, &kit(2)).await, Ok(true));
    assert_eq!(
        store.replace_recovery_kit(sam.id, &kit(1)).await,
        Err(stale.clone())
    );

    // A device copy says which version it was made for, when the client says.
    let phone = common::device(sam.id, "phone", T0);
    DeviceRepo::upsert(store, &phone).await.expect("device");
    let copy = DeviceKeyCopy {
        device: phone.id,
        wrapped_key: vec![1; 80],
        protection: KeyProtection::WebCrypto,
        created_at: T0,
        updated_at: T0,
    };
    assert_eq!(
        store.put_key_copy_at(&copy, Some(1)).await,
        Err(stale.clone())
    );
    assert_eq!(store.key_copy(phone.id).await, Ok(None));
    store
        .put_key_copy_at(&copy, Some(2))
        .await
        .expect("a copy for the current version");

    // A Send is sealed for the version its sealed key says; an edit says which it was made for.
    let send = SendRecord {
        id: SendId::random(),
        owner: sam.id,
        kind: SendKind::Text,
        meta: vec![1; 40],
        sealed_key: vec![2; 64],
        payload: vec![3; 60],
        file: None,
        password: None,
        max_access: None,
        access_count: 0,
        hide_email: false,
        disabled: false,
        expires_at: None,
        deletion_at: T0 + time::Duration::days(7),
        created_at: T0,
        revised_at: T0,
    };
    assert_eq!(
        SendRepo::add_send_within_quota_at(store, &send, None, Some(1)).await,
        Err(stale.clone())
    );
    assert_eq!(SendRepo::send_by_id(store, send.id).await, Ok(None));
    assert_eq!(
        SendRepo::add_send_within_quota_at(store, &send, None, Some(2)).await,
        Ok(Ok(()))
    );
    assert_eq!(
        SendRepo::update_send_at(store, &send, Some(1)).await,
        Err(stale)
    );
    SendRepo::update_send_at(store, &send, Some(2))
        .await
        .expect("an edit for the current version");
    SendRepo::update_send_at(store, &send, None)
        .await
        .expect("an old client says no version");
}

async fn all(store: &SqlStore) {
    a_vault_that_takes_signed_writes_only_installs_no_unsigned_item(store).await;
    rotation(store).await;
    a_stale_account_row_writes_nothing(store).await;
    staging_is_per_attempt_and_can_be_abandoned(store).await;
    wraps_written_through_the_repos_are_all_seen_and_replaced(store).await;
    an_approval_that_holds_the_old_root_key_does_not_survive_the_install(store).await;
    a_grant_that_names_the_account_as_contact_goes_back_to_waiting(store).await;
    a_wrap_written_while_the_install_runs_is_replaced_or_refused(store).await;
    a_wrap_for_the_old_key_version_is_refused_after_the_install(store).await;
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
