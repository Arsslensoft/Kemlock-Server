//! The use cases behind the app's sync client: signed manifests, the device list with per-API use,
//! one device row for both APIs, and the one-time move of a Compatible account to OPAQUE.

mod fakes;

use fakes::*;
use kemlock_app::account_keys::AccountKeys;
use kemlock_app::api_use::{ListDevices, RecordApiUse, USE_GRANULARITY};
use kemlock_app::bitwarden::BwAccount;
use kemlock_app::bitwarden::enrol::{
    BitwardenEnrol, BwPasswordCheck, EnrolFinishInput, EnrolStartInput,
};
use kemlock_app::devices::{KeyCopyRepo, bitwarden_device_id};
use kemlock_app::manifests::{
    GetManifest, ManifestError, ManifestHeader, ManifestVerifier, OwnVault, PutManifest,
    PutManifestInput,
};
use kemlock_app::ports::{
    Clock, CryptoError, DeviceRepo, RefreshToken, TokenRepo, TwoFactorMethod, TwoFactorRepo,
};
use kemlock_app::{Actor, AppError, DeviceInfo, SignedIn};
use kemlock_domain::api_use::ApiKind;
use kemlock_domain::manifest::SignedManifest;
use kemlock_domain::unlock::{DeviceKeyCopy, KeyProtection};
use kemlock_domain::{
    AccountMode, Device, DeviceId, DeviceKind, KdfParams, Owner, SpaceId, UserId,
};
use time::Duration;
use uuid::Uuid;

const EMAIL: &str = "sam@example.org";
const BW_HASH: &str = "the-bitwarden-master-password-hash";
const JKT: &str = "jkt-1";

// ---------------------------------------------------------------------------------------------
// Signed manifests.

/// Reads the manifest of these tests: the owner's 17 bytes, the counter as 8 bytes, and nothing
/// else. A signature of `GOOD` bytes verifies.
#[derive(Clone, Copy)]
struct FakeVerifier;

const GOOD: u8 = 0x5a;

fn manifest_bytes(owner: Owner, counter: u64) -> Vec<u8> {
    let mut bytes = owner.to_bytes().to_vec();
    bytes.extend_from_slice(&counter.to_be_bytes());
    bytes
}

fn good_signature() -> Vec<u8> {
    vec![GOOD; SignedManifest::SIGNATURE_LEN]
}

impl ManifestVerifier for FakeVerifier {
    fn verify(
        &self,
        bundle: &[u8],
        manifest: &[u8],
        signature: &[u8],
    ) -> Result<ManifestHeader, CryptoError> {
        if bundle.is_empty() || manifest.len() != 25 || signature.iter().any(|b| *b != GOOD) {
            return Err(CryptoError::Invalid);
        }
        let mut owner = [0u8; 17];
        owner.copy_from_slice(&manifest[..17]);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&manifest[17..]);
        Ok(ManifestHeader {
            owner: Owner::from_bytes(&owner).ok_or(CryptoError::Invalid)?,
            counter: u64::from_be_bytes(counter),
        })
    }
}

fn put_manifest(
    world: &World,
) -> PutManifest<FakeStore, FakeStore, FakeVerifier, FakeEnv, OwnVault> {
    PutManifest {
        manifests: world.store.clone(),
        users: world.store.clone(),
        verifier: FakeVerifier,
        clock: world.env.clone(),
        access: OwnVault,
    }
}

fn manifest_input(owner: Owner, counter: u64) -> PutManifestInput {
    PutManifestInput {
        owner,
        bytes: manifest_bytes(owner, counter),
        signature: good_signature(),
    }
}

async fn account() -> (World, UserId, Actor) {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let me = actor(user);
    (world, user, me)
}

#[tokio::test]
async fn a_signed_manifest_is_stored_with_its_signer_and_read_back() {
    let (world, user, me) = account().await;
    let owner = Owner::User(user);

    let stored = put_manifest(&world)
        .execute(&me, manifest_input(owner, 4))
        .await
        .expect("stores");
    assert_eq!(stored.counter, 4);
    assert_eq!(stored.signer, user);
    assert_eq!(stored.bytes, manifest_bytes(owner, 4));
    assert_eq!(stored.stored_at, world.env.now());

    let got = GetManifest {
        manifests: world.store.clone(),
        access: OwnVault,
    }
    .execute(&me, owner)
    .await
    .expect("reads");
    assert_eq!(got, stored);
}

#[tokio::test]
async fn a_counter_not_above_the_stored_one_is_stale() {
    let (world, user, me) = account().await;
    let owner = Owner::User(user);
    put_manifest(&world)
        .execute(&me, manifest_input(owner, 5))
        .await
        .expect("stores");

    for counter in [5, 4, 0] {
        let refused = put_manifest(&world)
            .execute(&me, manifest_input(owner, counter))
            .await;
        assert_eq!(
            refused.map(|_| ()),
            Err(ManifestError::Stale { current: 5 })
        );
    }
    assert_eq!(world.store.manifest_of(owner).expect("stored").counter, 5);

    put_manifest(&world)
        .execute(&me, manifest_input(owner, 6))
        .await
        .expect("a higher counter is accepted");
    assert_eq!(world.store.manifest_of(owner).expect("stored").counter, 6);
}

#[tokio::test]
async fn a_manifest_that_does_not_verify_or_names_another_owner_is_refused() {
    let (world, user, me) = account().await;
    let owner = Owner::User(user);

    let mut forged = manifest_input(owner, 1);
    forged.signature = vec![0x11; SignedManifest::SIGNATURE_LEN];
    let refused = put_manifest(&world).execute(&me, forged).await;
    assert!(matches!(
        refused,
        Err(ManifestError::App(AppError::Invalid(_)))
    ));

    // Signed rightly, but for a space: the bytes and the route disagree.
    let mut mismatched = manifest_input(owner, 1);
    mismatched.bytes = manifest_bytes(Owner::Space(SpaceId::random()), 1);
    let refused = put_manifest(&world).execute(&me, mismatched).await;
    assert!(matches!(
        refused,
        Err(ManifestError::App(AppError::Invalid(_)))
    ));
    assert_eq!(world.store.manifest_of(owner), None, "nothing was stored");
}

#[tokio::test]
async fn sizes_counters_and_owners_are_checked_before_anything_is_stored() {
    let (world, user, me) = account().await;
    let owner = Owner::User(user);
    let invalid = |r: Result<SignedManifest, ManifestError>| {
        matches!(r, Err(ManifestError::App(AppError::Invalid(_))))
    };

    let mut short_signature = manifest_input(owner, 1);
    short_signature.signature.truncate(100);
    assert!(invalid(
        put_manifest(&world).execute(&me, short_signature).await
    ));

    let mut empty = manifest_input(owner, 1);
    empty.bytes.clear();
    assert!(invalid(put_manifest(&world).execute(&me, empty).await));

    let mut huge = manifest_input(owner, 1);
    huge.bytes = vec![0; SignedManifest::MAX_BYTES + 1];
    assert!(invalid(put_manifest(&world).execute(&me, huge).await));

    let too_far = manifest_input(owner, SignedManifest::MAX_COUNTER + 1);
    assert!(invalid(put_manifest(&world).execute(&me, too_far).await));

    let space = Owner::Space(SpaceId::random());
    assert!(invalid(
        put_manifest(&world)
            .execute(&me, manifest_input(space, 1))
            .await
    ));

    let someone_else = Owner::User(UserId::random());
    let refused = put_manifest(&world)
        .execute(&me, manifest_input(someone_else, 1))
        .await;
    assert_eq!(
        refused.map(|_| ()),
        Err(ManifestError::App(AppError::Forbidden))
    );
    assert_eq!(world.store.manifest_of(owner), None);
}

#[tokio::test]
async fn an_account_with_no_published_keys_cannot_store_a_manifest() {
    let (world, user, me) = account().await;
    let mut bare = world.store.user(user).expect("the account");
    bare.public_bundle.clear();
    world.store.put_user(bare);
    let refused = put_manifest(&world)
        .execute(&me, manifest_input(Owner::User(user), 1))
        .await;
    assert!(matches!(
        refused,
        Err(ManifestError::App(AppError::Invalid(_)))
    ));
}

#[tokio::test]
async fn reading_a_manifest_is_for_its_owner_and_needs_one_to_exist() {
    let (world, user, me) = account().await;
    let get = GetManifest {
        manifests: world.store.clone(),
        access: OwnVault,
    };
    assert_eq!(
        get.execute(&me, Owner::User(user)).await,
        Err(AppError::NotFound)
    );
    assert_eq!(
        get.execute(&me, Owner::User(UserId::random())).await,
        Err(AppError::Forbidden)
    );
}

// ---------------------------------------------------------------------------------------------
// The device list and each API's last use.

async fn signed_in(world: &World, email: &str, info: DeviceInfo, jkt: &str) -> Actor {
    let SignedIn::Tokens(tokens) = sign_in_with(world, email, &PASSWORD, info, jkt)
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    Actor {
        user: tokens.user,
        device: tokens.device,
        admin: false,
    }
}

fn record(world: &World) -> RecordApiUse<FakeStore, FakeEnv> {
    RecordApiUse {
        uses: world.store.clone(),
        clock: world.env.clone(),
    }
}

fn list(world: &World) -> ListDevices<FakeStore, FakeStore, FakeStore> {
    ListDevices {
        devices: world.store.clone(),
        uses: world.store.clone(),
        copies: world.store.clone(),
    }
}

#[tokio::test]
async fn each_api_records_its_own_last_use() {
    let (world, _user, _me) = account().await;
    let phone = signed_in(&world, EMAIL, device("Pixel"), JKT).await;

    let t0 = world.env.now();
    record(&world)
        .execute(phone.device, ApiKind::Bitwarden)
        .await;
    world.env.clock.advance(Duration::hours(1));
    record(&world).execute(phone.device, ApiKind::Kemlock).await;

    let usage = world.store.use_of(phone.device).expect("a row");
    assert_eq!(usage.bitwarden, Some(t0));
    assert_eq!(usage.kemlock, Some(world.env.now()));
}

#[tokio::test]
async fn a_use_inside_the_granularity_does_not_move_and_a_gone_device_is_ignored() {
    let (world, _user, _me) = account().await;
    let phone = signed_in(&world, EMAIL, device("Pixel"), JKT).await;

    let first = world.env.now();
    record(&world).execute(phone.device, ApiKind::Kemlock).await;
    world.env.clock.advance(USE_GRANULARITY / 2);
    record(&world).execute(phone.device, ApiKind::Kemlock).await;
    assert_eq!(
        world.store.use_of(phone.device).expect("a row").kemlock,
        Some(first)
    );
    world.env.clock.advance(USE_GRANULARITY * 2);
    record(&world).execute(phone.device, ApiKind::Kemlock).await;
    assert_eq!(
        world.store.use_of(phone.device).expect("a row").kemlock,
        Some(world.env.now())
    );

    // A device signed out between the token check and the record: nothing happens, nothing fails.
    record(&world)
        .execute(DeviceId::random(), ApiKind::Kemlock)
        .await;
}

#[tokio::test]
async fn the_list_shows_name_kind_times_and_each_apis_use() {
    let (world, user, _me) = account().await;
    let phone = signed_in(&world, EMAIL, device("Pixel"), JKT).await;
    world.env.clock.advance(Duration::hours(1));
    let browser = signed_in(
        &world,
        EMAIL,
        DeviceInfo {
            id: None,
            name: "Firefox".to_owned(),
            kind: DeviceKind::Bitwarden,
            bitwarden_identifier: None,
        },
        "jkt-2",
    )
    .await;
    assert_eq!(browser.user, user);

    // The phone used the Kemlock API; the browser only the Bitwarden API, two hours later.
    record(&world).execute(phone.device, ApiKind::Kemlock).await;
    world.env.clock.advance(Duration::hours(2));
    record(&world)
        .execute(browser.device, ApiKind::Bitwarden)
        .await;
    let bitwarden_use = world.env.now();

    // The phone also keeps a trusted-device copy.
    world
        .store
        .put_key_copy(&DeviceKeyCopy {
            device: phone.device,
            wrapped_key: vec![1; 92],
            protection: KeyProtection::SecureEnclave,
            created_at: world.env.now(),
            updated_at: world.env.now(),
        })
        .await
        .expect("a key copy");

    let entries = list(&world).execute(&phone).await.expect("lists");
    assert_eq!(entries.len(), 2);
    // Most recently seen first: the browser's Bitwarden use is the newest event.
    assert_eq!(entries[0].id, browser.device);
    assert_eq!(entries[0].name, "Firefox");
    assert_eq!(entries[0].kind, DeviceKind::Bitwarden);
    assert_eq!(entries[0].last_bitwarden_use_at, Some(bitwarden_use));
    assert_eq!(entries[0].last_kemlock_use_at, None);
    assert_eq!(entries[0].last_seen_at, bitwarden_use);
    assert!(!entries[0].current && !entries[0].trusted);

    assert_eq!(entries[1].id, phone.device);
    assert_eq!(entries[1].name, "Pixel");
    assert_eq!(entries[1].kind, DeviceKind::KemlockAndroid);
    assert!(entries[1].last_kemlock_use_at.is_some());
    assert_eq!(entries[1].last_bitwarden_use_at, None);
    assert!(entries[1].current && entries[1].trusted);
}

#[tokio::test]
async fn the_list_holds_only_the_callers_devices() {
    let (world, _user, _me) = account().await;
    let phone = signed_in(&world, EMAIL, device("Pixel"), JKT).await;
    make_user(&world, "kim@example.org").await;
    signed_in(&world, "kim@example.org", device("Kims phone"), "jkt-k").await;

    let entries = list(&world).execute(&phone).await.expect("lists");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Pixel");
}

#[tokio::test]
async fn a_device_that_only_ever_used_the_bitwarden_api_is_listed_with_its_use() {
    let (world, user, _me) = account().await;
    let phone = signed_in(&world, EMAIL, device("Pixel"), JKT).await;
    world.env.clock.advance(Duration::hours(1));

    // Two phones the Bitwarden API signed in: no DPoP key, never a request on the Kemlock API.
    // One has a recorded use; the other signed in before uses were recorded.
    let bitwarden_phone = |name: &str| Device {
        id: DeviceId::random(),
        user,
        name: name.to_owned(),
        kind: DeviceKind::Bitwarden,
        dpop_jkt: None,
        created_at: world.env.now(),
        last_seen_at: world.env.now(),
    };
    let recorded = bitwarden_phone("Vaultwarden phone");
    let older = bitwarden_phone("Old Vaultwarden phone");
    for d in [&recorded, &older] {
        DeviceRepo::upsert(&world.store, d).await.expect("stored");
    }
    world.env.clock.advance(Duration::hours(1));
    record(&world)
        .execute(recorded.id, ApiKind::Bitwarden)
        .await;
    let used = world.env.now();

    let entries = list(&world).execute(&phone).await.expect("lists");
    assert_eq!(entries.len(), 3);
    let find = |id: DeviceId| entries.iter().find(|e| e.id == id).expect("listed");
    assert_eq!(find(recorded.id).last_bitwarden_use_at, Some(used));
    assert_eq!(find(recorded.id).last_kemlock_use_at, None);
    assert_eq!(
        find(older.id).last_bitwarden_use_at,
        Some(older.last_seen_at)
    );
    assert_eq!(find(older.id).last_kemlock_use_at, None);
    // The phone that signed in on the Kemlock API is not taken for one of them.
    assert_eq!(find(phone.device).last_bitwarden_use_at, None);
}

// ---------------------------------------------------------------------------------------------
// One device on both APIs.

fn identified(identifier: &str) -> DeviceInfo {
    DeviceInfo {
        id: None,
        name: "Kemlock on Pixel".to_owned(),
        kind: DeviceKind::KemlockAndroid,
        bitwarden_identifier: Some(identifier.to_owned()),
    }
}

/// The Bitwarden API's formula, written out again: `kemlock-api-bw` derives its device ids so.
fn bitwarden_id(user: UserId, identifier: &str) -> DeviceId {
    let mut input = b"kemlock/bitwarden/device".to_vec();
    input.extend_from_slice(user.as_bytes());
    input.extend_from_slice(identifier.as_bytes());
    let digest = kemlock_crypto::hash::sha256(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    DeviceId(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

#[tokio::test]
async fn signing_in_with_a_bitwarden_identifier_uses_the_bitwarden_devices_id() {
    let (world, user, _me) = account().await;
    let identifier = "6c1a1d3e-6d5c-4f3e-9d0e-0a0a0a0a0a0a";
    let phone = signed_in(&world, EMAIL, identified(identifier), JKT).await;

    assert_eq!(phone.device, bitwarden_id(user, identifier));
    assert_eq!(
        phone.device,
        bitwarden_device_id(kemlock_crypto::hash::sha256, user, identifier)
    );
    assert_eq!(world.store.devices_of(user).len(), 1);
}

#[tokio::test]
async fn the_identifier_wins_over_an_id_the_client_kept() {
    let (world, user, _me) = account().await;
    let identifier = "device-identifier";
    let mut info = identified(identifier);
    info.id = Some(DeviceId::random());
    let phone = signed_in(&world, EMAIL, info, JKT).await;
    assert_eq!(phone.device, bitwarden_id(user, identifier));
}

#[tokio::test]
async fn a_device_the_bitwarden_api_made_is_the_same_row_and_keeps_its_tokens() {
    let (world, user, _me) = account().await;
    let identifier = "6c1a1d3e-6d5c-4f3e-9d0e-0a0a0a0a0a0a";
    let id = bitwarden_id(user, identifier);
    let now = world.env.now();

    // What the Bitwarden API wrote at the phone's Vaultwarden sign-in: no DPoP key, one token.
    world
        .store
        .upsert(&Device {
            id,
            user,
            name: "Kemlock".to_owned(),
            kind: DeviceKind::Bitwarden,
            dpop_jkt: None,
            created_at: now,
            last_seen_at: now,
        })
        .await
        .expect("the Bitwarden API's device");
    TokenRepo::insert(
        &world.store,
        &RefreshToken {
            hash: [7; 32],
            family: Uuid::new_v4(),
            user,
            device: id,
            security_stamp: world.store.user(user).expect("the account").security_stamp,
            created_at: now,
            expires_at: now + Duration::days(30),
            used_at: None,
        },
    )
    .await
    .expect("the Bitwarden refresh token");

    let phone = signed_in(&world, EMAIL, identified(identifier), JKT).await;
    assert_eq!(phone.device, id, "one row for both APIs");
    assert_eq!(world.store.devices_of(user).len(), 1);
    let row = world.store.devices_of(user).remove(0);
    assert_eq!(row.dpop_jkt.as_deref(), Some(JKT));
    assert_eq!(row.name, "Kemlock on Pixel");
    assert!(
        world
            .store
            .refresh_tokens()
            .iter()
            .any(|t| t.hash == [7; 32]),
        "binding the first DPoP key must not end the Bitwarden API's session"
    );
}

#[tokio::test]
async fn a_replaced_dpop_key_still_ends_the_old_keys_tokens() {
    let (world, _user, _me) = account().await;
    let identifier = "device-identifier";
    let first = signed_in(&world, EMAIL, identified(identifier), "jkt-old").await;
    assert_eq!(world.store.refresh_tokens().len(), 1);
    let second = signed_in(&world, EMAIL, identified(identifier), "jkt-new").await;
    assert_eq!(first.device, second.device);
    let tokens = world.store.refresh_tokens();
    assert_eq!(tokens.len(), 1, "the old key's token is gone");
}

// ---------------------------------------------------------------------------------------------
// A Compatible account moves to OPAQUE.

#[derive(Clone, Copy)]
struct FakeCheck;

impl BwPasswordCheck for FakeCheck {
    fn matches(&self, secret: &[u8], _salt: &[u8], stored: &[u8], _iterations: u32) -> bool {
        !stored.is_empty() && secret == stored
    }
}

type Enrol = BitwardenEnrol<
    FakeStore,
    FakeStore,
    FakeCheck,
    FakePassword,
    FakeSeal,
    FakeStore,
    FakeTotp,
    FakeStore,
    FakeEnv,
>;

fn enrol(world: &World) -> Enrol {
    BitwardenEnrol {
        users: world.store.clone(),
        accounts: world.store.clone(),
        check: FakeCheck,
        auth: world.password.clone(),
        seal: world.seal.clone(),
        two_factor: world.store.clone(),
        totp: world.totp.clone(),
        events: world.store.clone(),
        env: world.env.clone(),
        config: world.config,
    }
}

fn bw_account(user: UserId) -> BwAccount {
    BwAccount {
        user,
        password_hash: BW_HASH.as_bytes().to_vec(),
        salt: vec![8; 64],
        password_iterations: 600_000,
        kdf_type: 0,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        akey: "2.iv|data|mac".to_owned(),
        private_key: None,
        public_key: None,
        password_hint: None,
        api_key: None,
        avatar_color: None,
        revision_ms: 1_000,
    }
}

/// A copied Vaultwarden account: Compatible, a Bitwarden record, and no OPAQUE record or keys.
async fn compatible_world() -> (World, UserId) {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let mut copied = world.store.user(user).expect("the account");
    copied.mode = AccountMode::Compatible;
    copied.opaque_record = None;
    copied.wrapped_root_key.clear();
    copied.public_bundle.clear();
    copied.bundle_signature.clear();
    copied.sealed_private_keys.clear();
    world.store.put_user(copied);
    world.store.put_bw_account(bw_account(user));
    (world, user)
}

fn start_input(hash: &str, request: Vec<u8>) -> EnrolStartInput {
    EnrolStartInput {
        email: EMAIL.to_owned(),
        master_password_hash: hash.to_owned(),
        request,
        jkt: JKT.to_owned(),
    }
}

fn finish_input(user: UserId, ticket: Vec<u8>, upload: Vec<u8>) -> EnrolFinishInput {
    EnrolFinishInput {
        ticket,
        upload,
        kdf: KdfParams::new_account([4u8; 16]),
        public_bundle: bundle(user),
        bundle_signature: bundle_signature(user),
        sealed_private_keys: vec![0x22; 64],
        wrapped_root_key: vec![0x33; kemlock_app::register::WRAPPED_ROOT_KEY_LEN],
        two_factor_code: None,
        jkt: JKT.to_owned(),
    }
}

/// Runs both enrolment messages with OPAQUE's client side; returns the ticket and the upload.
async fn start_and_upload(world: &World) -> (Vec<u8>, Vec<u8>) {
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let started = enrol(world)
        .start(start_input(BW_HASH, request))
        .await
        .expect("the hash is right");
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &started.response)
            .expect("client finish");
    (started.ticket, upload)
}

#[tokio::test]
async fn a_compatible_account_enrols_opaque_and_signs_in_with_it() {
    let (world, user) = compatible_world().await;
    let before = world.store.user(user).expect("the account");
    let account_before = world.store.bw_account_of(user).expect("bw record");

    let (ticket, upload) = start_and_upload(&world).await;
    let enrolled = enrol(&world)
        .finish(finish_input(user, ticket, upload))
        .await
        .expect("enrols");
    assert_eq!(enrolled, user);

    let after = world.store.user(user).expect("the account");
    assert_eq!(after.mode, AccountMode::Compatible, "it stays Compatible");
    assert!(after.opaque_record.is_some());
    assert_eq!(after.wrapped_root_key, vec![0x33; 92]);
    assert_eq!(after.public_bundle, bundle(user));
    assert_eq!(
        after.security_stamp, before.security_stamp,
        "Bitwarden apps stay signed in"
    );
    assert_eq!(after.email, before.email);
    assert_eq!(world.store.bw_account_of(user), Some(account_before));

    // Now OPAQUE signs it in on /kem/v1.
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), JKT)
        .await
        .expect("OPAQUE signs in")
    else {
        panic!("tokens expected");
    };
    assert_eq!(tokens.user, user);

    let events = world.store.events();
    assert!(events.iter().any(|e| e.action == "auth.bitwarden_enrol"));
}

#[tokio::test]
async fn the_start_answer_names_the_account_and_gives_its_wrapped_user_key() {
    let (world, user) = compatible_world().await;
    let akey = world.store.bw_account_of(user).expect("bw record").akey;
    let request = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client start")
        .1;

    let started = enrol(&world)
        .start(start_input(BW_HASH, request))
        .await
        .expect("the hash is right");

    assert_eq!(started.user, user);
    assert_eq!(
        started.key, akey,
        "the Bitwarden user key, wrapped as stored"
    );
}

#[tokio::test]
async fn the_hash_is_checked_and_answers_never_tell_accounts_apart() {
    let (world, _user) = compatible_world().await;
    let request = || {
        kemlock_crypto::opaque::client_registration_start(&PASSWORD)
            .expect("client start")
            .1
    };

    let wrong = enrol(&world)
        .start(start_input("another-hash", request()))
        .await;
    assert_eq!(wrong.map(|_| ()), Err(AppError::Unauthorized));

    let mut unknown = start_input(BW_HASH, request());
    unknown.email = "nobody@example.org".to_owned();
    assert_eq!(
        enrol(&world).start(unknown).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    let empty = enrol(&world).start(start_input("", request())).await;
    assert!(matches!(empty, Err(AppError::Invalid(_))));

    // A Kemlock-only account has no Bitwarden record: the same answer as a wrong hash.
    make_user(&world, "kim@example.org").await;
    let mut input = start_input(BW_HASH, request());
    input.email = "kim@example.org".to_owned();
    assert_eq!(
        enrol(&world).start(input).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn an_account_that_enrolled_cannot_enrol_again() {
    let (world, user) = compatible_world().await;
    let (ticket, upload) = start_and_upload(&world).await;
    enrol(&world)
        .finish(finish_input(user, ticket, upload))
        .await
        .expect("enrols");

    let request = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client start")
        .1;
    let again = enrol(&world).start(start_input(BW_HASH, request)).await;
    assert_eq!(again.map(|_| ()), Err(AppError::Duplicate));
}

#[tokio::test]
async fn a_ticket_is_for_one_key_and_a_few_minutes() {
    let (world, user) = compatible_world().await;
    let (ticket, upload) = start_and_upload(&world).await;

    let mut other_key = finish_input(user, ticket.clone(), upload.clone());
    other_key.jkt = "another-key".to_owned();
    assert_eq!(
        enrol(&world).finish(other_key).await,
        Err(AppError::Unauthorized)
    );

    let mut forged = finish_input(user, ticket.clone(), upload.clone());
    forged.ticket[10] ^= 1;
    assert!(matches!(
        enrol(&world).finish(forged).await,
        Err(AppError::Invalid(_))
    ));

    world.env.clock.advance(Duration::minutes(6));
    assert!(matches!(
        enrol(&world)
            .finish(finish_input(user, ticket, upload))
            .await,
        Err(AppError::Invalid(_))
    ));
    assert_eq!(world.store.user(user).expect("account").opaque_record, None);
}

#[tokio::test]
async fn the_same_checks_as_a_registration_apply_to_the_keys() {
    let (world, user) = compatible_world().await;
    let (ticket, upload) = start_and_upload(&world).await;

    let mut weak_kdf = finish_input(user, ticket.clone(), upload.clone());
    weak_kdf.kdf.iterations = 1;
    assert!(matches!(
        enrol(&world).finish(weak_kdf).await,
        Err(AppError::Invalid(_))
    ));

    let mut other_account = finish_input(user, ticket.clone(), upload.clone());
    other_account.public_bundle = bundle(UserId::random());
    assert!(matches!(
        enrol(&world).finish(other_account).await,
        Err(AppError::Invalid(_))
    ));

    let mut short_wrap = finish_input(user, ticket, upload);
    short_wrap.wrapped_root_key.truncate(10);
    assert!(matches!(
        enrol(&world).finish(short_wrap).await,
        Err(AppError::Invalid(_))
    ));
    assert_eq!(world.store.user(user).expect("account").opaque_record, None);
}

#[tokio::test]
async fn an_account_with_an_authenticator_needs_a_current_code() {
    let (world, user) = compatible_world().await;
    world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");
    let code = totp_code(&world, user);
    world
        .confirm_totp()
        .execute(user, &code)
        .await
        .expect("confirmed");

    let request = kemlock_crypto::opaque::client_registration_start(&PASSWORD)
        .expect("client start")
        .1;
    let started = enrol(&world)
        .start(start_input(BW_HASH, request))
        .await
        .expect("the hash is right");
    assert_eq!(started.two_factor, vec![TwoFactorMethod::Totp]);

    // The upload doesn't matter until the code is right.
    let upload = vec![0u8; 8];
    let without = enrol(&world)
        .finish(finish_input(user, started.ticket.clone(), upload.clone()))
        .await;
    assert_eq!(without, Err(AppError::Unauthorized));
    let mut wrong = finish_input(user, started.ticket.clone(), upload);
    wrong.two_factor_code = Some("000000".to_owned());
    assert_eq!(
        enrol(&world).finish(wrong).await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(world.store.user(user).expect("account").opaque_record, None);

    // With the right code it enrols.
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let started = enrol(&world)
        .start(start_input(BW_HASH, request))
        .await
        .expect("again");
    let (upload, _export_key) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &started.response)
            .expect("client finish");
    let mut input = finish_input(user, started.ticket, upload);
    input.two_factor_code = Some(totp_code(&world, user));
    enrol(&world).finish(input).await.expect("enrols");
}

#[tokio::test]
async fn a_security_key_only_account_signs_in_to_the_web_vault_first() {
    let (world, user) = compatible_world().await;
    TwoFactorRepo::put(
        &world.store,
        &kemlock_app::ports::TwoFactor {
            user,
            method: TwoFactorMethod::WebAuthn,
            sealed_secret: vec![1; 40],
            enabled: true,
            created_at: world.env.now(),
        },
    )
    .await
    .expect("a security-key enrolment");

    let (ticket, upload) = start_and_upload(&world).await;
    assert_eq!(
        enrol(&world)
            .finish(finish_input(user, ticket, upload))
            .await,
        Err(AppError::Forbidden)
    );
}

#[tokio::test]
async fn the_ticket_names_its_account_for_the_second_step_limit() {
    let (world, user) = compatible_world().await;
    let (ticket, _upload) = start_and_upload(&world).await;
    assert_eq!(enrol(&world).ticket_user(&ticket), Ok(user));
    assert!(enrol(&world).ticket_user(&[1, 2, 3]).is_err());
}

// ---------------------------------------------------------------------------------------------
// The account's keys.

#[tokio::test]
async fn the_account_keys_are_what_registration_stored() {
    let (world, user, _me) = account().await;
    let stored = world.store.user(user).expect("the account");
    let keys = AccountKeys {
        users: world.store.clone(),
    }
    .execute(user)
    .await
    .expect("keys");
    assert_eq!(keys.key_version, stored.key_version);
    assert_eq!(keys.kdf, stored.kdf);
    assert_eq!(keys.wrapped_root_key, stored.wrapped_root_key);
    assert_eq!(keys.public_bundle, stored.public_bundle);
    assert_eq!(keys.bundle_signature, stored.bundle_signature);
    assert_eq!(keys.sealed_private_keys, stored.sealed_private_keys);
}

#[tokio::test]
async fn an_account_without_keys_has_none_to_give() {
    let (world, user) = compatible_world().await;
    let keys = AccountKeys {
        users: world.store.clone(),
    };
    assert_eq!(keys.execute(user).await, Err(AppError::NotFound));
    assert_eq!(
        keys.execute(UserId::random()).await,
        Err(AppError::Unauthorized)
    );
}
