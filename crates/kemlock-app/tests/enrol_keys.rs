//! The first keys of an account that single sign-on made with none: the device makes them and
//! sends what the server may hold, with its own copy of the root key.

mod fakes;

use fakes::*;
use kemlock_app::account_keys::AccountKeys;
use kemlock_app::enrol_keys::{EnrolKeys, EnrolKeysInput};
use kemlock_app::register::{BUNDLE_SIGNATURE_LEN, FIRST_KEY_VERSION};
use kemlock_app::{Actor, AppError, SignedIn};
use kemlock_domain::UserId;
use kemlock_domain::unlock::KeyProtection;

const EMAIL: &str = "sam@example.org";

struct Scene {
    world: World,
    user: UserId,
    me: Actor,
}

/// An account with no key material at all, as `SsoFinish` makes one, and a signed-in device.
async fn scene() -> Scene {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let mut bare = world.store.user(user).expect("the account");
    bare.opaque_record = None;
    bare.wrapped_root_key.clear();
    bare.public_bundle.clear();
    bare.bundle_signature.clear();
    bare.sealed_private_keys.clear();
    bare.key_version = 0;
    world.store.put_user(bare);
    Scene {
        world,
        user,
        me: Actor {
            user,
            device: tokens.device,
            admin: false,
        },
    }
}

fn enrol(world: &World) -> EnrolKeys<FakeStore, FakeStore, FakeStore, FakeEnv, FakeStore> {
    EnrolKeys {
        users: world.store.clone(),
        devices: world.store.clone(),
        copies: world.store.clone(),
        clock: world.env.clone(),
        events: world.store.clone(),
    }
}

fn input(user: UserId) -> EnrolKeysInput {
    EnrolKeysInput {
        public_bundle: bundle(user),
        bundle_signature: bundle_signature(user),
        sealed_private_keys: vec![0x22; 64],
        device_copy: vec![0xc3; 93],
        protection: KeyProtection::SecureEnclave,
    }
}

#[tokio::test]
async fn the_device_makes_the_keys_and_keeps_its_copy() {
    let s = scene().await;
    let version = enrol(&s.world)
        .execute(&s.me, input(s.user))
        .await
        .expect("enrols");
    assert_eq!(version, FIRST_KEY_VERSION);

    let stored = s.world.store.user(s.user).expect("the account");
    assert_eq!(stored.key_version, FIRST_KEY_VERSION);
    assert_eq!(stored.public_bundle, bundle(s.user));
    assert_eq!(stored.sealed_private_keys, vec![0x22; 64]);
    assert!(
        stored.wrapped_root_key.is_empty() && stored.opaque_record.is_none(),
        "no password was made"
    );

    let copy = s
        .world
        .store
        .key_copy_of(s.me.device)
        .expect("the device's copy");
    assert_eq!(copy.wrapped_key, vec![0xc3; 93]);
    assert_eq!(copy.protection, KeyProtection::SecureEnclave);
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "account.keys_enrolled")
    );
}

#[tokio::test]
async fn the_keys_can_be_read_back_with_no_password_wrap() {
    let s = scene().await;
    let keys = AccountKeys {
        users: s.world.store.clone(),
    };
    assert_eq!(keys.execute(s.user).await, Err(AppError::NotFound));
    enrol(&s.world)
        .execute(&s.me, input(s.user))
        .await
        .expect("enrols");
    let view = keys.execute(s.user).await.expect("keys");
    assert_eq!(view.key_version, FIRST_KEY_VERSION);
    assert!(view.wrapped_root_key.is_empty());
    assert_eq!(view.public_bundle, bundle(s.user));
}

#[tokio::test]
async fn keys_are_made_once() {
    let s = scene().await;
    enrol(&s.world)
        .execute(&s.me, input(s.user))
        .await
        .expect("enrols");
    let mut again = input(s.user);
    again.sealed_private_keys = vec![0x99; 64];
    assert_eq!(
        enrol(&s.world).execute(&s.me, again).await,
        Err(AppError::Duplicate)
    );
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .sealed_private_keys,
        vec![0x22; 64],
        "the first keys stay"
    );
}

#[tokio::test]
async fn an_account_that_has_keys_is_refused() {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let me = Actor {
        user,
        device: tokens.device,
        admin: false,
    };
    assert_eq!(
        enrol(&world).execute(&me, input(user)).await,
        Err(AppError::Duplicate)
    );
}

#[tokio::test]
async fn a_malformed_or_foreign_bundle_is_refused_and_nothing_is_stored() {
    let s = scene().await;
    let mut cases = Vec::new();
    let mut other_account = input(s.user);
    other_account.public_bundle = bundle(UserId::random());
    cases.push(other_account);
    let mut short_bundle = input(s.user);
    short_bundle.public_bundle.pop();
    cases.push(short_bundle);
    let mut bad_signature = input(s.user);
    bad_signature.bundle_signature.pop();
    cases.push(bad_signature);
    let mut no_private_keys = input(s.user);
    no_private_keys.sealed_private_keys.clear();
    cases.push(no_private_keys);
    // The right length, but not the bundle's own signature: filler, a flipped byte in each half,
    // and a signature of another account's bundle.
    let mut filler = input(s.user);
    filler.bundle_signature = vec![0x11; BUNDLE_SIGNATURE_LEN];
    cases.push(filler);
    for index in [0, BUNDLE_SIGNATURE_LEN - 1] {
        let mut flipped = input(s.user);
        flipped.bundle_signature[index] ^= 1;
        cases.push(flipped);
    }
    let mut foreign_signature = input(s.user);
    foreign_signature.bundle_signature = bundle_signature(UserId::random());
    cases.push(foreign_signature);
    for bad in cases {
        let result = enrol(&s.world).execute(&s.me, bad).await;
        assert!(matches!(result, Err(AppError::Invalid(_))), "{result:?}");
    }
    assert_eq!(s.world.store.key_copy_of(s.me.device), None);
    assert_eq!(s.world.store.user(s.user).expect("account").key_version, 0);
}

#[tokio::test]
async fn an_empty_device_copy_is_refused_before_the_account_changes() {
    let s = scene().await;
    let mut empty = input(s.user);
    empty.device_copy.clear();
    let result = enrol(&s.world).execute(&s.me, empty).await;
    assert!(matches!(result, Err(AppError::Invalid(_))), "{result:?}");
    assert_eq!(s.world.store.user(s.user).expect("account").key_version, 0);
}

#[tokio::test]
async fn an_unknown_account_is_unauthorized() {
    let s = scene().await;
    let stranger = Actor {
        user: UserId::random(),
        device: s.me.device,
        admin: false,
    };
    assert_eq!(
        enrol(&s.world)
            .execute(&stranger, input(stranger.user))
            .await,
        Err(AppError::Unauthorized)
    );
}

/// Users as seen by the loser of an enrolment race: the account still has no keys when it looks,
/// and by the time it writes, the other enrolment has stored theirs.
#[derive(Clone)]
struct LosesTheRace {
    inner: FakeStore,
}

impl kemlock_app::ports::UserRepo for LosesTheRace {
    async fn by_id(
        &self,
        id: UserId,
    ) -> Result<Option<kemlock_domain::User>, kemlock_app::ports::StoreError> {
        self.inner.by_id(id).await
    }

    async fn by_email(
        &self,
        email: &kemlock_domain::Email,
    ) -> Result<Option<kemlock_domain::User>, kemlock_app::ports::StoreError> {
        self.inner.by_email(email).await
    }

    async fn insert(
        &self,
        user: &kemlock_domain::User,
    ) -> Result<(), kemlock_app::ports::StoreError> {
        self.inner.insert(user).await
    }

    async fn update(
        &self,
        user: &kemlock_domain::User,
    ) -> Result<(), kemlock_app::ports::StoreError> {
        self.inner.update(user).await
    }

    async fn set_first_keys(
        &self,
        _user: &kemlock_domain::User,
    ) -> Result<(), kemlock_app::ports::StoreError> {
        Err(kemlock_app::ports::StoreError::Duplicate)
    }

    async fn count_admins(&self) -> Result<u64, kemlock_app::ports::StoreError> {
        self.inner.count_admins().await
    }

    async fn account_disabled(&self, id: UserId) -> Result<bool, kemlock_app::ports::StoreError> {
        self.inner.account_disabled(id).await
    }
}

#[tokio::test]
async fn the_loser_of_an_enrolment_race_is_a_duplicate_and_writes_no_copy() {
    let s = scene().await;
    let loser = EnrolKeys {
        users: LosesTheRace {
            inner: s.world.store.clone(),
        },
        devices: s.world.store.clone(),
        copies: s.world.store.clone(),
        clock: s.world.env.clone(),
        events: s.world.store.clone(),
    };
    assert_eq!(
        loser.execute(&s.me, input(s.user)).await,
        Err(AppError::Duplicate)
    );
    assert_eq!(
        s.world.store.key_copy_of(s.me.device),
        None,
        "only the winner writes a copy of the root key"
    );
    assert!(
        !s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "account.keys_enrolled")
    );
}
