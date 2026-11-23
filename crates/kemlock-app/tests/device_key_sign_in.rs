//! A device signs in on a replica with the key its registration (copied from the home) names.

mod fakes;

use fakes::*;
use kemlock_app::devices::DeviceKeySignIn;
use kemlock_app::ports::{DeviceRepo, SecretSeal};
use kemlock_app::sso::{RequireSso, SpaceMembership, SpaceRole};
use kemlock_app::{AppError, SignedIn, TokenPair};
use kemlock_domain::{DeviceId, SpaceId, UserId};
use time::Duration;

const EMAIL: &str = "sam@example.org";
const JKT: &str = "registered-device-jkt";

type FakeKeySignIn = DeviceKeySignIn<
    FakeStore,
    FakeSeal,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeEnv,
    FakeStore,
    FakeStore,
    FakeStore,
>;

fn key_sign_in(world: &World) -> FakeKeySignIn {
    DeviceKeySignIn {
        users: world.store.clone(),
        seal: world.seal.clone(),
        sessions: world.sessions(),
        sso: RequireSso {
            membership: world.store.clone(),
        },
    }
}

struct Scene {
    world: World,
    user: UserId,
    device: DeviceId,
}

/// An account with one registered device, as a replica holds it after the home's copy.
async fn scene() -> Scene {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), JKT)
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    Scene {
        world,
        user,
        device: tokens.device,
    }
}

#[tokio::test]
async fn a_registered_device_signs_in_with_its_key() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);

    let challenge = sign_in
        .challenge(s.device, JKT)
        .await
        .expect("a challenge for the registered device");
    let tokens: TokenPair = sign_in
        .verify(&challenge, JKT)
        .await
        .expect("the device signs in");

    assert_eq!(tokens.user, s.user);
    assert_eq!(tokens.device, s.device);
    assert!(!tokens.admin);
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.device_key" && e.device == Some(s.device))
    );
    // The device is the same one: no second registration appeared.
    assert_eq!(s.world.store.devices_of(s.user).len(), 1);
    // Its refresh token works under the same key and no other.
    let refreshed = s
        .world
        .refresh()
        .execute(&tokens.refresh_token, JKT)
        .await
        .expect("the refresh works under the registered key");
    assert_eq!(refreshed.device, s.device);
}

#[tokio::test]
async fn another_key_or_an_unknown_device_gets_nothing() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);

    // The same answer for a wrong key and for a device id that doesn't exist.
    assert_eq!(
        sign_in.challenge(s.device, "other-key").await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        sign_in.challenge(DeviceId::random(), JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    // A challenge made for one key can't be used by another.
    let challenge = sign_in.challenge(s.device, JKT).await.expect("challenge");
    assert_eq!(
        sign_in.verify(&challenge, "other-key").await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    sign_in
        .verify(&challenge, JKT)
        .await
        .expect("the right key still signs in");
}

#[tokio::test]
async fn a_challenge_is_short_lived_and_tamper_proof() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);
    let challenge = sign_in.challenge(s.device, JKT).await.expect("challenge");

    let mut tampered = challenge.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        sign_in.verify(&tampered, JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        sign_in.verify(b"garbage", JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    s.world.env.clock.advance(Duration::minutes(5));
    assert_eq!(
        sign_in.verify(&challenge, JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    let again = sign_in
        .challenge(s.device, JKT)
        .await
        .expect("a fresh challenge");
    sign_in.verify(&again, JKT).await.expect("signs in");
}

#[tokio::test]
async fn a_device_signed_out_since_the_challenge_cannot_sign_in() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);
    let challenge = sign_in.challenge(s.device, JKT).await.expect("challenge");

    DeviceRepo::remove(&s.world.store, s.device)
        .await
        .expect("the device is removed");
    assert_eq!(
        sign_in.verify(&challenge, JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        sign_in.challenge(s.device, JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn a_challenge_of_another_purpose_is_not_accepted() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);
    // The approved-device challenge is sealed under another purpose, so a sealed value of the
    // right shape from there doesn't open here.
    let other = SecretSeal::seal(&s.world.seal, "device-sign-in-challenge", &[1; 80]);
    assert_eq!(
        sign_in.verify(&other, JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn a_disabled_account_is_refused_once_its_device_key_is_proved() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);
    let challenge = sign_in.challenge(s.device, JKT).await.expect("challenge");

    s.world.store.set_account_disabled(s.user, true);
    assert_eq!(
        sign_in.challenge(s.device, JKT).await.map(|_| ()),
        Err(AppError::AccountDisabled)
    );
    assert_eq!(
        sign_in.verify(&challenge, JKT).await.map(|_| ()),
        Err(AppError::AccountDisabled)
    );
    // Not the key: a stranger still learns nothing about the account.
    assert_eq!(
        sign_in.challenge(s.device, "other-key").await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    s.world.store.set_account_disabled(s.user, false);
    sign_in
        .verify(&challenge, JKT)
        .await
        .expect("an enabled account signs in again");
}

#[tokio::test]
async fn require_sso_closes_the_device_key_to_ordinary_members_only() {
    let s = scene().await;
    let sign_in = key_sign_in(&s.world);
    let space = SpaceId::random();
    let membership = |role| {
        vec![SpaceMembership {
            space,
            role,
            require_sso: true,
        }]
    };

    s.world
        .store
        .set_memberships(s.user, membership(SpaceRole::Member));
    assert_eq!(
        sign_in.challenge(s.device, JKT).await.map(|_| ()),
        Err(AppError::SsoRequired { space })
    );

    s.world
        .store
        .set_memberships(s.user, membership(SpaceRole::Admin));
    sign_in
        .challenge(s.device, JKT)
        .await
        .expect("admins are exempt");
}
