//! Trusted devices: the wrapped copy of the root key, and signing a device out.

mod fakes;

use fakes::unlock::*;
use fakes::*;
use kemlock_app::ports::{Clock, DeviceRepo};
use kemlock_app::{Actor, AppError, SignedIn};
use kemlock_domain::UserId;
use kemlock_domain::unlock::{KeyProtection, MAX_WRAPPED_KEY_LEN};
use time::Duration;

const EMAIL: &str = "sam@example.org";

struct Scene {
    world: World,
    user: UserId,
    /// The device the tests act as.
    me: Actor,
    my_refresh_token: String,
}

async fn scene() -> Scene {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    Scene {
        world,
        user,
        me: Actor {
            user,
            device: tokens.device,
            admin: false,
        },
        my_refresh_token: tokens.refresh_token,
    }
}

fn wrapped() -> Vec<u8> {
    vec![0xc3; 92]
}

#[tokio::test]
async fn a_device_stores_and_fetches_its_wrapped_copy() {
    let s = scene().await;
    let copies = key_copies(&s.world);

    let put = copies
        .put(&s.me, wrapped(), KeyProtection::SecureEnclave)
        .await
        .expect("stores");
    assert_eq!(put.device, s.me.device);

    let got = copies.get(&s.me).await.expect("fetches");
    assert_eq!(got.wrapped_key, wrapped());
    assert_eq!(got.protection, KeyProtection::SecureEnclave);
    assert_eq!(got, put);
}

#[tokio::test]
async fn a_device_without_a_copy_finds_none() {
    let s = scene().await;
    assert_eq!(
        key_copies(&s.world).get(&s.me).await,
        Err(AppError::NotFound)
    );
}

#[tokio::test]
async fn replacing_the_copy_keeps_when_it_was_first_made() {
    let s = scene().await;
    let copies = key_copies(&s.world);
    let first = copies
        .put(&s.me, wrapped(), KeyProtection::Keystore)
        .await
        .expect("stores");
    s.world.env.clock.advance(Duration::days(2));

    let second = copies
        .put(&s.me, vec![0x11; 100], KeyProtection::Keystore)
        .await
        .expect("replaces");

    assert_eq!(second.created_at, first.created_at);
    assert_eq!(second.updated_at, s.world.env.now());
    assert_eq!(second.wrapped_key, vec![0x11; 100]);
    assert_eq!(
        s.world.store.key_copy_of(s.me.device),
        Some(second),
        "one row per device"
    );
}

#[tokio::test]
async fn an_empty_or_oversized_copy_is_refused() {
    let s = scene().await;
    let copies = key_copies(&s.world);
    for bad in [vec![], vec![1; MAX_WRAPPED_KEY_LEN + 1]] {
        let result = copies.put(&s.me, bad, KeyProtection::Software).await;
        assert!(matches!(result, Err(AppError::Invalid(_))));
    }
    assert_eq!(s.world.store.key_copy_of(s.me.device), None);
    // The biggest allowed copy goes in.
    copies
        .put(&s.me, vec![1; MAX_WRAPPED_KEY_LEN], KeyProtection::Software)
        .await
        .expect("the limit itself is fine");
}

#[tokio::test]
async fn a_signed_out_device_can_not_store_a_copy() {
    let s = scene().await;
    // A token for a device the server no longer has.
    let gone = Actor {
        device: kemlock_domain::DeviceId::random(),
        ..s.me
    };
    let result = key_copies(&s.world)
        .put(&gone, wrapped(), KeyProtection::WebCrypto)
        .await;
    assert_eq!(result, Err(AppError::NotFound));
}

#[tokio::test]
async fn removing_trust_deletes_the_copy_and_keeps_the_session() {
    let s = scene().await;
    let copies = key_copies(&s.world);
    copies
        .put(&s.me, wrapped(), KeyProtection::SecureEnclave)
        .await
        .expect("stores");

    copies.remove(&s.me).await.expect("removes");

    assert_eq!(copies.get(&s.me).await, Err(AppError::NotFound));
    let device = DeviceRepo::get(&s.world.store, s.me.device)
        .await
        .expect("reads");
    assert!(device.is_some(), "the device stays signed in");
    s.world
        .refresh()
        .execute(&s.my_refresh_token, "jkt-1")
        .await
        .expect("its refresh token still works");
}

#[tokio::test]
async fn signing_a_device_out_deletes_its_tokens_and_its_copy() {
    let s = scene().await;
    // A second device of the account, with its own copy.
    let SignedIn::Tokens(other) = sign_in_with(&s.world, EMAIL, &PASSWORD, device("iPad"), "jkt-2")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let other_actor = Actor {
        device: other.device,
        ..s.me
    };
    let copies = key_copies(&s.world);
    copies
        .put(&other_actor, wrapped(), KeyProtection::SecureEnclave)
        .await
        .expect("stores");
    copies
        .put(&s.me, wrapped(), KeyProtection::SecureEnclave)
        .await
        .expect("stores");

    sign_out_device(&s.world)
        .execute(&s.me, other.device)
        .await
        .expect("signs the iPad out");

    assert_eq!(s.world.store.key_copy_of(other.device), None);
    assert!(
        DeviceRepo::get(&s.world.store, other.device)
            .await
            .expect("reads")
            .is_none()
    );
    assert!(
        s.world
            .store
            .refresh_tokens()
            .iter()
            .all(|t| t.device != other.device),
        "its refresh tokens are gone"
    );
    assert!(
        s.world
            .refresh()
            .execute(&other.refresh_token, "jkt-2")
            .await
            .is_err(),
        "the old refresh token no longer works"
    );
    // This device is untouched.
    assert!(s.world.store.key_copy_of(s.me.device).is_some());
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "device.sign_out")
    );
}

#[tokio::test]
async fn a_device_can_sign_itself_out() {
    let s = scene().await;
    key_copies(&s.world)
        .put(&s.me, wrapped(), KeyProtection::Keystore)
        .await
        .expect("stores");

    sign_out_device(&s.world)
        .execute(&s.me, s.me.device)
        .await
        .expect("signs itself out");

    assert_eq!(s.world.store.key_copy_of(s.me.device), None);
    assert!(s.world.store.devices_of(s.user).is_empty());
}

#[tokio::test]
async fn another_accounts_device_can_not_be_signed_out() {
    let s = scene().await;
    let stranger = make_user(&s.world, "kim@example.org").await;
    let result = sign_out_device(&s.world)
        .execute(&actor(stranger), s.me.device)
        .await;
    assert_eq!(result, Err(AppError::NotFound));
    assert_eq!(s.world.store.devices_of(s.user).len(), 1);
}

#[tokio::test]
async fn one_device_can_stop_trusting_another_and_its_session_goes_on() {
    let s = scene().await;
    let SignedIn::Tokens(other) = sign_in_with(&s.world, EMAIL, &PASSWORD, device("iPad"), "jkt-2")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let other_actor = Actor {
        device: other.device,
        ..s.me
    };
    let copies = key_copies(&s.world);
    for actor in [&other_actor, &s.me] {
        copies
            .put(actor, wrapped(), KeyProtection::SecureEnclave)
            .await
            .expect("stores");
    }

    untrust_device(&s.world)
        .execute(&s.me, other.device)
        .await
        .expect("stops trusting the iPad");

    assert_eq!(s.world.store.key_copy_of(other.device), None);
    assert!(
        DeviceRepo::get(&s.world.store, other.device)
            .await
            .expect("reads")
            .is_some(),
        "the iPad stays signed in"
    );
    s.world
        .refresh()
        .execute(&other.refresh_token, "jkt-2")
        .await
        .expect("its refresh token still works");
    // This device is untouched.
    assert!(s.world.store.key_copy_of(s.me.device).is_some());
    let events = s.world.store.events();
    let event = events
        .iter()
        .find(|e| e.action == "device.untrust")
        .expect("the change is in the event log");
    assert_eq!(event.actor, Some(s.user));
    assert_eq!(event.device, Some(s.me.device));
    assert_eq!(event.target, Some(other.device.to_string()));
}

#[tokio::test]
async fn stopping_trust_in_a_device_with_no_copy_is_not_an_error() {
    let s = scene().await;
    untrust_device(&s.world)
        .execute(&s.me, s.me.device)
        .await
        .expect("nothing to remove is fine");
    assert_eq!(s.world.store.key_copy_of(s.me.device), None);
}

#[tokio::test]
async fn another_accounts_device_can_not_be_untrusted() {
    let s = scene().await;
    copies_put(&s).await;
    let stranger = make_user(&s.world, "kim@example.org").await;
    let result = untrust_device(&s.world)
        .execute(&actor(stranger), s.me.device)
        .await;
    assert_eq!(result, Err(AppError::NotFound));
    assert!(
        s.world.store.key_copy_of(s.me.device).is_some(),
        "its copy is still there"
    );
}

async fn copies_put(s: &Scene) {
    key_copies(&s.world)
        .put(&s.me, wrapped(), KeyProtection::Keystore)
        .await
        .expect("stores");
}

#[tokio::test]
async fn signing_the_other_devices_out_keeps_the_one_asking() {
    let s = scene().await;
    let mut others = Vec::new();
    for (name, jkt) in [("iPad", "jkt-2"), ("Laptop", "jkt-3")] {
        let SignedIn::Tokens(tokens) = sign_in_with(&s.world, EMAIL, &PASSWORD, device(name), jkt)
            .await
            .expect("signs in")
        else {
            panic!("tokens expected");
        };
        key_copies(&s.world)
            .put(
                &Actor {
                    device: tokens.device,
                    ..s.me
                },
                wrapped(),
                KeyProtection::Keystore,
            )
            .await
            .expect("stores");
        others.push(tokens.device);
    }
    key_copies(&s.world)
        .put(&s.me, wrapped(), KeyProtection::Keystore)
        .await
        .expect("stores");
    // Another account's device is no business of this one.
    let stranger = make_user(&s.world, "kim@example.org").await;
    sign_in_with(
        &s.world,
        "kim@example.org",
        &PASSWORD,
        device("Pixel"),
        "jkt-9",
    )
    .await
    .expect("signs in");

    let signed_out = sign_out_device(&s.world)
        .execute_others(&s.me)
        .await
        .expect("signs the others out");

    assert_eq!(signed_out, 2);
    for gone in others {
        assert_eq!(s.world.store.key_copy_of(gone), None);
        assert!(
            DeviceRepo::get(&s.world.store, gone)
                .await
                .expect("reads")
                .is_none()
        );
    }
    // This device keeps its copy and its refresh token.
    assert!(s.world.store.key_copy_of(s.me.device).is_some());
    s.world
        .refresh()
        .execute(&s.my_refresh_token, "jkt-1")
        .await
        .expect("its refresh token still works");
    assert_eq!(s.world.store.devices_of(stranger).len(), 1);
    // And with no other device there is nothing to do.
    assert_eq!(sign_out_device(&s.world).execute_others(&s.me).await, Ok(0));
}

#[tokio::test]
async fn ending_a_session_keeps_the_device_and_its_key_copy() {
    let s = scene().await;
    key_copies(&s.world)
        .put(&s.me, wrapped(), KeyProtection::Keystore)
        .await
        .expect("stores");

    end_session(&s.world)
        .execute(&s.me)
        .await
        .expect("ends the session");

    // The way back in for an account with no password stays.
    assert!(s.world.store.key_copy_of(s.me.device).is_some());
    let device = DeviceRepo::get(&s.world.store, s.me.device)
        .await
        .expect("reads")
        .expect("the device is still there");
    assert_eq!(device.dpop_jkt, None, "its key vouches for nothing now");
    assert!(
        s.world
            .store
            .refresh_tokens()
            .iter()
            .all(|t| t.device != s.me.device),
        "its refresh tokens are gone"
    );
    assert!(
        s.world
            .refresh()
            .execute(&s.my_refresh_token, "jkt-1")
            .await
            .is_err(),
        "the refresh token no longer works"
    );
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "device.session_end")
    );
}

#[tokio::test]
async fn ending_a_session_leaves_the_other_devices_alone() {
    let s = scene().await;
    let SignedIn::Tokens(other) = sign_in_with(&s.world, EMAIL, &PASSWORD, device("iPad"), "jkt-2")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    end_session(&s.world)
        .execute(&s.me)
        .await
        .expect("ends the session");
    assert!(
        s.world
            .refresh()
            .execute(&other.refresh_token, "jkt-2")
            .await
            .is_ok(),
        "the iPad's session goes on"
    );
}

/// A second sign-in on the same device, a few seconds after `scene()`'s: a new session of it.
async fn sign_in_again(s: &Scene) -> kemlock_app::TokenPair {
    s.world.env.clock.advance(Duration::seconds(5));
    let again = kemlock_app::DeviceInfo {
        id: Some(s.me.device),
        ..device("Pixel")
    };
    let SignedIn::Tokens(second) = sign_in_with(&s.world, EMAIL, &PASSWORD, again, "jkt-1")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    assert_eq!(second.device, s.me.device, "the same device");
    second
}

#[tokio::test]
async fn ending_the_other_sessions_keeps_this_one_the_device_and_its_key_copy() {
    let s = scene().await;
    key_copies(&s.world)
        .put(&s.me, wrapped(), KeyProtection::Keystore)
        .await
        .expect("stores");
    let second = sign_in_again(&s).await;
    let signed_in_at = s.world.env.clock.now().unix_timestamp();

    let ended = end_session(&s.world)
        .execute_others(&s.me, signed_in_at)
        .await
        .expect("ends the others");

    assert_eq!(ended, 1);
    assert!(
        s.world
            .refresh()
            .execute(&s.my_refresh_token, "jkt-1")
            .await
            .is_err(),
        "the earlier session's refresh token, as an old closed tab holds it, no longer works"
    );
    assert!(
        s.world
            .refresh()
            .execute(&second.refresh_token, "jkt-1")
            .await
            .is_ok(),
        "this session goes on"
    );
    assert!(s.world.store.key_copy_of(s.me.device).is_some());
    let device = DeviceRepo::get(&s.world.store, s.me.device)
        .await
        .expect("reads")
        .expect("the device is still there");
    assert_eq!(device.dpop_jkt.as_deref(), Some("jkt-1"), "its key stays bound");
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "device.other_sessions_end")
    );
}

#[tokio::test]
async fn ending_the_other_sessions_with_none_is_a_no_op() {
    let s = scene().await;
    let signed_in_at = s.world.env.clock.now().unix_timestamp();
    assert_eq!(
        end_session(&s.world)
            .execute_others(&s.me, signed_in_at)
            .await,
        Ok(0)
    );
    assert!(
        s.world
            .refresh()
            .execute(&s.my_refresh_token, "jkt-1")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn ending_the_other_sessions_leaves_other_devices_alone() {
    let s = scene().await;
    let SignedIn::Tokens(other) = sign_in_with(&s.world, EMAIL, &PASSWORD, device("iPad"), "jkt-2")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let signed_in_at = s.world.env.clock.now().unix_timestamp();
    end_session(&s.world)
        .execute_others(&s.me, signed_in_at)
        .await
        .expect("ends the others");
    assert!(
        s.world
            .refresh()
            .execute(&other.refresh_token, "jkt-2")
            .await
            .is_ok(),
        "the iPad's session goes on"
    );
}
