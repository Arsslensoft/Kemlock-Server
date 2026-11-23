//! An approved device signs in with the key it registered with its request.

mod fakes;

use fakes::unlock::*;
use fakes::*;
use kemlock_app::devices::{Answer, ApprovalRequestInput, Poll, Requested};
use kemlock_app::{Actor, AppError, DeviceInfo, SignedIn, TokenPair};
use kemlock_domain::unlock::{ApprovalState, KX1_PUBLIC_KEY_LEN, SEALED_BOX_OVERHEAD};
use kemlock_domain::{DeviceKind, UserId};
use std::net::{IpAddr, Ipv6Addr};
use time::Duration;

const EMAIL: &str = "sam@example.org";
const NEW_JKT: &str = "new-device-jkt";

struct Scene {
    world: World,
    user: UserId,
    open: Actor,
    notices: FakeNotices,
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
    let open = Actor {
        user,
        device: tokens.device,
        admin: false,
    };
    Scene {
        world,
        user,
        open,
        notices: FakeNotices::default(),
    }
}

impl Scene {
    async fn request(&self) -> Requested {
        request_approval(&self.world, &self.notices)
            .execute(ApprovalRequestInput {
                email: EMAIL.to_owned(),
                device: DeviceInfo {
                    id: None,
                    name: "Firefox on Linux".to_owned(),
                    kind: DeviceKind::KemlockWeb,
                    bitwarden_identifier: None,
                },
                public_key: vec![9; KX1_PUBLIC_KEY_LEN],
                jkt: NEW_JKT.to_owned(),
                ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            })
            .await
            .expect("the request is accepted")
    }

    async fn approve(&self, requested: &Requested) {
        answer_approval(&self.world)
            .execute(
                &self.open,
                requested.id,
                Answer::Approve {
                    sealed_key: vec![0x5b; SEALED_BOX_OVERHEAD + 64],
                },
            )
            .await
            .expect("approves");
    }

    async fn approved(&self) -> Requested {
        let requested = self.request().await;
        self.approve(&requested).await;
        requested
    }
}

#[tokio::test]
async fn an_approved_device_signs_in_with_its_registered_key() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);

    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("a challenge for the approved request");
    let tokens: TokenPair = sign_in
        .verify(&challenge, NEW_JKT)
        .await
        .expect("the device signs in");

    assert_eq!(tokens.user, s.user);
    assert!(!tokens.admin);
    // The device is registered under the id and key it asked with.
    let stored = s.world.store.devices_of(s.user);
    assert_eq!(stored.len(), 2, "the first device and the new one");
    let new = stored
        .iter()
        .find(|d| d.id == tokens.device)
        .expect("the new device is listed");
    assert_eq!(new.name, "Firefox on Linux");
    assert_eq!(new.kind, DeviceKind::KemlockWeb);
    assert_eq!(new.dpop_jkt.as_deref(), Some(NEW_JKT));
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.device_approval")
    );
}

#[tokio::test]
async fn the_new_devices_tokens_refresh_under_its_key() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);
    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("challenge");
    let tokens = sign_in.verify(&challenge, NEW_JKT).await.expect("signs in");

    let refreshed = s
        .world
        .refresh()
        .execute(&tokens.refresh_token, NEW_JKT)
        .await
        .expect("the refresh works under the registered key");
    assert_eq!(refreshed.device, tokens.device);
    let other = s
        .world
        .refresh()
        .execute(&refreshed.refresh_token, "some-other-key")
        .await;
    assert!(other.is_err(), "another key can't refresh");
}

#[tokio::test]
async fn the_approval_is_used_up_by_the_sign_in() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);
    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("challenge");
    sign_in.verify(&challenge, NEW_JKT).await.expect("signs in");

    // The same challenge again, and a fresh one, both find the approval consumed.
    assert_eq!(
        sign_in.verify(&challenge, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        sign_in.challenge(requested.id, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    let stored = s.world.store.auth_request(requested.id).expect("stored");
    assert_eq!(stored.state, ApprovalState::Consumed);
    assert_eq!(stored.sealed_key, None, "the box is dropped");
    assert_eq!(
        poll_approval(&s.world)
            .execute(requested.id, NEW_JKT)
            .await
            .expect("polls"),
        Poll::Used
    );
}

#[tokio::test]
async fn no_challenge_before_approval_or_after_a_denial() {
    let s = scene().await;
    let pending = s.request().await;
    let sign_in = device_sign_in(&s.world);
    assert_eq!(
        sign_in.challenge(pending.id, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    answer_approval(&s.world)
        .execute(&s.open, pending.id, Answer::Deny)
        .await
        .expect("denies");
    assert_eq!(
        sign_in.challenge(pending.id, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn another_key_gets_no_challenge_and_can_not_use_one() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);

    assert_eq!(
        sign_in
            .challenge(requested.id, "other-key")
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("challenge");
    assert_eq!(
        sign_in.verify(&challenge, "other-key").await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    // The approval is untouched by the failed attempts.
    sign_in
        .verify(&challenge, NEW_JKT)
        .await
        .expect("the right key still signs in");
}

#[tokio::test]
async fn a_challenge_is_short_lived_and_tamper_proof() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);
    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("challenge");

    let mut tampered = challenge.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        sign_in.verify(&tampered, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        sign_in.verify(b"garbage", NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    // Five minutes is the challenge's life; the approval itself would last ten more.
    s.world.env.clock.advance(Duration::minutes(5));
    assert_eq!(
        sign_in.verify(&challenge, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    // A new challenge works while the approval does.
    let again = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("a fresh challenge");
    sign_in.verify(&again, NEW_JKT).await.expect("signs in");
}

#[tokio::test]
async fn an_approval_that_expired_signs_nobody_in() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);
    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("challenge");

    s.world.env.clock.advance(Duration::minutes(15));
    assert_eq!(
        sign_in.verify(&challenge, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        sign_in.challenge(requested.id, NEW_JKT).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(s.world.store.devices_of(s.user).len(), 1);
}

#[tokio::test]
async fn a_disabled_account_is_refused_after_the_approval_and_the_key_check_out() {
    let s = scene().await;
    let requested = s.approved().await;
    let sign_in = device_sign_in(&s.world);
    let challenge = sign_in
        .challenge(requested.id, NEW_JKT)
        .await
        .expect("challenge");

    s.world.store.set_account_disabled(s.user, true);
    assert_eq!(
        sign_in.challenge(requested.id, NEW_JKT).await.map(|_| ()),
        Err(AppError::AccountDisabled)
    );
    assert_eq!(
        sign_in.verify(&challenge, NEW_JKT).await.map(|_| ()),
        Err(AppError::AccountDisabled)
    );
    // Another key is not the approved device: it learns nothing about the account.
    assert_eq!(
        sign_in
            .challenge(requested.id, "other-key")
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        s.world.store.refresh_tokens().len(),
        1,
        "only the first device has a session"
    );

    // The refusal left the approval standing.
    s.world.store.set_account_disabled(s.user, false);
    sign_in
        .verify(&challenge, NEW_JKT)
        .await
        .expect("an enabled account signs in");
}
