//! Require SSO on the ways in that follow it: the OPAQUE password and an approved device. A
//! space that requires single sign-on closes both to its ordinary members, once the password or
//! the approval has shown who is signing in.

mod fakes;

use fakes::unlock::*;
use fakes::*;
use kemlock_app::devices::{Answer, ApprovalRequestInput};
use kemlock_app::sso::{SpaceMembership, SpaceRole};
use kemlock_app::{Actor, AppError, DeviceInfo, OpaqueFinishInput, SignedIn};
use kemlock_domain::unlock::{KX1_PUBLIC_KEY_LEN, SEALED_BOX_OVERHEAD};
use kemlock_domain::{DeviceKind, SpaceId, UserId};
use std::net::{IpAddr, Ipv6Addr};

const EMAIL: &str = "sam@example.org";

fn requiring(space: SpaceId, role: SpaceRole) -> Vec<SpaceMembership> {
    vec![SpaceMembership {
        space,
        role,
        require_sso: true,
    }]
}

async fn world_with_user() -> (World, UserId) {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    (world, user)
}

#[tokio::test]
async fn a_password_sign_in_is_refused_for_a_member_of_a_requiring_space() {
    let (world, user) = world_with_user().await;
    let space = SpaceId::random();
    world
        .store
        .set_memberships(user, requiring(space, SpaceRole::Member));

    let refused = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .map(|_| ());
    assert_eq!(refused, Err(AppError::SsoRequired { space }));
    assert!(
        world.store.devices_of(user).is_empty(),
        "no device is registered"
    );
    assert!(
        world.store.refresh_tokens().is_empty(),
        "no tokens are issued"
    );
}

#[tokio::test]
async fn a_wrong_proof_says_nothing_about_the_policy() {
    let (world, user) = world_with_user().await;
    world
        .store
        .set_memberships(user, requiring(SpaceId::random(), SpaceRole::Member));

    let (login_state, mut finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    let last = finalization.len() - 1;
    finalization[last] ^= 1;
    let wrong = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state,
            finalization,
            device: device("Pixel"),
            jkt: "jkt-1".to_owned(),
        })
        .await
        .map(|_| ());
    assert_eq!(wrong, Err(AppError::Unauthorized));
}

#[tokio::test]
async fn owners_and_admins_and_spaces_without_the_policy_do_not_block_the_password() {
    for membership in [
        requiring(SpaceId::random(), SpaceRole::Owner),
        requiring(SpaceId::random(), SpaceRole::Admin),
        vec![SpaceMembership {
            space: SpaceId::random(),
            role: SpaceRole::Member,
            require_sso: false,
        }],
        Vec::new(),
    ] {
        let (world, user) = world_with_user().await;
        world.store.set_memberships(user, membership);
        let signed = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
            .await
            .expect("signs in");
        assert!(matches!(signed, SignedIn::Tokens(_)));
    }
}

#[tokio::test]
async fn an_approved_device_is_refused_for_a_member_of_a_requiring_space() {
    let (world, user) = world_with_user().await;
    // The account's first device, signed in before the space asked for SSO.
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
    let notices = FakeNotices::default();
    let requested = request_approval(&world, &notices)
        .execute(ApprovalRequestInput {
            email: EMAIL.to_owned(),
            device: DeviceInfo {
                id: None,
                name: "Firefox on Linux".to_owned(),
                kind: DeviceKind::KemlockWeb,
                bitwarden_identifier: None,
            },
            public_key: vec![9; KX1_PUBLIC_KEY_LEN],
            jkt: "new-device-jkt".to_owned(),
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        })
        .await
        .expect("the request is accepted");
    answer_approval(&world)
        .execute(
            &open,
            requested.id,
            Answer::Approve {
                sealed_key: vec![0x5b; SEALED_BOX_OVERHEAD + 64],
            },
        )
        .await
        .expect("approves");

    let space = SpaceId::random();
    world
        .store
        .set_memberships(user, requiring(space, SpaceRole::Member));
    let sign_in = device_sign_in(&world);
    assert_eq!(
        sign_in
            .challenge(requested.id, "new-device-jkt")
            .await
            .map(|_| ()),
        Err(AppError::SsoRequired { space })
    );

    // The policy is lifted: the approval was not used up by the refusal.
    world.store.set_memberships(user, Vec::new());
    let challenge = sign_in
        .challenge(requested.id, "new-device-jkt")
        .await
        .expect("a challenge");
    world
        .store
        .set_memberships(user, requiring(space, SpaceRole::Member));
    assert_eq!(
        sign_in
            .verify(&challenge, "new-device-jkt")
            .await
            .map(|_| ()),
        Err(AppError::SsoRequired { space }),
        "the check runs again when the device proves its key"
    );
    world.store.set_memberships(user, Vec::new());
    sign_in
        .verify(&challenge, "new-device-jkt")
        .await
        .expect("the approval still stands");
}
