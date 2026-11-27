mod fakes;

use fakes::*;
use kemlock_app::ports::{Clock, SecretSeal, TokenSigner, TwoFactorMethod};
use kemlock_app::{
    AppError, DeviceInfo, OpaqueFinishInput, OpaqueStartInput, SecondStepInput, SignedIn, b64url,
};
use kemlock_domain::{DeviceKind, UserId};
use time::Duration;

const EMAIL: &str = "sam@example.org";

async fn signed_in_world() -> (World, UserId) {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    (world, user)
}

async fn two_step_world() -> (World, UserId) {
    let (world, user) = signed_in_world().await;
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
    (world, user)
}

#[tokio::test]
async fn the_right_password_signs_in_and_issues_bound_tokens() {
    let (world, user) = signed_in_world().await;
    let signed = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("signs in");
    let SignedIn::Tokens(tokens) = signed else {
        panic!("no second step is expected");
    };
    assert_eq!(tokens.user, user);
    assert!(!tokens.admin);

    // The device is registered with the proof key's thumbprint.
    let devices = world.store.devices_of(user);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, tokens.device);
    assert_eq!(devices[0].name, "Pixel");
    assert_eq!(devices[0].kind, DeviceKind::KemlockAndroid);
    assert_eq!(devices[0].dpop_jkt.as_deref(), Some("jkt-1"));

    // The access token lives 10 minutes and is bound to that key and the account's stamp.
    let claims = world
        .signer
        .verify(&tokens.access_token, world.env.now())
        .expect("the access token verifies");
    assert_eq!(claims.user, user);
    assert_eq!(claims.device, tokens.device);
    assert_eq!(claims.jkt, "jkt-1");
    assert_eq!(
        claims.security_stamp,
        world.store.user(user).expect("user").security_stamp
    );
    assert_eq!(claims.expires_at - claims.issued_at, Duration::minutes(10));

    // The refresh token is 32 random bytes, stored only as its SHA-256, for 30 days.
    let raw = b64url::decode(&tokens.refresh_token).expect("base64url");
    assert_eq!(raw.len(), 32);
    let rows = world.store.refresh_tokens();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].hash, kemlock_crypto::hash::sha256(&raw));
    assert_ne!(rows[0].hash.as_slice(), raw.as_slice());
    assert_eq!(rows[0].expires_at - rows[0].created_at, Duration::days(30));
    assert_eq!(rows[0].used_at, None);

    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.sign_in" && e.actor == Some(user))
    );
}

#[tokio::test]
async fn a_wrong_finalization_is_unauthorized() {
    let (world, _user) = signed_in_world().await;
    let (login_state, mut finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    let last = finalization.len() - 1;
    finalization[last] ^= 1;
    let result = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state,
            finalization,
            device: device("Pixel"),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(result, Err(AppError::Unauthorized));
    assert!(world.store.refresh_tokens().is_empty());
}

#[tokio::test]
async fn an_unknown_email_gets_a_response_that_looks_real_and_never_signs_in() {
    let (world, _user) = signed_in_world().await;
    let (state, request) =
        kemlock_crypto::opaque::client_login_start(&PASSWORD).expect("client login start");
    let ghost = world
        .sign_in()
        .start(OpaqueStartInput {
            email: "ghost@example.org".to_owned(),
            request: request.clone(),
            jkt: "jkt-1".to_owned(),
        })
        .await
        .expect("an unknown email still gets a response");
    let known = world
        .sign_in()
        .start(OpaqueStartInput {
            email: EMAIL.to_owned(),
            request,
            jkt: "jkt-1".to_owned(),
        })
        .await
        .expect("a known email gets a response");
    assert_eq!(ghost.response.len(), known.response.len());

    match kemlock_crypto::opaque::client_login_finish(state, &PASSWORD, &ghost.response) {
        // The client can't finish against a fake record, which is the usual outcome.
        Err(_) => {}
        Ok((finalization, _, _)) => {
            let result = world
                .sign_in()
                .finish(OpaqueFinishInput {
                    email: "ghost@example.org".to_owned(),
                    login_state: ghost.login_state,
                    finalization,
                    device: device("Pixel"),
                    jkt: "jkt-1".to_owned(),
                })
                .await;
            assert_eq!(result, Err(AppError::Unauthorized));
        }
    }
}

#[tokio::test]
async fn the_login_state_expires_after_five_minutes() {
    let (world, _user) = signed_in_world().await;
    let (login_state, finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    world.env.clock.advance(Duration::minutes(5));
    let result = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state,
            finalization,
            device: device("Pixel"),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert!(matches!(result, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn the_login_state_belongs_to_one_email() {
    let (world, _user) = signed_in_world().await;
    make_user(&world, "other@example.org").await;
    let (login_state, finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    let result = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: "other@example.org".to_owned(),
            login_state,
            finalization,
            device: device("Pixel"),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert!(matches!(result, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn a_login_state_that_is_garbage_or_sealed_for_another_purpose_is_refused() {
    let (world, _user) = signed_in_world().await;
    let (_, finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    for login_state in [
        vec![1, 2, 3],
        world
            .seal
            .seal("two-factor-challenge", b"not a login state"),
    ] {
        let result = world
            .sign_in()
            .finish(OpaqueFinishInput {
                email: EMAIL.to_owned(),
                login_state,
                finalization: finalization.clone(),
                device: device("Pixel"),
                jkt: "jkt-1".to_owned(),
            })
            .await;
        assert!(matches!(result, Err(AppError::Invalid(_))));
    }
}

#[tokio::test]
async fn an_account_with_two_step_login_gets_a_challenge_and_no_device_yet() {
    let (world, user) = two_step_world().await;
    let signed = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("the password step passes");
    let SignedIn::SecondStep(step) = signed else {
        panic!("a second step is expected");
    };
    assert_eq!(step.methods, vec![TwoFactorMethod::Totp]);
    assert!(world.store.devices_of(user).is_empty());
    assert!(world.store.refresh_tokens().is_empty());

    let tokens = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge: step.challenge,
            method: TwoFactorMethod::Totp,
            code: totp_code(&world, user),
            jkt: "jkt-1".to_owned(),
        })
        .await
        .expect("the right code signs in");
    assert_eq!(tokens.user, user);
    let devices = world.store.devices_of(user);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, tokens.device);
    assert_eq!(devices[0].name, "Pixel");
    assert_eq!(devices[0].dpop_jkt.as_deref(), Some("jkt-1"));
}

async fn challenge_for(world: &World) -> Vec<u8> {
    let signed = sign_in_with(world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("the password step passes");
    let SignedIn::SecondStep(step) = signed else {
        panic!("a second step is expected");
    };
    step.challenge
}

#[tokio::test]
async fn a_wrong_second_step_code_is_unauthorized() {
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    let right = totp_code(&world, user);
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    let result = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge,
            method: TwoFactorMethod::Totp,
            code: wrong.to_owned(),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(result.map(|_| ()), Err(AppError::Unauthorized));
    assert!(world.store.devices_of(user).is_empty());
}

#[tokio::test]
async fn a_challenge_only_works_for_the_key_that_passed_the_password() {
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    let result = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge,
            method: TwoFactorMethod::Totp,
            code: totp_code(&world, user),
            jkt: "jkt-other".to_owned(),
        })
        .await;
    assert_eq!(result.map(|_| ()), Err(AppError::Unauthorized));
}

#[tokio::test]
async fn a_challenge_expires_and_a_method_the_account_lacks_is_refused() {
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    let code = totp_code(&world, user);

    let missing = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge: challenge.clone(),
            method: TwoFactorMethod::WebAuthn,
            code: code.clone(),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(missing.map(|_| ()), Err(AppError::Unauthorized));

    world.env.clock.advance(Duration::minutes(6));
    let late = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge,
            method: TwoFactorMethod::Totp,
            code: totp_code(&world, user),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert!(matches!(late, Err(AppError::Invalid(_))));
}

#[tokio::test]
async fn a_forged_challenge_is_refused() {
    let (world, user) = two_step_world().await;
    let result = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge: vec![0; 40],
            method: TwoFactorMethod::Totp,
            code: totp_code(&world, user),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert!(matches!(result, Err(AppError::Invalid(_))));
}

fn known_device(id: kemlock_domain::DeviceId) -> DeviceInfo {
    DeviceInfo {
        id: Some(id),
        name: "Pixel".to_owned(),
        kind: DeviceKind::KemlockAndroid,
        bitwarden_identifier: None,
    }
}

#[tokio::test]
async fn signing_in_again_from_a_device_with_a_new_key_ends_its_old_tokens() {
    let (world, user) = signed_in_world().await;
    let SignedIn::Tokens(first) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("first sign-in")
    else {
        panic!("tokens expected");
    };
    let SignedIn::Tokens(second) = sign_in_with(
        &world,
        EMAIL,
        &PASSWORD,
        known_device(first.device),
        "jkt-2",
    )
    .await
    .expect("second sign-in") else {
        panic!("tokens expected");
    };
    assert_eq!(second.device, first.device);

    let devices = world.store.devices_of(user);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].dpop_jkt.as_deref(), Some("jkt-2"));
    // The first sign-in's refresh token is gone; only the new one remains.
    let rows = world.store.refresh_tokens();
    assert_eq!(rows.len(), 1);
    let raw = b64url::decode(&second.refresh_token).expect("base64url");
    assert_eq!(rows[0].hash, kemlock_crypto::hash::sha256(&raw));
}

#[tokio::test]
async fn signing_in_again_with_the_same_key_keeps_the_device_and_its_tokens() {
    let (world, user) = signed_in_world().await;
    let SignedIn::Tokens(first) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("first sign-in")
    else {
        panic!("tokens expected");
    };
    sign_in_with(
        &world,
        EMAIL,
        &PASSWORD,
        known_device(first.device),
        "jkt-1",
    )
    .await
    .expect("second sign-in");
    assert_eq!(world.store.devices_of(user).len(), 1);
    assert_eq!(world.store.refresh_tokens().len(), 2);
}

#[tokio::test]
async fn a_device_id_of_another_account_is_refused() {
    let (world, _user) = signed_in_world().await;
    make_user(&world, "other@example.org").await;
    let SignedIn::Tokens(theirs) = sign_in_with(
        &world,
        "other@example.org",
        &PASSWORD,
        device("Pixel"),
        "jkt-x",
    )
    .await
    .expect("their sign-in") else {
        panic!("tokens expected");
    };
    let result = sign_in_with(
        &world,
        EMAIL,
        &PASSWORD,
        known_device(theirs.device),
        "jkt-1",
    )
    .await;
    assert_eq!(result.map(|_| ()), Err(AppError::Duplicate));
}

async fn second_step_with(
    world: &World,
    challenge: Vec<u8>,
    code: String,
) -> Result<kemlock_app::TokenPair, AppError> {
    world
        .sign_in()
        .second_step(SecondStepInput {
            challenge,
            method: TwoFactorMethod::Totp,
            code,
            jkt: "jkt-1".to_owned(),
        })
        .await
}

/// The code for the account's TOTP secret at `unix` seconds.
fn code_at(world: &World, user: UserId, unix: u64) -> String {
    let row = world
        .store
        .two_factor_of(user)
        .into_iter()
        .find(|t| t.method == TwoFactorMethod::Totp)
        .expect("the user has a TOTP enrolment");
    let secret = world
        .seal
        .open(
            &kemlock_app::sealed::bound_purpose("totp", user),
            &row.sealed_secret,
        )
        .expect("the secret opens");
    kemlock_crypto::totp::code_at(&secret, unix)
}

#[tokio::test]
async fn a_totp_code_signs_in_once_and_is_a_replay_after_that() {
    let (world, user) = two_step_world().await;
    let code = totp_code(&world, user);

    second_step_with(&world, challenge_for(&world).await, code.clone())
        .await
        .expect("the first use of the code signs in");

    // The same code, a minute-long window it is still valid in, from a second sign-in: refused,
    // so a code seen over a shoulder or in a proxy log is worthless once it was used.
    let replay = second_step_with(&world, challenge_for(&world).await, code).await;
    assert_eq!(replay.map(|_| ()), Err(AppError::Unauthorized));
    assert_eq!(
        world.store.devices_of(user).len(),
        1,
        "no device for a replay"
    );

    // An older step, still inside the one-step tolerance, is a replay too.
    let now = unix(world.env.now());
    let older = code_at(&world, user, now - 30);
    let behind = second_step_with(&world, challenge_for(&world).await, older).await;
    assert_eq!(behind.map(|_| ()), Err(AppError::Unauthorized));

    // The next step's code is new and works, now and when its time has come.
    let newer = code_at(&world, user, now + 30);
    second_step_with(&world, challenge_for(&world).await, newer)
        .await
        .expect("a newer step signs in");
    world.env.clock.advance(Duration::seconds(60));
    let later = totp_code(&world, user);
    second_step_with(&world, challenge_for(&world).await, later)
        .await
        .expect("a later code signs in");
}

#[tokio::test]
async fn a_challenge_names_its_account_only_while_it_is_fresh_and_genuine() {
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    assert_eq!(world.sign_in().challenge_user(&challenge), Ok(user));
    assert!(matches!(
        world.sign_in().challenge_user(&[0; 40]),
        Err(AppError::Invalid(_))
    ));
    world.env.clock.advance(Duration::minutes(6));
    assert!(matches!(
        world.sign_in().challenge_user(&challenge),
        Err(AppError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_login_state_only_finishes_for_the_key_that_asked_for_it() {
    let (world, user) = signed_in_world().await;
    let (login_state, finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-phone")
        .await
        .expect("messages");

    // Another key, holding a copy of the state and the finalization (both travel in the open
    // between the app and the server's first answer), can't use them.
    let thief = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state: login_state.clone(),
            finalization: finalization.clone(),
            device: device("Thief"),
            jkt: "jkt-thief".to_owned(),
        })
        .await;
    assert_eq!(thief, Err(AppError::Unauthorized));
    assert!(world.store.devices_of(user).is_empty());
    assert!(world.store.refresh_tokens().is_empty());

    // The key that asked finishes it.
    let signed = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state,
            finalization,
            device: device("Phone"),
            jkt: "jkt-phone".to_owned(),
        })
        .await
        .expect("the key that asked signs in");
    assert!(matches!(signed, SignedIn::Tokens(_)));
}

#[tokio::test]
async fn check_login_state_accepts_only_genuine_fresh_states() {
    let (world, _user) = signed_in_world().await;
    let (login_state, _) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    assert_eq!(world.sign_in().check_login_state(&login_state), Ok(()));
    assert!(matches!(
        world.sign_in().check_login_state(&[1, 2, 3]),
        Err(AppError::Invalid(_))
    ));
    world.env.clock.advance(Duration::minutes(5));
    assert!(matches!(
        world.sign_in().check_login_state(&login_state),
        Err(AppError::Invalid(_))
    ));
}

#[tokio::test]
async fn check_login_state_for_wants_the_state_made_for_that_email() {
    let (world, _user) = signed_in_world().await;
    let (login_state, _) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    assert_eq!(
        world.sign_in().check_login_state_for(&login_state, EMAIL),
        Ok(())
    );
    // The email is compared as the sign-in name is: trimmed and lower-cased.
    assert_eq!(
        world
            .sign_in()
            .check_login_state_for(&login_state, " Sam@Example.org "),
        Ok(())
    );
    assert!(matches!(
        world
            .sign_in()
            .check_login_state_for(&login_state, "alex@example.org"),
        Err(AppError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_disabled_account_gets_no_session_with_the_right_password() {
    let (world, user) = signed_in_world().await;
    world.store.set_account_disabled(user, true);

    let result = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1").await;
    assert_eq!(result, Err(AppError::AccountDisabled));
    assert!(world.store.devices_of(user).is_empty());
    assert!(world.store.refresh_tokens().is_empty());

    // Enabling the account lets it in again.
    world.store.set_account_disabled(user, false);
    let signed = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1").await;
    assert!(matches!(signed, Ok(SignedIn::Tokens(_))), "{signed:?}");
}

#[tokio::test]
async fn a_disabled_account_is_not_named_to_someone_without_its_password() {
    let (world, user) = signed_in_world().await;
    world.store.set_account_disabled(user, true);
    let (login_state, mut finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    let last = finalization.len() - 1;
    finalization[last] ^= 1;
    let result = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state,
            finalization,
            device: device("Pixel"),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(result, Err(AppError::Unauthorized));
}

#[tokio::test]
async fn an_account_disabled_between_the_password_and_the_code_gets_no_session() {
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    world.store.set_account_disabled(user, true);
    let result = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge,
            method: TwoFactorMethod::Totp,
            code: totp_code(&world, user),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(result.map(|_| ()), Err(AppError::AccountDisabled));
    assert!(world.store.devices_of(user).is_empty());
    assert!(world.store.refresh_tokens().is_empty());
}

#[tokio::test]
async fn an_account_whose_deletion_is_pending_gets_no_session_with_the_right_password() {
    let (world, user) = signed_in_world().await;
    world.store.set_erasure_pending(user, true);

    let result = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1").await;
    assert_eq!(result, Err(AppError::AccountBeingDeleted));
    assert!(world.store.devices_of(user).is_empty());
    assert!(world.store.refresh_tokens().is_empty());

    // Signing in does not cancel the deletion; once it is cancelled the account signs in again.
    world.store.set_erasure_pending(user, false);
    let signed = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1").await;
    assert!(matches!(signed, Ok(SignedIn::Tokens(_))), "{signed:?}");
}

#[tokio::test]
async fn a_pending_deletion_is_not_named_to_someone_without_the_password() {
    let (world, user) = signed_in_world().await;
    world.store.set_erasure_pending(user, true);
    let (login_state, mut finalization) = login_messages(&world, EMAIL, &PASSWORD, "jkt-1")
        .await
        .expect("messages");
    let last = finalization.len() - 1;
    finalization[last] ^= 1;
    let result = world
        .sign_in()
        .finish(OpaqueFinishInput {
            email: EMAIL.to_owned(),
            login_state,
            finalization,
            device: device("Pixel"),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(result, Err(AppError::Unauthorized));
}

#[tokio::test]
async fn a_deletion_scheduled_between_the_password_and_the_code_gets_no_session() {
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    world.store.set_erasure_pending(user, true);
    let result = world
        .sign_in()
        .second_step(SecondStepInput {
            challenge,
            method: TwoFactorMethod::Totp,
            code: totp_code(&world, user),
            jkt: "jkt-1".to_owned(),
        })
        .await;
    assert_eq!(result.map(|_| ()), Err(AppError::AccountBeingDeleted));
    assert!(world.store.devices_of(user).is_empty());
}

/// The account's TOTP row as the store has it.
fn totp_row(world: &World, user: UserId) -> kemlock_app::ports::TwoFactor {
    world
        .store
        .two_factor_of(user)
        .into_iter()
        .find(|t| t.method == TwoFactorMethod::Totp)
        .expect("the user has a TOTP enrolment")
}

#[tokio::test]
async fn a_secret_stored_before_binding_still_signs_in_and_is_sealed_to_its_account() {
    use kemlock_app::ports::TwoFactorRepo;
    use kemlock_app::sealed::bound_purpose;
    let (world, user) = two_step_world().await;
    // Put the secret back the way earlier versions (and an import from Vaultwarden) stored it:
    // under the bare purpose.
    let mut row = totp_row(&world, user);
    let secret = world
        .seal
        .open(&bound_purpose("totp", user), &row.sealed_secret)
        .expect("opens");
    row.sealed_secret = world.seal.seal("totp", &secret);
    TwoFactorRepo::put(&world.store, &row)
        .await
        .expect("stored");

    let code = totp_code_of(&world, user, &secret);
    second_step_with(&world, challenge_for(&world).await, code)
        .await
        .expect("a legacy secret still signs in");

    let after = totp_row(&world, user);
    assert!(
        world
            .seal
            .open(&bound_purpose("totp", user), &after.sealed_secret)
            .is_ok(),
        "sealed to the account once it was used"
    );
    assert!(world.seal.open("totp", &after.sealed_secret).is_err());
    assert!(after.enabled);
}

fn totp_code_of(world: &World, _user: UserId, secret: &[u8]) -> String {
    kemlock_crypto::totp::code_at(secret, unix(world.env.now()))
}

#[tokio::test]
async fn a_secret_copied_from_another_accounts_row_does_not_sign_in() {
    use kemlock_app::ports::TwoFactorRepo;
    let (world, user) = two_step_world().await;
    // Another account with its own enrolled authenticator.
    let other = make_user(&world, "kim@example.org").await;
    world
        .enrol_totp()
        .execute(other)
        .await
        .expect("enrolment works");
    let other_code = totp_code(&world, other);
    world
        .confirm_totp()
        .execute(other, &other_code)
        .await
        .expect("confirmed");

    // Someone who can write the database, not read `server.key`, copies their own sealed secret
    // into the victim's row, and holds the code for it.
    let mut victim = totp_row(&world, user);
    victim.sealed_secret = totp_row(&world, other).sealed_secret;
    TwoFactorRepo::put(&world.store, &victim)
        .await
        .expect("stored");
    let code = totp_code(&world, other);

    let result = second_step_with(&world, challenge_for(&world).await, code).await;
    assert!(result.is_err(), "the copied secret does not open here");
    assert_eq!(world.store.devices_of(user).len(), 0);
}

#[tokio::test]
async fn an_account_held_for_its_email_is_refused_once_the_password_checks_out() {
    use kemlock_app::ports::{Clock, UserRepo};
    let (world, user) = signed_in_world().await;
    let world = world.with_email_verification();
    let now = Clock::now(&world.env);
    UserRepo::hold_unconfirmed(&world.store, user, [2; 32], now, now + Duration::hours(1))
        .await
        .expect("held");

    let result = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1").await;
    assert_eq!(result.map(|_| ()), Err(AppError::EmailNotConfirmed));
    assert!(world.store.devices_of(user).is_empty());
    assert!(world.store.refresh_tokens().is_empty());

    UserRepo::spend_confirmation(&world.store, [2; 32], now)
        .await
        .expect("opened");
    sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), "jkt-1")
        .await
        .expect("signs in once confirmed");
}

#[tokio::test]
async fn an_account_at_its_device_cap_refuses_a_new_device_but_not_a_known_one() {
    use kemlock_app::ports::{Clock, DeviceRepo};
    use kemlock_app::session::MAX_DEVICES_PER_ACCOUNT;
    use kemlock_domain::{Device, DeviceId};
    let (world, user) = signed_in_world().await;
    let now = Clock::now(&world.env);
    let first = DeviceId::random();
    for n in 0..MAX_DEVICES_PER_ACCOUNT {
        let id = if n == 0 { first } else { DeviceId::random() };
        DeviceRepo::upsert(
            &world.store,
            &Device {
                id,
                user,
                name: format!("Phone {n}"),
                kind: DeviceKind::KemlockAndroid,
                dpop_jkt: Some(format!("jkt-{n}")),
                created_at: now,
                last_seen_at: now,
            },
        )
        .await
        .expect("stored");
    }

    let refused = sign_in_with(&world, EMAIL, &PASSWORD, device("One too many"), "jkt-new")
        .await
        .map(|_| ());
    assert!(
        matches!(refused, Err(AppError::Invalid(text)) if text.contains("too many")),
        "{refused:?}"
    );
    assert_eq!(world.store.devices_of(user).len(), MAX_DEVICES_PER_ACCOUNT);

    // A device the account already has signs in again, with a new key.
    let mut known = device("Phone 0");
    known.id = Some(first);
    sign_in_with(&world, EMAIL, &PASSWORD, known, "jkt-0-rotated")
        .await
        .expect("a known device is not a new one");
}

#[tokio::test]
async fn every_second_step_finish_checks_the_policy_and_a_pending_erasure() {
    use kemlock_app::sso::{SpaceMembership, SpaceRole};
    use kemlock_domain::SpaceId;
    let (world, user) = two_step_world().await;
    let challenge = challenge_for(&world).await;
    assert_eq!(world.sign_in().check_second_step_allowed(&challenge).await, Ok(()));

    // A space turns Require SSO on after the password step: the second step is refused for
    // whatever method answers it, not only for the authenticator app.
    let space = SpaceId::random();
    world.store.set_memberships(
        user,
        vec![SpaceMembership {
            space,
            role: SpaceRole::Member,
            require_sso: true,
        }],
    );
    assert_eq!(
        world.sign_in().check_second_step_allowed(&challenge).await,
        Err(AppError::SsoRequired { space })
    );
    world.store.set_memberships(user, Vec::new());
    assert_eq!(world.sign_in().check_second_step_allowed(&challenge).await, Ok(()));

    // A disabled account, and one waiting out its erasure, are refused too.
    world.store.set_account_disabled(user, true);
    assert_eq!(
        world.sign_in().check_second_step_allowed(&challenge).await,
        Err(AppError::AccountDisabled)
    );
    world.store.set_account_disabled(user, false);
    // A challenge that is garbage is refused as one.
    assert!(matches!(
        world.sign_in().check_second_step_allowed(&[1, 2, 3]).await,
        Err(AppError::Invalid(_))
    ));
}
