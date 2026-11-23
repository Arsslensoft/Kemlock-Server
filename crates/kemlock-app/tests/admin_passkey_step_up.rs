//! Step-up with a passkey, over fakes and the scripted relying party: a fresh assertion from one
//! of the admin's own passkeys, with user verification, makes the same token the password and the
//! authenticator code make.

mod fakes;
mod passkey_fakes;

use fakes::*;
use kemlock_app::Actor;
use kemlock_app::admin::passkey_step_up::CHALLENGE_TTL;
use kemlock_app::admin::{AdminError, PasskeyStepUp, PasskeyStepper, StepUp};
use kemlock_domain::{DeviceId, UserId};
use passkey_fakes::*;
use time::Duration;

type Stepper = PasskeyStepUp<FakePasskeys, ScriptedWebAuthn, FakeSeal, FakeEnv>;

struct Fx {
    passkeys: FakePasskeys,
    seal: FakeSeal,
    env: FakeEnv,
    stepper: Stepper,
    me: Actor,
}

const CREDENTIAL: &[u8] = b"credential-one";

fn fx() -> Fx {
    let passkeys = FakePasskeys::default();
    let seal = FakeSeal::new();
    let env = FakeEnv::new();
    let me = Actor {
        user: UserId::random(),
        device: DeviceId::random(),
        admin: true,
    };
    passkeys.insert_for_test(me.user, "Work key", CREDENTIAL);
    Fx {
        stepper: PasskeyStepUp {
            passkeys: passkeys.clone(),
            webauthn: ScriptedWebAuthn::default(),
            seal: seal.clone(),
            env: env.clone(),
        },
        passkeys,
        seal,
        env,
        me,
    }
}

impl Fx {
    /// The check a write runs on its `Step-Up-Token` header.
    fn accepts(&self, actor: &Actor, token: &str) -> bool {
        StepUp {
            users: FakeStore::new(),
            two_factor: FakeStore::new(),
            auth: FakePassword::new(),
            seal: self.seal.clone(),
            totp: FakeTotp,
            env: self.env.clone(),
        }
        .check(actor, token)
        .is_ok()
    }

    /// An assertion for the challenge in `options`, from the credential `id`.
    fn answer(&self, options: &serde_json::Value, id: &[u8], counter: u32, uv: bool) -> Vec<u8> {
        assertion_answer(options, id, Some(self.me.user.as_bytes()), counter, uv)
    }
}

#[tokio::test]
async fn a_verified_assertion_from_the_admins_passkey_makes_a_step_up_token() {
    let fx = fx();
    let challenge = fx.stepper.options(&fx.me).await.expect("options");
    assert_eq!(challenge.options["kind"], "Passkey");
    assert_eq!(challenge.options["allowCredentials"], 1, "only their own");
    fx.stepper
        .check_challenge(&fx.me, &challenge.challenge)
        .expect("genuine and fresh");

    let answer = fx.answer(&challenge.options, CREDENTIAL, 1, true);
    let issued = fx
        .stepper
        .finish(&fx.me, &challenge.challenge, &answer)
        .await
        .expect("a token");
    assert!(fx.accepts(&fx.me, &issued.token), "the writes take it");
    // Not for another device of the same account, nor another account.
    let other_device = Actor {
        device: DeviceId::random(),
        ..fx.me
    };
    assert!(!fx.accepts(&other_device, &issued.token));

    // The authenticator's counter moved on and the use is recorded.
    let stored = fx.passkeys.of(fx.me.user);
    assert_eq!(stored[0].credential, credential_blob(CREDENTIAL, 1));
    assert!(stored[0].last_used_at.is_some());
}

#[tokio::test]
async fn an_account_without_a_passkey_is_told_to_use_another_way() {
    let fx = fx();
    let stranger = Actor {
        user: UserId::random(),
        device: DeviceId::random(),
        admin: true,
    };
    let refused = fx.stepper.options(&stranger).await;
    assert!(matches!(refused, Err(AdminError::State(_))), "{refused:?}");
}

#[tokio::test]
async fn an_assertion_without_user_verification_is_refused() {
    let fx = fx();
    let challenge = fx.stepper.options(&fx.me).await.expect("options");
    let answer = fx.answer(&challenge.options, CREDENTIAL, 1, false);
    let refused = fx
        .stepper
        .finish(&fx.me, &challenge.challenge, &answer)
        .await;
    assert_eq!(refused, Err(AdminError::StepUpFailed));
    // Nothing was recorded for a refused answer.
    assert!(fx.passkeys.of(fx.me.user)[0].last_used_at.is_none());
}

#[tokio::test]
async fn another_accounts_passkey_or_handle_is_refused() {
    let fx = fx();
    let other = UserId::random();
    fx.passkeys
        .insert_for_test(other, "Theirs", b"credential-two");
    let challenge = fx.stepper.options(&fx.me).await.expect("options");

    // A credential that is somebody else's.
    let answer = fx.answer(&challenge.options, b"credential-two", 1, true);
    assert_eq!(
        fx.stepper
            .finish(&fx.me, &challenge.challenge, &answer)
            .await,
        Err(AdminError::StepUpFailed)
    );
    // The admin's credential, with another account's user handle.
    let answer = assertion_answer(
        &challenge.options,
        CREDENTIAL,
        Some(other.as_bytes()),
        1,
        true,
    );
    assert_eq!(
        fx.stepper
            .finish(&fx.me, &challenge.challenge, &answer)
            .await,
        Err(AdminError::StepUpFailed)
    );
}

#[tokio::test]
async fn a_replayed_counter_is_refused() {
    let fx = fx();
    let first = fx.stepper.options(&fx.me).await.expect("options");
    let answer = fx.answer(&first.options, CREDENTIAL, 5, true);
    fx.stepper
        .finish(&fx.me, &first.challenge, &answer)
        .await
        .expect("a token");

    let second = fx.stepper.options(&fx.me).await.expect("options");
    let replay = fx.answer(&second.options, CREDENTIAL, 5, true);
    assert_eq!(
        fx.stepper.finish(&fx.me, &second.challenge, &replay).await,
        Err(AdminError::StepUpFailed)
    );
}

#[tokio::test]
async fn a_challenge_is_for_its_account_and_device_and_expires() {
    let fx = fx();
    let challenge = fx.stepper.options(&fx.me).await.expect("options");
    let answer = fx.answer(&challenge.options, CREDENTIAL, 1, true);

    let other_device = Actor {
        device: DeviceId::random(),
        ..fx.me
    };
    assert_eq!(
        fx.stepper
            .finish(&other_device, &challenge.challenge, &answer)
            .await,
        Err(AdminError::StepUpFailed)
    );
    assert_eq!(
        fx.stepper
            .check_challenge(&other_device, &challenge.challenge),
        Err(AdminError::StepUpFailed)
    );

    // Made-up bytes aren't a challenge at all.
    assert!(matches!(
        fx.stepper.check_challenge(&fx.me, b"not a challenge"),
        Err(AdminError::Invalid(_))
    ));

    fx.env.clock.advance(CHALLENGE_TTL + Duration::seconds(1));
    let late = fx
        .stepper
        .finish(&fx.me, &challenge.challenge, &answer)
        .await;
    assert!(matches!(late, Err(AdminError::Invalid(_))), "{late:?}");
}

#[tokio::test]
async fn a_challenge_answers_with_its_own_options_only() {
    let fx = fx();
    let first = fx.stepper.options(&fx.me).await.expect("options");
    let second = fx.stepper.options(&fx.me).await.expect("options");
    // An answer to the second challenge doesn't finish the first.
    let answer = fx.answer(&second.options, CREDENTIAL, 1, true);
    assert_eq!(
        fx.stepper.finish(&fx.me, &first.challenge, &answer).await,
        Err(AdminError::StepUpFailed)
    );
}
