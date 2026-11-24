//! Emailed codes, YubiKey OTPs and Duo as second steps, over fakes: the code and the services the
//! use cases call out to are scripted. Rows written the way the move from Vaultwarden writes them
//! (Vaultwarden's own JSON, sealed) sign in as the rows the use cases make.

mod fakes;
mod passkey_fakes;

use fakes::*;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::passkeys::ChallengeKind;
use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{
    Duo, DuoError, DuoKeys, DuoPrompt, DuoStatus, PROTECTED_REQUEST_DELAY_SECS, PURPOSE_DUO,
    PURPOSE_EMAIL, PURPOSE_YUBIKEY, ProtectedError, TwoStep, TwoStepInput, TwoStepSettings,
    TwoStepSignIn, Yubico, YubicoError, obscure_email,
};
use kemlock_app::{AppError, SecondStep, SignedIn};
use kemlock_domain::{User, UserId};
use passkey_fakes::FakePasskeys;
use std::sync::{Arc, Mutex};
use time::Duration;

type Steps = TwoStep<FakeStore, FakeSeal, FakeEnv, FakePasskeys>;
type StepIn = TwoStepSignIn<
    FakeStore,
    FakeStore,
    FakeSeal,
    FakeEnv,
    FakePasskeys,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeStore,
>;

const EMAIL: &str = "ada@example.org";
const JKT: &str = "device-key-thumbprint";
const OTP: &str = "cccccccccccckhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv";
const YUBI_ID: &str = "cccccccccccc";

/// What the mail sender was asked to send.
#[derive(Clone, Default)]
struct Mailbox(Arc<Mutex<Vec<Notice>>>);

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.lock().expect("the mailbox lock").push(notice);
        })
    }
}

impl Mailbox {
    /// The address and code of every code mailed, oldest first.
    fn codes(&self) -> Vec<(String, String)> {
        self.0
            .lock()
            .expect("the mailbox lock")
            .iter()
            .filter_map(|n| match n {
                Notice::TwoStepCode(code) => Some((code.to.as_str().to_owned(), code.code.clone())),
                _ => None,
            })
            .collect()
    }

    fn last_code(&self) -> String {
        self.codes().pop().expect("a code was mailed").1
    }

    /// The address and code of every protected-action code mailed, oldest first.
    fn protected_codes(&self) -> Vec<(String, String)> {
        self.0
            .lock()
            .expect("the mailbox lock")
            .iter()
            .filter_map(|n| match n {
                Notice::ProtectedAction(code) => {
                    Some((code.to.as_str().to_owned(), code.code.clone()))
                }
                _ => None,
            })
            .collect()
    }

    fn last_protected_code(&self) -> String {
        self.protected_codes()
            .pop()
            .expect("a protected-action code was mailed")
            .1
    }
}

/// Yubico's service: it accepts the OTPs it was told about.
#[derive(Clone, Default)]
struct FakeYubico {
    accepted: Arc<Mutex<Vec<String>>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl FakeYubico {
    fn accept(&self, otp: &str) {
        self.accepted.lock().expect("the lock").push(otp.to_owned());
    }

    fn asked(&self) -> usize {
        self.asked.lock().expect("the lock").len()
    }
}

impl Yubico for FakeYubico {
    fn verify<'a>(&'a self, otp: &'a str) -> BoxFuture<'a, Result<(), YubicoError>> {
        Box::pin(async move {
            self.asked.lock().expect("the lock").push(otp.to_owned());
            if self
                .accepted
                .lock()
                .expect("the lock")
                .iter()
                .any(|o| o == otp)
            {
                Ok(())
            } else {
                Err(YubicoError::Rejected)
            }
        })
    }
}

/// A prompt Duo was asked to start: the username, the device, the state and the host.
type Started = (String, String, String, String);

/// Duo: a prompt is for a person and a device, and the code `duo-says-yes` answers it.
#[derive(Clone, Default)]
struct FakeDuo {
    prompts: Arc<Mutex<Vec<Started>>>,
}

impl FakeDuo {
    fn last_prompt(&self) -> Started {
        self.prompts
            .lock()
            .expect("the lock")
            .last()
            .cloned()
            .expect("a prompt was started")
    }
}

impl Duo for FakeDuo {
    fn check_keys<'a>(&'a self, keys: &'a DuoKeys) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async move {
            if keys.host.contains("bad") {
                Err(DuoError::Rejected)
            } else {
                Ok(())
            }
        })
    }

    fn auth_url<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
    ) -> BoxFuture<'a, Result<String, DuoError>> {
        Box::pin(async move {
            self.prompts.lock().expect("the lock").push((
                prompt.username.to_owned(),
                prompt.device.to_owned(),
                prompt.state.to_owned(),
                prompt.keys.host.clone(),
            ));
            Ok(format!(
                "https://{}/oauth/v1/authorize?state={}",
                prompt.keys.host, prompt.state
            ))
        })
    }

    fn verify<'a>(
        &'a self,
        prompt: &'a DuoPrompt<'a>,
        code: &'a str,
    ) -> BoxFuture<'a, Result<(), DuoError>> {
        Box::pin(async move {
            let known = self
                .prompts
                .lock()
                .expect("the lock")
                .iter()
                .any(|p| p.0 == prompt.username && p.1 == prompt.device && p.2 == prompt.state);
            if known && code == "duo-says-yes" {
                Ok(())
            } else {
                Err(DuoError::Rejected)
            }
        })
    }
}

fn global_duo() -> DuoKeys {
    DuoKeys {
        host: "api-global.duosecurity.com".to_owned(),
        ik: "DIGLOBALGLOBALGLOBAL".to_owned(),
        sk: "global-secret-key".to_owned(),
    }
}

fn own_duo() -> DuoKeys {
    DuoKeys {
        host: "api-own.duosecurity.com".to_owned(),
        ik: "DIOWNOWNOWNOWNOWNOWN".to_owned(),
        sk: "own-secret".to_owned(),
    }
}

struct Fx {
    world: World,
    mailbox: Mailbox,
    yubico: FakeYubico,
    duo: FakeDuo,
    passkeys: FakePasskeys,
    settings: TwoStepSettings,
}

impl Fx {
    fn new() -> Self {
        Fx {
            world: World::new().with_signups(),
            mailbox: Mailbox::default(),
            yubico: FakeYubico::default(),
            duo: FakeDuo::default(),
            passkeys: FakePasskeys::default(),
            settings: TwoStepSettings {
                email_enabled: true,
                yubico_enabled: true,
                duo_global: Some(global_duo()),
                ..TwoStepSettings::default()
            },
        }
    }

    async fn user(&self) -> User {
        let id = make_user(&self.world, EMAIL).await;
        self.world.store.user(id).expect("the account exists")
    }

    fn steps(&self) -> Steps {
        TwoStep {
            two_factor: self.world.store.clone(),
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            challenges: self.passkeys.clone(),
            notices: Notices::with_outbox(Arc::new(self.mailbox.clone())),
            yubico: Arc::new(self.yubico.clone()),
            duo: Arc::new(self.duo.clone()),
            settings: self.settings.clone(),
        }
    }

    fn step(&self) -> StepIn {
        TwoStepSignIn {
            users: self.world.store.clone(),
            two_step: self.steps(),
            sessions: self.world.sessions(),
        }
    }

    /// A row as the move from Vaultwarden writes it: Vaultwarden's JSON, sealed.
    async fn imported(&self, user: UserId, method: TwoFactorMethod, purpose: &str, json: &str) {
        self.world
            .store
            .put(&TwoFactor {
                user,
                method,
                sealed_secret: self.world.seal.seal(purpose, json.as_bytes()),
                enabled: true,
                created_at: self.world.env.now(),
            })
            .await
            .expect("the row is stored");
    }

    async fn password_step(&self) -> SecondStep {
        match sign_in_with(&self.world, EMAIL, &PASSWORD, device("Pixel"), JKT)
            .await
            .expect("the password is right")
        {
            SignedIn::SecondStep(step) => step,
            other => panic!("a second step was expected, got {other:?}"),
        }
    }

    fn input(&self, step: &SecondStep, method: TwoFactorMethod, code: &str) -> TwoStepInput {
        TwoStepInput {
            challenge: step.challenge.clone(),
            method,
            code: code.to_owned(),
            jkt: JKT.to_owned(),
            client: "web".to_owned(),
        }
    }

    /// Turns the email method on for `user` through the setup calls.
    async fn enable_email(&self, user: UserId) {
        self.steps()
            .email_begin(user, EMAIL)
            .await
            .expect("a code is sent");
        self.steps()
            .email_confirm(user, EMAIL, &self.mailbox.last_code())
            .await
            .expect("the method is on");
    }
}

// ---------------------------------------------------------------------------------------------
// Email.

#[tokio::test]
async fn an_address_is_confirmed_with_a_first_code_before_the_method_is_on() {
    let fx = Fx::new();
    let user = fx.user().await.id;

    fx.steps()
        .email_begin(user, "mfa@example.org")
        .await
        .expect("a code is sent");
    let codes = fx.mailbox.codes();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0].0, "mfa@example.org");
    assert_eq!(codes[0].1.len(), 6);
    assert!(codes[0].1.bytes().all(|b| b.is_ascii_digit()));
    // Not on yet: nothing is stored until the code comes back.
    assert!(fx.world.store.two_factor_of(user).is_empty());
    assert_eq!(fx.steps().email_address(user).await, Ok(None));

    assert_eq!(
        fx.steps()
            .email_confirm(user, "mfa@example.org", "not-the-code")
            .await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        fx.steps()
            .email_confirm(user, "other@example.org", &fx.mailbox.last_code())
            .await,
        Err(AppError::Unauthorized),
        "the address the code was sent to is the one confirmed"
    );
    fx.steps()
        .email_confirm(user, "mfa@example.org", &fx.mailbox.last_code())
        .await
        .expect("the method is on");
    assert_eq!(
        fx.steps().email_address(user).await,
        Ok(Some("mfa@example.org".to_owned()))
    );
    let rows = fx.world.store.two_factor_of(user);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].method, TwoFactorMethod::Email);
    assert!(rows[0].enabled);
    // The code is spent: asking to confirm again finds none.
    assert_eq!(
        fx.steps()
            .email_confirm(user, "mfa@example.org", &fx.mailbox.last_code())
            .await,
        Err(AppError::Invalid(
            "no email code was asked for, or it expired"
        ))
    );
}

#[tokio::test]
async fn beginning_again_takes_the_method_off_until_the_new_address_is_confirmed() {
    let fx = Fx::new();
    let user = fx.user().await.id;
    fx.enable_email(user).await;
    assert_eq!(fx.world.store.two_factor_of(user).len(), 1);
    fx.steps()
        .email_begin(user, "new@example.org")
        .await
        .expect("a code is sent");
    assert!(fx.world.store.two_factor_of(user).is_empty());
    fx.steps()
        .email_confirm(user, "new@example.org", &fx.mailbox.last_code())
        .await
        .expect("on again");
    assert_eq!(
        fx.steps().email_address(user).await,
        Ok(Some("new@example.org".to_owned()))
    );
    fx.steps().email_disable(user).await.expect("off");
    assert!(fx.world.store.two_factor_of(user).is_empty());
}

#[tokio::test]
async fn a_server_without_a_mailer_offers_no_email_codes() {
    let mut fx = Fx::new();
    fx.settings.email_enabled = false;
    let user = fx.user().await.id;
    assert_eq!(
        fx.steps().email_begin(user, EMAIL).await,
        Err(AppError::Invalid(
            "email codes are not enabled on this server"
        ))
    );
    assert!(fx.mailbox.codes().is_empty());
}

#[tokio::test]
async fn an_address_that_is_not_one_gets_no_code() {
    let fx = Fx::new();
    let user = fx.user().await.id;
    assert_eq!(
        fx.steps().email_begin(user, "no at sign").await,
        Err(AppError::Invalid("the email address isn't valid"))
    );
    assert!(fx.mailbox.codes().is_empty());
}

#[tokio::test]
async fn an_emailed_code_answers_the_second_step_once() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.enable_email(user.id).await;

    let step = fx.password_step().await;
    assert_eq!(step.methods, vec![TwoFactorMethod::Email]);
    assert!(fx.world.store.devices_of(user.id).is_empty());
    fx.step()
        .send_email_code(&step.challenge, JKT)
        .await
        .expect("a code is sent");
    let code = fx.mailbox.last_code();
    let sent = fx.mailbox.codes();
    assert_eq!(sent.last().map(|c| c.0.as_str()), Some(EMAIL));

    // Another device key can't ask for the code or answer it.
    assert_eq!(
        fx.step()
            .send_email_code(&step.challenge, "another-key")
            .await,
        Err(AppError::Unauthorized)
    );
    let mut stolen = fx.input(&step, TwoFactorMethod::Email, &code);
    stolen.jkt = "another-key".to_owned();
    assert_eq!(
        fx.step().verify(stolen).await.map(|_| ()),
        Err(AppError::Unauthorized)
    );

    let tokens = fx
        .step()
        .verify(fx.input(&step, TwoFactorMethod::Email, &code))
        .await
        .expect("signed in");
    assert_eq!(tokens.user, user.id);
    assert_eq!(fx.world.store.devices_of(user.id).len(), 1);
    // A code is good once.
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::Email, &code))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn a_code_survives_two_wrong_entries_and_is_gone_after_the_third() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.enable_email(user.id).await;
    fx.steps().email_send_login_code(&user).await.expect("sent");
    let code = fx.mailbox.last_code();

    for _ in 0..3 {
        assert_eq!(
            fx.steps().email_verify(user.id, "wrong!").await,
            Err(AppError::Unauthorized)
        );
    }
    assert_eq!(
        fx.steps().email_verify(user.id, &code).await,
        Err(AppError::Unauthorized),
        "the code was reset by the third wrong entry"
    );

    // A fresh code works, and two wrong entries before it do not spend it.
    fx.steps().email_send_login_code(&user).await.expect("sent");
    let code = fx.mailbox.last_code();
    for _ in 0..2 {
        assert_eq!(
            fx.steps().email_verify(user.id, "wrong!").await,
            Err(AppError::Unauthorized)
        );
    }
    assert_eq!(fx.steps().email_verify(user.id, &code).await, Ok(()));
}

#[tokio::test]
async fn a_code_expires() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.enable_email(user.id).await;
    fx.steps().email_send_login_code(&user).await.expect("sent");
    let code = fx.mailbox.last_code();
    fx.world.env.clock.advance(Duration::seconds(601));
    assert_eq!(
        fx.steps().email_verify(user.id, &code).await,
        Err(AppError::Unauthorized)
    );
    // And it was used up by being entered late.
    assert_eq!(
        fx.steps().email_verify(user.id, &code).await,
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn an_email_setup_from_vaultwarden_signs_in_and_keeps_its_address() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.imported(
        user.id,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"old.address@example.org","last_token":null,"token_sent":1700000000,"attempts":0}"#,
    )
    .await;

    let step = fx.password_step().await;
    assert_eq!(step.methods, vec![TwoFactorMethod::Email]);
    assert_eq!(
        fx.steps()
            .login_options(&user, TwoFactorMethod::Email, "web", "d")
            .await,
        Ok(serde_json::json!({"Email": "ol*********@example.org"}))
    );
    fx.step()
        .send_email_code(&step.challenge, JKT)
        .await
        .expect("sent");
    let (to, code) = fx.mailbox.codes().pop().expect("a code");
    assert_eq!(to, "old.address@example.org");
    fx.step()
        .verify(fx.input(&step, TwoFactorMethod::Email, &code))
        .await
        .expect("signed in with the imported setup");
}

#[test]
fn addresses_are_hidden_but_two_characters() {
    assert_eq!(
        obscure_email("ada.lovelace@example.org"),
        format!("ad{}@example.org", "*".repeat(10))
    );
}

// ---------------------------------------------------------------------------------------------
// YubiKey.

fn other_otp() -> String {
    "ddddddddddddkhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv".to_owned()
}

#[tokio::test]
async fn yubikeys_are_registered_from_their_otps_and_answer_the_second_step() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.yubico.accept(OTP);
    fx.yubico.accept(&other_otp());

    assert_eq!(
        fx.steps().yubikey_set(user.id, &[], false).await,
        Err(AppError::Invalid("A key is required."))
    );
    assert_eq!(
        fx.steps()
            .yubikey_set(
                user.id,
                &["eeeeeeeeeeeekhvfhkbjtkjlkhdfhjcehcbvlnbtjhgv".to_owned()],
                false
            )
            .await,
        Err(AppError::Invalid("Invalid Yubikey OTP provided")),
        "an OTP Yubico doesn't know is no key"
    );
    let data = fx
        .steps()
        .yubikey_set(user.id, &[OTP.to_owned(), "ffffffffffff".to_owned()], true)
        .await
        .expect("the keys are registered");
    assert_eq!(
        data.keys,
        vec![YUBI_ID.to_owned(), "ffffffffffff".to_owned()]
    );
    assert!(data.nfc);
    // Both OTPs were asked about (the unknown one and the good one); the bare id wasn't.
    assert_eq!(fx.yubico.asked(), 2);

    let step = fx.password_step().await;
    assert_eq!(step.methods, vec![TwoFactorMethod::YubiKey]);
    assert_eq!(
        fx.steps()
            .login_options(&user, TwoFactorMethod::YubiKey, "web", "d")
            .await,
        Ok(serde_json::json!({"Nfc": true}))
    );
    // Not registered, wrong length, refused by Yubico.
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::YubiKey, &other_otp()))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::YubiKey, "cccccccccccc"))
            .await
            .map(|_| ()),
        Err(AppError::Invalid("Invalid Yubikey OTP length"))
    );
    let replayed = OTP.replace("khvf", "xxxx");
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::YubiKey, &replayed))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    let tokens = fx
        .step()
        .verify(fx.input(&step, TwoFactorMethod::YubiKey, OTP))
        .await
        .expect("signed in");
    assert_eq!(tokens.user, user.id);
}

#[tokio::test]
async fn a_yubikey_setup_from_vaultwarden_signs_in() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.imported(
        user.id,
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    fx.yubico.accept(OTP);
    assert_eq!(
        fx.steps()
            .yubikey_keys(user.id)
            .await
            .expect("reads")
            .map(|d| d.keys),
        Some(vec![YUBI_ID.to_owned()])
    );
    let step = fx.password_step().await;
    fx.step()
        .verify(fx.input(&step, TwoFactorMethod::YubiKey, OTP))
        .await
        .expect("signed in with the imported key");
}

#[tokio::test]
async fn yubikeys_need_yubico_set_up() {
    let mut fx = Fx::new();
    fx.settings.yubico_enabled = false;
    let user = fx.user().await;
    assert_eq!(
        fx.steps()
            .yubikey_set(user.id, &[OTP.to_owned()], false)
            .await,
        Err(AppError::Invalid("Yubico support is disabled"))
    );
    // An imported key is not usable either, as Vaultwarden has it.
    fx.imported(
        user.id,
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    fx.yubico.accept(OTP);
    let step = fx.password_step().await;
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::YubiKey, OTP))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    fx.steps().yubikey_remove(user.id).await.expect("removed");
    assert!(fx.world.store.two_factor_of(user.id).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Duo.

#[tokio::test]
async fn duo_answers_the_second_step_with_the_servers_keys() {
    let fx = Fx::new();
    let user = fx.user().await;
    assert_eq!(
        fx.steps().duo_status(user.id).await,
        Ok(DuoStatus::Disabled {
            global_available: true
        })
    );
    let status = fx.steps().duo_set(user.id, None).await.expect("on");
    assert_eq!(status, DuoStatus::Global(global_duo()));

    let step = fx.password_step().await;
    assert_eq!(step.methods, vec![TwoFactorMethod::Duo]);
    let url = fx
        .step()
        .duo_url(&step.challenge, JKT, "web")
        .await
        .expect("a prompt starts");
    let (username, device, state, host) = fx.duo.last_prompt();
    assert_eq!(username, EMAIL);
    assert_eq!(host, "api-global.duosecurity.com");
    assert!(url.contains(&state));
    assert_eq!(state.len(), 64);

    // Another state uses the prompt up; answers that aren't `<code>|<state>` are refused outright.
    for answer in ["duo-says-yes", "duo-says-yes|a|b"] {
        assert_eq!(
            fx.step()
                .verify(fx.input(&step, TwoFactorMethod::Duo, answer))
                .await
                .map(|_| ()),
            Err(AppError::Unauthorized),
            "{answer}"
        );
    }
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::Duo, "duo-says-yes|another-state"))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        fx.step()
            .verify(fx.input(
                &step,
                TwoFactorMethod::Duo,
                &format!("duo-says-yes|{state}")
            ))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized),
        "the wrong state used the prompt up"
    );

    // A wrong code uses a prompt up too.
    fx.step()
        .duo_url(&step.challenge, JKT, "web")
        .await
        .expect("a second prompt");
    let (_, _, state, _) = fx.duo.last_prompt();
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::Duo, &format!("wrong-code|{state}")))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        fx.step()
            .verify(fx.input(
                &step,
                TwoFactorMethod::Duo,
                &format!("duo-says-yes|{state}")
            ))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized),
        "the wrong code used the prompt up"
    );

    fx.step()
        .duo_url(&step.challenge, JKT, "web")
        .await
        .expect("a third prompt");
    let (_, device_again, state, _) = fx.duo.last_prompt();
    assert_eq!(
        device_again, device,
        "a prompt is for the device in the challenge"
    );
    let tokens = fx
        .step()
        .verify(fx.input(
            &step,
            TwoFactorMethod::Duo,
            &format!("duo-says-yes|{state}"),
        ))
        .await
        .expect("signed in");
    assert_eq!(tokens.user, user.id);
}

#[tokio::test]
async fn an_account_may_save_keys_of_its_own_and_they_are_checked_with_duo() {
    let fx = Fx::new();
    let user = fx.user().await;
    let bad = DuoKeys {
        host: "api-bad.duosecurity.com".to_owned(),
        ..own_duo()
    };
    assert_eq!(
        fx.steps().duo_set(user.id, Some(bad)).await,
        Err(AppError::Invalid("Failed to validate Duo credentials"))
    );
    assert!(fx.world.store.two_factor_of(user.id).is_empty());
    assert_eq!(
        fx.steps().duo_set(user.id, Some(own_duo())).await,
        Ok(DuoStatus::User(own_duo()))
    );
    let step = fx.password_step().await;
    fx.step()
        .duo_url(&step.challenge, JKT, "desktop")
        .await
        .expect("a prompt");
    assert_eq!(fx.duo.last_prompt().3, "api-own.duosecurity.com");
    fx.steps().duo_remove(user.id).await.expect("off");
    assert!(fx.world.store.two_factor_of(user.id).is_empty());
}

#[tokio::test]
async fn duo_setups_from_vaultwarden_use_their_own_keys_or_the_global_ones() {
    let fx = Fx::new();
    let user = fx.user().await;
    // Vaultwarden keeps an empty string for an account that uses the global integration.
    fx.imported(user.id, TwoFactorMethod::Duo, PURPOSE_DUO, "")
        .await;
    assert_eq!(
        fx.steps().duo_status(user.id).await,
        Ok(DuoStatus::Global(global_duo()))
    );
    fx.imported(
        user.id,
        TwoFactorMethod::Duo,
        PURPOSE_DUO,
        r#"{"host":"api-own.duosecurity.com","ik":"DIOWNOWNOWNOWNOWNOWN","sk":"own-secret"}"#,
    )
    .await;
    let step = fx.password_step().await;
    assert_eq!(step.methods, vec![TwoFactorMethod::Duo]);
    fx.step()
        .duo_url(&step.challenge, JKT, "web")
        .await
        .expect("a prompt");
    let (_, _, state, host) = fx.duo.last_prompt();
    assert_eq!(host, "api-own.duosecurity.com");
    fx.step()
        .verify(fx.input(
            &step,
            TwoFactorMethod::Duo,
            &format!("duo-says-yes|{state}"),
        ))
        .await
        .expect("signed in with the imported setup");
}

#[tokio::test]
async fn duo_with_no_keys_anywhere_is_not_usable() {
    let mut fx = Fx::new();
    fx.settings.duo_global = None;
    let user = fx.user().await;
    assert_eq!(
        fx.steps().duo_set(user.id, None).await,
        Err(AppError::Invalid("this server has no Duo keys to use"))
    );
    fx.imported(user.id, TwoFactorMethod::Duo, PURPOSE_DUO, "")
        .await;
    let step = fx.password_step().await;
    assert_eq!(
        fx.step().duo_url(&step.challenge, JKT, "web").await,
        Err(AppError::Invalid("Can't fetch Duo Keys"))
    );
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::Duo, "duo-says-yes|x"))
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn a_prompt_is_kept_five_minutes() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.steps().duo_set(user.id, None).await.expect("on");
    let step = fx.password_step().await;
    fx.step()
        .duo_url(&step.challenge, JKT, "web")
        .await
        .expect("a prompt");
    let (_, device, state, _) = fx.duo.last_prompt();
    assert!(fx.passkeys.has_challenge(user.id, ChallengeKind::DuoPrompt));
    fx.world.env.clock.advance(Duration::seconds(301));
    assert_eq!(
        fx.steps()
            .duo_verify(&user, "web", &device, &format!("duo-says-yes|{state}"))
            .await,
        Err(AppError::Unauthorized)
    );
}

// ---------------------------------------------------------------------------------------------
// Several methods, and the methods that have their own endpoints.

#[tokio::test]
async fn an_account_lists_every_method_it_has_and_the_password_endpoint_refuses_them() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.imported(
        user.id,
        TwoFactorMethod::YubiKey,
        PURPOSE_YUBIKEY,
        r#"{"keys":["cccccccccccc"],"nfc":false}"#,
    )
    .await;
    fx.imported(
        user.id,
        TwoFactorMethod::Email,
        PURPOSE_EMAIL,
        r#"{"email":"a@b.example","last_token":null,"token_sent":0,"attempts":0}"#,
    )
    .await;
    let step = fx.password_step().await;
    let mut methods = step.methods.clone();
    methods.sort_by_key(|m| m.as_str());
    assert_eq!(
        methods,
        vec![TwoFactorMethod::Email, TwoFactorMethod::YubiKey]
    );
    for method in [TwoFactorMethod::Email, TwoFactorMethod::YubiKey] {
        let refused = fx
            .world
            .sign_in()
            .second_step(kemlock_app::SecondStepInput {
                challenge: step.challenge.clone(),
                method,
                code: "123456".to_owned(),
                jkt: JKT.to_owned(),
            })
            .await;
        assert_eq!(
            refused.map(|_| ()),
            Err(AppError::Invalid(
                "this method is answered at its own endpoint"
            )),
            "{method:?}"
        );
    }
    // An authenticator app isn't one of these methods.
    assert_eq!(
        fx.step()
            .verify(fx.input(&step, TwoFactorMethod::Totp, "123456"))
            .await
            .map(|_| ()),
        Err(AppError::Invalid(
            "this method is answered at its own endpoint"
        ))
    );
}

// ---------------------------------------------------------------------------------------------
// Protected actions.

#[tokio::test]
async fn a_protected_action_code_is_mailed_to_the_account_and_good_once() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.steps().protected_request(&user).await.expect("sent");
    let codes = fx.mailbox.protected_codes();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0].0, EMAIL);
    let code = codes[0].1.clone();
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));

    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Ok(())
    );
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Err(ProtectedError::NotFound),
        "the code was used up"
    );
}

#[tokio::test]
async fn a_code_kept_for_the_next_call_answers_again() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.steps().protected_request(&user).await.expect("sent");
    let code = fx.mailbox.last_protected_code();
    for _ in 0..2 {
        assert_eq!(
            fx.steps().protected_validate(user.id, &code, false).await,
            Ok(())
        );
    }
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Ok(())
    );
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Err(ProtectedError::NotFound)
    );
}

#[tokio::test]
async fn a_protected_code_survives_two_wrong_entries_and_is_refused_after_the_third() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.steps().protected_request(&user).await.expect("sent");
    let code = fx.mailbox.last_protected_code();
    for _ in 0..3 {
        assert_eq!(
            fx.steps()
                .protected_validate(user.id, "wrong!", false)
                .await,
            Err(ProtectedError::Invalid)
        );
    }
    // The count is kept, so even the right code is refused now.
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Err(ProtectedError::Expired)
    );

    // A new code (after the wait) works, and two wrong entries before it do not spend it.
    fx.world
        .env
        .clock
        .advance(Duration::seconds(PROTECTED_REQUEST_DELAY_SECS));
    fx.steps().protected_request(&user).await.expect("sent");
    let code = fx.mailbox.last_protected_code();
    for _ in 0..2 {
        assert_eq!(
            fx.steps()
                .protected_validate(user.id, "wrong!", false)
                .await,
            Err(ProtectedError::Invalid)
        );
    }
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Ok(())
    );
}

#[tokio::test]
async fn a_protected_code_expires_and_is_gone_for_good() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.steps().protected_request(&user).await.expect("sent");
    let code = fx.mailbox.last_protected_code();
    fx.world.env.clock.advance(Duration::seconds(601));
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Err(ProtectedError::Expired)
    );
    assert_eq!(
        fx.steps().protected_validate(user.id, &code, true).await,
        Err(ProtectedError::NotFound)
    );
}

#[tokio::test]
async fn another_code_is_not_sent_within_thirty_seconds() {
    let fx = Fx::new();
    let user = fx.user().await;
    fx.steps().protected_request(&user).await.expect("sent");
    let first = fx.mailbox.last_protected_code();

    fx.world.env.clock.advance(Duration::seconds(12));
    assert_eq!(
        fx.steps().protected_request(&user).await,
        Err(ProtectedError::Wait(18))
    );
    assert_eq!(fx.mailbox.protected_codes().len(), 1, "nothing was sent");
    // The first code still works: the refused request left it alone.
    assert_eq!(
        fx.steps().protected_validate(user.id, &first, false).await,
        Ok(())
    );

    // After thirty seconds a new code replaces it.
    fx.world.env.clock.advance(Duration::seconds(18));
    fx.steps().protected_request(&user).await.expect("sent");
    assert_eq!(fx.mailbox.protected_codes().len(), 2);
    let second = fx.mailbox.last_protected_code();
    assert_ne!(first, second);
    assert_eq!(
        fx.steps().protected_validate(user.id, &first, false).await,
        Err(ProtectedError::Invalid)
    );
    assert_eq!(
        fx.steps().protected_validate(user.id, &second, true).await,
        Ok(())
    );
}

#[tokio::test]
async fn a_code_that_was_never_asked_for_is_not_found_and_a_server_without_mail_sends_none() {
    let mut fx = Fx::new();
    let user = fx.user().await;
    assert_eq!(
        fx.steps().protected_validate(user.id, "123456", true).await,
        Err(ProtectedError::NotFound)
    );
    fx.settings.email_enabled = false;
    assert_eq!(
        fx.steps().protected_request(&user).await,
        Err(ProtectedError::Disabled)
    );
    assert!(fx.mailbox.protected_codes().is_empty());
}

#[tokio::test]
async fn asking_for_another_setup_code_keeps_the_wrong_entries_so_far() {
    let fx = Fx::new();
    let user = fx.user().await.id;
    let address = "mfa@example.org";

    fx.steps().email_begin(user, address).await.expect("sent");
    for _ in 0..2 {
        assert_eq!(
            fx.steps().email_confirm(user, address, "000000x").await,
            Err(AppError::Unauthorized)
        );
    }
    // Asking again must not give the three tries back: one more wrong entry ends the code.
    fx.steps().email_begin(user, address).await.expect("sent");
    assert_eq!(
        fx.steps().email_confirm(user, address, "000000x").await,
        Err(AppError::Unauthorized)
    );
    assert!(
        fx.steps()
            .email_confirm(user, address, &fx.mailbox.last_code())
            .await
            .is_err(),
        "the code was used up by the wrong entries, even the right one is refused"
    );
    assert_eq!(fx.steps().email_address(user).await, Ok(None));
}
