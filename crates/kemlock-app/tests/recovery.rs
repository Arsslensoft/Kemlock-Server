//! The recovery code over fakes: made at the first enrolment, shown, spent as a second step that
//! switches every method off, and read from the legacy column of an account moved from
//! Vaultwarden.

mod fakes;

use fakes::*;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox, TwoStepRecoveredNotice};
use kemlock_app::ports::{Clock, SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_app::two_step::{
    PURPOSE_LEGACY_RECOVERY, RecoveryCodeRepo, RecoveryCodes, RecoverySignIn,
};
use kemlock_app::{AppError, SecondStep, SignedIn};
use kemlock_domain::UserId;
use std::sync::{Arc, Mutex};

const EMAIL: &str = "ada@example.org";
const JKT: &str = "device-key-thumbprint";

type Codes = RecoveryCodes<FakeStore, FakeStore, FakeSeal, FakeEnv>;
type Recover = RecoverySignIn<
    FakeStore,
    FakeStore,
    FakeStore,
    FakeSeal,
    FakeEnv,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeStore,
>;

fn codes(world: &World) -> Codes {
    RecoveryCodes {
        recovery: world.store.clone(),
        two_factor: world.store.clone(),
        seal: world.seal.clone(),
        env: world.env.clone(),
    }
}

fn recover(world: &World) -> Recover {
    recover_with(world, Notices::default())
}

fn recover_with(world: &World, notices: Notices) -> Recover {
    RecoverySignIn {
        users: world.store.clone(),
        recovery: codes(world),
        sessions: world.sessions(),
        notices,
    }
}

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

/// An account with an authenticator app and an email method on.
async fn account_with_two_methods(world: &World) -> UserId {
    let user = make_user(world, EMAIL).await;
    for method in [TwoFactorMethod::Totp, TwoFactorMethod::Email] {
        world
            .store
            .put(&TwoFactor {
                user,
                method,
                sealed_secret: world.seal.seal("test", b"secret"),
                enabled: true,
                created_at: world.env.now(),
            })
            .await
            .expect("a method is on");
    }
    user
}

async fn password_step(world: &World) -> SecondStep {
    match sign_in_with(world, EMAIL, &PASSWORD, device("Pixel"), JKT)
        .await
        .expect("the password is right")
    {
        SignedIn::SecondStep(step) => step,
        other => panic!("a second step was expected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_code_is_made_once_as_base32_and_shown() {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    assert_eq!(codes(&world).show(user).await, Ok(None), "none before");

    codes(&world).ensure(user).await.expect("made");
    let code = codes(&world)
        .show(user)
        .await
        .expect("read")
        .expect("a code");
    assert_eq!(code.len(), 32);
    assert!(
        code.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
        "{code}"
    );
    // Turning on a second method leaves the code alone.
    codes(&world).ensure(user).await.expect("kept");
    assert_eq!(codes(&world).show(user).await, Ok(Some(code)));
}

#[tokio::test]
async fn the_code_switches_every_method_off_and_is_spent() {
    let world = World::new().with_signups();
    let user = account_with_two_methods(&world).await;
    codes(&world).ensure(user).await.expect("made");
    let code = codes(&world)
        .show(user)
        .await
        .expect("read")
        .expect("a code");

    // A wrong code changes nothing.
    assert_eq!(
        codes(&world)
            .recover(user, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(world.store.two_factor_of(user).len(), 2);

    // Spaces and case don't matter, as in Vaultwarden.
    let typed = format!("{} {}", code[..16].to_lowercase(), &code[16..]);
    assert_eq!(codes(&world).recover(user, &typed).await, Ok(()));
    assert!(world.store.two_factor_of(user).is_empty());

    // It was spent: it is gone, and the next method turned on makes a different one.
    assert_eq!(
        codes(&world).recover(user, &code).await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(codes(&world).show(user).await, Ok(None));
    codes(&world).ensure(user).await.expect("made again");
    let fresh = codes(&world)
        .show(user)
        .await
        .expect("read")
        .expect("a code");
    assert_ne!(fresh, code);
}

#[tokio::test]
async fn an_account_with_no_code_cannot_recover() {
    let world = World::new().with_signups();
    let user = account_with_two_methods(&world).await;
    assert_eq!(
        codes(&world).recover(user, "anything").await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(world.store.two_factor_of(user).len(), 2);
}

#[tokio::test]
async fn a_code_an_import_left_is_read_from_the_legacy_column_and_no_other_is_made() {
    let world = World::new().with_signups();
    let user = account_with_two_methods(&world).await;
    world.store.set_legacy_recovery(
        user,
        world
            .seal
            .seal(PURPOSE_LEGACY_RECOVERY, b"LEGACYCODELEGACYCODELEGACYCODE22"),
    );

    codes(&world).ensure(user).await.expect("nothing to make");
    assert_eq!(
        world.store.recovery_code(user).await,
        Ok(None),
        "no second code beside the legacy one"
    );
    assert_eq!(
        codes(&world).show(user).await,
        Ok(Some("LEGACYCODELEGACYCODELEGACYCODE22".to_owned()))
    );
    assert_eq!(
        codes(&world)
            .recover(user, "legacycodelegacycodelegacycode22")
            .await,
        Ok(())
    );
    assert!(world.store.two_factor_of(user).is_empty());
    assert_eq!(codes(&world).show(user).await, Ok(None), "spent");
}

#[tokio::test]
async fn the_code_answers_the_kemlock_second_step_and_signs_the_device_in() {
    let world = World::new().with_signups();
    let user = account_with_two_methods(&world).await;
    codes(&world).ensure(user).await.expect("made");
    let code = codes(&world)
        .show(user)
        .await
        .expect("read")
        .expect("a code");
    let step = password_step(&world).await;
    assert_eq!(world.store.devices_of(user).len(), 0, "not yet a device");

    // Another device key, or a wrong code, gets nothing and spends nothing.
    assert_eq!(
        recover(&world)
            .recover(&step.challenge, &code, "another-key")
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        recover(&world)
            .recover(&step.challenge, "wrong", JKT)
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    assert_eq!(world.store.two_factor_of(user).len(), 2);

    recover(&world)
        .recover(&step.challenge, &code, JKT)
        .await
        .expect("signed in");
    assert!(world.store.two_factor_of(user).is_empty());
    assert_eq!(world.store.devices_of(user).len(), 1);
    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.two_step_recovered" && e.actor == Some(user))
    );
    // The same code can't be used again.
    assert_eq!(
        recover(&world)
            .recover(&step.challenge, &code, JKT)
            .await
            .map(|_| ()),
        Err(AppError::Unauthorized)
    );
    // And the account signs in with the password alone now.
    assert!(matches!(
        sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), JKT).await,
        Ok(SignedIn::Tokens(_))
    ));
}

#[tokio::test]
async fn a_disabled_account_gets_no_code_looked_at() {
    let world = World::new().with_signups();
    let user = account_with_two_methods(&world).await;
    codes(&world).ensure(user).await.expect("made");
    let code = codes(&world)
        .show(user)
        .await
        .expect("read")
        .expect("a code");
    let step = password_step(&world).await;
    world.store.set_account_disabled(user, true);
    assert_eq!(
        recover(&world)
            .recover(&step.challenge, &code, JKT)
            .await
            .map(|_| ()),
        Err(AppError::AccountDisabled)
    );
    assert_eq!(
        world.store.two_factor_of(user).len(),
        2,
        "nothing was spent"
    );
    assert!(codes(&world).show(user).await.expect("read").is_some());
}

#[tokio::test]
async fn using_the_code_mails_the_owner_and_a_failed_try_mails_no_one() {
    let world = World::new().with_signups();
    let user = account_with_two_methods(&world).await;
    codes(&world).ensure(user).await.expect("made");
    let code = codes(&world)
        .show(user)
        .await
        .expect("read")
        .expect("a code");
    let step = password_step(&world).await;
    let mailbox = Mailbox::default();
    let notices = Notices::with_outbox(Arc::new(mailbox.clone()));

    recover_with(&world, notices.clone())
        .recover(&step.challenge, "wrong", JKT)
        .await
        .expect_err("a wrong code");
    assert!(mailbox.0.lock().expect("the mailbox lock").is_empty());

    recover_with(&world, notices)
        .recover(&step.challenge, &code, JKT)
        .await
        .expect("signed in");
    let sent = mailbox.0.lock().expect("the mailbox lock").clone();
    assert_eq!(sent.len(), 1);
    let Notice::TwoStepRecovered(TwoStepRecoveredNotice { to, .. }) = &sent[0] else {
        panic!("expected a recovery notice, got {:?}", sent[0]);
    };
    assert_eq!(to.as_str(), EMAIL);
}
