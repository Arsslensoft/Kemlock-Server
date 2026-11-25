//! The profile over fakes: the name, the master password's records, and the change of the sign-in
//! address that waits for its link. The client's side of OPAQUE is the real one from
//! `kemlock-crypto`, so a record made here signs in, or doesn't, exactly as it would on a server.

mod fakes;

use fakes::profile::FakeProfile;
use fakes::*;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::platform::Hasher;
use kemlock_app::ports::Clock;
use kemlock_app::profile::{
    ConfirmEmailChange, Credentials, EmailChanges, NewCredentials, Profile, ProfileError,
    ProfileView,
};
use kemlock_app::register::WRAPPED_ROOT_KEY_LEN;
use kemlock_app::{AppError, OpaqueFinishInput, OpaqueStartInput, SignedIn};
use kemlock_domain::{AccountMode, KdfParams, UserId};
use std::sync::{Arc, Mutex};
use time::Duration;

const EMAIL: &str = "sam@example.org";
const NEW_EMAIL: &str = "sam@example.com";
const JKT: &str = "device-key-thumbprint";
/// The master key of the password a person changes to.
const NEW_PASSWORD: [u8; 32] = [6u8; 32];

// ---- fakes ----

/// What the mail sender was asked to send; with `fail`, it says every send failed.
#[derive(Clone, Default)]
struct Mailbox {
    sent: Arc<Mutex<Vec<Notice>>>,
    fail: bool,
}

impl Outbox for Mailbox {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.sent.lock().expect("the lock").push(notice);
        })
    }

    fn deliver_checked(&self, notice: Notice) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            if self.fail {
                return Err("the mail server is down".to_owned());
            }
            self.sent.lock().expect("the lock").push(notice);
            Ok(())
        })
    }
}

impl Mailbox {
    fn notices(&self) -> Notices {
        Notices::with_outbox(Arc::new(self.clone()))
    }

    /// The token of the last link mailed to `to`.
    fn link_token(&self, to: &str) -> String {
        self.sent
            .lock()
            .expect("the lock")
            .iter()
            .rev()
            .find_map(|notice| match notice {
                Notice::EmailChange(n) if n.to.as_str() == to => Some(n.token.clone()),
                _ => None,
            })
            .expect("a link was mailed")
    }

    /// Who was told a change was asked for, and which address it names.
    fn told(&self) -> Vec<(String, String)> {
        self.sent
            .lock()
            .expect("the lock")
            .iter()
            .filter_map(|notice| match notice {
                Notice::EmailChangeRequested(n) => {
                    Some((n.to.as_str().to_owned(), n.new_address.as_str().to_owned()))
                }
                _ => None,
            })
            .collect()
    }
}

// ---- the scene ----

struct Scene {
    world: World,
    repo: FakeProfile,
    mailbox: Mailbox,
    user: UserId,
}

async fn scene() -> Scene {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    Scene {
        world,
        repo: FakeProfile::default(),
        mailbox: Mailbox::default(),
        user,
    }
}

impl Scene {
    fn profile(&self) -> Profile<FakeStore, FakeProfile, FakeEnv> {
        Profile {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            clock: self.world.env.clone(),
        }
    }

    fn credentials(&self) -> Credentials<FakeStore, FakeProfile, FakePassword, FakeEnv> {
        Credentials {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            auth: self.world.password.clone(),
            clock: self.world.env.clone(),
        }
    }

    fn changes(&self) -> EmailChanges<FakeStore, FakeProfile, FakePassword, FakeEnv> {
        self.changes_with(self.mailbox.notices())
    }

    fn changes_with(
        &self,
        notices: Notices,
    ) -> EmailChanges<FakeStore, FakeProfile, FakePassword, FakeEnv> {
        EmailChanges {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            auth: self.world.password.clone(),
            env: self.world.env.clone(),
            notices,
        }
    }

    fn confirm(&self) -> ConfirmEmailChange<FakeStore, FakeProfile, FakeStore, FakeStore, FakeEnv> {
        ConfirmEmailChange {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            devices: self.world.store.clone(),
            tokens: self.world.store.clone(),
            env: self.world.env.clone(),
        }
    }

    /// What the browser sends for `NEW_PASSWORD`: a registration whose first message the server
    /// answered for `email` (the account's own, or a new address).
    async fn new_credentials(&self, email: Option<&str>) -> NewCredentials {
        let (state, request) = kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD)
            .expect("client registration start");
        let response = self
            .credentials()
            .start(self.user, email, &request)
            .await
            .expect("the server answers the registration");
        let (upload, _export_key) =
            kemlock_crypto::opaque::client_registration_finish(state, &NEW_PASSWORD, &response)
                .expect("client registration finish");
        NewCredentials {
            upload,
            kdf: KdfParams::new_account([8u8; 16]),
            wrapped_root_key: vec![0x44; WRAPPED_ROOT_KEY_LEN],
        }
    }

    async fn signs_in(&self, email: &str, password: &[u8]) -> Result<SignedIn, AppError> {
        sign_in_with(&self.world, email, password, device("Pixel"), JKT).await
    }

    /// Whether signing in as `email` with `password` fails: a client with the wrong password
    /// usually can't even finish OPAQUE, and if it could, the server would refuse it.
    async fn cannot_sign_in(&self, email: &str, password: &[u8]) -> bool {
        let (state, request) =
            kemlock_crypto::opaque::client_login_start(password).expect("client login start");
        let started = self
            .world
            .sign_in()
            .start(OpaqueStartInput {
                email: email.to_owned(),
                request,
                jkt: JKT.to_owned(),
            })
            .await
            .expect("every address gets a response");
        match kemlock_crypto::opaque::client_login_finish(state, password, &started.response) {
            Err(_) => true,
            Ok((finalization, _session_key, _export_key)) => self
                .world
                .sign_in()
                .finish(OpaqueFinishInput {
                    email: email.to_owned(),
                    login_state: started.login_state,
                    finalization,
                    device: device("Pixel"),
                    jkt: JKT.to_owned(),
                })
                .await
                .is_err(),
        }
    }
}

fn is_tokens(result: &Result<SignedIn, AppError>) -> bool {
    matches!(result, Ok(SignedIn::Tokens(_)))
}

// ---- the profile and the name ----

#[tokio::test]
async fn the_profile_says_what_the_account_is() {
    let s = scene().await;

    let view = s.profile().show(s.user).await.expect("the profile");

    assert_eq!(
        view,
        ProfileView {
            user: s.user,
            email: kemlock_domain::Email::parse(EMAIL).expect("an address"),
            name: Some("Test Person".to_owned()),
            sso: false,
            has_password: true,
            compatible: false,
            pending_email: None,
        }
    );
}

#[tokio::test]
async fn a_person_changes_their_name_and_a_blank_one_clears_it() {
    let s = scene().await;

    let view = s
        .profile()
        .rename(s.user, "  Sam Rivera  ")
        .await
        .expect("renamed");
    assert_eq!(view.name.as_deref(), Some("Sam Rivera"));
    assert_eq!(
        s.world.store.user(s.user).expect("the account").name,
        Some("Sam Rivera".to_owned())
    );

    let view = s.profile().rename(s.user, "   ").await.expect("cleared");
    assert_eq!(view.name, None);
    assert_eq!(s.world.store.user(s.user).expect("the account").name, None);
}

#[tokio::test]
async fn a_name_that_is_too_long_or_holds_control_characters_is_refused() {
    let s = scene().await;

    let long = "x".repeat(kemlock_app::register::MAX_NAME_LEN + 1);
    assert!(matches!(
        s.profile().rename(s.user, &long).await,
        Err(ProfileError::App(AppError::Invalid(_)))
    ));
    let just_fits = "x".repeat(kemlock_app::register::MAX_NAME_LEN);
    s.profile()
        .rename(s.user, &just_fits)
        .await
        .expect("the longest name fits");
    assert!(matches!(
        s.profile().rename(s.user, "Sam\nRivera").await,
        Err(ProfileError::App(AppError::Invalid(_)))
    ));
}

#[tokio::test]
async fn a_single_sign_on_account_keeps_the_name_its_provider_gives() {
    let s = scene().await;
    s.repo.link_sso(s.user);

    assert_eq!(
        s.profile().rename(s.user, "Someone Else").await,
        Err(ProfileError::SsoManaged)
    );
    let view = s.profile().show(s.user).await.expect("the profile");
    assert!(view.sso);
    assert_eq!(view.name.as_deref(), Some("Test Person"));
}

#[tokio::test]
async fn an_unknown_account_is_an_ended_session() {
    let s = scene().await;
    assert_eq!(
        s.profile().show(UserId::random()).await,
        Err(ProfileError::App(AppError::Unauthorized))
    );
}

// ---- the master password ----

#[tokio::test]
async fn a_new_password_signs_in_and_the_old_one_does_not() {
    let s = scene().await;
    let before = s.world.store.user(s.user).expect("the account");
    let new = s.new_credentials(None).await;
    let wrap = new.wrapped_root_key.clone();

    s.credentials()
        .change_password(s.user, new)
        .await
        .expect("the password changes");

    let after = s.world.store.user(s.user).expect("the account");
    assert_eq!(after.wrapped_root_key, wrap);
    assert_eq!(after.kdf.salt, vec![8u8; 16]);
    assert_ne!(after.opaque_record, before.opaque_record);
    // The root key stays: so do the keys, the version and the sessions' stamp.
    assert_eq!(after.public_bundle, before.public_bundle);
    assert_eq!(after.bundle_signature, before.bundle_signature);
    assert_eq!(after.sealed_private_keys, before.sealed_private_keys);
    assert_eq!(after.key_version, before.key_version);
    assert_eq!(after.security_stamp, before.security_stamp);
    assert_eq!(after.email, before.email);

    assert!(is_tokens(&s.signs_in(EMAIL, &NEW_PASSWORD).await));
    assert!(s.cannot_sign_in(EMAIL, &PASSWORD).await);
}

#[tokio::test]
async fn credentials_that_break_the_rules_change_nothing() {
    let s = scene().await;
    let before = s.world.store.user(s.user).expect("the account");

    let mut odd_kdf = s.new_credentials(None).await;
    odd_kdf.kdf.iterations = 4;
    let mut short_salt = s.new_credentials(None).await;
    short_salt.kdf.salt = vec![1; 8];
    let mut short_wrap = s.new_credentials(None).await;
    short_wrap.wrapped_root_key.pop();
    let mut garbage = s.new_credentials(None).await;
    garbage.upload = vec![9; 12];

    for bad in [odd_kdf, short_salt, short_wrap, garbage] {
        assert!(matches!(
            s.credentials().change_password(s.user, bad).await,
            Err(ProfileError::App(AppError::Invalid(_)))
        ));
    }
    assert_eq!(s.world.store.user(s.user), Some(before));
    assert!(is_tokens(&s.signs_in(EMAIL, &PASSWORD).await));
}

#[tokio::test]
async fn an_account_shared_with_bitwarden_apps_or_with_no_password_is_refused() {
    let s = scene().await;
    let new = s.new_credentials(None).await;
    let account = s.world.store.user(s.user).expect("the account");

    s.world.store.put_user(kemlock_domain::User {
        mode: AccountMode::Compatible,
        ..account.clone()
    });
    assert_eq!(
        s.credentials().change_password(s.user, new.clone()).await,
        Err(ProfileError::CompatibleAccount)
    );
    assert_eq!(
        s.credentials().check(s.user).await,
        Err(ProfileError::CompatibleAccount)
    );
    assert_eq!(
        s.credentials().start(s.user, None, &[1; 32]).await,
        Err(ProfileError::CompatibleAccount)
    );

    s.world.store.put_user(kemlock_domain::User {
        opaque_record: None,
        wrapped_root_key: Vec::new(),
        ..account
    });
    assert_eq!(
        s.credentials().change_password(s.user, new).await,
        Err(ProfileError::NoPassword)
    );
    assert_eq!(
        s.credentials().check(s.user).await,
        Err(ProfileError::NoPassword)
    );
    let view = s.profile().show(s.user).await.expect("the profile");
    assert!(!view.has_password);
}

#[tokio::test]
async fn a_registration_for_a_new_address_needs_a_free_one() {
    let s = scene().await;
    make_user(&s.world, "kim@example.org").await;

    let (_state, request) = kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD)
        .expect("client registration start");
    let start = |email: &'static str| {
        let credentials = s.credentials();
        let request = request.clone();
        let user = s.user;
        async move { credentials.start(user, Some(email), &request).await }
    };

    assert_eq!(start("kim@example.org").await, Err(ProfileError::EmailTaken));
    assert!(matches!(
        start(EMAIL).await,
        Err(ProfileError::App(AppError::Invalid(_)))
    ));
    assert!(matches!(
        start("not an address").await,
        Err(ProfileError::App(AppError::Invalid(_)))
    ));
    assert!(start(NEW_EMAIL).await.is_ok());

    // An account its identity provider owns keeps its address, and may still change its password.
    s.repo.link_sso(s.user);
    assert_eq!(start(NEW_EMAIL).await, Err(ProfileError::SsoManaged));
    assert!(
        s.credentials()
            .start(s.user, None, &request)
            .await
            .is_ok()
    );
}

// ---- the sign-in address ----

#[tokio::test]
async fn an_address_changes_only_when_its_link_is_opened() {
    let s = scene().await;
    let new = s.new_credentials(Some(NEW_EMAIL)).await;
    let wrap = new.wrapped_root_key.clone();
    // A device is signed in, to see the sessions end.
    let SignedIn::Tokens(tokens) = s.signs_in(EMAIL, &PASSWORD).await.expect("signs in") else {
        panic!("tokens expected");
    };
    let before = s.world.store.user(s.user).expect("the account");

    let asked = s
        .changes()
        .request(s.user, "  Sam@Example.COM ", new)
        .await
        .expect("the change is asked for");

    // Asking changes nothing yet, and the profile says what waits.
    assert_eq!(asked.email.as_str(), NEW_EMAIL);
    assert_eq!(asked.expires_at, s.world.env.now() + Duration::hours(24));
    assert_eq!(s.world.store.user(s.user), Some(before.clone()));
    let view = s.profile().show(s.user).await.expect("the profile");
    assert_eq!(view.email.as_str(), EMAIL);
    assert_eq!(
        view.pending_email.as_ref().map(|e| e.as_str()),
        Some(NEW_EMAIL)
    );
    assert!(is_tokens(&s.signs_in(EMAIL, &PASSWORD).await));
    // The link went to the new address, the news to the old one, and only the hash is kept.
    let token = s.mailbox.link_token(NEW_EMAIL);
    assert_eq!(
        s.mailbox.told(),
        vec![(EMAIL.to_owned(), NEW_EMAIL.to_owned())]
    );
    let stored = s.repo.pending(s.user).expect("a pending change");
    assert_eq!(stored.token_hash, s.world.env.sha256(token.as_bytes()));
    assert!(!format!("{stored:?}").contains(&token));

    let done = s.confirm().confirm(&token).await.expect("the link opens");

    assert_eq!(done.user, s.user);
    assert_eq!(done.email.as_str(), NEW_EMAIL);
    let after = s.world.store.user(s.user).expect("the account");
    assert_eq!(after.email.as_str(), NEW_EMAIL);
    assert_eq!(after.wrapped_root_key, wrap);
    assert_eq!(after.kdf.salt, vec![8u8; 16]);
    assert_ne!(after.security_stamp, before.security_stamp);
    assert_eq!(after.key_version, before.key_version);
    assert_eq!(after.sealed_private_keys, before.sealed_private_keys);
    assert_eq!(s.repo.pending(s.user), None);
    // Every session ended: no refresh token is left, whatever the device.
    assert!(s.world.store.refresh_tokens().is_empty(), "{tokens:?}");
    // The new address and password sign in; the old address no longer does.
    assert!(is_tokens(&s.signs_in(NEW_EMAIL, &NEW_PASSWORD).await));
    assert!(s.cannot_sign_in(EMAIL, &PASSWORD).await);
    assert!(s.cannot_sign_in(EMAIL, &NEW_PASSWORD).await);
}

#[tokio::test]
async fn a_link_is_good_once_and_only_its_own_token_opens_it() {
    let s = scene().await;
    let new = s.new_credentials(Some(NEW_EMAIL)).await;
    s.changes()
        .request(s.user, NEW_EMAIL, new)
        .await
        .expect("asked");
    let token = s.mailbox.link_token(NEW_EMAIL);

    assert_eq!(
        s.confirm().confirm("not-the-token").await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(
        s.confirm().confirm("").await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert!(s.repo.pending(s.user).is_some(), "a wrong token spends nothing");

    s.confirm().confirm(&token).await.expect("opens");
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
}

#[tokio::test]
async fn a_link_runs_out_after_a_day() {
    let s = scene().await;
    let new = s.new_credentials(Some(NEW_EMAIL)).await;
    s.changes()
        .request(s.user, NEW_EMAIL, new)
        .await
        .expect("asked");
    let token = s.mailbox.link_token(NEW_EMAIL);

    s.world.env.clock.advance(Duration::hours(24));

    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(
        s.world.store.user(s.user).expect("the account").email.as_str(),
        EMAIL
    );
    // An ask that ran out is not shown as waiting.
    let view = s.profile().show(s.user).await.expect("the profile");
    assert_eq!(view.pending_email, None);
}

#[tokio::test]
async fn asking_again_replaces_the_ask_and_cancelling_takes_it_back() {
    let s = scene().await;
    let first = s.new_credentials(Some(NEW_EMAIL)).await;
    s.changes()
        .request(s.user, NEW_EMAIL, first)
        .await
        .expect("asked");
    let first_token = s.mailbox.link_token(NEW_EMAIL);
    let second = s.new_credentials(Some("sam@example.net")).await;
    s.changes()
        .request(s.user, "sam@example.net", second)
        .await
        .expect("asked again");
    let second_token = s.mailbox.link_token("sam@example.net");

    assert_eq!(
        s.confirm().confirm(&first_token).await,
        Err(ProfileError::EmailChangeInvalid),
        "the first link stopped working"
    );

    s.changes().cancel(s.user).await.expect("cancelled");
    s.changes().cancel(s.user).await.expect("nothing to cancel is fine");
    assert_eq!(
        s.confirm().confirm(&second_token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(
        s.world.store.user(s.user).expect("the account").email.as_str(),
        EMAIL
    );
}

#[tokio::test]
async fn an_address_taken_in_the_meantime_is_not_given_away() {
    let s = scene().await;
    let new = s.new_credentials(Some(NEW_EMAIL)).await;
    s.changes()
        .request(s.user, NEW_EMAIL, new.clone())
        .await
        .expect("asked");
    let token = s.mailbox.link_token(NEW_EMAIL);
    make_user(&s.world, NEW_EMAIL).await;

    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailTaken)
    );
    assert_eq!(
        s.world.store.user(s.user).expect("the account").email.as_str(),
        EMAIL
    );
    assert_eq!(s.repo.pending(s.user), None, "the ask is gone");
    // Asking for an address someone has is refused up front.
    assert_eq!(
        s.changes().request(s.user, NEW_EMAIL, new).await,
        Err(ProfileError::EmailTaken)
    );
}

#[tokio::test]
async fn a_change_of_password_drops_the_change_of_address_made_from_the_old_one() {
    let s = scene().await;
    let for_address = s.new_credentials(Some(NEW_EMAIL)).await;
    s.changes()
        .request(s.user, NEW_EMAIL, for_address)
        .await
        .expect("asked");
    let token = s.mailbox.link_token(NEW_EMAIL);

    let for_password = s.new_credentials(None).await;
    s.credentials()
        .change_password(s.user, for_password)
        .await
        .expect("the password changes");

    assert_eq!(s.repo.pending(s.user), None);
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
}

#[tokio::test]
async fn an_address_is_not_changed_without_mail_or_for_the_wrong_kind_of_account() {
    let s = scene().await;
    let new = s.new_credentials(Some(NEW_EMAIL)).await;

    // No mail sender: no one could open the link.
    assert_eq!(
        s.changes_with(Notices::logging())
            .request(s.user, NEW_EMAIL, new.clone())
            .await,
        Err(ProfileError::MailOff)
    );
    assert_eq!(s.repo.pending(s.user), None);

    // A mail that does not go out leaves nothing waiting.
    let failing = Mailbox {
        fail: true,
        ..Mailbox::default()
    };
    assert_eq!(
        s.changes_with(failing.notices())
            .request(s.user, NEW_EMAIL, new.clone())
            .await,
        Err(ProfileError::MailFailed)
    );
    assert_eq!(s.repo.pending(s.user), None);

    // The same address, or one that is no address.
    assert!(matches!(
        s.changes().request(s.user, EMAIL, new.clone()).await,
        Err(ProfileError::App(AppError::Invalid(_)))
    ));
    assert!(matches!(
        s.changes().request(s.user, "nope", new.clone()).await,
        Err(ProfileError::App(AppError::Invalid(_)))
    ));

    // An identity provider's account, and one shared with Bitwarden apps.
    s.repo.link_sso(s.user);
    assert_eq!(
        s.changes().request(s.user, NEW_EMAIL, new.clone()).await,
        Err(ProfileError::SsoManaged)
    );
    let account = s.world.store.user(s.user).expect("the account");
    s.world.store.put_user(kemlock_domain::User {
        mode: AccountMode::Compatible,
        ..account
    });
    assert_eq!(
        s.changes().request(s.user, NEW_EMAIL, new).await,
        Err(ProfileError::CompatibleAccount)
    );
}
