//! The profile over fakes: the name, the master password's records, and the change of the sign-in
//! address that waits for its link. The client's side of OPAQUE is the real one from
//! `kemlock-crypto`, so a record made here signs in, or doesn't, exactly as it would on a server.

mod fakes;

use fakes::profile::FakeProfile;
use fakes::unlock::sign_out_device;
use fakes::*;
use kemlock_app::notices::{BoxFuture, Notice, Notices, Outbox};
use kemlock_app::platform::Hasher;
use kemlock_app::ports::{Clock, DeviceRepo, PasswordAuth};
use kemlock_app::profile::{
    ConfirmEmailChange, Credentials, EmailChangeAsked, EmailChanges, NewCredentials, OtherDevices,
    PasswordChanged, Profile, ProfileError, ProfileView,
};
use kemlock_app::register::WRAPPED_ROOT_KEY_LEN;
use kemlock_app::{Actor, AppError, OpaqueFinishInput, OpaqueStartInput, SignedIn, TokenPair};
use kemlock_domain::unlock::{EmergencyGrant, EmergencyKind, GrantId};
use kemlock_domain::{AccountMode, Email, KdfParams, UserId};
use std::sync::{Arc, Mutex};
use time::Duration;

const EMAIL: &str = "sam@example.org";
const NEW_EMAIL: &str = "sam@example.com";
const TAKEN_EMAIL: &str = "kim@example.org";
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

    fn all(&self) -> Vec<Notice> {
        self.sent.lock().expect("the lock").clone()
    }

    /// The token of the last link mailed to `to`.
    fn link_token(&self, to: &str) -> String {
        self.all()
            .iter()
            .rev()
            .find_map(|notice| match notice {
                Notice::EmailChange(n) if n.to.as_str() == to => Some(n.token.clone()),
                _ => None,
            })
            .expect("a link was mailed")
    }

    /// How many links, whatever address they went to.
    fn links(&self) -> usize {
        self.all()
            .iter()
            .filter(|notice| matches!(notice, Notice::EmailChange(_)))
            .count()
    }

    /// Who was told a change was asked for, and which address it names.
    fn told(&self) -> Vec<(String, String)> {
        self.all()
            .iter()
            .filter_map(|notice| match notice {
                Notice::EmailChangeRequested(n) => {
                    Some((n.to.as_str().to_owned(), n.new_address.as_str().to_owned()))
                }
                _ => None,
            })
            .collect()
    }

    /// The addresses that were told they already have an account.
    fn told_taken(&self) -> Vec<String> {
        self.all()
            .iter()
            .filter_map(|notice| match notice {
                Notice::EmailTaken(n) => Some(n.to.as_str().to_owned()),
                _ => None,
            })
            .collect()
    }

    /// The old addresses told a change was made, and the address it names.
    fn told_changed(&self) -> Vec<(String, String)> {
        self.all()
            .iter()
            .filter_map(|notice| match notice {
                Notice::EmailChanged(n) => {
                    Some((n.to.as_str().to_owned(), n.new_address.as_str().to_owned()))
                }
                _ => None,
            })
            .collect()
    }

    /// The addresses told a new password was set, and whether the other devices were signed out.
    fn told_password(&self) -> Vec<(String, bool)> {
        self.all()
            .iter()
            .filter_map(|notice| match notice {
                Notice::PasswordChanged(n) => Some((n.to.as_str().to_owned(), n.others_signed_out)),
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

/// What the browser sends for `NEW_PASSWORD`, and the ticket the server gave with its first
/// message.
struct Registration {
    new: NewCredentials,
    ticket: Vec<u8>,
}

async fn scene() -> Scene {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let repo = FakeProfile::over(&world.store);
    Scene {
        world,
        repo,
        mailbox: Mailbox::default(),
        user,
    }
}

type Creds = Credentials<FakeStore, FakeProfile, FakePassword, FakeSeal, FakeEnv>;
type Changes = EmailChanges<FakeStore, FakeProfile, FakePassword, FakeSeal, FakeEnv>;
type Confirm = ConfirmEmailChange<FakeStore, FakeProfile, FakeStore, FakeStore, FakeEnv>;
type Others =
    OtherDevices<FakeStore, FakeStore, FakeStore, FakeTokenSigner, FakeEnv, FakeStore, FakeStore>;

fn invalid<T>(result: Result<T, ProfileError>) -> bool {
    matches!(result, Err(ProfileError::App(AppError::Invalid(_))))
}

impl Scene {
    fn profile(&self) -> Profile<FakeStore, FakeProfile, FakeEnv> {
        Profile {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            clock: self.world.env.clone(),
        }
    }

    fn credentials(&self) -> Creds {
        Credentials {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            auth: self.world.password.clone(),
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            notices: self.mailbox.notices(),
            config: self.world.config,
        }
    }

    fn changes(&self) -> Changes {
        self.changes_with(self.mailbox.notices())
    }

    fn changes_with(&self, notices: Notices) -> Changes {
        EmailChanges {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            auth: self.world.password.clone(),
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            notices,
            config: self.world.config,
        }
    }

    fn confirm(&self) -> Confirm {
        ConfirmEmailChange {
            users: self.world.store.clone(),
            repo: self.repo.clone(),
            devices: self.world.store.clone(),
            tokens: self.world.store.clone(),
            env: self.world.env.clone(),
            notices: self.mailbox.notices(),
        }
    }

    fn others(&self) -> Others {
        OtherDevices {
            sign_out: sign_out_device(&self.world),
            sessions: self.world.sessions(),
        }
    }

    /// The first registration message, answered by the server for `email` (the account's own, or
    /// a new address) to `user` on the device key `jkt`, and the last one made from the answer.
    async fn registration_as(&self, user: UserId, email: Option<&str>, jkt: &str) -> Registration {
        let (state, request) = kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD)
            .expect("client registration start");
        let started = self
            .credentials()
            .start(user, email, &request, jkt)
            .await
            .expect("the server answers the registration");
        let (upload, _export_key) = kemlock_crypto::opaque::client_registration_finish(
            state,
            &NEW_PASSWORD,
            &started.response,
        )
        .expect("client registration finish");
        Registration {
            new: NewCredentials {
                upload,
                kdf: KdfParams::new_account([8u8; 16]),
                wrapped_root_key: vec![0x44; WRAPPED_ROOT_KEY_LEN],
            },
            ticket: started.ticket,
        }
    }

    async fn registration(&self, email: Option<&str>) -> Registration {
        self.registration_as(self.user, email, JKT).await
    }

    async fn change_password(
        &self,
        registration: Registration,
        sign_out_others: bool,
    ) -> Result<PasswordChanged, ProfileError> {
        self.credentials()
            .change_password(
                self.user,
                registration.new,
                &registration.ticket,
                JKT,
                sign_out_others,
            )
            .await
    }

    async fn ask(
        &self,
        email: &str,
        registration: Registration,
    ) -> Result<EmailChangeAsked, ProfileError> {
        self.changes()
            .request(
                self.user,
                email,
                registration.new,
                &registration.ticket,
                JKT,
            )
            .await
    }

    /// Asks for `NEW_EMAIL` and returns the token of the link mailed to it.
    async fn asked(&self) -> String {
        let registration = self.registration(Some(NEW_EMAIL)).await;
        self.ask(NEW_EMAIL, registration).await.expect("asked");
        self.mailbox.link_token(NEW_EMAIL)
    }

    async fn signs_in(&self, email: &str, password: &[u8]) -> Result<SignedIn, AppError> {
        sign_in_with(&self.world, email, password, device("Pixel"), JKT).await
    }

    /// The account signed in on a device of its own, with its own key.
    async fn device(&self, name: &str, jkt: &str) -> TokenPair {
        let SignedIn::Tokens(tokens) =
            sign_in_with(&self.world, EMAIL, &PASSWORD, device(name), jkt)
                .await
                .expect("signs in")
        else {
            panic!("tokens expected");
        };
        tokens
    }

    async fn is_signed_in(&self, tokens: &TokenPair, jkt: &str) -> bool {
        self.world
            .authenticate()
            .execute(&tokens.access_token, jkt)
            .await
            .is_ok()
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
            email: Email::parse(EMAIL).expect("an address"),
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
async fn a_new_name_keeps_what_another_request_wrote_in_between() {
    let s = scene().await;
    let before = s.world.store.user(s.user).expect("the account");

    // Another request writes the account after the rename read it.
    s.repo.interfere_once();
    s.profile()
        .rename(s.user, "Sam Rivera")
        .await
        .expect("renamed");

    // The rename wrote only the name: the other request's write stays, nothing is put back.
    let now = s.world.store.user(s.user).expect("the account");
    assert_eq!(now.name.as_deref(), Some("Sam Rivera"));
    assert_ne!(now.updated_at, before.updated_at);
    assert_eq!(now.opaque_record, before.opaque_record);
    assert_eq!(now.security_stamp, before.security_stamp);
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
    let registration = s.registration(None).await;
    let wrap = registration.new.wrapped_root_key.clone();

    let changed = s
        .change_password(registration, false)
        .await
        .expect("the password changes");

    assert!(!changed.others_signed_out);
    let after = s.world.store.user(s.user).expect("the account");
    assert_eq!(changed.account, after);
    assert_eq!(after.wrapped_root_key, wrap);
    assert_eq!(after.kdf.salt, vec![8u8; 16]);
    assert_ne!(after.opaque_record, before.opaque_record);
    // The root key stays: so do the keys, the version and, with no other device signed out, the
    // sessions' stamp.
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

    let mut odd_kdf = s.registration(None).await;
    odd_kdf.new.kdf.iterations = 4;
    let mut short_salt = s.registration(None).await;
    short_salt.new.kdf.salt = vec![1; 8];
    let mut short_wrap = s.registration(None).await;
    short_wrap.new.wrapped_root_key.pop();
    let mut garbage = s.registration(None).await;
    garbage.new.upload = vec![9; 12];

    for bad in [odd_kdf, short_salt, short_wrap, garbage] {
        assert!(invalid(s.change_password(bad, false).await));
    }
    assert_eq!(s.world.store.user(s.user), Some(before));
    assert!(is_tokens(&s.signs_in(EMAIL, &PASSWORD).await));
}

#[tokio::test]
async fn an_account_shared_with_bitwarden_apps_or_with_no_password_is_refused() {
    let s = scene().await;
    let registration = s.registration(None).await;
    let ticket = registration.ticket.clone();
    let account = s.world.store.user(s.user).expect("the account");

    s.world.store.put_user(kemlock_domain::User {
        mode: AccountMode::Compatible,
        ..account.clone()
    });
    assert_eq!(
        s.change_password(registration, false).await,
        Err(ProfileError::CompatibleAccount)
    );
    assert_eq!(
        s.credentials().check(s.user, &ticket, JKT).await,
        Err(ProfileError::CompatibleAccount)
    );
    assert_eq!(
        s.credentials().start(s.user, None, &[1; 32], JKT).await,
        Err(ProfileError::CompatibleAccount)
    );

    s.world.store.put_user(kemlock_domain::User {
        opaque_record: None,
        wrapped_root_key: Vec::new(),
        ..account
    });
    let registration = Registration {
        new: NewCredentials {
            upload: Vec::new(),
            kdf: KdfParams::new_account([8u8; 16]),
            wrapped_root_key: vec![0x44; WRAPPED_ROOT_KEY_LEN],
        },
        ticket: ticket.clone(),
    };
    assert_eq!(
        s.change_password(registration, false).await,
        Err(ProfileError::NoPassword)
    );
    assert_eq!(
        s.credentials().check(s.user, &ticket, JKT).await,
        Err(ProfileError::NoPassword)
    );
    let view = s.profile().show(s.user).await.expect("the profile");
    assert!(!view.has_password);
}

#[tokio::test]
async fn a_new_password_is_mailed_to_the_account_without_a_secret_in_it() {
    let s = scene().await;

    let registration = s.registration(None).await;
    s.change_password(registration, false)
        .await
        .expect("changes");
    let registration = s.registration(None).await;
    s.change_password(registration, true)
        .await
        .expect("changes");

    assert_eq!(
        s.mailbox.told_password(),
        vec![(EMAIL.to_owned(), false), (EMAIL.to_owned(), true)]
    );
    assert_eq!(s.mailbox.links(), 0);
}

#[tokio::test]
async fn a_refused_password_change_mails_nobody() {
    let s = scene().await;
    let mut registration = s.registration(None).await;
    registration.new.kdf.iterations = 4;
    assert!(invalid(s.change_password(registration, false).await));
    assert_eq!(s.mailbox.told_password(), Vec::new());
}

// ---- the registration's ticket ----

#[tokio::test]
async fn a_registration_is_good_only_for_what_it_was_made_for() {
    let s = scene().await;
    let before = s.world.store.user(s.user).expect("the account");
    let kim = make_user(&s.world, TAKEN_EMAIL).await;

    // A ticket for another account, from another device key, for no ticket at all.
    let for_kim = s.registration_as(kim, None, JKT).await;
    assert!(invalid(
        s.credentials()
            .change_password(s.user, for_kim.new, &for_kim.ticket, JKT, false)
            .await
    ));
    let other_key = s.registration(None).await;
    assert!(invalid(
        s.credentials()
            .change_password(
                s.user,
                other_key.new,
                &other_key.ticket,
                "another-key",
                false
            )
            .await
    ));
    for ticket in [Vec::new(), vec![1u8; 40], b"not a ticket".to_vec()] {
        let registration = s.registration(None).await;
        assert!(invalid(
            s.credentials()
                .change_password(s.user, registration.new, &ticket, JKT, false)
                .await
        ));
    }
    // A ticket with one byte changed.
    let tampered = s.registration(None).await;
    let mut ticket = tampered.ticket.clone();
    let last = ticket.len() - 1;
    ticket[last] ^= 1;
    assert!(invalid(
        s.credentials()
            .change_password(s.user, tampered.new, &ticket, JKT, false)
            .await
    ));

    // A registration made for an address is not one for a password, and the other way round.
    let for_address = s.registration(Some(NEW_EMAIL)).await;
    assert!(invalid(
        s.credentials()
            .change_password(s.user, for_address.new, &for_address.ticket, JKT, false)
            .await
    ));
    let for_password = s.registration(None).await;
    assert!(invalid(
        s.changes()
            .request(
                s.user,
                NEW_EMAIL,
                for_password.new,
                &for_password.ticket,
                JKT
            )
            .await
    ));

    // A registration for one address is not one for another, and the check is the same whether or
    // not the address has an account.
    for asked in ["sam@example.net", TAKEN_EMAIL] {
        let for_new = s.registration(Some(NEW_EMAIL)).await;
        assert!(invalid(
            s.changes()
                .request(s.user, asked, for_new.new, &for_new.ticket, JKT)
                .await
        ));
    }
    let for_taken = s.registration(Some(TAKEN_EMAIL)).await;
    assert!(invalid(
        s.changes()
            .request(s.user, NEW_EMAIL, for_taken.new, &for_taken.ticket, JKT)
            .await
    ));

    // A ticket runs out with the login state's lifetime.
    let late = s.registration(None).await;
    s.world.env.clock.advance(s.world.config.challenge_ttl);
    assert!(invalid(s.change_password(late, false).await));

    assert_eq!(s.world.store.user(s.user), Some(before));
    assert_eq!(s.repo.pending(s.user), None);
    // And a fresh one is good.
    let fresh = s.registration(None).await;
    s.change_password(fresh, false).await.expect("changes");
}

#[tokio::test]
async fn a_ticket_for_the_old_address_is_no_good_once_the_address_changed() {
    let s = scene().await;
    let stale = s.registration(None).await;
    let token = s.asked().await;
    s.confirm().confirm(&token).await.expect("opens");

    // The ticket was asked for the address the account had; the record it made is bound to it.
    assert!(invalid(s.change_password(stale, false).await));
}

#[tokio::test]
async fn the_ticket_checks_come_before_the_password_is_spent() {
    let s = scene().await;
    let registration = s.registration(None).await;
    assert!(invalid(s.credentials().check(s.user, b"nope", JKT).await));
    assert_eq!(
        s.credentials()
            .check(s.user, &registration.ticket, JKT)
            .await,
        Ok(())
    );
    let for_address = s.registration(Some(NEW_EMAIL)).await;
    assert!(invalid(
        s.changes()
            .check(s.user, NEW_EMAIL, &registration.ticket, JKT)
            .await
    ));
    assert_eq!(
        s.changes()
            .check(s.user, NEW_EMAIL, &for_address.ticket, JKT)
            .await,
        Ok(())
    );
}

// ---- signing the other devices out ----

#[tokio::test]
async fn signing_the_other_devices_out_ends_every_session_in_the_same_write() {
    let s = scene().await;
    let laptop = s.device("Laptop", "jkt-laptop").await;
    let phone = s.device("Phone", "jkt-phone").await;
    assert!(s.is_signed_in(&laptop, "jkt-laptop").await);
    assert!(s.is_signed_in(&phone, "jkt-phone").await);
    let before = s.world.store.user(s.user).expect("the account");
    let registration = s.registration_as(s.user, None, "jkt-laptop").await;

    let changed = s
        .credentials()
        .change_password(
            s.user,
            registration.new,
            &registration.ticket,
            "jkt-laptop",
            true,
        )
        .await
        .expect("the password changes");

    // One write replaced the records and the stamp.
    assert!(changed.others_signed_out);
    let after = s.world.store.user(s.user).expect("the account");
    assert_ne!(after.security_stamp, before.security_stamp);
    assert_eq!(changed.account, after);
    // Every session ended with it, the one that asked included: access and refresh tokens alike.
    for (tokens, jkt) in [(&laptop, "jkt-laptop"), (&phone, "jkt-phone")] {
        assert_eq!(
            s.world
                .authenticate()
                .execute(&tokens.access_token, jkt)
                .await,
            Err(AppError::SessionEnded("security-stamp-changed"))
        );
        assert_eq!(
            s.world.refresh().execute(&tokens.refresh_token, jkt).await,
            Err(AppError::SessionEnded("security-stamp-changed"))
        );
    }

    // The asking device gets a new session on the new stamp, bound to its key and its device; the
    // other device is gone with its tokens.
    let actor = Actor {
        user: s.user,
        device: laptop.device,
        admin: false,
    };
    let renewed = s
        .others()
        .renew(&actor, &changed.account, "jkt-laptop")
        .await
        .expect("new tokens");
    assert_eq!(renewed.device, laptop.device);
    assert!(s.is_signed_in(&renewed, "jkt-laptop").await);
    assert!(
        !s.is_signed_in(&renewed, "jkt-phone").await,
        "bound to its key"
    );
    s.world
        .refresh()
        .execute(&renewed.refresh_token, "jkt-laptop")
        .await
        .expect("the new refresh token works");
    assert!(
        DeviceRepo::get(&s.world.store, phone.device)
            .await
            .expect("reads")
            .is_none()
    );
    assert!(
        DeviceRepo::get(&s.world.store, laptop.device)
            .await
            .expect("reads")
            .is_some()
    );
    assert!(!s.is_signed_in(&phone, "jkt-phone").await);
}

#[tokio::test]
async fn without_signing_the_others_out_every_session_goes_on() {
    let s = scene().await;
    let laptop = s.device("Laptop", "jkt-laptop").await;
    let phone = s.device("Phone", "jkt-phone").await;
    let registration = s.registration_as(s.user, None, "jkt-laptop").await;
    let before = s.world.store.user(s.user).expect("the account");

    let changed = s
        .credentials()
        .change_password(
            s.user,
            registration.new,
            &registration.ticket,
            "jkt-laptop",
            false,
        )
        .await
        .expect("the password changes");

    assert!(!changed.others_signed_out);
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .security_stamp,
        before.security_stamp
    );
    assert!(s.is_signed_in(&laptop, "jkt-laptop").await);
    assert!(s.is_signed_in(&phone, "jkt-phone").await);
    s.world
        .refresh()
        .execute(&phone.refresh_token, "jkt-phone")
        .await
        .expect("the other device's refresh token works");
}

// ---- the sign-in address ----

#[tokio::test]
async fn an_address_changes_only_when_its_link_is_opened() {
    let s = scene().await;
    let registration = s.registration(Some(NEW_EMAIL)).await;
    let wrap = registration.new.wrapped_root_key.clone();
    // A device is signed in, to see the sessions end.
    let SignedIn::Tokens(tokens) = s.signs_in(EMAIL, &PASSWORD).await.expect("signs in") else {
        panic!("tokens expected");
    };
    let before = s.world.store.user(s.user).expect("the account");

    let asked = s
        .changes()
        .request(
            s.user,
            "  Sam@Example.COM ",
            registration.new,
            &registration.ticket,
            JKT,
        )
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
    // Every session ended: no refresh token is left, whatever the device, and the access token
    // carries the old stamp.
    assert!(s.world.store.refresh_tokens().is_empty(), "{tokens:?}");
    assert!(!s.is_signed_in(&tokens, JKT).await);
    // The new address and password sign in; the old address no longer does.
    assert!(is_tokens(&s.signs_in(NEW_EMAIL, &NEW_PASSWORD).await));
    assert!(s.cannot_sign_in(EMAIL, &PASSWORD).await);
    assert!(s.cannot_sign_in(EMAIL, &NEW_PASSWORD).await);
    // The old address is told, with the new one named and no link.
    assert_eq!(
        s.mailbox.told_changed(),
        vec![(EMAIL.to_owned(), NEW_EMAIL.to_owned())]
    );
}

#[tokio::test]
async fn a_link_is_good_once_and_only_its_own_token_opens_it() {
    let s = scene().await;
    let token = s.asked().await;

    assert_eq!(
        s.confirm().confirm("not-the-token").await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(
        s.confirm().confirm("").await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert!(
        s.repo.pending(s.user).is_some(),
        "a wrong token spends nothing"
    );

    s.confirm().confirm(&token).await.expect("opens");
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
}

#[tokio::test]
async fn a_link_runs_out_after_a_day() {
    let s = scene().await;
    let token = s.asked().await;

    s.world.env.clock.advance(Duration::hours(24));

    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .email
            .as_str(),
        EMAIL
    );
    // An ask that ran out is not shown as waiting.
    let view = s.profile().show(s.user).await.expect("the profile");
    assert_eq!(view.pending_email, None);
}

#[tokio::test]
async fn asking_again_replaces_the_ask_and_cancelling_takes_it_back() {
    let s = scene().await;
    let first_token = s.asked().await;
    let second = s.registration(Some("sam@example.net")).await;
    s.ask("sam@example.net", second).await.expect("asked again");
    let second_token = s.mailbox.link_token("sam@example.net");

    assert_eq!(
        s.confirm().confirm(&first_token).await,
        Err(ProfileError::EmailChangeInvalid),
        "the first link stopped working"
    );

    s.changes().cancel(s.user).await.expect("cancelled");
    s.changes()
        .cancel(s.user)
        .await
        .expect("nothing to cancel is fine");
    assert_eq!(
        s.confirm().confirm(&second_token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .email
            .as_str(),
        EMAIL
    );
}

#[tokio::test]
async fn an_address_taken_in_the_meantime_is_not_given_away() {
    let s = scene().await;
    let token = s.asked().await;
    make_user(&s.world, NEW_EMAIL).await;

    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailTaken)
    );
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .email
            .as_str(),
        EMAIL
    );
    assert_eq!(s.repo.pending(s.user), None, "the ask is gone");
    // Asking for an address someone has is answered as for any other, and no one is told.
    let registration = s.registration(Some(NEW_EMAIL)).await;
    assert!(s.ask(NEW_EMAIL, registration).await.is_ok());
}

#[tokio::test]
async fn a_change_of_password_drops_the_change_of_address_made_from_the_old_one() {
    let s = scene().await;
    let token = s.asked().await;

    let for_password = s.registration(None).await;
    s.change_password(for_password, false)
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
    let registration = s.registration(Some(NEW_EMAIL)).await;
    let ask = |changes: Changes, email: &'static str| {
        let new = registration.new.clone();
        let ticket = registration.ticket.clone();
        let user = s.user;
        async move { changes.request(user, email, new, &ticket, JKT).await }
    };

    // No mail sender: no one could open the link.
    assert_eq!(
        ask(s.changes_with(Notices::logging()), NEW_EMAIL).await,
        Err(ProfileError::MailOff)
    );
    assert_eq!(s.repo.pending(s.user), None);

    // A mail that does not go out leaves nothing waiting.
    let failing = Mailbox {
        fail: true,
        ..Mailbox::default()
    };
    assert_eq!(
        ask(s.changes_with(failing.notices()), NEW_EMAIL).await,
        Err(ProfileError::MailFailed)
    );
    assert_eq!(s.repo.pending(s.user), None);

    // The same address, or one that is no address.
    assert!(invalid(ask(s.changes(), EMAIL).await));
    assert!(invalid(ask(s.changes(), "nope").await));

    // An identity provider's account, and one shared with Bitwarden apps.
    s.repo.link_sso(s.user);
    assert_eq!(
        ask(s.changes(), NEW_EMAIL).await,
        Err(ProfileError::SsoManaged)
    );
    let account = s.world.store.user(s.user).expect("the account");
    s.world.store.put_user(kemlock_domain::User {
        mode: AccountMode::Compatible,
        ..account
    });
    assert_eq!(
        ask(s.changes(), NEW_EMAIL).await,
        Err(ProfileError::CompatibleAccount)
    );
}

// ---- asking for an address another account has ----

#[tokio::test]
async fn a_registration_for_a_taken_address_is_answered_like_one_for_a_free_address() {
    let s = scene().await;
    make_user(&s.world, TAKEN_EMAIL).await;
    let (_state, request) = kemlock_crypto::opaque::client_registration_start(&NEW_PASSWORD)
        .expect("client registration start");
    let start = |email: &'static str| {
        let credentials = s.credentials();
        let request = request.clone();
        let user = s.user;
        async move { credentials.start(user, Some(email), &request, JKT).await }
    };

    let free = start(NEW_EMAIL).await.expect("answered");
    let taken = start(TAKEN_EMAIL).await.expect("answered all the same");

    // Both are well formed and the same size, the tickets too (for addresses of one length), so
    // neither says which is which.
    assert_eq!(free.response.len(), taken.response.len());
    assert_eq!(free.ticket.len(), taken.ticket.len());
    // The server's half for a free address is the one for that address. For a taken one it is
    // not the one for the account that has it: that identifier is never evaluated.
    let evaluated = |email: &str| {
        s.world
            .password
            .registration_response(email.as_bytes(), &request)
            .expect("evaluates")
    };
    assert_eq!(free.response, evaluated(NEW_EMAIL));
    assert_ne!(taken.response, evaluated(TAKEN_EMAIL));
    // Nor is it the same twice: random bytes each time.
    let again = start(TAKEN_EMAIL).await.expect("answered");
    assert_ne!(taken.response, again.response);

    // Only the account's own address, a malformed one and an identity provider's account are said.
    assert!(invalid(start(EMAIL).await));
    assert!(invalid(start("not an address").await));
    s.repo.link_sso(s.user);
    assert_eq!(start(TAKEN_EMAIL).await, Err(ProfileError::SsoManaged));
}

#[tokio::test]
async fn asking_for_a_taken_address_looks_like_asking_for_a_free_one() {
    let s = scene().await;
    make_user(&s.world, TAKEN_EMAIL).await;

    let taken = s.registration(Some(TAKEN_EMAIL)).await;
    let asked_taken = s.ask(TAKEN_EMAIL, taken).await.expect("answered");
    let view_taken = s.profile().show(s.user).await.expect("the profile");
    let told_taken = s.mailbox.told();
    let pending_taken = s.repo.pending(s.user).expect("a pending change");

    let free = s.registration(Some(NEW_EMAIL)).await;
    let asked_free = s.ask(NEW_EMAIL, free).await.expect("answered");
    let view_free = s.profile().show(s.user).await.expect("the profile");
    let pending_free = s.repo.pending(s.user).expect("a pending change");

    // The same answer, the same life, the same pending change on the profile, the same news to
    // the old address.
    assert_eq!(asked_taken.email.as_str(), TAKEN_EMAIL);
    assert_eq!(asked_free.email.as_str(), NEW_EMAIL);
    assert_eq!(asked_taken.expires_at, asked_free.expires_at);
    assert_eq!(
        view_taken.pending_email.as_ref().map(|e| e.as_str()),
        Some(TAKEN_EMAIL)
    );
    assert_eq!(
        view_free.pending_email.as_ref().map(|e| e.as_str()),
        Some(NEW_EMAIL)
    );
    assert_eq!(pending_taken.expires_at, pending_free.expires_at);
    assert_eq!(told_taken, vec![(EMAIL.to_owned(), TAKEN_EMAIL.to_owned())]);

    // The address that has an account is told so, in a mail with no link; the free one gets the
    // link. The one pending change that stands in for the real one has a token nobody was given.
    assert_eq!(s.mailbox.told_taken(), vec![TAKEN_EMAIL.to_owned()]);
    assert_eq!(s.mailbox.links(), 1);
    assert!(
        s.mailbox.all().iter().all(
            |notice| !matches!(notice, Notice::EmailChange(n) if n.to.as_str() == TAKEN_EMAIL)
        )
    );
}

#[tokio::test]
async fn the_stand_in_for_a_taken_address_opens_nothing() {
    let s = scene().await;
    make_user(&s.world, TAKEN_EMAIL).await;
    let taken = s.registration(Some(TAKEN_EMAIL)).await;
    s.ask(TAKEN_EMAIL, taken).await.expect("answered");
    let stand_in = s.repo.pending(s.user).expect("a pending change");
    assert_eq!(s.mailbox.links(), 0, "no token was mailed");

    // No token anyone could have: not one seen anywhere, not the hash itself, not nothing.
    let hash_text = format!("{:?}", stand_in.token_hash);
    for guess in ["", "token", hash_text.as_str()] {
        assert_eq!(
            s.confirm().confirm(guess).await,
            Err(ProfileError::EmailChangeInvalid)
        );
    }
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .email
            .as_str(),
        EMAIL
    );
    // It can be taken back like any other ask.
    s.changes().cancel(s.user).await.expect("cancelled");
    assert_eq!(s.repo.pending(s.user), None);
}

// ---- opening the link looks at the account again ----

#[tokio::test]
async fn a_disabled_account_or_one_being_deleted_opens_nothing() {
    let s = scene().await;
    let token = s.asked().await;
    let account = s.world.store.user(s.user).expect("the account");

    s.world.store.set_account_disabled(s.user, true);
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    s.world.store.set_account_disabled(s.user, false);
    s.world.store.set_erasure_pending(s.user, true);
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(s.world.store.user(s.user), Some(account));
    // Nothing was spent: once the account is as it was, the link works.
    s.world.store.set_erasure_pending(s.user, false);
    s.confirm().confirm(&token).await.expect("opens");
}

#[tokio::test]
async fn a_link_asked_for_before_a_key_rotation_is_refused_and_the_ask_dropped() {
    let s = scene().await;
    let token = s.asked().await;
    // A root-key rotation ran since the link was mailed: the wrap in the change is of the old root.
    let account = s.world.store.user(s.user).expect("the account");
    s.world.store.put_user(kemlock_domain::User {
        key_version: account.key_version + 1,
        ..account.clone()
    });
    let rotated = s.world.store.user(s.user).expect("the account");

    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::EmailChangeInvalid)
    );
    assert_eq!(s.repo.pending(s.user), None, "the stale ask is dropped");
    // Nothing was put back: the account is as the rotation left it.
    assert_eq!(s.world.store.user(s.user), Some(rotated));
}

#[tokio::test]
async fn an_account_that_cannot_change_its_address_any_more_is_refused_and_the_ask_dropped() {
    let account = || async {
        let s = scene().await;
        let token = s.asked().await;
        let account = s.world.store.user(s.user).expect("the account");
        (s, token, account)
    };

    // Linked to an identity provider since the link was mailed.
    let (s, token, before) = account().await;
    s.repo.link_sso(s.user);
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::SsoManaged)
    );
    assert_eq!(s.repo.pending(s.user), None);
    assert_eq!(s.world.store.user(s.user), Some(before));

    // Shared with the Bitwarden apps since then.
    let (s, token, before) = account().await;
    s.world.store.put_user(kemlock_domain::User {
        mode: AccountMode::Compatible,
        ..before.clone()
    });
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::CompatibleAccount)
    );
    assert_eq!(s.repo.pending(s.user), None);

    // Left with no password since then.
    let (s, token, before) = account().await;
    s.world.store.put_user(kemlock_domain::User {
        opaque_record: None,
        wrapped_root_key: Vec::new(),
        ..before
    });
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::NoPassword)
    );
    assert_eq!(s.repo.pending(s.user), None);
}

// ---- no lost updates ----

#[tokio::test]
async fn a_write_of_another_request_in_between_changes_nothing_and_spends_no_link() {
    let s = scene().await;
    let token = s.asked().await;

    // Another request writes the account between the read and the write: nothing is applied, and
    // the link is still good.
    s.repo.interfere_once();
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::AccountChanged)
    );
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .email
            .as_str(),
        EMAIL
    );
    assert!(s.repo.pending(s.user).is_some(), "the link was not spent");
    assert!(s.mailbox.told_changed().is_empty());

    // Asking again: the link opens.
    s.confirm().confirm(&token).await.expect("opens");
    assert_eq!(
        s.world
            .store
            .user(s.user)
            .expect("the account")
            .email
            .as_str(),
        NEW_EMAIL
    );
}

#[tokio::test]
async fn a_new_password_does_not_overwrite_a_write_made_meanwhile() {
    let s = scene().await;
    let before = s.world.store.user(s.user).expect("the account");
    let registration = s.registration(None).await;

    s.repo.interfere_once();
    assert_eq!(
        s.change_password(registration, true).await,
        Err(ProfileError::AccountChanged)
    );

    // Only the other request's write is there: the records and the stamp are as they were, and no
    // one was told.
    let now = s.world.store.user(s.user).expect("the account");
    assert_eq!(now.opaque_record, before.opaque_record);
    assert_eq!(now.security_stamp, before.security_stamp);
    assert_eq!(s.mailbox.told_password(), Vec::new());
    assert!(is_tokens(&s.signs_in(EMAIL, &PASSWORD).await));

    // Asking again goes through.
    let registration = s.registration(None).await;
    s.change_password(registration, false)
        .await
        .expect("changes");
}

// ---- emergency access follows the address ----

fn grant(
    grantor: UserId,
    contact: &str,
    grantee: Option<UserId>,
    now: time::OffsetDateTime,
) -> EmergencyGrant {
    let mut grant = EmergencyGrant::invite(
        GrantId::random(),
        grantor,
        Email::parse(contact).expect("an address"),
        EmergencyKind::Takeover,
        7,
        now,
    )
    .expect("a grant");
    grant.grantee = grantee;
    grant
}

#[tokio::test]
async fn emergency_access_follows_the_new_address() {
    let s = scene().await;
    let now = s.world.env.now();
    let (ada, bob, kim, lee) = (
        UserId::random(),
        UserId::random(),
        UserId::random(),
        UserId::random(),
    );
    // Ada's contact is Sam, who accepted. Bob's invitation to the old address waits. Kim invited
    // both addresses. Lee invited someone else.
    let accepted = grant(ada, EMAIL, Some(s.user), now);
    let waiting = grant(bob, EMAIL, None, now);
    let kim_old = grant(kim, EMAIL, None, now);
    let kim_new = grant(kim, NEW_EMAIL, None, now);
    let unrelated = grant(lee, "pat@example.org", None, now);
    for g in [&accepted, &waiting, &kim_old, &kim_new, &unrelated] {
        s.repo.add_grant(g.clone());
    }
    let token = s.asked().await;

    s.confirm().confirm(&token).await.expect("opens");

    let email_of = |id: GrantId| {
        s.repo
            .grants()
            .into_iter()
            .find(|g| g.id == id)
            .expect("the grant")
            .grantee_email
            .as_str()
            .to_owned()
    };
    assert_eq!(email_of(accepted.id), NEW_EMAIL, "a contact who accepted");
    assert_eq!(
        email_of(waiting.id),
        NEW_EMAIL,
        "an invitation at the old address"
    );
    assert_eq!(
        email_of(kim_old.id),
        EMAIL,
        "the grantor has a grant to the new address already: both stay"
    );
    assert_eq!(email_of(kim_new.id), NEW_EMAIL);
    assert_eq!(email_of(unrelated.id), "pat@example.org");
}

#[tokio::test]
async fn emergency_access_stays_put_when_the_address_does() {
    let s = scene().await;
    let now = s.world.env.now();
    let accepted = grant(UserId::random(), EMAIL, Some(s.user), now);
    s.repo.add_grant(accepted.clone());
    let token = s.asked().await;

    s.repo.interfere_once();
    assert_eq!(
        s.confirm().confirm(&token).await,
        Err(ProfileError::AccountChanged)
    );

    assert_eq!(s.repo.grants(), vec![accepted]);
}
