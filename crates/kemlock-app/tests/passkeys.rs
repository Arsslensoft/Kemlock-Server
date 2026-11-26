//! Passkeys, passkey sign-in and security keys, over fakes and a scripted relying party.

mod fakes;
mod passkey_fakes;
mod sso_fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_app::b64url;
use kemlock_app::passkeys::{
    ChallengeKind, FinishRegistration, KeyList, ManagePasskeys, PasskeySignIn, PasskeyVerifyInput,
    SecurityKeyError, SecurityKeyInfo, SecurityKeyStep, SecurityKeys,
};
use kemlock_app::ports::{SecretSeal, TwoFactorMethod};
use kemlock_app::sso::{RequireSso, SpaceMembership, SpaceRole, SsoError};
use kemlock_app::{SignedIn, TokenPair};
use kemlock_domain::{Passkey, PrfWrap, SpaceId, UserId};
use passkey_fakes::*;
use serde_json::json;
use sso_fakes::FakeMembership;
use time::Duration;

type Manage =
    ManagePasskeys<FakeStore, FakePasskeys, FakePasskeys, ScriptedWebAuthn, FakeEnv, FakeStore>;
type PasskeyIn = PasskeySignIn<
    FakeStore,
    FakePasskeys,
    ScriptedWebAuthn,
    FakeSeal,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeEnv,
    FakeStore,
    FakeStore,
    FakeMembership,
>;
type Keys = SecurityKeys<FakeStore, FakeStore, FakePasskeys, ScriptedWebAuthn, FakeSeal, FakeEnv>;
type KeyStep = SecurityKeyStep<
    FakeStore,
    FakeStore,
    FakePasskeys,
    ScriptedWebAuthn,
    FakeSeal,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeEnv,
    FakeStore,
>;

const EMAIL: &str = "sam@example.org";
const JKT: &str = "device-key-thumbprint";
const NOT_ACCEPTED: &str = "the authenticator's answer wasn't accepted";
const NO_REGISTRATION: &str = "no passkey registration is in progress, or it expired";

struct Fx {
    world: World,
    passkeys: FakePasskeys,
    engine: ScriptedWebAuthn,
    membership: FakeMembership,
}

impl Fx {
    fn new() -> Self {
        Fx {
            world: World::new().with_signups(),
            passkeys: FakePasskeys::default(),
            engine: ScriptedWebAuthn::default(),
            membership: FakeMembership::default(),
        }
    }

    async fn user(&self, email: &str) -> UserId {
        make_user(&self.world, email).await
    }

    fn manage(&self) -> Manage {
        ManagePasskeys {
            users: self.world.store.clone(),
            passkeys: self.passkeys.clone(),
            challenges: self.passkeys.clone(),
            webauthn: self.engine.clone(),
            env: self.world.env.clone(),
            events: self.world.store.clone(),
            config: self.world.config,
        }
    }

    fn sign_in(&self) -> PasskeyIn {
        PasskeySignIn {
            users: self.world.store.clone(),
            passkeys: self.passkeys.clone(),
            webauthn: self.engine.clone(),
            seal: self.world.seal.clone(),
            sso: RequireSso {
                membership: self.membership.clone(),
            },
            sessions: self.world.sessions(),
        }
    }

    fn keys(&self) -> Keys {
        SecurityKeys {
            users: self.world.store.clone(),
            two_factor: self.world.store.clone(),
            challenges: self.passkeys.clone(),
            webauthn: self.engine.clone(),
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            config: self.world.config,
        }
    }

    fn step(&self) -> KeyStep {
        SecurityKeyStep {
            keys: self.keys(),
            sessions: self.world.sessions(),
        }
    }

    async fn register_passkey(&self, user: UserId, name: &str, credential: &[u8]) -> Passkey {
        let options = self
            .manage()
            .start_registration(user)
            .await
            .expect("registration starts");
        self.manage()
            .finish_registration(FinishRegistration {
                user,
                name: name.to_owned(),
                response: registration_answer(&options, credential),
                prf: None,
            })
            .await
            .expect("registration finishes")
    }

    async fn finish_passkey(&self, user: UserId, response: Vec<u8>) -> Result<Passkey, AppError> {
        self.manage()
            .finish_registration(FinishRegistration {
                user,
                name: "Laptop".to_owned(),
                response,
                prf: None,
            })
            .await
    }

    async fn verify(
        &self,
        challenge: Vec<u8>,
        response: Vec<u8>,
        jkt: &str,
    ) -> Result<kemlock_app::passkeys::PasskeySignedIn, SsoError> {
        self.sign_in()
            .verify(PasskeyVerifyInput {
                challenge,
                response,
                device: device("Pixel"),
                jkt: jkt.to_owned(),
            })
            .await
    }

    async fn register_key(
        &self,
        user: UserId,
        slot: Option<u8>,
        name: &str,
        credential: &[u8],
    ) -> KeyList {
        let options = self
            .keys()
            .start_registration(user)
            .await
            .expect("registration starts");
        self.keys()
            .finish_registration(user, slot, name, &registration_answer(&options, credential))
            .await
            .expect("registration finishes")
    }

    fn key_version(&self, user: UserId) -> u32 {
        self.world
            .store
            .user(user)
            .expect("the account exists")
            .key_version
    }

    fn wrap(&self, user: UserId) -> PrfWrap {
        PrfWrap {
            wrapped_key: vec![0x5a; PrfWrap::WRAPPED_KEY_LEN],
            key_version: self.key_version(user),
        }
    }

    /// Signs in with the passkey `credential` at `counter`, as a client does: options, then the
    /// authenticator's answer to them.
    async fn passkey_sign_in(
        &self,
        user: UserId,
        credential: &[u8],
        counter: u32,
    ) -> Result<kemlock_app::passkeys::PasskeySignedIn, SsoError> {
        let started = self.sign_in().options(JKT).expect("options");
        let response = assertion_answer(
            &started.options,
            credential,
            Some(&user.as_bytes()[..]),
            counter,
            true,
        );
        self.sign_in()
            .verify(PasskeyVerifyInput {
                challenge: started.challenge,
                response,
                device: device("Pixel"),
                jkt: JKT.to_owned(),
            })
            .await
    }
}

fn unauthorized() -> SsoError {
    SsoError::App(AppError::Unauthorized)
}

// ---------------------------------------------------------------------------------------------
// Registering and managing passkeys.

#[tokio::test]
async fn a_passkey_is_registered_in_two_calls_and_listed() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;

    let options = fx.manage().start_registration(user).await.expect("options");
    assert_eq!(options["kind"], "Passkey");
    assert_eq!(options["name"], EMAIL);
    assert_eq!(options["user"], b64url::encode(user.as_bytes()));
    assert!(
        fx.passkeys
            .has_challenge(user, ChallengeKind::PasskeyRegistration)
    );

    let passkey = fx
        .manage()
        .finish_registration(FinishRegistration {
            user,
            name: "  Work laptop ".to_owned(),
            response: registration_answer(&options, b"credential-one"),
            prf: None,
        })
        .await
        .expect("registered");
    assert_eq!(passkey.name, "Work laptop");
    assert_eq!(passkey.credential_id, b"credential-one");
    assert_eq!(passkey.prf_wrap, None);
    assert_eq!(passkey.last_used_at, None);
    assert!(
        !fx.passkeys
            .has_challenge(user, ChallengeKind::PasskeyRegistration),
        "the challenge is used up"
    );
    assert_eq!(
        fx.manage().list(user).await.expect("list"),
        vec![passkey.clone()]
    );
    assert!(
        fx.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "passkey.register" && e.target == Some(passkey.id.to_string()))
    );
}

#[tokio::test]
async fn the_registration_excludes_the_passkeys_the_account_has() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_passkey(user, "One", b"one").await;
    fx.register_passkey(user, "Two", b"two").await;
    let options = fx.manage().start_registration(user).await.expect("options");
    assert_eq!(options["exclude"], 2);
}

#[tokio::test]
async fn an_account_has_at_most_five_passkeys() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    for i in 0..5 {
        fx.register_passkey(user, &format!("key {i}"), format!("cred-{i}").as_bytes())
            .await;
    }
    assert_eq!(
        fx.manage().start_registration(user).await,
        Err(AppError::Invalid(
            "an account may have at most five passkeys"
        ))
    );
    assert_eq!(fx.passkeys.of(user).len(), 5);
}

#[tokio::test]
async fn a_sixth_passkey_is_refused_even_when_its_challenge_began_earlier() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let options = fx.manage().start_registration(user).await.expect("options");
    // Another device fills the account while this one's challenge waits.
    for i in 0..5 {
        fx.passkeys
            .insert_for_test(user, &format!("other {i}"), format!("other-{i}").as_bytes());
    }
    let refused = fx
        .manage()
        .finish_registration(FinishRegistration {
            user,
            name: "Late".to_owned(),
            response: registration_answer(&options, b"late"),
            prf: None,
        })
        .await;
    assert_eq!(
        refused.expect_err("refused"),
        AppError::Invalid("an account may have at most five passkeys")
    );
}

#[tokio::test]
async fn a_wrong_answer_uses_the_challenge_up() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let options = fx.manage().start_registration(user).await.expect("options");
    let wrong = registration_answer(&json!({"challenge": "not it"}), b"cred");
    assert_eq!(
        fx.finish_passkey(user, wrong).await.expect_err("refused"),
        AppError::Invalid(NOT_ACCEPTED)
    );
    // The right answer to the same challenge finds nothing to answer.
    assert_eq!(
        fx.finish_passkey(user, registration_answer(&options, b"cred"))
            .await
            .expect_err("refused"),
        AppError::Invalid(NO_REGISTRATION)
    );
    assert!(fx.passkeys.all().is_empty());
}

#[tokio::test]
async fn a_new_registration_replaces_the_one_before_and_an_old_one_expires() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let first = fx.manage().start_registration(user).await.expect("first");
    let _second = fx.manage().start_registration(user).await.expect("second");
    let answer = |options| FinishRegistration {
        user,
        name: "Laptop".to_owned(),
        response: registration_answer(options, b"cred"),
        prf: None,
    };
    assert_eq!(
        fx.manage()
            .finish_registration(answer(&first))
            .await
            .expect_err("refused"),
        AppError::Invalid(NOT_ACCEPTED),
        "the first challenge's answer meets the second's state"
    );

    let third = fx.manage().start_registration(user).await.expect("third");
    fx.world.env.clock.advance(Duration::minutes(6));
    assert_eq!(
        fx.manage()
            .finish_registration(answer(&third))
            .await
            .expect_err("refused"),
        AppError::Invalid(NO_REGISTRATION),
        "five minutes is all a challenge lives"
    );
}

#[tokio::test]
async fn a_credential_another_account_has_is_refused() {
    let fx = Fx::new();
    let sam = fx.user(EMAIL).await;
    let ada = fx.user("ada@example.org").await;
    fx.register_passkey(sam, "Sam's", b"shared").await;

    let options = fx.manage().start_registration(ada).await.expect("options");
    let refused = fx
        .manage()
        .finish_registration(FinishRegistration {
            user: ada,
            name: "Ada's".to_owned(),
            response: registration_answer(&options, b"shared"),
            prf: None,
        })
        .await;
    assert_eq!(refused.expect_err("refused"), AppError::Duplicate);
    assert!(fx.passkeys.of(ada).is_empty());
}

#[tokio::test]
async fn a_nameless_passkey_is_refused_before_it_uses_the_challenge() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let options = fx.manage().start_registration(user).await.expect("options");
    let refused = fx
        .manage()
        .finish_registration(FinishRegistration {
            user,
            name: " \u{7} ".to_owned(),
            response: registration_answer(&options, b"cred"),
            prf: None,
        })
        .await;
    assert_eq!(
        refused.expect_err("refused"),
        AppError::Invalid("a passkey needs a name")
    );
    // The same challenge still answers.
    fx.manage()
        .finish_registration(FinishRegistration {
            user,
            name: "Laptop".to_owned(),
            response: registration_answer(&options, b"cred"),
            prf: None,
        })
        .await
        .expect("the challenge was kept");
}

#[tokio::test]
async fn the_prf_copy_of_the_root_key_is_stored_when_it_fits() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let wrap = fx.wrap(user);
    let options = fx.manage().start_registration(user).await.expect("options");
    let answer = |prf| FinishRegistration {
        user,
        name: "Laptop".to_owned(),
        response: registration_answer(&options, b"cred"),
        prf,
    };

    let short = PrfWrap {
        wrapped_key: vec![1; 91],
        ..wrap.clone()
    };
    assert_eq!(
        fx.manage()
            .finish_registration(answer(Some(short)))
            .await
            .expect_err("refused"),
        AppError::Invalid("the wrapped key has the wrong length")
    );
    let stale = PrfWrap {
        key_version: wrap.key_version + 1,
        ..wrap.clone()
    };
    assert_eq!(
        fx.manage()
            .finish_registration(answer(Some(stale)))
            .await
            .expect_err("refused"),
        AppError::Invalid("the wrapped key is for another key version than the account's")
    );

    let passkey = fx
        .manage()
        .finish_registration(answer(Some(wrap.clone())))
        .await
        .expect("a wrap that fits");
    assert_eq!(passkey.prf_wrap, Some(wrap));
}

#[tokio::test]
async fn a_passkey_made_without_prf_gets_its_copy_later() {
    let fx = Fx::new();
    let sam = fx.user(EMAIL).await;
    let ada = fx.user("ada@example.org").await;
    let passkey = fx.register_passkey(sam, "Laptop", b"cred").await;
    let wrap = fx.wrap(sam);

    assert_eq!(
        fx.manage().set_wrap(ada, passkey.id, wrap.clone()).await,
        Err(AppError::NotFound),
        "another account's passkey"
    );
    assert_eq!(
        fx.manage()
            .set_wrap(
                sam,
                passkey.id,
                PrfWrap {
                    key_version: wrap.key_version + 1,
                    ..wrap.clone()
                }
            )
            .await,
        Err(AppError::Invalid(
            "the wrapped key is for another key version than the account's"
        ))
    );
    fx.manage()
        .set_wrap(sam, passkey.id, wrap.clone())
        .await
        .expect("set");
    assert_eq!(fx.passkeys.of(sam)[0].prf_wrap, Some(wrap));
}

#[tokio::test]
async fn passkeys_are_renamed_and_deleted_by_their_owner_only() {
    let fx = Fx::new();
    let sam = fx.user(EMAIL).await;
    let ada = fx.user("ada@example.org").await;
    let passkey = fx.register_passkey(sam, "Laptop", b"cred").await;

    assert_eq!(
        fx.manage().rename(sam, passkey.id, "  ").await,
        Err(AppError::Invalid("a passkey needs a name"))
    );
    assert_eq!(
        fx.manage().rename(ada, passkey.id, "Mine now").await,
        Err(AppError::NotFound)
    );
    fx.manage()
        .rename(sam, passkey.id, "Home desktop")
        .await
        .expect("renamed");
    assert_eq!(fx.passkeys.of(sam)[0].name, "Home desktop");

    assert_eq!(
        fx.manage().delete(ada, passkey.id).await,
        Err(AppError::NotFound)
    );
    fx.manage().delete(sam, passkey.id).await.expect("deleted");
    assert!(fx.passkeys.of(sam).is_empty());
    assert_eq!(
        fx.manage().delete(sam, passkey.id).await,
        Err(AppError::NotFound)
    );
    assert!(
        fx.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "passkey.delete")
    );
}

// ---------------------------------------------------------------------------------------------
// Signing in with a passkey.

#[tokio::test]
async fn a_passkey_signs_in_and_the_counter_moves_on() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let passkey = fx.register_passkey(user, "Laptop", b"cred").await;

    let started = fx.sign_in().options(JKT).expect("options");
    assert_eq!(
        started.options["allowCredentials"], 0,
        "a discoverable credential: nothing about an account is listed"
    );
    assert_eq!(started.options["kind"], "Passkey");
    let response = assertion_answer(
        &started.options,
        b"cred",
        Some(&user.as_bytes()[..]),
        1,
        true,
    );
    let signed = fx
        .sign_in()
        .verify(PasskeyVerifyInput {
            challenge: started.challenge,
            response,
            device: device("Pixel"),
            jkt: JKT.to_owned(),
        })
        .await
        .expect("signed in");

    let tokens: TokenPair = signed.tokens;
    assert_eq!(tokens.user, user);
    assert_eq!(signed.passkey, passkey.id);
    assert_eq!(
        signed.prf_wrap, None,
        "a passkey without PRF opens no vault"
    );
    let stored = fx.passkeys.of(user).remove(0);
    assert_eq!(stored.credential, credential_blob(b"cred", 1));
    assert_eq!(
        stored.last_used_at,
        Some(kemlock_app::ports::Clock::now(&fx.world.env))
    );
    let devices = fx.world.store.devices_of(user);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].dpop_jkt.as_deref(), Some(JKT));
    assert_eq!(fx.world.store.refresh_tokens().len(), 1);
    assert!(
        fx.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.passkey_sign_in")
    );
}

#[tokio::test]
async fn a_passkey_with_prf_hands_back_its_copy_while_the_key_version_matches() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let wrap = fx.wrap(user);
    let options = fx.manage().start_registration(user).await.expect("options");
    fx.manage()
        .finish_registration(FinishRegistration {
            user,
            name: "Laptop".to_owned(),
            response: registration_answer(&options, b"cred"),
            prf: Some(wrap.clone()),
        })
        .await
        .expect("registered with PRF");

    let signed = fx
        .passkey_sign_in(user, b"cred", 1)
        .await
        .expect("signed in");
    assert_eq!(signed.prf_wrap, Some(wrap));
    assert_eq!(signed.key_version, fx.key_version(user));

    // A key replacement bumps the version: the copy is for the old one, so it is not handed out.
    let mut account = fx.world.store.user(user).expect("the account");
    account.key_version += 1;
    fx.world.store.put_user(account);
    let later = fx
        .passkey_sign_in(user, b"cred", 2)
        .await
        .expect("signed in");
    assert_eq!(later.prf_wrap, None);
    assert_eq!(later.key_version, fx.key_version(user));
}

#[tokio::test]
async fn a_sign_in_that_is_not_right_is_unauthorized_and_leaves_no_device() {
    let fx = Fx::new();
    let sam = fx.user(EMAIL).await;
    let ada = fx.user("ada@example.org").await;
    fx.register_passkey(sam, "Laptop", b"cred").await;
    // Another device key.
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(&started.options, b"cred", None, 1, true);
    assert_eq!(
        fx.verify(started.challenge, answer, "another-key")
            .await
            .expect_err("refused"),
        unauthorized()
    );

    // A challenge that isn't ours, or is old.
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(&started.options, b"cred", None, 1, true);
    assert_eq!(
        fx.verify(vec![1, 2, 3], answer.clone(), JKT)
            .await
            .expect_err("refused"),
        unauthorized()
    );
    fx.world.env.clock.advance(Duration::minutes(6));
    assert_eq!(
        fx.verify(started.challenge, answer, JKT)
            .await
            .expect_err("refused"),
        unauthorized()
    );

    // A credential the server doesn't know.
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(&started.options, b"nobody", None, 1, true);
    assert_eq!(
        fx.verify(started.challenge, answer, JKT)
            .await
            .expect_err("refused"),
        unauthorized()
    );

    // The right credential with another account's user handle.
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(
        &started.options,
        b"cred",
        Some(&ada.as_bytes()[..]),
        1,
        true,
    );
    assert_eq!(
        fx.verify(started.challenge, answer, JKT)
            .await
            .expect_err("refused"),
        unauthorized()
    );

    // An answer without user verification.
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(&started.options, b"cred", None, 1, false);
    assert_eq!(
        fx.verify(started.challenge, answer, JKT)
            .await
            .expect_err("refused"),
        unauthorized()
    );

    assert!(fx.world.store.devices_of(sam).is_empty());
    assert!(fx.world.store.refresh_tokens().is_empty());
    assert_eq!(fx.passkeys.of(sam)[0].last_used_at, None);
}

#[tokio::test]
async fn a_counter_that_did_not_grow_is_refused() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_passkey(user, "Laptop", b"cred").await;
    fx.passkey_sign_in(user, b"cred", 5)
        .await
        .expect("the first sign-in");
    assert_eq!(
        fx.passkey_sign_in(user, b"cred", 5)
            .await
            .expect_err("refused"),
        unauthorized(),
        "a cloned authenticator repeats a counter"
    );
    fx.passkey_sign_in(user, b"cred", 6)
        .await
        .expect("a counter that grew");
}

#[tokio::test]
async fn require_sso_blocks_a_member_after_the_passkey_checks_out() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_passkey(user, "Laptop", b"cred").await;
    let space = SpaceId::random();
    let membership = |role| {
        vec![SpaceMembership {
            space,
            role,
            require_sso: true,
        }]
    };

    fx.membership.put(user, membership(SpaceRole::Member));
    assert_eq!(
        fx.passkey_sign_in(user, b"cred", 1)
            .await
            .expect_err("refused"),
        SsoError::SsoRequired { space }
    );
    assert!(fx.world.store.devices_of(user).is_empty());
    assert!(fx.world.store.refresh_tokens().is_empty());

    // The owners and admins of the space are exempt, so they can fix the provider.
    for (counter, role) in [(2, SpaceRole::Admin), (3, SpaceRole::Owner)] {
        fx.membership.put(user, membership(role));
        fx.passkey_sign_in(user, b"cred", counter)
            .await
            .expect("exempt");
    }
    // And a space that doesn't require SSO binds nobody.
    fx.membership.put(
        user,
        vec![SpaceMembership {
            space,
            role: SpaceRole::Member,
            require_sso: false,
        }],
    );
    fx.passkey_sign_in(user, b"cred", 4)
        .await
        .expect("not required");
}

#[tokio::test]
async fn require_sso_does_not_tell_a_stranger_who_belongs_to_a_space() {
    // The check comes after the signature: a wrong answer is Unauthorized whatever the spaces say.
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_passkey(user, "Laptop", b"cred").await;
    fx.membership.put(
        user,
        vec![SpaceMembership {
            space: SpaceId::random(),
            role: SpaceRole::Member,
            require_sso: true,
        }],
    );
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(&started.options, b"cred", None, 1, false);
    let refused = fx
        .sign_in()
        .verify(PasskeyVerifyInput {
            challenge: started.challenge,
            response: answer,
            device: device("Pixel"),
            jkt: JKT.to_owned(),
        })
        .await;
    assert_eq!(refused.expect_err("refused"), unauthorized());
}

#[tokio::test]
async fn a_disabled_account_is_refused_after_the_passkey_checks_out() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_passkey(user, "Laptop", b"cred").await;

    fx.world.store.set_account_disabled(user, true);
    assert_eq!(
        fx.passkey_sign_in(user, b"cred", 1)
            .await
            .expect_err("refused"),
        SsoError::App(AppError::AccountDisabled)
    );
    assert!(fx.world.store.devices_of(user).is_empty());
    assert!(fx.world.store.refresh_tokens().is_empty());

    // A wrong answer is still just Unauthorized: nothing is said before the passkey is proved.
    let started = fx.sign_in().options(JKT).expect("options");
    let answer = assertion_answer(&started.options, b"cred", None, 2, false);
    let refused = fx.verify(started.challenge, answer, JKT).await;
    assert_eq!(refused.expect_err("refused"), unauthorized());

    fx.world.store.set_account_disabled(user, false);
    fx.passkey_sign_in(user, b"cred", 3)
        .await
        .expect("an enabled account signs in");
}

// ---------------------------------------------------------------------------------------------
// Security keys.

fn info(id: u8, name: &str) -> SecurityKeyInfo {
    SecurityKeyInfo {
        id,
        name: name.to_owned(),
    }
}

#[tokio::test]
async fn a_security_key_turns_the_method_on_with_a_sealed_list() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    assert_eq!(
        fx.keys().keys(user).await.expect("keys"),
        KeyList {
            enabled: false,
            keys: Vec::new()
        }
    );

    let list = fx.register_key(user, None, "Yubi", b"yubi-1").await;
    assert_eq!(
        list,
        KeyList {
            enabled: true,
            keys: vec![info(1, "Yubi")]
        }
    );
    let rows = fx.world.store.two_factor_of(user);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].method, TwoFactorMethod::WebAuthn);
    assert!(rows[0].enabled);
    assert!(
        fx.world
            .seal
            .open(
                &kemlock_app::sealed::bound_purpose("webauthn", user),
                &rows[0].sealed_secret
            )
            .is_ok()
    );
    assert!(fx.world.seal.open("totp", &rows[0].sealed_secret).is_err());
    assert_eq!(fx.keys().keys(user).await.expect("keys"), list);
}

#[tokio::test]
async fn slots_are_one_to_five_and_a_chosen_slot_replaces_its_key() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "First", b"k1").await;
    let list = fx.register_key(user, None, "Second", b"k2").await;
    assert_eq!(list.keys, vec![info(1, "First"), info(2, "Second")]);

    let list = fx.register_key(user, Some(5), "Fifth", b"k5").await;
    assert_eq!(
        list.keys,
        vec![info(1, "First"), info(2, "Second"), info(5, "Fifth")]
    );
    let list = fx.register_key(user, Some(1), "Replaced", b"k1b").await;
    assert_eq!(
        list.keys,
        vec![info(1, "Replaced"), info(2, "Second"), info(5, "Fifth")]
    );

    let options = fx.keys().start_registration(user).await.expect("options");
    for slot in [0, 6] {
        assert_eq!(
            fx.keys()
                .finish_registration(user, Some(slot), "x", &registration_answer(&options, b"z"))
                .await,
            Err(SecurityKeyError::App(AppError::Invalid(
                "the key slot must be 1 to 5"
            )))
        );
    }
}

#[tokio::test]
async fn an_account_has_at_most_five_security_keys() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    for i in 0..5 {
        fx.register_key(user, None, &format!("key {i}"), format!("k{i}").as_bytes())
            .await;
    }
    assert_eq!(
        fx.keys().start_registration(user).await,
        Err(AppError::Invalid(
            "an account may have at most five security keys"
        ))
    );
    assert_eq!(fx.keys().keys(user).await.expect("keys").keys.len(), 5);
}

#[tokio::test]
async fn the_same_security_key_twice_is_refused() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "Yubi", b"yubi").await;
    let options = fx.keys().start_registration(user).await.expect("options");
    assert_eq!(
        fx.keys()
            .finish_registration(user, None, "Again", &registration_answer(&options, b"yubi"))
            .await,
        Err(SecurityKeyError::Duplicate)
    );
}

#[tokio::test]
async fn a_security_key_registration_answer_that_is_wrong_uses_its_challenge_up() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    let options = fx.keys().start_registration(user).await.expect("options");
    let wrong = registration_answer(&json!({"challenge": "not it"}), b"yubi");
    assert_eq!(
        fx.keys()
            .finish_registration(user, None, "Yubi", &wrong)
            .await,
        Err(SecurityKeyError::Refused)
    );
    assert_eq!(
        fx.keys()
            .finish_registration(user, None, "Yubi", &registration_answer(&options, b"yubi"))
            .await,
        Err(SecurityKeyError::NoChallenge)
    );
    assert!(fx.world.store.two_factor_of(user).is_empty());
}

#[tokio::test]
async fn removing_keys_empties_the_list_and_switches_the_method_off() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "One", b"k1").await;
    fx.register_key(user, None, "Two", b"k2").await;

    assert_eq!(fx.keys().remove(user, 3).await, Err(AppError::NotFound));
    let list = fx.keys().remove(user, 1).await.expect("removed");
    assert_eq!(list.keys, vec![info(2, "Two")]);
    assert!(list.enabled);
    let list = fx.keys().remove(user, 2).await.expect("removed");
    assert_eq!(
        list,
        KeyList {
            enabled: false,
            keys: Vec::new()
        }
    );
    assert!(fx.world.store.two_factor_of(user).is_empty());
}

#[tokio::test]
async fn a_security_key_answer_is_checked_and_its_counter_kept() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "Yubi", b"yubi").await;

    let options = fx.keys().start_login(user).await.expect("options");
    assert_eq!(options["kind"], "SecurityKey");
    assert_eq!(options["allowCredentials"], 1);
    fx.keys()
        .finish_login(user, &assertion_answer(&options, b"yubi", None, 3, false))
        .await
        .expect("a right answer");

    // The counter is now 3: an answer at 3 is refused.
    let options = fx.keys().start_login(user).await.expect("options");
    assert_eq!(
        fx.keys()
            .finish_login(user, &assertion_answer(&options, b"yubi", None, 3, false))
            .await,
        Err(SecurityKeyError::Refused)
    );
    // And the refused answer used the challenge up.
    assert_eq!(
        fx.keys()
            .finish_login(user, &assertion_answer(&options, b"yubi", None, 4, false))
            .await,
        Err(SecurityKeyError::NoChallenge)
    );
}

#[tokio::test]
async fn a_security_key_challenge_is_good_once_and_a_newer_one_replaces_it() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "Yubi", b"yubi").await;

    let options = fx.keys().start_login(user).await.expect("options");
    let answer = assertion_answer(&options, b"yubi", None, 1, false);
    fx.keys()
        .finish_login(user, &answer)
        .await
        .expect("the first use");
    assert_eq!(
        fx.keys().finish_login(user, &answer).await,
        Err(SecurityKeyError::NoChallenge),
        "an accepted answer sent again"
    );

    let older = fx.keys().start_login(user).await.expect("older");
    let newer = fx.keys().start_login(user).await.expect("newer");
    assert_eq!(
        fx.keys()
            .finish_login(user, &assertion_answer(&older, b"yubi", None, 2, false))
            .await,
        Err(SecurityKeyError::Refused),
        "an answer to the older challenge, after a newer one was asked for"
    );
    assert_eq!(
        fx.keys()
            .finish_login(user, &assertion_answer(&newer, b"yubi", None, 2, false))
            .await,
        Err(SecurityKeyError::NoChallenge),
        "and it used the newer one up"
    );
}

#[tokio::test]
async fn a_security_key_challenge_expires_and_an_account_with_no_key_has_none() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    assert_eq!(fx.keys().start_login(user).await, Err(AppError::NotFound));

    fx.register_key(user, None, "Yubi", b"yubi").await;
    let options = fx.keys().start_login(user).await.expect("options");
    fx.world.env.clock.advance(Duration::minutes(6));
    assert_eq!(
        fx.keys()
            .finish_login(user, &assertion_answer(&options, b"yubi", None, 1, false))
            .await,
        Err(SecurityKeyError::NoChallenge)
    );
}

// ---------------------------------------------------------------------------------------------
// The second step of a Kemlock sign-in.

async fn password_step(fx: &Fx, jkt: &str) -> kemlock_app::SecondStep {
    match sign_in_with(&fx.world, EMAIL, &PASSWORD, device("Pixel"), jkt)
        .await
        .expect("the password is right")
    {
        SignedIn::SecondStep(step) => step,
        other => panic!("a second step was expected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_security_key_answers_the_second_step_of_a_password_sign_in() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "Yubi", b"yubi").await;

    let step = password_step(&fx, JKT).await;
    assert_eq!(step.methods, vec![TwoFactorMethod::WebAuthn]);
    assert_eq!(fx.step().challenge_user(&step.challenge), Ok(user));
    assert!(fx.world.store.devices_of(user).is_empty());

    let options = fx
        .step()
        .options(&step.challenge, JKT)
        .await
        .expect("options");
    assert_eq!(options["allowCredentials"], 1);
    let answer = assertion_answer(&options, b"yubi", None, 1, false);
    let tokens = fx
        .step()
        .verify(&step.challenge, &answer, JKT)
        .await
        .expect("signed in");
    assert_eq!(tokens.user, user);
    let devices = fx.world.store.devices_of(user);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].dpop_jkt.as_deref(), Some(JKT));
}

#[tokio::test]
async fn the_second_step_refuses_another_key_a_wrong_answer_and_a_replay() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "Yubi", b"yubi").await;
    let step = password_step(&fx, JKT).await;

    assert_eq!(
        fx.step().options(&step.challenge, "another-key").await,
        Err(AppError::Unauthorized)
    );
    assert_eq!(
        fx.step().options(b"not a challenge", JKT).await,
        Err(AppError::Invalid("the challenge is invalid"))
    );

    let options = fx
        .step()
        .options(&step.challenge, JKT)
        .await
        .expect("options");
    assert_eq!(
        fx.step()
            .verify(
                &step.challenge,
                &assertion_answer(&options, b"stranger", None, 1, false),
                JKT
            )
            .await
            .expect_err("refused"),
        AppError::Unauthorized
    );
    // The wrong answer used the challenge up: a right one now finds none.
    assert_eq!(
        fx.step()
            .verify(
                &step.challenge,
                &assertion_answer(&options, b"yubi", None, 1, false),
                JKT
            )
            .await
            .expect_err("refused"),
        AppError::Unauthorized
    );
    assert!(fx.world.store.devices_of(user).is_empty());

    // A fresh challenge and a right answer sign in; sending it again does not.
    let options = fx
        .step()
        .options(&step.challenge, JKT)
        .await
        .expect("options");
    let answer = assertion_answer(&options, b"yubi", None, 1, false);
    fx.step()
        .verify(&step.challenge, &answer, JKT)
        .await
        .expect("signed in");
    assert_eq!(
        fx.step()
            .verify(&step.challenge, &answer, JKT)
            .await
            .expect_err("refused"),
        AppError::Unauthorized
    );
}

#[tokio::test]
async fn a_disabled_account_gets_no_session_from_a_security_key() {
    let fx = Fx::new();
    let user = fx.user(EMAIL).await;
    fx.register_key(user, None, "Yubi", b"yubi").await;
    let step = password_step(&fx, JKT).await;
    let options = fx
        .step()
        .options(&step.challenge, JKT)
        .await
        .expect("options");
    let answer = assertion_answer(&options, b"yubi", None, 1, false);

    fx.world.store.set_account_disabled(user, true);
    assert_eq!(
        fx.step()
            .verify(&step.challenge, &answer, JKT)
            .await
            .map(|_| ()),
        Err(AppError::AccountDisabled)
    );
    assert!(fx.world.store.devices_of(user).is_empty());
}
