//! The SSO use cases end to end over fakes: start, callback, finish, the account rules, the email
//! rules, the amr rule, group mapping and back-channel logout. The provider is scripted.

mod fakes;
mod sso_fakes;

use fakes::*;
use kemlock_app::ports::{
    Clock, SecretSeal, StoreError, TwoFactor, TwoFactorMethod, TwoFactorRepo, UserRepo,
};
use kemlock_app::sso::{
    CallbackInput, FinishInput, GroupRule, LogoutOutcome, SpaceRole, SsoCallback, SsoConfig,
    SsoError, SsoFinish, SsoLogout, SsoSettings, SsoSignedIn, SsoStart, StartInput,
};
use kemlock_app::{AppError, DeviceInfo, SecondStepInput, SignedIn, b64url};
use kemlock_domain::{DeviceKind, Email, Role, SpaceId, User, UserId};
use sso_fakes::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use time::Duration;
use uuid::Uuid;

const JKT: &str = "jkt-phone";
const APP_STATE: &str = "app-state-0123456789";

type FakeFinish = SsoFinish<
    FakeStore,
    FakeStore,
    FakeSsoRepos,
    ScriptedProvider,
    RecordingGroups,
    FakeSeal,
    FakeStore,
    FakeStore,
    FakeTokenSigner,
    FakeEnv,
    FakeStore,
    FakeStore,
>;
type FakeLogout = SsoLogout<
    FakeStore,
    FakeStore,
    FakeStore,
    FakeSsoRepos,
    ScriptedProvider,
    FakeSeal,
    FakeEnv,
    FakeStore,
>;

struct Sso {
    world: World,
    repos: FakeSsoRepos,
    provider: ScriptedProvider,
    groups: RecordingGroups,
    config: SsoConfig,
    /// The phone's PKCE verifier.
    verifier: String,
}

impl Sso {
    fn new() -> Self {
        Self::with_groups(RecordingGroups::default())
    }

    fn with_groups(groups: RecordingGroups) -> Self {
        let world = World::new().with_signups();
        let repos = FakeSsoRepos::default();
        let mut settings = SsoSettings::new(ISSUER, "kemlock", world.env.now());
        settings.set_client_secret(&world.seal, "s3cret");
        repos.set_settings(settings);
        Sso {
            world,
            repos,
            provider: ScriptedProvider::new(),
            groups,
            config: SsoConfig::new("https://kemlock.test"),
            verifier: b64url::encode(&[7u8; 32]),
        }
    }

    fn configure(&self, change: impl FnOnce(&mut SsoSettings)) {
        let mut settings = self.repos.settings().expect("settings are set");
        change(&mut settings);
        self.repos.set_settings(settings);
    }

    fn start(&self) -> SsoStart<FakeSsoRepos, ScriptedProvider, FakeSeal, FakeEnv> {
        SsoStart {
            repos: self.repos.clone(),
            provider: self.provider.clone(),
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            config: self.config.clone(),
        }
    }

    fn callback(&self) -> SsoCallback<FakeSeal, FakeEnv> {
        SsoCallback {
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            config: self.config.clone(),
        }
    }

    fn finish(&self) -> FakeFinish {
        SsoFinish {
            users: self.world.store.clone(),
            two_factor: self.world.store.clone(),
            repos: self.repos.clone(),
            provider: self.provider.clone(),
            groups: self.groups.clone(),
            seal: self.world.seal.clone(),
            sessions: self.world.sessions(),
            config: self.config.clone(),
        }
    }

    fn logout(&self) -> FakeLogout {
        SsoLogout {
            users: self.world.store.clone(),
            devices: self.world.store.clone(),
            tokens: self.world.store.clone(),
            repos: self.repos.clone(),
            provider: self.provider.clone(),
            seal: self.world.seal.clone(),
            env: self.world.env.clone(),
            events: self.world.store.clone(),
        }
    }

    fn challenge(&self) -> String {
        b64url::encode(&kemlock_crypto::hash::sha256(self.verifier.as_bytes()))
    }

    fn start_input(&self) -> StartInput {
        StartInput {
            challenge: self.challenge(),
            app_state: APP_STATE.to_owned(),
            redirect: "kemlock://sso".to_owned(),
            jkt: JKT.to_owned(),
            device_kind: DeviceKind::Other,
        }
    }

    fn finish_input(&self, code: String) -> FinishInput {
        FinishInput {
            code,
            verifier: self.verifier.clone(),
            device: device("Pixel"),
            jkt: JKT.to_owned(),
        }
    }

    /// `start`, the provider's redirect with `provider_code`, and the server's callback: the
    /// one-time code the app would get.
    async fn one_time_code(&self, provider_code: &str) -> String {
        self.start()
            .execute(self.start_input())
            .await
            .expect("start works");
        let state = self
            .provider
            .last_request()
            .expect("the provider was asked")
            .state;
        let redirect = self
            .callback()
            .execute(CallbackInput {
                state,
                code: Some(provider_code.to_owned()),
                error: None,
            })
            .expect("the callback works");
        code_of(&redirect)
    }

    async fn sign_in(&self, provider_code: &str) -> Result<SsoSignedIn, SsoError> {
        let code = self.one_time_code(provider_code).await;
        self.finish().execute(self.finish_input(code)).await
    }
}

/// The `code` parameter of the app's redirect.
fn code_of(redirect: &str) -> String {
    redirect
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("the redirect carries a code")
        .to_owned()
}

fn tokens_of(signed_in: &SsoSignedIn) -> &kemlock_app::TokenPair {
    match &signed_in.outcome {
        SignedIn::Tokens(tokens) => tokens,
        SignedIn::SecondStep(_) => panic!("tokens expected"),
    }
}

async fn enable_totp(world: &World, user: UserId) {
    TwoFactorRepo::put(
        &world.store,
        &TwoFactor {
            user,
            method: TwoFactorMethod::Totp,
            sealed_secret: world.seal.seal("totp", &[9u8; 20]),
            enabled: true,
            created_at: world.env.now(),
        },
    )
    .await
    .expect("the enrolment is stored");
}

// ---------------------------------------------------------------------------------------------
// start and callback

#[tokio::test]
async fn start_returns_the_providers_url_with_a_sealed_state_and_the_servers_callback() {
    let sso = Sso::new();
    let started = sso
        .start()
        .execute(sso.start_input())
        .await
        .expect("start works");
    assert_eq!(started.provider_name, "Single sign-on");
    assert!(
        started
            .authorization_url
            .starts_with("https://idp.test/authorize?")
    );

    let asked = sso.provider.last_request().expect("the provider was asked");
    assert_eq!(
        asked.redirect_uri,
        "https://kemlock.test/kem/v1/auth/sso/callback"
    );
    assert!(started.authorization_url.contains(&asked.state));
    assert_eq!(asked.code_verifier.len(), 43, "a 32-byte PKCE verifier");
    assert!(!asked.nonce.is_empty());
    // The state is sealed: it shows none of what it binds.
    assert!(!asked.state.contains(JKT));
    // The client secret was opened for the provider.
    let client = sso.provider.last_client().expect("a client config");
    assert_eq!(client.client_secret.as_deref(), Some("s3cret"));
    assert_eq!(client.client_id, "kemlock");
}

#[tokio::test]
async fn each_start_makes_a_fresh_nonce_state_and_verifier() {
    let sso = Sso::new();
    sso.start().execute(sso.start_input()).await.expect("first");
    let first = sso.provider.last_request().expect("asked");
    sso.start()
        .execute(sso.start_input())
        .await
        .expect("second");
    let second = sso.provider.last_request().expect("asked");
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.state, second.state);
    assert_ne!(first.code_verifier, second.code_verifier);
}

#[tokio::test]
async fn start_without_a_provider_or_with_it_off_is_refused() {
    let sso = Sso::new();
    sso.configure(|s| s.enabled = false);
    assert_eq!(
        sso.start().execute(sso.start_input()).await,
        Err(SsoError::NotConfigured)
    );

    let bare = Sso::new();
    let empty = Sso {
        repos: FakeSsoRepos::default(),
        ..bare
    };
    assert_eq!(
        empty.start().execute(empty.start_input()).await,
        Err(SsoError::NotConfigured)
    );
}

#[tokio::test]
async fn start_refuses_a_bad_challenge_state_or_redirect() {
    let sso = Sso::new();
    for bad in [
        StartInput {
            challenge: "short".to_owned(),
            ..sso.start_input()
        },
        StartInput {
            app_state: "tiny".to_owned(),
            ..sso.start_input()
        },
        StartInput {
            app_state: "has spaces and &amp; in it".to_owned(),
            ..sso.start_input()
        },
        StartInput {
            redirect: "https://evil.example/steal".to_owned(),
            ..sso.start_input()
        },
        StartInput {
            redirect: "kemlock://sso#frag".to_owned(),
            ..sso.start_input()
        },
    ] {
        assert!(
            matches!(
                sso.start().execute(bad.clone()).await,
                Err(SsoError::Invalid(_))
            ),
            "{bad:?}"
        );
    }
    assert!(
        sso.provider.last_request().is_none(),
        "the provider wasn't asked"
    );
}

#[tokio::test]
async fn the_callback_redirects_to_the_app_with_a_code_and_the_apps_state() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    assert!(!code.is_empty());
    sso.start().execute(sso.start_input()).await.expect("start");
    let state = sso.provider.last_request().expect("asked").state;
    let redirect = sso
        .callback()
        .execute(CallbackInput {
            state,
            code: Some("provider-code-2".to_owned()),
            error: None,
        })
        .expect("callback");
    assert!(redirect.starts_with("kemlock://sso?code="), "{redirect}");
    assert!(
        redirect.ends_with(&format!("&state={APP_STATE}")),
        "{redirect}"
    );
    assert!(
        !redirect.contains("provider-code-2"),
        "the provider's code stays sealed"
    );
}

#[tokio::test]
async fn the_callback_passes_a_provider_error_on_without_a_code() {
    let sso = Sso::new();
    sso.start().execute(sso.start_input()).await.expect("start");
    let state = sso.provider.last_request().expect("asked").state;
    let denied = sso
        .callback()
        .execute(CallbackInput {
            state: state.clone(),
            code: None,
            error: Some("access_denied".to_owned()),
        })
        .expect("callback");
    assert_eq!(
        denied,
        format!("kemlock://sso?error=access_denied&state={APP_STATE}")
    );

    // An error code the server doesn't know is not echoed.
    let odd = sso
        .callback()
        .execute(CallbackInput {
            state,
            code: None,
            error: Some("<script>".to_owned()),
        })
        .expect("callback");
    assert_eq!(
        odd,
        format!("kemlock://sso?error=server_error&state={APP_STATE}")
    );
}

#[tokio::test]
async fn the_callback_refuses_a_foreign_expired_or_codeless_state() {
    let sso = Sso::new();
    let call = |state: String, code: Option<&str>| {
        sso.callback().execute(CallbackInput {
            state,
            code: code.map(str::to_owned),
            error: None,
        })
    };
    assert_eq!(
        call("garbage".to_owned(), Some("c")),
        Err(SsoError::BadState)
    );
    assert_eq!(call(String::new(), Some("c")), Err(SsoError::BadState));

    sso.start().execute(sso.start_input()).await.expect("start");
    let state = sso.provider.last_request().expect("asked").state;
    assert!(matches!(
        call(state.clone(), None),
        Err(SsoError::Invalid(_))
    ));
    assert!(matches!(
        call(state.clone(), Some("")),
        Err(SsoError::Invalid(_))
    ));

    sso.world.env.clock.advance(Duration::minutes(11));
    assert_eq!(call(state, Some("c")), Err(SsoError::BadState));
}

#[tokio::test]
async fn a_one_time_code_isnt_a_state_and_a_state_isnt_a_code() {
    let sso = Sso::new();
    sso.start().execute(sso.start_input()).await.expect("start");
    let state = sso.provider.last_request().expect("asked").state;
    // The state offered as a finish code.
    assert_eq!(
        sso.finish().execute(sso.finish_input(state)).await,
        Err(SsoError::BadState)
    );
    // A finish code offered as a callback state.
    let code = sso.one_time_code("provider-code-1").await;
    assert_eq!(
        sso.callback().execute(CallbackInput {
            state: code,
            code: Some("x".to_owned()),
            error: None
        }),
        Err(SsoError::BadState)
    );
}

// ---------------------------------------------------------------------------------------------
// finish: binding

#[tokio::test]
async fn finish_needs_the_phones_verifier() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    let mut input = sso.finish_input(code);
    input.verifier = b64url::encode(&[8u8; 32]);
    assert_eq!(
        sso.finish().execute(input).await,
        Err(SsoError::Unauthorized)
    );
    assert_eq!(
        sso.provider.exchanges(),
        0,
        "the provider's code wasn't spent"
    );
    assert!(sso.world.store.user_by_email("ada@example.org").is_none());
}

const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const EXTENSION_REDIRECT: &str = "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/";

impl Sso {
    /// The same server, told which extensions are the admin's.
    fn with_extensions(mut self, ids: &[&str]) -> Self {
        let ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
        self.config = self.config.with_browser_extensions(&ids);
        self
    }

    fn browser_start(&self, kind: DeviceKind) -> StartInput {
        StartInput {
            redirect: EXTENSION_REDIRECT.to_owned(),
            device_kind: kind,
            ..self.start_input()
        }
    }

    /// The server's redirect for a sign-in that began with `start`.
    fn redirect_after(&self, state: String) -> Result<String, SsoError> {
        self.callback().execute(CallbackInput {
            state,
            code: Some("provider-code-1".to_owned()),
            error: None,
        })
    }
}

#[tokio::test]
async fn a_browser_extension_gets_its_code_at_its_own_address() {
    let sso = Sso::new().with_extensions(&[EXTENSION_ID]);
    sso.start()
        .execute(sso.browser_start(DeviceKind::KemlockBrowser))
        .await
        .expect("an extension on the list may start");
    let state = sso.provider.last_request().expect("asked").state;
    let redirect = sso.redirect_after(state).expect("callback");
    assert!(
        redirect.starts_with(&format!("{EXTENSION_REDIRECT}?code=")),
        "{redirect}"
    );
    assert!(
        redirect.ends_with(&format!("&state={APP_STATE}")),
        "{redirect}"
    );

    // And the browser device finishes the sign-in with that code.
    let mut input = sso.finish_input(code_of(&redirect));
    input.device = DeviceInfo {
        kind: DeviceKind::KemlockBrowser,
        ..input.device
    };
    let signed_in = sso.finish().execute(input).await.expect("signed in");
    assert!(matches!(signed_in.outcome, SignedIn::Tokens(_)));
}

#[tokio::test]
async fn an_extension_not_on_the_list_gets_no_code() {
    for sso in [
        Sso::new(),
        Sso::new().with_extensions(&["ponmlkjihgfedcbaponmlkjihgfedcba"]),
    ] {
        assert!(matches!(
            sso.start()
                .execute(sso.browser_start(DeviceKind::KemlockBrowser))
                .await,
            Err(SsoError::Invalid(_))
        ));
        assert!(
            sso.provider.last_request().is_none(),
            "the provider wasn't asked"
        );
    }
}

#[tokio::test]
async fn only_a_browser_device_may_start_at_an_extensions_address() {
    let sso = Sso::new().with_extensions(&[EXTENSION_ID]);
    for kind in [
        DeviceKind::Other,
        DeviceKind::KemlockWeb,
        DeviceKind::KemlockAndroid,
        DeviceKind::Bitwarden,
    ] {
        assert!(
            matches!(
                sso.start().execute(sso.browser_start(kind)).await,
                Err(SsoError::Invalid(_))
            ),
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn a_sign_in_that_began_as_the_extensions_finishes_only_as_its_device() {
    let sso = Sso::new().with_extensions(&[EXTENSION_ID]);
    sso.start()
        .execute(sso.browser_start(DeviceKind::KemlockBrowser))
        .await
        .expect("start");
    let state = sso.provider.last_request().expect("asked").state;
    let redirect = sso.redirect_after(state).expect("callback");
    for kind in [DeviceKind::Other, DeviceKind::KemlockWeb] {
        let mut input = sso.finish_input(code_of(&redirect));
        input.device = DeviceInfo {
            kind,
            ..input.device
        };
        assert_eq!(
            sso.finish().execute(input).await,
            Err(SsoError::Unauthorized),
            "{kind:?}"
        );
    }
    assert_eq!(sso.provider.exchanges(), 0);
}

#[tokio::test]
async fn the_callback_checks_the_extensions_address_again() {
    // The state was sealed while the extension was on the list; the admin took it off since.
    let before = Sso::new().with_extensions(&[EXTENSION_ID]);
    before
        .start()
        .execute(before.browser_start(DeviceKind::KemlockBrowser))
        .await
        .expect("start");
    let state = before.provider.last_request().expect("asked").state;
    let after = Sso {
        config: SsoConfig::new("https://kemlock.test"),
        ..before
    };
    assert_eq!(after.redirect_after(state), Err(SsoError::BadState));
}

#[tokio::test]
async fn finish_needs_the_device_key_that_started() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    let mut input = sso.finish_input(code);
    input.jkt = "another-device-key".to_owned();
    assert_eq!(
        sso.finish().execute(input).await,
        Err(SsoError::Unauthorized)
    );
    assert_eq!(sso.provider.exchanges(), 0);
}

#[tokio::test]
async fn finish_refuses_a_malformed_verifier() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    let mut input = sso.finish_input(code);
    input.verifier = "short".to_owned();
    assert_eq!(
        sso.finish().execute(input).await,
        Err(SsoError::Unauthorized)
    );
}

#[tokio::test]
async fn an_expired_code_is_refused() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    sso.world.env.clock.advance(Duration::minutes(3));
    assert_eq!(
        sso.finish().execute(sso.finish_input(code)).await,
        Err(SsoError::BadState)
    );
}

#[tokio::test]
async fn a_code_cannot_be_used_twice() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    sso.finish()
        .execute(sso.finish_input(code.clone()))
        .await
        .expect("the first finish works");
    // The provider's code is spent, so the second exchange fails there.
    assert!(matches!(
        sso.finish().execute(sso.finish_input(code)).await,
        Err(SsoError::Provider(_))
    ));
}

#[tokio::test]
async fn a_token_with_the_wrong_nonce_is_refused() {
    let sso = Sso::new();
    let code = sso.one_time_code("provider-code-1").await;
    // A second start makes the scripted provider remember a different nonce.
    sso.start().execute(sso.start_input()).await.expect("start");
    assert!(matches!(
        sso.finish().execute(sso.finish_input(code)).await,
        Err(SsoError::Token(_))
    ));
    assert!(sso.world.store.user_by_email("ada@example.org").is_none());
}

#[tokio::test]
async fn an_issuer_other_than_the_configured_one_is_refused() {
    let sso = Sso::new();
    let mut other = claims("sub-1", "ada@example.org");
    other.issuer = "https://evil.example".to_owned();
    sso.provider.say(other);
    assert!(matches!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::Token(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// finish: accounts and sessions

#[tokio::test]
async fn a_first_sign_in_makes_an_account_with_no_keys_and_issues_tokens() {
    let sso = Sso::new();
    let signed_in = sso.sign_in("provider-code-1").await.expect("signs in");
    assert!(signed_in.new_account);
    assert!(!signed_in.mfa_via_sso);
    let tokens = tokens_of(&signed_in);
    assert_eq!(tokens.user, signed_in.user);

    let user = sso
        .world
        .store
        .user_by_email("ada@example.org")
        .expect("the account exists");
    assert_eq!(user.id, signed_in.user);
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.role, kemlock_domain::Role::User);
    // No keys, no password: its devices make their keys, and only SSO signs in.
    assert_eq!(user.key_version, 0);
    assert!(user.opaque_record.is_none());
    assert!(user.wrapped_root_key.is_empty());
    assert!(user.public_bundle.is_empty());
    assert!(user.bundle_signature.is_empty());
    assert!(user.sealed_private_keys.is_empty());

    // Linked by issuer and subject.
    let identities = sso.repos.identities();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].issuer, ISSUER);
    assert_eq!(identities[0].subject, "sub-1");
    assert_eq!(identities[0].user, user.id);

    // A device bound to the key, and tokens the rest of the API accepts.
    let devices = sso.world.store.devices_of(user.id);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].dpop_jkt.as_deref(), Some(JKT));
    assert_eq!(devices[0].id, tokens.device);
    assert_eq!(sso.world.store.refresh_tokens().len(), 1);
    let actor = sso
        .world
        .authenticate()
        .execute(&tokens.access_token, JKT)
        .await
        .expect("the access token authenticates");
    assert_eq!(actor.user, user.id);
    assert!(
        sso.world
            .authenticate()
            .execute(&tokens.access_token, "another-key")
            .await
            .is_err()
    );

    let actions: Vec<&str> = sso.world.store.events().iter().map(|e| e.action).collect();
    assert!(actions.contains(&"account.sso_created"));
    assert!(actions.contains(&"auth.sso_sign_in"));
}

#[tokio::test]
async fn a_second_sign_in_finds_the_account_by_subject_even_when_the_email_changed() {
    let sso = Sso::new();
    let first = sso.sign_in("provider-code-1").await.expect("first");
    sso.provider.say(claims("sub-1", "ada.new@example.org"));
    let second = sso.sign_in("provider-code-2").await.expect("second");
    assert_eq!(second.user, first.user);
    assert!(!second.new_account);
    assert_eq!(sso.repos.identities().len(), 1);
    assert_eq!(
        sso.repos.identities()[0].email,
        "ada.new@example.org",
        "the identity keeps the latest email"
    );
    assert_eq!(
        sso.world.store.devices_of(first.user).len(),
        2,
        "a device per sign-in"
    );
}

#[tokio::test]
async fn an_existing_account_with_the_same_verified_email_is_linked_and_left_alone() {
    let sso = Sso::new();
    let existing = make_user(&sso.world, "ada@example.org").await;
    let before = sso.world.store.user(existing).expect("the account");

    let signed_in = sso.sign_in("provider-code-1").await.expect("signs in");
    assert_eq!(signed_in.user, existing);
    assert!(!signed_in.new_account);
    assert_eq!(sso.repos.identities()[0].user, existing);
    // SSO never touches a key: the account row is exactly as it was.
    assert_eq!(sso.world.store.user(existing), Some(before));
}

#[tokio::test]
async fn the_sign_in_that_links_by_email_never_takes_the_providers_word_for_the_second_step() {
    let sso = Sso::new();
    let existing = make_user(&sso.world, "ada@example.org").await;
    enable_totp(&sso.world, existing).await;
    let mfa = || {
        let mut c = claims("sub-1", "ada@example.org");
        c.amr = vec!["mfa".to_owned()];
        c
    };

    // The provider says its user did multi-factor authentication, which says nothing about who
    // owns this account: the account's own second step is asked all the same.
    sso.provider.say(mfa());
    let first = sso.sign_in("provider-code-1").await.expect("links");
    assert_eq!(first.user, existing);
    assert!(!first.new_account);
    assert!(!first.mfa_via_sso);
    let SignedIn::SecondStep(step) = &first.outcome else {
        panic!("a second step expected");
    };
    assert_eq!(step.methods, vec![TwoFactorMethod::Totp]);
    assert_eq!(sso.repos.identities().len(), 1, "the identity is linked");
    assert!(
        sso.world.store.devices_of(existing).is_empty(),
        "no device before the second step"
    );

    // Once linked, the provider's multi-factor answer is taken as before.
    sso.provider.say(mfa());
    let again = sso.sign_in("provider-code-2").await.expect("signs in");
    assert!(matches!(again.outcome, SignedIn::Tokens(_)));
    assert!(again.mfa_via_sso);
}

#[tokio::test]
async fn linking_to_an_administrators_account_by_email_asks_for_its_second_step_first() {
    let sso = Sso::new();
    let existing = make_user(&sso.world, "ada@example.org").await;
    let mut account = sso.world.store.user(existing).expect("the account");
    account.role = Role::Admin;
    sso.world.store.put_user(account);
    enable_totp(&sso.world, existing).await;
    // The provider says its user did multi-factor authentication: no help for the admin's account.
    sso.provider.say({
        let mut c = claims("sub-1", "ada@example.org");
        c.amr = vec!["mfa".to_owned()];
        c
    });

    let signed_in = sso.sign_in("provider-code-1").await.expect("links");
    assert_eq!(signed_in.user, existing);
    assert!(!signed_in.mfa_via_sso);
    let SignedIn::SecondStep(step) = &signed_in.outcome else {
        panic!("the admin's second step is owed, not tokens");
    };
    assert_eq!(step.methods, vec![TwoFactorMethod::Totp]);
    assert!(sso.world.store.devices_of(existing).is_empty());
    assert!(sso.world.store.refresh_tokens().is_empty());

    // The second step then issues the tokens, with the admin's rights.
    let tokens = sso
        .world
        .sign_in()
        .second_step(SecondStepInput {
            challenge: step.challenge.clone(),
            method: TwoFactorMethod::Totp,
            code: totp_code(&sso.world, existing),
            jkt: JKT.to_owned(),
        })
        .await
        .expect("the second step completes");
    assert_eq!(tokens.user, existing);
    assert!(tokens.admin);
}

#[tokio::test]
async fn an_account_whose_email_isnt_confirmed_is_not_linked_by_email() {
    let sso = Sso::new();
    let existing = make_user(&sso.world, "ada@example.org").await;
    let now = sso.world.env.now();
    UserRepo::hold_unconfirmed(&sso.world.store, existing, [1; 32], now, now + Duration::hours(1))
        .await
        .expect("held");

    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::App(AppError::EmailNotConfirmed))
    );
    assert!(sso.repos.identities().is_empty(), "nothing is linked");
    assert!(sso.world.store.devices_of(existing).is_empty());
}

#[tokio::test]
async fn a_disabled_account_is_refused_once_the_provider_has_said_who_it_is() {
    let sso = Sso::new();
    let existing = make_user(&sso.world, "ada@example.org").await;
    sso.world.store.set_account_disabled(existing, true);

    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::App(AppError::AccountDisabled))
    );
    assert!(sso.world.store.devices_of(existing).is_empty());
    assert!(sso.world.store.refresh_tokens().is_empty());
    assert!(
        sso.repos.identities().is_empty(),
        "a disabled account links nothing"
    );

    // Enabled again, the same person signs in.
    sso.world.store.set_account_disabled(existing, false);
    sso.sign_in("provider-code-2")
        .await
        .expect("an enabled account signs in");
}

#[tokio::test]
async fn linking_by_email_can_be_turned_off() {
    let sso = Sso::new();
    make_user(&sso.world, "ada@example.org").await;
    sso.configure(|s| s.link_by_email = false);
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::LinkingNotAllowed)
    );
    assert!(sso.repos.identities().is_empty());
}

#[tokio::test]
async fn automatic_account_creation_can_be_turned_off() {
    let sso = Sso::new();
    sso.configure(|s| s.create_accounts = false);
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::NoAccount)
    );
    assert!(sso.world.store.user_by_email("ada@example.org").is_none());

    // An account that already exists still links.
    make_user(&sso.world, "ada@example.org").await;
    sso.sign_in("provider-code-2")
        .await
        .expect("links the existing one");
}

/// Users as seen by the loser of a race: the first lookup by email finds nothing, because the
/// other device's sign-in hasn't made the account yet; by the time this one inserts, it has.
#[derive(Clone)]
struct RacyUsers {
    inner: FakeStore,
    first_lookup_done: Arc<AtomicBool>,
}

impl UserRepo for RacyUsers {
    async fn by_id(&self, id: UserId) -> Result<Option<User>, StoreError> {
        self.inner.by_id(id).await
    }

    async fn by_email(&self, email: &Email) -> Result<Option<User>, StoreError> {
        if !self.first_lookup_done.swap(true, Ordering::SeqCst) {
            return Ok(None);
        }
        self.inner.by_email(email).await
    }

    async fn insert(&self, user: &User) -> Result<(), StoreError> {
        self.inner.insert(user).await
    }

    async fn update(&self, user: &User) -> Result<(), StoreError> {
        self.inner.update(user).await
    }

    async fn count_admins(&self) -> Result<u64, StoreError> {
        self.inner.count_admins().await
    }

    async fn account_disabled(&self, id: UserId) -> Result<bool, StoreError> {
        self.inner.account_disabled(id).await
    }
}

#[tokio::test]
async fn the_loser_of_a_first_sign_in_race_finds_the_winners_account() {
    let sso = Sso::new();
    let winner = make_user(&sso.world, "ada@example.org").await;
    let code = sso.one_time_code("provider-code-1").await;

    let racy: SsoFinish<
        RacyUsers,
        FakeStore,
        FakeSsoRepos,
        ScriptedProvider,
        RecordingGroups,
        FakeSeal,
        FakeStore,
        FakeStore,
        FakeTokenSigner,
        FakeEnv,
        FakeStore,
        FakeStore,
    > = SsoFinish {
        users: RacyUsers {
            inner: sso.world.store.clone(),
            first_lookup_done: Arc::new(AtomicBool::new(false)),
        },
        two_factor: sso.world.store.clone(),
        repos: sso.repos.clone(),
        provider: sso.provider.clone(),
        groups: sso.groups.clone(),
        seal: sso.world.seal.clone(),
        sessions: sso.world.sessions(),
        config: sso.config.clone(),
    };
    let signed_in = racy
        .execute(sso.finish_input(code))
        .await
        .expect("the duplicate is retried, not surfaced");
    assert_eq!(signed_in.user, winner);
    assert!(!signed_in.new_account, "the account was the winner's");
    assert_eq!(sso.repos.identities().len(), 1);
    assert_eq!(sso.repos.identities()[0].user, winner);
}

#[tokio::test]
async fn the_name_is_trimmed_and_an_empty_one_dropped() {
    let sso = Sso::new();
    let mut c = claims("sub-9", "nameless@example.org");
    c.name = Some("   ".to_owned());
    sso.provider.say(c);
    sso.sign_in("provider-code-1").await.expect("signs in");
    assert_eq!(
        sso.world
            .store
            .user_by_email("nameless@example.org")
            .expect("exists")
            .name,
        None
    );
}

// ---------------------------------------------------------------------------------------------
// finish: the email rules

#[tokio::test]
async fn an_unverified_email_is_refused() {
    let sso = Sso::new();
    let mut c = claims("sub-1", "ada@example.org");
    c.email_verified = Some(false);
    sso.provider.say(c);
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::EmailNotVerified)
    );
    assert!(sso.world.store.user_by_email("ada@example.org").is_none());
    assert!(sso.repos.identities().is_empty());
}

#[tokio::test]
async fn an_unverified_email_is_refused_even_with_the_exception_on() {
    let sso = Sso::new();
    sso.configure(|s| s.allow_unknown_email_verification = true);
    sso.repos
        .add_verified_domain("example.org", sso.world.env.now());
    let mut c = claims("sub-1", "ada@example.org");
    c.email_verified = Some(false);
    sso.provider.say(c);
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::EmailNotVerified)
    );
}

#[tokio::test]
async fn a_missing_claim_is_refused_unless_the_exception_is_on_and_the_domain_is_proven() {
    let sso = Sso::new();
    let mut c = claims("sub-1", "ada@example.org");
    c.email_verified = None;
    sso.provider.say(c);

    // Off: refused.
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::EmailNotVerified)
    );

    // On, but the domain isn't proven.
    sso.configure(|s| s.allow_unknown_email_verification = true);
    assert_eq!(
        sso.sign_in("provider-code-2").await,
        Err(SsoError::DomainNotVerified)
    );
    assert!(sso.world.store.user_by_email("ada@example.org").is_none());

    // On, and the domain is proven by DNS.
    sso.repos
        .add_verified_domain("example.org", sso.world.env.now());
    let signed_in = sso.sign_in("provider-code-3").await.expect("signs in");
    assert!(signed_in.new_account);
}

#[tokio::test]
async fn a_token_without_an_email_is_refused() {
    let sso = Sso::new();
    let mut c = claims("sub-1", "ada@example.org");
    c.email = None;
    sso.provider.say(c);
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::EmailNotVerified)
    );
}

#[tokio::test]
async fn sign_up_rules_can_wait_for_a_proven_domain() {
    let sso = Sso::new();
    sso.configure(|s| s.require_verified_domain = true);
    assert_eq!(
        sso.sign_in("provider-code-1").await,
        Err(SsoError::DomainNotVerified)
    );
    sso.repos
        .add_verified_domain("example.org", sso.world.env.now());
    sso.sign_in("provider-code-2").await.expect("signs in");
    // Once linked, a later sign-in doesn't need the proof again.
    sso.configure(|s| s.require_verified_domain = true);
    sso.sign_in("provider-code-3")
        .await
        .expect("still signs in");
}

// ---------------------------------------------------------------------------------------------
// finish: the second step and amr

#[tokio::test]
async fn an_account_with_two_step_still_owes_it_when_amr_shows_no_mfa() {
    let sso = Sso::new();
    let first = sso.sign_in("provider-code-1").await.expect("first sign-in");
    enable_totp(&sso.world, first.user).await;
    let devices_before = sso.world.store.devices_of(first.user).len();
    sso.provider.say({
        let mut c = claims("sub-1", "ada@example.org");
        c.amr = vec!["pwd".to_owned()];
        c
    });

    let second = sso
        .sign_in("provider-code-2")
        .await
        .expect("second sign-in");
    assert!(!second.mfa_via_sso);
    let SignedIn::SecondStep(step) = &second.outcome else {
        panic!("a second step expected");
    };
    assert_eq!(step.methods, vec![TwoFactorMethod::Totp]);
    assert_eq!(
        sso.world.store.devices_of(first.user).len(),
        devices_before,
        "no device is registered before the second step"
    );

    // The existing second-step route finishes it, with the same device key.
    let tokens = sso
        .world
        .sign_in()
        .second_step(SecondStepInput {
            challenge: step.challenge.clone(),
            method: TwoFactorMethod::Totp,
            code: totp_code(&sso.world, first.user),
            jkt: JKT.to_owned(),
        })
        .await
        .expect("the second step completes");
    assert_eq!(tokens.user, first.user);
}

#[tokio::test]
async fn the_second_step_is_bound_to_the_device_key() {
    let sso = Sso::new();
    let first = sso.sign_in("provider-code-1").await.expect("first sign-in");
    enable_totp(&sso.world, first.user).await;
    let second = sso
        .sign_in("provider-code-2")
        .await
        .expect("second sign-in");
    let SignedIn::SecondStep(step) = &second.outcome else {
        panic!("a second step expected");
    };
    let stolen = sso
        .world
        .sign_in()
        .second_step(SecondStepInput {
            challenge: step.challenge.clone(),
            method: TwoFactorMethod::Totp,
            code: totp_code(&sso.world, first.user),
            jkt: "another-key".to_owned(),
        })
        .await;
    assert_eq!(stolen, Err(AppError::Unauthorized));
}

#[tokio::test]
async fn the_second_step_is_skipped_only_when_amr_shows_mfa() {
    let sso = Sso::new();
    let first = sso.sign_in("provider-code-1").await.expect("first sign-in");
    enable_totp(&sso.world, first.user).await;

    for (n, (amr, skipped)) in [
        (vec!["mfa"], true),
        (vec!["pwd", "otp"], true),
        (vec!["pwd"], false),
        (vec![], false),
        (vec!["otp", "hwk"], false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut c = claims("sub-1", "ada@example.org");
        c.amr = amr.iter().map(|a| (*a).to_owned()).collect();
        sso.provider.say(c);
        let signed_in = sso
            .sign_in(&format!("provider-code-{}", n + 2))
            .await
            .expect("signs in");
        assert_eq!(
            matches!(signed_in.outcome, SignedIn::Tokens(_)),
            skipped,
            "{amr:?}"
        );
        assert_eq!(signed_in.mfa_via_sso, skipped, "{amr:?}");
    }
}

#[tokio::test]
async fn an_account_without_two_step_gets_tokens_whatever_amr_says() {
    let sso = Sso::new();
    let signed_in = sso.sign_in("provider-code-1").await.expect("signs in");
    assert!(matches!(signed_in.outcome, SignedIn::Tokens(_)));
    assert!(
        !signed_in.mfa_via_sso,
        "nothing was skipped, so nothing says Via SSO"
    );
}

// ---------------------------------------------------------------------------------------------
// finish: groups

fn rule(group: &str, space: SpaceId, role: SpaceRole) -> GroupRule {
    GroupRule {
        group: group.to_owned(),
        space,
        role,
        collections: vec![Uuid::from_u128(5)],
    }
}

#[tokio::test]
async fn the_groups_claim_is_mapped_at_each_sign_in() {
    let sso = Sso::new();
    let space = SpaceId::random();
    sso.configure(|s| {
        s.group_rules = vec![
            rule("eng", space, SpaceRole::Member),
            rule("eng-leads", space, SpaceRole::Admin),
            rule("finance", SpaceId::random(), SpaceRole::Member),
        ];
    });
    let mut c = claims("sub-1", "ada@example.org");
    c.groups = vec![
        "eng".to_owned(),
        "eng-leads".to_owned(),
        "unrelated".to_owned(),
    ];
    sso.provider.say(c);

    let signed_in = sso.sign_in("provider-code-1").await.expect("signs in");
    let calls = sso.groups.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, signed_in.user);
    assert_eq!(calls[0].1.len(), 1);
    assert_eq!(calls[0].1[0].space, space);
    assert_eq!(calls[0].1[0].role, SpaceRole::Admin);
    assert_eq!(calls[0].1[0].collections, vec![Uuid::from_u128(5)]);

    // Next sign-in the person has left every group: the rules' result is empty, and still applied.
    sso.provider.say(claims("sub-1", "ada@example.org"));
    sso.sign_in("provider-code-2")
        .await
        .expect("signs in again");
    let calls = sso.groups.calls();
    assert_eq!(calls.len(), 2);
    assert!(calls[1].1.is_empty());
}

#[tokio::test]
async fn no_rules_means_no_call_to_the_spaces_port() {
    let sso = Sso::new();
    sso.sign_in("provider-code-1").await.expect("signs in");
    assert!(sso.groups.calls().is_empty());
}

#[tokio::test]
async fn a_failing_group_sync_does_not_stop_the_sign_in() {
    let sso = Sso::with_groups(RecordingGroups::failing());
    sso.configure(|s| s.group_rules = vec![rule("eng", SpaceId::random(), SpaceRole::Member)]);
    let mut c = claims("sub-1", "ada@example.org");
    c.groups = vec!["eng".to_owned()];
    sso.provider.say(c);
    let signed_in = sso
        .sign_in("provider-code-1")
        .await
        .expect("still signs in");
    assert!(matches!(signed_in.outcome, SignedIn::Tokens(_)));
    assert_eq!(sso.groups.calls().len(), 1);
}

// ---------------------------------------------------------------------------------------------
// back-channel logout

#[tokio::test]
async fn a_logout_token_ends_the_subjects_sessions_on_every_device() {
    let sso = Sso::new();
    let first = sso.sign_in("provider-code-1").await.expect("phone");
    let second = sso.sign_in("provider-code-2").await.expect("laptop");
    assert_eq!(first.user, second.user);
    assert_eq!(sso.world.store.refresh_tokens().len(), 2);
    let phone_token = tokens_of(&first).clone();
    sso.world
        .authenticate()
        .execute(&phone_token.access_token, JKT)
        .await
        .expect("the access token works before");

    let outcome = sso
        .logout()
        .execute("a.logout.token")
        .await
        .expect("logs out");
    assert_eq!(
        outcome,
        LogoutOutcome::Revoked {
            user: first.user,
            devices: 2
        }
    );
    assert!(
        sso.world.store.refresh_tokens().is_empty(),
        "no refresh token survives"
    );
    assert_eq!(
        sso.world
            .authenticate()
            .execute(&phone_token.access_token, JKT)
            .await,
        Err(AppError::SessionEnded("security-stamp-changed")),
        "an access token already issued stops at once"
    );
    assert_eq!(
        sso.world
            .refresh()
            .execute(&phone_token.refresh_token, JKT)
            .await,
        Err(AppError::Unauthorized)
    );
    // The account and its devices remain; only the sessions ended.
    assert!(sso.world.store.user(first.user).is_some());
    assert_eq!(sso.world.store.devices_of(first.user).len(), 2);
    // No device keeps the key it could sign back in with (a replica's device-key sign-in).
    assert!(
        sso.world
            .store
            .devices_of(first.user)
            .iter()
            .all(|d| d.dpop_jkt.is_none())
    );
    assert!(
        sso.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.sso_logout")
    );
}

#[tokio::test]
async fn a_logout_for_another_account_leaves_this_one_signed_in() {
    let sso = Sso::new();
    let ada = sso.sign_in("provider-code-1").await.expect("ada");
    sso.provider.say(claims("sub-2", "bob@example.org"));
    let bob = sso.sign_in("provider-code-2").await.expect("bob");
    assert_ne!(ada.user, bob.user);

    sso.provider.say_logout(Ok(kemlock_app::sso::LogoutClaims {
        issuer: ISSUER.to_owned(),
        subject: Some("sub-2".to_owned()),
        session_id: None,
    }));
    sso.logout().execute("t").await.expect("logs bob out");
    let ada_token = tokens_of(&ada);
    sso.world
        .authenticate()
        .execute(&ada_token.access_token, JKT)
        .await
        .expect("ada is still signed in");
    assert_eq!(sso.world.store.refresh_tokens().len(), 1);
}

#[tokio::test]
async fn a_logout_for_an_unlinked_subject_or_a_session_id_alone_changes_nothing() {
    let sso = Sso::new();
    sso.sign_in("provider-code-1").await.expect("signs in");

    sso.provider.say_logout(Ok(kemlock_app::sso::LogoutClaims {
        issuer: ISSUER.to_owned(),
        subject: Some("nobody".to_owned()),
        session_id: None,
    }));
    assert_eq!(
        sso.logout().execute("t").await,
        Ok(LogoutOutcome::UnknownSubject)
    );

    sso.provider.say_logout(Ok(kemlock_app::sso::LogoutClaims {
        issuer: ISSUER.to_owned(),
        subject: None,
        session_id: Some("sid-1".to_owned()),
    }));
    assert_eq!(
        sso.logout().execute("t").await,
        Ok(LogoutOutcome::SessionOnly)
    );
    assert_eq!(sso.world.store.refresh_tokens().len(), 1);
}

#[tokio::test]
async fn an_invalid_logout_token_is_an_error_and_ends_nothing() {
    let sso = Sso::new();
    sso.sign_in("provider-code-1").await.expect("signs in");
    sso.provider
        .say_logout(Err(SsoError::Token("bad signature".to_owned())));
    assert!(matches!(
        sso.logout().execute("forged").await,
        Err(SsoError::Token(_))
    ));
    assert_eq!(sso.world.store.refresh_tokens().len(), 1);
}

#[tokio::test]
async fn logout_without_a_provider_is_refused() {
    let sso = Sso::new();
    sso.configure(|s| s.enabled = false);
    assert_eq!(
        sso.logout().execute("t").await,
        Err(SsoError::NotConfigured)
    );
}
