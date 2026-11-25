//! The state every handler shares: the ports, the settings and the in-memory guards (DPoP replay
//! cache, rate limits, setup state).

use crate::dpop::DpopVerifier;
use crate::live::LiveHub;
use crate::ratelimit::Limiter;
use crate::replay::TimedSet;
use kemlock_app::admin::{InviteGate, InviteTicket, Live};
use kemlock_app::api_use::{ApiUseRepo, RecordApiUse, USE_GRANULARITY};
use kemlock_app::dedup::TagStore;
use kemlock_app::ports::{
    DeviceRepo, EventLog, ItemStore, PasswordAuth, SecretSeal, ServerInfo, TokenRepo, TokenSigner,
    Totp, TwoFactorRepo, UserRepo,
};
use kemlock_app::privacy::PrivacyLog;
use kemlock_app::spaces::{PutSpaceBatch, PutSpaceItem};
use kemlock_app::sso::{
    MembershipFacts, RequireSso, SignInMethods, SsoSettingsRepo, VerifiedDomainRepo,
};
use kemlock_app::two_step::{RecoveryCodeRepo, RecoveryCodes, RecoverySignIn};
use kemlock_app::{
    AppError, AuthConfig, Authenticate, ConfirmTotp, EnrolTotp, FinishSetup, FirstAdminRepo,
    FirstRun, Platform, Prelogin, PutBatch, PutItem, Refresh, Register, Sessions, SetupCode,
    SetupState, SignIn, SyncDelta,
};
use kemlock_domain::api_use::ApiKind;
use kemlock_domain::{DeviceId, Email, UserId};
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use uuid::Uuid;

/// Every repository port in one bound. `SqlStore` implements all of them. `PrivacyLog` is the
/// sign-in log: every sign-in attempt on every route writes a row through it.
pub trait Store:
    UserRepo
    + FirstAdminRepo
    + DeviceRepo
    + TokenRepo
    + TwoFactorRepo
    + ItemStore
    + TagStore
    + EventLog
    + PrivacyLog
    + ServerInfo
    + ApiUseRepo
    + MembershipFacts
    + SsoSettingsRepo
    + VerifiedDomainRepo
    + RecoveryCodeRepo
    + Clone
    + 'static
{
}

impl<T> Store for T where
    T: UserRepo
        + FirstAdminRepo
        + DeviceRepo
        + TokenRepo
        + TwoFactorRepo
        + ItemStore
        + TagStore
        + EventLog
        + PrivacyLog
        + ServerInfo
        + ApiUseRepo
        + MembershipFacts
        + SsoSettingsRepo
        + VerifiedDomainRepo
        + RecoveryCodeRepo
        + Clone
        + 'static
{
}

/// Every non-store port in one bound: OPAQUE, sealing, TOTP, time, randomness and hashing.
pub trait Crypto: PasswordAuth + SecretSeal + Totp + Platform + Clone + 'static {}

impl<T> Crypto for T where T: PasswordAuth + SecretSeal + Totp + Platform + Clone + 'static {}

/// The most spent login states remembered at once, like the DPoP proof ids.
const MAX_USED_STATES: usize = 100_000;
/// How long after a resend of an invitation the same member's invitation can't be resent.
pub(crate) const RESEND_WINDOW_SECS: i64 = 600;

/// Settings of the API.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// `DOMAIN`: the address clients use, such as `https://vault.example.org`. DPoP proofs name
    /// it in `htu`. It says nothing about the connection a request came over.
    pub domain: String,
    /// The server's version, for `/config`.
    pub version: String,
    /// The git commit this build was made from, when the build knew it, for `/config`.
    pub commit: Option<String>,
    /// Where the Corresponding Source of this exact build can be had, for `/config`: AGPL-3.0
    /// section 13 offers it to every user of the server over the network.
    pub source_url: String,
    /// Token lifetimes, `SIGNUPS_ALLOWED` and item limits.
    pub auth: AuthConfig,
    /// `KEMLOCK_TRUSTED_PROXIES`: peers whose forwarded header is believed.
    pub trusted_proxies: Vec<IpAddr>,
    /// `IP_HEADER`: the header naming the client behind a trusted proxy.
    pub ip_header: Option<String>,
    /// `KEMLOCK_BROWSER_EXTENSION_IDS`: the ids of the Kemlock browser extensions that may take an
    /// SSO code at their own redirect address. Empty by default: any other extension gets none.
    pub browser_extension_ids: Vec<String>,
}

/// Secrets derived from `server.key` that the API itself needs.
#[derive(Clone)]
pub struct ApiSecrets {
    /// Keys the fake salts of unknown emails in prelogin.
    pub prelogin: [u8; 32],
    /// Keys DPoP server nonces.
    pub dpop_nonce: [u8; 32],
}

impl std::fmt::Debug for ApiSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiSecrets").finish_non_exhaustive()
    }
}

/// The rate limiters (design, "Security"): per IP for sign-in starts, two-step codes, the setup
/// code and registration; per account for failed password finishes.
#[derive(Debug)]
pub struct Limits {
    /// Password sign-in starts and two-step codes: 10 a minute per IP, then doubling delays.
    pub sign_in: Limiter,
    /// Failed password finishes per account: 10 in 15 minutes, then doubling delays. Only
    /// failures count, so asking for a login (which anyone can do for any email) never slows an
    /// account down.
    pub account: Limiter,
    /// Failed second-step codes per account: 5 in 15 minutes, then doubling delays, whichever
    /// address or challenge they come from.
    pub second_step: Limiter,
    /// DPoP proofs checked before anyone is authenticated, per IP: 120 a minute, then doubling
    /// delays. Honest devices make a handful; the limit only stops a flood.
    pub proof: Limiter,
    /// The first-run setup code: 5 a minute.
    pub setup: Limiter,
    /// Registration: 10 an hour.
    pub register: Limiter,
    /// Account lookups by email before an invitation, per caller: 30 in 10 minutes, then
    /// doubling delays. Only a space's admins may look, so this stops one of them harvesting
    /// which emails have accounts.
    pub lookup: Limiter,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            sign_in: Limiter::new(10, 60),
            account: Limiter::new(10, 900),
            second_step: Limiter::new(5, 900),
            proof: Limiter::new(120, 60),
            setup: Limiter::new(5, 60),
            register: Limiter::new(10, 3600),
            lookup: Limiter::new(30, 600),
        }
    }
}

/// An invitation token that was accepted, with the gate that consumes it.
pub(crate) struct Invitation {
    gate: Arc<dyn InviteGate>,
    ticket: InviteTicket,
}

impl Invitation {
    /// Marks the invitation used, once the account exists. A failure is logged, not returned:
    /// the account is made, and the address is taken, so the token can't make another.
    pub(crate) async fn consume(self) {
        if let Err(error) = self.gate.consume(&self.ticket).await {
            tracing::warn!(%error, "couldn't mark an invitation as used");
        }
    }
}

/// Everything behind the router. Reached through [`Api`].
#[derive(Debug)]
pub struct Inner<S, P, K> {
    pub store: S,
    pub crypto: P,
    pub signer: K,
    pub hub: LiveHub,
    pub config: ApiConfig,
    pub secrets: ApiSecrets,
    pub setup: Arc<SetupState>,
    pub dpop: DpopVerifier,
    pub limits: Limits,
    /// The settings the console changes while the server runs: sign-ups, the invitation gate and
    /// the largest file. The server's settings watcher writes to it.
    pub live: Live,
    /// OPAQUE login states that were finished (rightly or wrongly): each is good once.
    pub used_states: TimedSet,
    /// Devices whose use of this API was recorded in the last minute, so an authenticated request
    /// costs the store a write at most once a minute per device.
    pub(crate) recorded_use: TimedSet,
    /// Members whose invitation was mailed again in the last 10 minutes: one resend each.
    pub(crate) resent_invitations: TimedSet,
    /// How the routes that live beside the main router's (the authenticator app's, the recovery
    /// code's) check a mailed proof: set by `two_step_router`, which holds the store of codes.
    /// Unset, only what needs no store proves it.
    pub(crate) proofs: std::sync::OnceLock<Arc<dyn crate::routes::two_step::MailedProof>>,
    /// How a proof by a security key or passkey is checked and its options made: set by
    /// `passkeys_router`, which holds the relying party and the stored keys. Unset, no such proof
    /// is accepted.
    pub(crate) assertions: std::sync::OnceLock<Arc<dyn crate::routes::two_step::AssertionChecker>>,
}

/// The API's shared state: cheap to clone, handed to every handler. `S` is the store, `P` the
/// crypto and platform ports, `K` the access-token signer.
#[derive(Debug)]
pub struct Api<S, P, K>(Arc<Inner<S, P, K>>);

impl<S, P, K> Clone for Api<S, P, K> {
    fn clone(&self) -> Self {
        Api(Arc::clone(&self.0))
    }
}

impl<S, P, K> Api<S, P, K> {
    /// A handle that doesn't keep the state alive, for what the state itself holds.
    pub(crate) fn downgrade(&self) -> std::sync::Weak<Inner<S, P, K>> {
        Arc::downgrade(&self.0)
    }

    pub(crate) fn upgrade(weak: &std::sync::Weak<Inner<S, P, K>>) -> Option<Self> {
        weak.upgrade().map(Api)
    }
}

impl<S, P, K> Deref for Api<S, P, K> {
    type Target = Inner<S, P, K>;
    fn deref(&self) -> &Inner<S, P, K> {
        &self.0
    }
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// Builds the state. Fails when `config.domain` isn't an http(s) URL.
    pub fn new(
        store: S,
        crypto: P,
        signer: K,
        hub: LiveHub,
        config: ApiConfig,
        secrets: ApiSecrets,
    ) -> Result<Self, String> {
        let dpop = DpopVerifier::new(&config.domain, secrets.dpop_nonce)?;
        // A state is remembered for as long as it could still be valid, and a minute more.
        let states_ttl = config.auth.challenge_ttl.whole_seconds() + 60;
        let live = Live::new(config.auth.signups_allowed);
        Ok(Api(Arc::new(Inner {
            store,
            crypto,
            signer,
            hub,
            config,
            secrets,
            setup: SetupState::new(),
            dpop,
            limits: Limits::default(),
            live,
            used_states: TimedSet::new(states_ttl, MAX_USED_STATES),
            recorded_use: TimedSet::new(USE_GRANULARITY.whole_seconds(), MAX_USED_STATES),
            resent_invitations: TimedSet::new(RESEND_WINDOW_SECS, MAX_USED_STATES),
            proofs: std::sync::OnceLock::new(),
            assertions: std::sync::OnceLock::new(),
        })))
    }

    /// Called once at start: with no admin yet, opens setup and returns its code for the log.
    pub async fn start_setup(&self) -> Result<Option<SetupCode>, AppError> {
        self.first_run().start().await
    }

    /// The auth settings, with sign-ups as the console last set them.
    pub(crate) fn auth_config(&self) -> AuthConfig {
        AuthConfig {
            signups_allowed: self.live.signups_allowed(),
            ..self.config.auth
        }
    }

    pub(crate) fn first_run(&self) -> FirstRun<S, P> {
        FirstRun {
            users: self.store.clone(),
            env: self.crypto.clone(),
            setup: self.setup.clone(),
            config: self.auth_config(),
        }
    }

    pub(crate) fn prelogin(&self) -> Prelogin<S, P> {
        Prelogin {
            users: self.store.clone(),
            hasher: self.crypto.clone(),
            secret: self.secrets.prelogin,
        }
    }

    /// Registration for `email`: open when sign-ups are on for its domain, or when `invited` (a
    /// valid invitation token came with it).
    pub(crate) fn register_for(&self, email: &str, invited: bool) -> Register<S, P, P> {
        let open =
            invited || Email::parse(email).is_ok_and(|email| self.live.signups_open_for(&email));
        Register {
            users: self.store.clone(),
            auth: self.crypto.clone(),
            env: self.crypto.clone(),
            setup: self.setup.clone(),
            config: AuthConfig {
                signups_allowed: open,
                ..self.auth_config()
            },
        }
    }

    /// Checks an invitation token for `email`. `Ok(None)` for no token, and for one that isn't
    /// good (unknown, used, expired, another address) or invitations being off: the caller then
    /// registers the address the ordinary way, which refuses it while sign-ups are closed.
    pub(crate) async fn accept_invitation(
        &self,
        email: &str,
        token: Option<&str>,
    ) -> Result<Option<Invitation>, AppError> {
        let (Some(token), Some(gate)) = (token, self.live.invites()) else {
            return Ok(None);
        };
        let Ok(email) = Email::parse(email) else {
            return Ok(None);
        };
        match gate.accept(token, &email).await {
            Ok(ticket) => Ok(Some(Invitation { gate, ticket })),
            Err(AppError::Forbidden) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn enrol_totp(&self) -> EnrolTotp<S, S, P, P> {
        EnrolTotp {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            seal: self.crypto.clone(),
            env: self.crypto.clone(),
        }
    }

    pub(crate) fn confirm_totp(&self) -> ConfirmTotp<S, P, P, P> {
        ConfirmTotp {
            two_factor: self.store.clone(),
            seal: self.crypto.clone(),
            totp: self.crypto.clone(),
            env: self.crypto.clone(),
        }
    }

    pub(crate) fn recovery_codes(&self) -> RecoveryCodes<S, S, P, P> {
        RecoveryCodes {
            recovery: self.store.clone(),
            two_factor: self.store.clone(),
            seal: self.crypto.clone(),
            env: self.crypto.clone(),
        }
    }

    pub(crate) fn recovery_sign_in(&self) -> RecoverySignIn<S, S, S, P, P, S, S, K, S> {
        RecoverySignIn {
            users: self.store.clone(),
            recovery: self.recovery_codes(),
            sessions: self.sessions(),
            notices: self.hub.notices(),
        }
    }

    pub(crate) fn finish_setup(&self) -> FinishSetup<S, S, P> {
        FinishSetup {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            setup: self.setup.clone(),
            clock: self.crypto.clone(),
        }
    }

    pub(crate) fn sessions(&self) -> Sessions<S, S, K, P, S, S> {
        Sessions {
            devices: self.store.clone(),
            tokens: self.store.clone(),
            signer: self.signer.clone(),
            env: self.crypto.clone(),
            events: self.store.clone(),
            two_factor: self.store.clone(),
            config: self.auth_config(),
        }
    }

    pub(crate) fn sign_in(&self) -> SignIn<S, S, S, S, P, P, P, K, P, S, S> {
        SignIn {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            auth: self.crypto.clone(),
            seal: self.crypto.clone(),
            totp: self.crypto.clone(),
            sessions: self.sessions(),
            sso: RequireSso {
                membership: self.store.clone(),
            },
        }
    }

    pub(crate) fn refresh(&self) -> Refresh<S, S, S, K, P, S, S> {
        Refresh {
            users: self.store.clone(),
            sessions: self.sessions(),
        }
    }

    pub(crate) fn authenticate(&self) -> Authenticate<S, S, K, P> {
        Authenticate {
            users: self.store.clone(),
            two_factor: self.store.clone(),
            signer: self.signer.clone(),
            clock: self.crypto.clone(),
        }
    }

    pub(crate) fn put_item(&self) -> PutItem<S, S, LiveHub, P> {
        PutItem {
            items: self.store.clone(),
            events: self.store.clone(),
            push: self.hub.clone(),
            clock: self.crypto.clone(),
            config: self.auth_config(),
        }
    }

    pub(crate) fn put_batch(&self) -> PutBatch<S, S, LiveHub, P> {
        PutBatch {
            items: self.store.clone(),
            events: self.store.clone(),
            push: self.hub.clone(),
            clock: self.crypto.clone(),
            config: self.auth_config(),
        }
    }

    pub(crate) fn put_space_item<R>(&self, spaces: R) -> PutSpaceItem<R, S, S, LiveHub, P> {
        PutSpaceItem {
            spaces,
            items: self.store.clone(),
            events: self.store.clone(),
            push: self.hub.clone(),
            clock: self.crypto.clone(),
            config: self.auth_config(),
        }
    }

    pub(crate) fn put_space_batch<R>(&self, spaces: R) -> PutSpaceBatch<R, S, S, LiveHub, P> {
        PutSpaceBatch {
            spaces,
            items: self.store.clone(),
            events: self.store.clone(),
            push: self.hub.clone(),
            clock: self.crypto.clone(),
            config: self.auth_config(),
        }
    }

    pub(crate) fn sign_in_methods(&self) -> SignInMethods<S> {
        SignInMethods {
            repos: self.store.clone(),
        }
    }

    /// Notes that `device` used the Kemlock API now, for the device list. Once a minute per
    /// device it reaches the store; it never fails, as the request it rides on has succeeded.
    pub(crate) async fn note_use(&self, device: DeviceId) {
        let mut key = device.as_bytes().to_vec();
        key.extend_from_slice(b"kemlock");
        if matches!(self.recorded_use.insert(&key, self.now()), Ok(false)) {
            return;
        }
        RecordApiUse {
            uses: self.store.clone(),
            clock: self.crypto.clone(),
        }
        .execute(device, ApiKind::Kemlock)
        .await;
    }

    pub(crate) fn sync_delta<R>(&self, spaces: R) -> SyncDelta<S, R> {
        SyncDelta {
            items: self.store.clone(),
            spaces,
        }
    }

    /// Whether the session behind an open connection still stands: the account exists with the
    /// security stamp its token carried, and the device is still registered with the token's DPoP
    /// key. Live sockets ask this every minute; a store failure counts as no.
    pub async fn session_is_live(
        &self,
        user: UserId,
        device: DeviceId,
        jkt: &str,
        security_stamp: Uuid,
    ) -> bool {
        let Ok(Some(account)) = UserRepo::by_id(&self.store, user).await else {
            return false;
        };
        if account.security_stamp != security_stamp {
            return false;
        }
        let Ok(Some(registered)) = DeviceRepo::get(&self.store, device).await else {
            return false;
        };
        registered.user == user && registered.dpop_jkt.as_deref() == Some(jkt)
    }

    /// Seconds since the Unix epoch, from the platform clock.
    pub(crate) fn now(&self) -> i64 {
        self.crypto.now().unix_timestamp()
    }
}
