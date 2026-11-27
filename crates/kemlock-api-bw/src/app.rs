//! The state every handler shares, and the extractor that turns a bearer token into a user.

use crate::blob::BlobStore;
use crate::dates::epoch_millis;
use crate::env::Env;
use crate::error::{BwError, BwResult};
use crate::live::BwLive;
use crate::sends::{MemorySends, SendStore};
use crate::settings::BwSettings;
use crate::tokens::{LoginClaims, TokenKeys};
use crate::two_step::TwoStepParts;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use kemlock_app::api_use::ApiUseRepo;
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo, BwOrgStore, BwTryRepo, BwUserKeyIdRepo};
use kemlock_app::bw_events::{BwDeviceRepo, BwEvents, BwRelay};
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::event_reader::EventReader;
use kemlock_app::notices::Notices;
use kemlock_app::passkeys::{ChallengeRepo, WebAuthn};
use kemlock_app::ports::{
    DeviceRepo, EventLog, ItemStore, StoreError, TokenRepo, TwoFactorRepo, UserRepo,
};
use kemlock_app::privacy::{OwnErasure, PrivacyLog};
use kemlock_app::second_step_guard::SecondStepGuard;
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::sso::SsoSettingsRepo;
use kemlock_app::two_step::RecoveryCodeRepo;
use kemlock_crypto::hash;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::api_use::ApiKind;
use kemlock_domain::{Device, DeviceId, User, UserId};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// Every repository port the Bitwarden API needs, in one bound. `SqlStore` implements them all.
/// `PrivacyLog` is the sign-in log: every token request that checks credentials writes a row.
pub trait BwStore:
    UserRepo
    + DeviceRepo
    + TokenRepo
    + TwoFactorRepo
    + ItemStore
    + BwAccountRepo
    + BwUserKeyIdRepo
    + BwTryRepo
    + SecondStepGuard
    + BwDeviceRepo
    + ApiUseRepo
    + ChallengeRepo
    + BwOrgStore
    + SpaceRepo
    + SsoSettingsRepo
    + EmergencyRepo
    + RecoveryCodeRepo
    + EventLog
    + EventReader
    + PrivacyLog
    + Clone
    + 'static
{
}

impl<T> BwStore for T where
    T: UserRepo
        + DeviceRepo
        + TokenRepo
        + TwoFactorRepo
        + ItemStore
        + BwAccountRepo
        + BwUserKeyIdRepo
        + BwTryRepo
        + SecondStepGuard
        + BwDeviceRepo
        + ApiUseRepo
        + ChallengeRepo
        + BwOrgStore
        + SpaceRepo
        + SsoSettingsRepo
        + EmergencyRepo
        + RecoveryCodeRepo
        + EventLog
        + EventReader
        + PrivacyLog
        + Clone
        + 'static
{
}

/// What the API is built from.
pub struct AppParts<S> {
    pub store: S,
    pub env: Arc<dyn Env>,
    pub keys: TokenKeys,
    /// Seals and opens the two-step secrets (`server.key`, purpose `totp`).
    pub seal: ServerSeal,
    pub blobs: Arc<dyn BlobStore>,
    /// The emailed code, YubiKey and Duo second steps (providers 1, 3 and 2): their settings and
    /// the services they call. The default offers none of them.
    pub two_step: TwoStepParts,
    pub settings: BwSettings,
    /// The WebAuthn relying party for security keys (provider 7). `None` leaves them off: the
    /// account routes refuse and the token endpoint offers no provider 7.
    pub webauthn: Option<Arc<dyn WebAuthn>>,
    /// Where Sends live; `None` keeps them in memory (see [`crate::sends`]).
    pub sends: Option<Arc<dyn SendStore>>,
    /// Where the API tells live clients of a change, and Bitwarden's push relay (see [`BwLive`]).
    pub live: BwLive,
}

impl<S> std::fmt::Debug for AppParts<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppParts").finish_non_exhaustive()
    }
}

/// What the state holds; reached through [`App`].
pub struct Inner<S> {
    pub(crate) store: S,
    pub(crate) env: Arc<dyn Env>,
    pub(crate) keys: TokenKeys,
    pub(crate) seal: ServerSeal,
    pub(crate) blobs: Arc<dyn BlobStore>,
    pub(crate) two_step: TwoStepParts,
    pub(crate) settings: BwSettings,
    pub(crate) webauthn: Option<Arc<dyn WebAuthn>>,
    pub(crate) sends: Arc<dyn SendStore>,
    /// Counts password attempts at each Send (see [`crate::send_limit`]).
    pub(crate) send_limit: crate::send_limit::SendAccessLimit,
    /// Vaultwarden's login rate limiter, per client address, for the unauthenticated routes it
    /// guards (see [`crate::ip_limit`]).
    pub(crate) login_limit: crate::ip_limit::IpLimit,
    /// Vaultwarden's limiter for the other routes with no sign-in (`check_limit_unauthenticated`).
    pub(crate) unauthenticated_limit: crate::ip_limit::IpLimit,
    /// How often one address may ask for an account's KDF settings (`prelogin`): the burst of the
    /// unauthenticated limit, then one every 10 seconds. A person asks once per sign-in.
    pub(crate) prelogin_limit: crate::ip_limit::IpLimit,
    /// How many verification mails (`send-verification-email`) an address may ask for: a burst of 5,
    /// then one every 5 minutes.
    pub(crate) verification_mail_limit: crate::ip_limit::IpLimit,
    /// When each address was last mailed a verification link.
    pub(crate) verification_mailed: crate::signup_hold::RecipientLimit,
    pub(crate) events: Arc<dyn BwEvents>,
    pub(crate) relay: Option<Arc<dyn BwRelay>>,
    pub(crate) notices: Notices,
    pub(crate) require_device_email: bool,
    pub(crate) erasure: Option<Arc<dyn OwnErasure>>,
    /// Keys the KDF settings of unknown emails, derived from the token key like Vaultwarden's.
    pub(crate) prelogin_key: [u8; 32],
    /// Held from the check of a storage quota to the save of what it covers, so announces that
    /// arrive together can't each read the same sum and all pass. One server owns the data, so one
    /// lock is enough.
    pub(crate) quota_gate: tokio::sync::Mutex<()>,
    /// Lets [`crate::account::HASH_PERMITS`] password hash checks run at once (see
    /// [`App::hashing`]).
    pub(crate) hash_gate: tokio::sync::Semaphore,
}

impl<S> std::fmt::Debug for Inner<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").finish_non_exhaustive()
    }
}

/// The API's shared state: cheap to clone, handed to every handler.
pub struct App<S>(Arc<Inner<S>>);

impl<S> Clone for App<S> {
    fn clone(&self) -> Self {
        App(Arc::clone(&self.0))
    }
}

impl<S> Deref for App<S> {
    type Target = Inner<S>;
    fn deref(&self) -> &Inner<S> {
        &self.0
    }
}

impl<S> std::fmt::Debug for App<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App").finish_non_exhaustive()
    }
}

impl<S: BwStore> App<S> {
    pub fn new(parts: AppParts<S>) -> Self {
        let prelogin_key = hash::hmac_sha256(parts.keys.pem().as_bytes(), b"prelogin-kdf");
        let login_limit = crate::ip_limit::IpLimit::new(
            parts.settings.login_ratelimit_max_burst,
            parts.settings.login_ratelimit_seconds,
        );
        let unauthenticated_limit = crate::ip_limit::IpLimit::new(
            parts.settings.unauthenticated_ratelimit_max_burst,
            parts.settings.unauthenticated_ratelimit_seconds,
        );
        let prelogin_limit =
            crate::ip_limit::IpLimit::new(parts.settings.unauthenticated_ratelimit_max_burst, 10);
        App(Arc::new(Inner {
            store: parts.store,
            env: parts.env,
            keys: parts.keys,
            seal: parts.seal,
            blobs: parts.blobs,
            two_step: parts.two_step,
            settings: parts.settings,
            webauthn: parts.webauthn,
            sends: parts
                .sends
                .unwrap_or_else(|| Arc::new(MemorySends::default())),
            send_limit: crate::send_limit::SendAccessLimit::default(),
            login_limit,
            unauthenticated_limit,
            prelogin_limit,
            verification_mail_limit: crate::ip_limit::IpLimit::new(5, 300),
            verification_mailed: crate::signup_hold::RecipientLimit::default(),
            events: parts.live.events,
            relay: parts.live.relay,
            notices: parts.live.notices,
            require_device_email: parts.live.require_device_email,
            erasure: parts.live.erasure,
            prelogin_key,
            quota_gate: tokio::sync::Mutex::new(()),
            hash_gate: tokio::sync::Semaphore::new(crate::account::HASH_PERMITS),
        }))
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.env.now()
    }

    pub(crate) fn now_secs(&self) -> i64 {
        self.env.now().unix_timestamp()
    }

    /// Moves the user's revision date: every change a client should sync calls this once.
    pub(crate) async fn touch(&self, user: UserId) -> BwResult<()> {
        BwAccountRepo::touch(&self.store, user, epoch_millis(self.now())).await?;
        Ok(())
    }

    /// Records that the device used the Bitwarden API, for the device list. It never fails: the
    /// request it rides on has succeeded already.
    pub(crate) async fn record_use(&self, device: DeviceId) {
        match ApiUseRepo::record_use(&self.store, device, ApiKind::Bitwarden, self.now()).await {
            Ok(()) | Err(StoreError::NotFound) => {}
            Err(e) => tracing::warn!(error = %e, "could not record a device's Bitwarden API use"),
        }
    }

    /// The address links point at.
    pub(crate) fn host(&self) -> &str {
        &self.settings.domain
    }

    /// Reads the user, the Bitwarden account and the device a token names. Anything missing or a
    /// changed security stamp is `Unauthorized`.
    pub(crate) async fn session(&self, claims: &LoginClaims, ip: IpAddr) -> BwResult<Authed> {
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| BwError::Unauthorized)?;
        let device_id = Uuid::parse_str(&claims.device).map_err(|_| BwError::Unauthorized)?;
        let user_id = UserId(user_id);
        let device = DeviceRepo::get(&self.store, DeviceId(device_id))
            .await?
            .filter(|d| d.user == user_id)
            .ok_or(BwError::Unauthorized)?;
        let user = UserRepo::by_id(&self.store, user_id)
            .await?
            .ok_or(BwError::Unauthorized)?;
        let account = BwAccountRepo::get(&self.store, user_id)
            .await?
            .ok_or(BwError::Unauthorized)?;
        if user.security_stamp.to_string() != claims.sstamp {
            return Err(BwError::Unauthorized);
        }
        // The device used the Bitwarden API: the device list shows it beside the Kemlock API's use.
        self.record_use(device.id).await;
        Ok(Authed {
            ip,
            user,
            device,
            account,
            // The app's identifier, which a session that began before the server kept it lacks.
            identifier: claims
                .appid
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok()),
        })
    }
}

/// A request that carries a valid access token: the account it is for.
#[derive(Debug)]
pub struct Authed {
    pub user: User,
    pub device: Device,
    pub account: BwAccount,
    /// The address the request came from, which organization events record cut short.
    pub ip: IpAddr,
    /// The identifier the app signs in with (what its `ContextId` is), when the token has it.
    pub identifier: Option<Uuid>,
}

impl<S: BwStore> FromRequestParts<App<S>> for Authed {
    type Rejection = BwError;

    async fn from_request_parts(parts: &mut Parts, app: &App<S>) -> Result<Self, BwError> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(BwError::Unauthorized)?;
        // Vaultwarden takes what follows the last `Bearer `, or the whole value without one.
        let token = header.rsplit("Bearer ").next().unwrap_or(header);
        let claims: LoginClaims = app
            .keys
            .decode(token, &app.settings.issuer("login"), app.now_secs())
            .map_err(|_| BwError::Unauthorized)?;
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
        app.session(&claims, ip).await
    }
}

/// A request that may carry an access token: the accept routes of an invitation take the signed
/// token of the link as proof, and an account made through the Bitwarden API may have no way to
/// sign in that the web vault offers. With an `Authorization` header it must be a good one, as for
/// [`Authed`]; with none, there is no caller.
#[derive(Debug)]
pub(crate) struct MaybeAuthed(pub(crate) Option<Authed>);

impl<S: BwStore> FromRequestParts<App<S>> for MaybeAuthed {
    type Rejection = BwError;

    async fn from_request_parts(parts: &mut Parts, app: &App<S>) -> Result<Self, BwError> {
        if !parts.headers.contains_key(AUTHORIZATION) {
            return Ok(MaybeAuthed(None));
        }
        Authed::from_request_parts(parts, app)
            .await
            .map(|authed| MaybeAuthed(Some(authed)))
    }
}
