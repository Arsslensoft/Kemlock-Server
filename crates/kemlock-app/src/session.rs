//! Devices and tokens: what `sign_in` and `refresh` share. A device is registered or updated with
//! its DPoP key thumbprint, then an access token (10 minutes, bound to that key) and a refresh
//! token (30 days, random, stored as its SHA-256) are issued.

use crate::authenticate::is_effective_admin;
use crate::b64url;
use crate::config::AuthConfig;
use crate::devices::bitwarden_device_id;
use crate::error::AppError;
use crate::platform::{Platform, random_uuid};
use crate::ports::{
    AccessClaims, DeviceRepo, Event, EventLog, RefreshToken, StoreError, TokenApi, TokenRepo,
    TokenSigner, TwoFactorRepo,
};
use kemlock_domain::{Device, DeviceId, DeviceKind, User, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

/// The most devices one account may have. A new device past it is refused at sign-in (one that
/// is already registered still signs in), so the account has to sign one out first.
pub const MAX_DEVICES_PER_ACCOUNT: usize = 100;

/// What a client says about the device it signs in from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The id the device kept from an earlier sign-in; `None` on the first.
    pub id: Option<DeviceId>,
    pub name: String,
    pub kind: DeviceKind,
    /// The identifier the same phone uses on the Bitwarden API (Vaultwarden's `deviceIdentifier`).
    /// When it is set the device's id is the one the Bitwarden API makes from it, so both APIs
    /// share one device row, and `id` is ignored.
    pub bitwarden_identifier: Option<String>,
}

impl DeviceInfo {
    /// The id this device has on `user`'s account: the Bitwarden API's id for its identifier when
    /// it names one, else the id it kept, else a new random one.
    pub fn resolve<E: Platform>(&self, user: UserId, env: &E) -> DeviceId {
        match &self.bitwarden_identifier {
            Some(identifier) => {
                bitwarden_device_id(|data| env.sha256(data), user, identifier.as_str())
            }
            None => self.id.unwrap_or_else(|| DeviceId(random_uuid(env))),
        }
    }
}

/// A rotation the new tokens continue: the family of the refresh token that was just used, and
/// when the sign-in that family descends from happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Continued {
    pub family: Uuid,
    pub signed_in_at: OffsetDateTime,
}

/// A signed-in session: the tokens and who they are for.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenPair {
    pub access_token: String,
    pub access_expires_at: OffsetDateTime,
    /// The refresh token as sent to the client (unpadded base64url of 32 random bytes).
    pub refresh_token: String,
    pub refresh_expires_at: OffsetDateTime,
    pub user: UserId,
    pub device: DeviceId,
    pub admin: bool,
}

impl std::fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPair")
            .field("user", &self.user)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Sessions<D, T, K, E, V, F> {
    pub devices: D,
    pub tokens: T,
    pub signer: K,
    pub env: E,
    pub events: V,
    /// Read to tell whether an admin has the two-step method that admin access needs.
    pub two_factor: F,
    pub config: AuthConfig,
}

impl<D: DeviceRepo, T: TokenRepo, K: TokenSigner, E: Platform, V: EventLog, F: TwoFactorRepo>
    Sessions<D, T, K, E, V, F>
{
    /// Registers a new device or updates a known one. A device id that belongs to another
    /// account is refused. A changed DPoP key ends the device's old refresh tokens.
    pub async fn register_device(
        &self,
        user: UserId,
        info: &DeviceInfo,
        jkt: &str,
    ) -> Result<Device, AppError> {
        let now = self.env.now();
        let id = info.resolve(user, &self.env);
        let known = self.devices.get(id).await?;
        let device = match known {
            Some(d) if d.user != user => return Err(AppError::Duplicate),
            Some(d) => {
                // A device the Bitwarden API made has no DPoP key yet: binding its first one ends
                // nothing, because the refresh tokens it holds are the Bitwarden API's, which this
                // phone still uses. A key that replaces another does end the old key's tokens.
                if d.dpop_jkt.as_deref().is_some_and(|old| old != jkt) {
                    self.tokens.revoke_device(id).await?;
                }
                Device {
                    name: Device::clean_name(&info.name),
                    kind: info.kind,
                    dpop_jkt: Some(jkt.to_owned()),
                    last_seen_at: now,
                    ..d
                }
            }
            None => {
                // Each device may make its own stream of authenticated requests, so one account
                // with endless devices would take a large share of what every account shares.
                if self.devices.list(user).await?.len() >= MAX_DEVICES_PER_ACCOUNT {
                    return Err(AppError::Invalid(
                        "this account has too many signed-in devices: sign one out first",
                    ));
                }
                Device {
                    id,
                    user,
                    name: Device::clean_name(&info.name),
                    kind: info.kind,
                    dpop_jkt: Some(jkt.to_owned()),
                    created_at: now,
                    last_seen_at: now,
                }
            }
        };
        self.devices.upsert(&device).await?;
        // However this device was signed in before, this sign-in is a new one: it is an SSO session
        // only when [`Sessions::start_sso_session`] says so after.
        self.devices.forget_sso_session(id).await?;
        Ok(device)
    }

    /// Records that an SSO sign-in (named by the sealed challenge a second step finishes) started
    /// `device`, so a back-channel logout for that identity or `sid` ends it. Nothing for a sign-in
    /// that did not begin with SSO. A failed write fails the sign-in: a session no logout could end
    /// is not one to hand out.
    pub(crate) async fn start_sso_session(
        &self,
        origin: Option<&crate::sealed::SsoOrigin>,
        user: UserId,
        device: &Device,
    ) -> Result<(), AppError> {
        let Some(origin) = origin else {
            return Ok(());
        };
        self.devices
            .record_sso_session(&crate::sso::SsoSession {
                device: device.id,
                user,
                issuer: origin.issuer.clone(),
                subject: origin.subject.clone(),
                session_id: origin.session_id.clone(),
                started_at: self.env.now(),
            })
            .await?;
        Ok(())
    }

    /// Issues an access token and a new refresh token for `device`. `continuing` carries a
    /// rotation on, keeping the time of its sign-in; `None` starts a new family (a sign-in, now).
    pub async fn issue(
        &self,
        user: &User,
        device: &Device,
        jkt: &str,
        continuing: Option<Continued>,
    ) -> Result<TokenPair, AppError> {
        let now = self.env.now();
        let signed_in_at = continuing.map_or(now, |c| c.signed_in_at);
        let admin = is_effective_admin(user, &self.two_factor).await?;
        let claims = AccessClaims {
            user: user.id,
            device: device.id,
            jkt: jkt.to_owned(),
            security_stamp: user.security_stamp,
            admin,
            auth_time: signed_in_at,
            issued_at: now,
            expires_at: now + self.config.access_ttl,
        };
        let access_token = self.signer.sign(&claims);
        let raw = self.env.bytes::<32>();
        let refresh_expires_at = now + self.config.refresh_ttl;
        let inserted = self
            .tokens
            .insert(&RefreshToken {
                hash: self.env.sha256(&raw),
                family: continuing.map_or_else(|| random_uuid(&self.env), |c| c.family),
                user: user.id,
                device: device.id,
                security_stamp: user.security_stamp,
                created_at: signed_in_at,
                expires_at: refresh_expires_at,
                used_at: None,
                api: TokenApi::Kemlock,
            })
            .await;
        match inserted {
            Ok(()) => {}
            // The family was revoked while this rotation ran: the same token was used twice, and
            // the other use was caught. This rotation was the racing half; its session is over.
            Err(StoreError::NotFound) if continuing.is_some() => {
                return Err(AppError::SessionEnded("refresh-token-reuse"));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(TokenPair {
            access_token,
            access_expires_at: claims.expires_at,
            refresh_token: b64url::encode(&raw),
            refresh_expires_at,
            user: user.id,
            device: device.id,
            admin,
        })
    }

    /// Writes an event; a failure is logged, never raised, because what the event describes has
    /// already happened.
    pub async fn record(&self, action: &'static str, user: UserId, device: Option<DeviceId>) {
        let event = Event {
            actor: Some(user),
            device,
            action,
            target: None,
            at: self.env.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(action, error = %e, "couldn't record an event");
        }
    }
}
