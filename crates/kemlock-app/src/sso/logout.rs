//! Back-channel logout (OpenID Connect Back-Channel Logout 1.0). When the provider's session for a
//! person ends, it posts a signed logout token to the server; the server revokes that subject's
//! sessions, so their devices find out at their next sync and open vaults lock.
//!
//! The use case ends every session of the account, not only those that began with SSO: refresh
//! tokens of all its devices go, and the account's security stamp changes so access tokens
//! already issued stop working at once instead of at their 10-minute expiry. The vault keys stay
//! where they are; locking is the device's job when its session ends.

use crate::platform::{Platform, random_uuid};
use crate::ports::{DeviceRepo, Event, EventLog, SecretSeal, TokenRepo, UserRepo};
use crate::sso::error::SsoError;
use crate::sso::ports::{OidcProvider, SsoIdentityRepo, SsoSettingsRepo};
use kemlock_domain::UserId;

#[derive(Debug)]
pub struct SsoLogout<U, D, T, R, O, S, E, V> {
    pub users: U,
    pub devices: D,
    pub tokens: T,
    pub repos: R,
    pub provider: O,
    pub seal: S,
    pub env: E,
    pub events: V,
}

/// What a valid logout token did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// The subject's sessions are revoked: `devices` of them lost their refresh tokens.
    Revoked { user: UserId, devices: usize },
    /// The token is valid but names no subject this server has linked. The provider is told
    /// success anyway, as the specification asks, so it can't probe for accounts.
    UnknownSubject,
    /// The token names only a provider session id (`sid`), which this server doesn't track, so
    /// there is no account to end. Valid, and answered with success.
    SessionOnly,
}

impl<U, D, T, R, O, S, E, V> SsoLogout<U, D, T, R, O, S, E, V>
where
    U: UserRepo,
    D: DeviceRepo,
    T: TokenRepo,
    R: SsoSettingsRepo + SsoIdentityRepo,
    O: OidcProvider,
    S: SecretSeal,
    E: Platform,
    V: EventLog,
{
    /// Validates `logout_token` and ends the sessions it names. An invalid token is an error
    /// (the route answers 400, as the specification says).
    pub async fn execute(&self, logout_token: &str) -> Result<LogoutOutcome, SsoError> {
        let settings = self
            .repos
            .sso_settings()
            .await?
            .filter(|s| s.enabled)
            .ok_or(SsoError::NotConfigured)?;
        let client = settings.client_config(&self.seal)?;
        let claims = self
            .provider
            .validate_logout_token(&client, logout_token)
            .await?;

        let Some(subject) = claims.subject else {
            return Ok(LogoutOutcome::SessionOnly);
        };
        let Some(identity) = self.repos.find_identity(&claims.issuer, &subject).await? else {
            return Ok(LogoutOutcome::UnknownSubject);
        };
        let Some(mut user) = self.users.by_id(identity.user).await? else {
            return Ok(LogoutOutcome::UnknownSubject);
        };

        let devices = self.devices.list(user.id).await?;
        for device in &devices {
            self.tokens.revoke_device(device.id).await?;
        }
        user.security_stamp = random_uuid(&self.env);
        user.updated_at = self.env.now();
        self.users.update(&user).await?;

        let event = Event {
            actor: Some(user.id),
            device: None,
            action: "auth.sso_logout",
            target: None,
            at: self.env.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a back-channel logout");
        }
        Ok(LogoutOutcome::Revoked {
            user: user.id,
            devices: devices.len(),
        })
    }
}
