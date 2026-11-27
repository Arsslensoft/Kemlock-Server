//! Back-channel logout (OpenID Connect Back-Channel Logout 1.0). When the provider's session for a
//! person ends, it posts a signed logout token to the server; the server revokes that subject's
//! sessions, so their devices find out at their next sync and open vaults lock.
//!
//! The use case ends the devices that identity signed in (`sso_sessions`, written when an SSO
//! sign-in issues tokens), or that provider session (`sid`) did, and no others: refresh tokens of
//! those devices go and their key is cleared, so an access token already issued stops at its next
//! request. A device the account signed in by password, or through another identity, stays. The
//! vault keys stay where they are; locking is the device's job when its session ends.

use crate::platform::Platform;
use crate::ports::{DeviceRepo, Event, EventLog, SecretSeal, TokenRepo, UserRepo};
use crate::sso::error::SsoError;
use crate::sso::model::LogoutClaims;
use crate::sso::ports::{OidcProvider, SsoIdentityRepo, SsoSettingsRepo};
use kemlock_domain::{Device, DeviceId, UserId};

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
    /// The token names a subject that signed no device in. The provider is told success anyway, as
    /// the specification asks, so it can't probe for accounts.
    UnknownSubject,
    /// The token names only a provider session id (`sid`) that began no device here, so there is
    /// nothing to end. Valid, and answered with success.
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

        let Some(subject) = claims.subject.as_deref() else {
            // A token that names only a provider session id ends the devices that session began.
            if claims.session_id.is_none() {
                return Ok(LogoutOutcome::SessionOnly);
            }
            return self.end(&claims, None).await;
        };
        self.end(&claims, Some(subject)).await
    }

    /// Ends the devices the named identity or provider session signed in, and only those. Another
    /// device of the same account, signed in by password or by another identity, is left alone: the
    /// holder of a provider identity (say, one an admin pointed at) must not be able to sign an
    /// account out everywhere, again and again.
    async fn end(
        &self,
        claims: &LogoutClaims,
        subject: Option<&str>,
    ) -> Result<LogoutOutcome, SsoError> {
        let sessions = self
            .repos
            .sso_sessions(&claims.issuer, subject, claims.session_id.as_deref())
            .await?;
        let Some(first) = sessions.first() else {
            return Ok(if subject.is_some() {
                LogoutOutcome::UnknownSubject
            } else {
                LogoutOutcome::SessionOnly
            });
        };
        let user = first.user;
        let mut ended = 0usize;
        let mut owners: Vec<UserId> = Vec::new();
        for session in &sessions {
            if !owners.contains(&session.user) {
                owners.push(session.user);
            }
        }
        for owner in owners {
            let named: Vec<DeviceId> = sessions
                .iter()
                .filter(|s| s.user == owner)
                .map(|s| s.device)
                .collect();
            for device in self.devices.list(owner).await? {
                if !named.contains(&device.id) {
                    continue;
                }
                self.tokens.revoke_device(device.id).await?;
                // The device's key no longer vouches for it either: with it, a replica's
                // device-key sign-in would put the session straight back, and an access token
                // already issued stops working at its next request. The trusted-device copy stays.
                if device.dpop_jkt.is_some() {
                    let device = Device {
                        dpop_jkt: None,
                        ..device
                    };
                    self.devices.upsert(&device).await?;
                }
                ended += 1;
            }
        }

        let event = Event {
            actor: Some(user),
            device: None,
            action: "auth.sso_logout",
            target: None,
            at: self.env.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "couldn't record a back-channel logout");
        }
        Ok(LogoutOutcome::Revoked {
            user,
            devices: ended,
        })
    }
}
