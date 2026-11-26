//! Refresh: rotation. Every refresh returns a new refresh token and the old one stops working. A
//! refresh token used twice revokes its whole family and the device's tokens (design, "API and
//! sync"), because only a copy of it could have been used the second time. A token also carries
//! the security stamp of the account when it was issued; once the account's stamp changed, no
//! refresh is allowed.

use crate::b64url;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{DeviceRepo, EventLog, TokenRepo, TokenSigner, TwoFactorRepo, UserRepo};
use crate::session::{Continued, Sessions, TokenPair};

#[derive(Debug)]
pub struct Refresh<U, D, T, K, E, V, F> {
    pub users: U,
    pub sessions: Sessions<D, T, K, E, V, F>,
}

impl<
    U: UserRepo,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    F: TwoFactorRepo,
> Refresh<U, D, T, K, E, V, F>
{
    /// `refresh_token` is what the client holds; `jkt` the thumbprint of the DPoP key that signed
    /// this request, which must be the device's key.
    pub async fn execute(&self, refresh_token: &str, jkt: &str) -> Result<TokenPair, AppError> {
        let raw = b64url::decode(refresh_token)
            .filter(|b| b.len() == 32)
            .ok_or(AppError::Unauthorized)?;
        let now = self.sessions.env.now();
        let token = self
            .sessions
            .tokens
            .take(self.sessions.env.sha256(&raw), now)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if token.used_at.is_some() {
            self.sessions.tokens.revoke_family(token.family).await?;
            self.sessions.tokens.revoke_device(token.device).await?;
            // The device's key no longer vouches for anything until the next sign-in: this is
            // what open live sockets notice within a minute (they check it against their token).
            if let Some(mut device) = self.sessions.devices.get(token.device).await? {
                device.dpop_jkt = None;
                self.sessions.devices.upsert(&device).await?;
            }
            self.sessions
                .record("auth.refresh_reuse", token.user, Some(token.device))
                .await;
            return Err(AppError::SessionEnded("refresh-token-reuse"));
        }
        if token.expires_at <= now {
            return Err(AppError::SessionEnded("expired"));
        }
        let mut device = self
            .sessions
            .devices
            .get(token.device)
            .await?
            .ok_or(AppError::SessionEnded("signed-out"))?;
        if device.user != token.user || device.dpop_jkt.as_deref() != Some(jkt) {
            // A refresh token presented by a key that isn't the device's: it was copied.
            self.sessions.tokens.revoke_family(token.family).await?;
            self.sessions
                .record("auth.refresh_key_mismatch", token.user, Some(token.device))
                .await;
            return Err(AppError::SessionEnded("dpop-key-mismatch"));
        }
        let user = self
            .users
            .by_id(token.user)
            .await?
            .ok_or(AppError::SessionEnded("signed-out"))?;
        if self.users.account_disabled(user.id).await? {
            // The account was disabled after this token was issued. Disabling from the admin
            // console also changes the stamp, but an account Vaultwarden had disabled keeps its
            // stamp, and neither may carry a session on.
            self.sessions.tokens.revoke_family(token.family).await?;
            self.sessions
                .record("auth.refresh_disabled", token.user, Some(token.device))
                .await;
            return Err(AppError::SessionEnded("account-disabled"));
        }
        if self.users.erasure_pending(user.id).await?.is_some() {
            // The account was deleted after this token was issued: the grace period ends its
            // sessions, as the new stamp does, with a reason the device can show.
            self.sessions.tokens.revoke_family(token.family).await?;
            return Err(AppError::SessionEnded("account-being-deleted"));
        }
        if user.security_stamp != token.security_stamp {
            // The account ended its sessions (a password change, a key replacement) after this
            // token was issued; a refresh must not carry the session over the change.
            self.sessions.tokens.revoke_family(token.family).await?;
            self.sessions
                .record("auth.refresh_stamp_changed", token.user, Some(token.device))
                .await;
            return Err(AppError::SessionEnded("security-stamp-changed"));
        }

        // Only the time is written, and only while the device still has this key: sessions may
        // have been ended since it was read, and writing the whole row back would put its key back.
        if !self
            .sessions
            .devices
            .touch_seen(device.id, jkt, now)
            .await?
        {
            self.sessions.tokens.revoke_family(token.family).await?;
            return Err(AppError::SessionEnded("signed-out"));
        }
        device.last_seen_at = now;
        self.sessions
            .issue(
                &user,
                &device,
                jkt,
                Some(Continued {
                    family: token.family,
                    signed_in_at: token.created_at,
                }),
            )
            .await
    }
}
