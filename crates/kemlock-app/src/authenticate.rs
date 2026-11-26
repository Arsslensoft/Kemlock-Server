//! Authenticate: turns an access token and the key that signed the request into an actor.
//!
//! The token's signature and expiry are checked by the `TokenSigner`; here its `cnf.jkt` must be
//! the proof's key (a token copied off a phone is useless elsewhere), its security stamp must
//! still be the account's (a password change ends every session), and its device must still be one
//! of the account's, registered with that same key (signing a device out, or a refresh token used
//! twice, ends its session at once, not when the token runs out).

use crate::error::AppError;
use crate::ports::{Clock, DeviceRepo, TokenSigner, TwoFactorRepo, UserRepo};
use kemlock_domain::{DeviceId, User, UserId};
use subtle::ConstantTimeEq;

/// Who is calling: a signed-in account on one of its devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actor {
    pub user: UserId,
    pub device: DeviceId,
    pub admin: bool,
}

/// Whether `user` may act as an admin now: the role is admin, **and** the account has a confirmed
/// two-step method. An admin without one (setup was interrupted, or the method was removed) is
/// an ordinary user until it has one again.
pub async fn is_effective_admin<F: TwoFactorRepo>(
    user: &User,
    two_factor: &F,
) -> Result<bool, AppError> {
    if !user.is_admin() {
        return Ok(false);
    }
    Ok(two_factor.list(user.id).await?.iter().any(|t| t.enabled))
}

#[derive(Debug)]
pub struct Authenticate<U, D, F, K, C> {
    pub users: U,
    pub devices: D,
    pub two_factor: F,
    pub signer: K,
    pub clock: C,
    /// Whether held accounts are refused (`AuthConfig::signups_verify`).
    pub verify_email: bool,
}

impl<U: UserRepo, D: DeviceRepo, F: TwoFactorRepo, K: TokenSigner, C: Clock>
    Authenticate<U, D, F, K, C>
{
    pub async fn execute(&self, token: &str, jkt: &str) -> Result<Actor, AppError> {
        let claims = self
            .signer
            .verify(token, self.clock.now())
            .map_err(|_| AppError::Unauthorized)?;
        if !bool::from(claims.jkt.as_bytes().ct_eq(jkt.as_bytes())) {
            return Err(AppError::Unauthorized);
        }
        let user = self
            .users
            .by_id(claims.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if user.security_stamp != claims.security_stamp {
            return Err(AppError::SessionEnded("security-stamp-changed"));
        }
        // An account made on a sign-up that asks for a confirmed address is not used until the link
        // mailed to it is opened, whatever tokens it holds.
        if self.verify_email && self.users.email_unconfirmed(user.id).await? {
            return Err(AppError::EmailNotConfirmed);
        }
        // A device that was signed out is gone from the account: its access token, which would
        // otherwise live out its ten minutes, goes with it. So does one whose key no longer
        // vouches for it (a refresh token used twice, or sessions ended everywhere, clear the
        // device's key): the same check an open socket makes every minute.
        self.devices
            .get(claims.device)
            .await?
            .filter(|device| {
                device.user == claims.user
                    && device.dpop_jkt.as_deref().is_some_and(|registered| {
                        bool::from(registered.as_bytes().ct_eq(jkt.as_bytes()))
                    })
            })
            .ok_or(AppError::SessionEnded("signed-out"))?;
        Ok(Actor {
            user: claims.user,
            device: claims.device,
            // The account's role now, not the role it had when the token was issued, and only
            // with a confirmed two-step method.
            admin: is_effective_admin(&user, &self.two_factor).await?,
        })
    }
}
