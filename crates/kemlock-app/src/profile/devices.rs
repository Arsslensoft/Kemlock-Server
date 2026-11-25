//! After a change that replaced the account's security stamp (a new master password with "Sign out
//! my other devices"), every session of the account has ended at once, the asking device's too:
//! this signs the other devices out for good and gives the asking device a new session.

use crate::authenticate::Actor;
use crate::devices::{KeyCopyRepo, SignOutDevice};
use crate::platform::Platform;
use crate::ports::{DeviceRepo, EventLog, TokenRepo, TokenSigner, TwoFactorRepo};
use crate::session::{Sessions, TokenPair};
use kemlock_domain::User;

#[derive(Debug)]
pub struct OtherDevices<D, C, T, K, E, V, F> {
    pub sign_out: SignOutDevice<D, C, T, E, V>,
    pub sessions: Sessions<D, T, K, E, V, F>,
}

impl<
    D: DeviceRepo,
    C: KeyCopyRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    F: TwoFactorRepo,
> OtherDevices<D, C, T, K, E, V, F>
{
    /// Deletes every other device of the account, with its tokens and its key copy, and returns new
    /// tokens for the device that asked, bound to its DPoP key `jkt` and to the account's new
    /// stamp (`user` is the account as the change left it). The old tokens of the asking device
    /// carry the old stamp and are dead already; its refresh tokens are deleted too.
    ///
    /// The change is made when this runs, so nothing here fails it: what could not be done is
    /// logged. The other devices' tokens are dead by their stamp whether or not their rows go, and
    /// an asking device that gets no tokens (`None`) signs in again with the new password.
    pub async fn renew(&self, actor: &Actor, user: &User, jkt: &str) -> Option<TokenPair> {
        if let Err(error) = self.sign_out.execute_others(actor).await {
            tracing::warn!(%error, "couldn't sign the other devices out after a change of password");
        }
        if let Err(error) = self.sessions.tokens.revoke_device(actor.device).await {
            tracing::warn!(%error, "couldn't delete the old tokens of the device that changed the password");
        }
        let device = match self.sessions.devices.get(actor.device).await {
            Ok(Some(device)) if device.user == user.id => device,
            Ok(_) => return None,
            Err(error) => {
                tracing::warn!(%error, "couldn't read the device that changed the password");
                return None;
            }
        };
        match self.sessions.issue(user, &device, jkt, None).await {
            Ok(tokens) => Some(tokens),
            Err(error) => {
                tracing::warn!(%error, "couldn't give the device that changed the password new tokens");
                None
            }
        }
    }
}
