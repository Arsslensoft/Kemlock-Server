//! The sign-in log of the Kemlock API: every sign-in route reports each attempt it answered, with
//! the client's address, through the privacy port (which truncates the address on write).
//! `attempt` reads a use case's result as a log row and `log_attempt` writes it, so a route says in
//! two lines what happened and who it was for.

use crate::state::{Api, Crypto, Store};
use kemlock_app::ports::TokenSigner;
use kemlock_app::privacy::{NewSignIn, record_sign_in, sign_in_entry};
use kemlock_app::{AppError, SignedIn, TokenPair};
use kemlock_domain::{DeviceId, UserId};
use std::net::IpAddr;

/// The account and device of a session that was issued.
pub(crate) fn token_ids(tokens: &TokenPair) -> (Option<UserId>, Option<DeviceId>) {
    (Some(tokens.user), Some(tokens.device))
}

/// The account and device of a password or single sign-on step: known when tokens were issued, not
/// when a second step is still owed (the challenge is sealed and the log never opens it).
pub(crate) fn signed_in_ids(signed_in: &SignedIn) -> (Option<UserId>, Option<DeviceId>) {
    match signed_in {
        SignedIn::Tokens(tokens) => token_ids(tokens),
        SignedIn::SecondStep(_) => (None, None),
    }
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// The log row for a sign-in attempt that ended in `result`; `None` when `result` is not an
    /// attempt (a malformed request, a store failure). `known` is the account the request named,
    /// for a failure that has no tokens to read it from.
    pub(crate) fn attempt<T, E: Clone + Into<AppError>>(
        &self,
        method: &'static str,
        known: Option<UserId>,
        result: &Result<T, E>,
        ip: IpAddr,
        ids: impl FnOnce(&T) -> (Option<UserId>, Option<DeviceId>),
    ) -> Option<NewSignIn> {
        sign_in_entry(method, known, result, self.crypto.now(), Some(ip), ids)
    }

    /// Writes a row from [`attempt`](Self::attempt). A log failure is only logged.
    pub(crate) async fn log_attempt(&self, entry: Option<NewSignIn>) {
        record_sign_in(&self.store, entry).await;
    }
}
