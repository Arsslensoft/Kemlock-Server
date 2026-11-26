//! Writing the sign-in log from the API layer. Both APIs record every sign-in attempt, whatever
//! the method and however it ended, through the [`PrivacyLog`](super::ports::PrivacyLog) port,
//! which cuts the address to its /24 or /48 on the way in (and keeps the whole one only while the
//! admin's retention settings keep full addresses, for up to 30 days).
//!
//! An attempt is one credential check that was answered: the password's last message, a second
//! step's code, a passkey, a device approval or key, a single sign-on code, a refresh token, a
//! Bitwarden API key. A request that never reached a credential check (a malformed body, a
//! rate-limit refusal) is not an attempt and leaves no row. A password that is right but owes a
//! second step is a successful `password` attempt; the second step is its own row.

use super::ports::{NewSignIn, PrivacyLog};
use crate::error::AppError;
use kemlock_domain::privacy::SignInOutcome;
use kemlock_domain::{DeviceId, UserId};
use std::net::IpAddr;
use time::OffsetDateTime;

/// The client's address as the server settled it, put in a request's extensions by the server's
/// request layer (the peer, or the forwarded address when the peer is a trusted proxy). The
/// Bitwarden API reads it for the sign-in log; the Kemlock API works its own out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAddr(pub IpAddr);

/// How a result reads as a sign-in attempt: `Some(Success)` for an `Ok`, `Some(Failure)` for a
/// refusal of the credentials or of the account (`E` is `AppError`, or an error that converts to
/// one, like the single sign-on use cases'), and `None` for anything else (a bad request, a store
/// failure), which is not an attempt.
pub fn attempt_outcome<T, E: Clone + Into<AppError>>(
    result: &Result<T, E>,
) -> Option<SignInOutcome> {
    match result {
        Ok(_) => Some(SignInOutcome::Success),
        Err(e) => {
            let refusal: AppError = e.clone().into();
            match refusal {
                AppError::Unauthorized
                | AppError::AccountDisabled
                | AppError::AccountBeingDeleted
                | AppError::EmailNotConfirmed
                | AppError::SsoRequired { .. }
                | AppError::SessionEnded(_)
                | AppError::Forbidden => Some(SignInOutcome::Failure),
                _ => None,
            }
        }
    }
}

/// The log row for a sign-in attempt that ended in `result`, or `None` when the result is not an
/// attempt. `known` is who the attempt was for when the request named them (a failure has no
/// token to read it from); `ids` reads the account and device from what a success returned.
pub fn sign_in_entry<T, E: Clone + Into<AppError>>(
    method: &'static str,
    known: Option<UserId>,
    result: &Result<T, E>,
    at: OffsetDateTime,
    ip: Option<IpAddr>,
    ids: impl FnOnce(&T) -> (Option<UserId>, Option<DeviceId>),
) -> Option<NewSignIn> {
    let outcome = attempt_outcome(result)?;
    let (user, device) = match result {
        Ok(value) => ids(value),
        Err(_) => (None, None),
    };
    Some(NewSignIn {
        user: user.or(known),
        device,
        method,
        outcome,
        at,
        ip,
    })
}

/// Writes the row, if there is one. The sign-in has been answered, so a log failure is only
/// logged: it never turns a sign-in into an error.
pub async fn record_sign_in<L: PrivacyLog>(log: &L, entry: Option<NewSignIn>) {
    let Some(entry) = entry else {
        return;
    };
    let method = entry.method;
    if let Err(e) = log.record_sign_in(entry).await {
        tracing::warn!(method, error = %e, "couldn't record a sign-in attempt");
    }
}
