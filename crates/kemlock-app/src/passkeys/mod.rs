//! Passkeys and WebAuthn security keys.
//!
//! - A **passkey** signs the person in ([`PasskeySignIn`]). One whose authenticator supports the
//!   WebAuthn PRF extension also opens the vault: the client wraps a copy of the root key under a
//!   key made from the PRF output and the server stores it ([`ManagePasskeys`]), never able to
//!   open it. Without PRF the passkey only signs in, and a device or the password opens the vault.
//!   An account has at most five. "Require SSO" blocks passkey sign-in for the members it binds.
//! - A **security key** is a second step, Bitwarden's type 7 ([`SecurityKeys`]). Both APIs share the
//!   stored keys and the ceremonies; [`SecurityKeyStep`] is the Kemlock API's second step.
//!
//! The WebAuthn protocol itself is behind the [`WebAuthn`] port, which `kemlock-identity`
//! implements. The ports for storage are in [`ports`].

mod manage;
pub mod ports;
mod second_step;
mod security_keys;
mod sign_in;
pub mod webauthn;

use crate::error::AppError;
pub use manage::{FinishRegistration, ManagePasskeys};
pub use ports::{ChallengeKind, ChallengeRepo, PasskeyRepo, PasskeyStore};
pub use second_step::SecurityKeyStep;
pub use security_keys::{
    ImportedKey, KeyList, MAX_KEYS, PURPOSE_WEBAUTHN, SecurityKeyError, SecurityKeyInfo,
    SecurityKeys, encode_key_list,
};
pub use sign_in::{
    PURPOSE_PASSKEY_CHALLENGE, PasskeyChallenge, PasskeySignIn, PasskeySignedIn, PasskeyVerifyInput,
};
pub use webauthn::{
    Assertion, CredentialKind, NewCredential, RegistrationStart, ResponseIds, Started, WebAuthn,
    WebAuthnError,
};

/// What a failed ceremony is to a caller that doesn't look inside: a refused or malformed answer
/// is the client's mistake, a relying-party failure is the server's.
pub(crate) fn ceremony_error(e: WebAuthnError) -> AppError {
    match e {
        WebAuthnError::Refused(why) => {
            tracing::debug!(%why, "a WebAuthn response was refused");
            AppError::Invalid("the authenticator's answer wasn't accepted")
        }
        WebAuthnError::Malformed(why) => AppError::Invalid(why),
        WebAuthnError::Failed(message) => AppError::Store(message),
    }
}
