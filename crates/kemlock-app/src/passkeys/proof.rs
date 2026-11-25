//! A security key or a passkey as a fresh proof: the account's owner, at a keyboard with a key in
//! hand, for the actions that ask for one beyond a session (adding or removing a second step,
//! showing the recovery code, the Recovery Kit).
//!
//! The challenge is the stored state of a ceremony (`ChallengeKind::Proof`), one per account and
//! good for [`PROOF_TTL`]: [`AssertionProof::verify`] takes it out first, so an answer, right or
//! wrong, uses it up and a replay finds none. It lists the credentials of the account's own
//! security keys and passkeys, so a key of another account has nothing to answer with. A passkey's
//! answer must carry user verification (as at sign-in); a security key's need not.

use super::ceremony_error;
use super::ports::{ChallengeKind, ChallengeRepo, PasskeyRepo};
use super::security_keys::{SecurityKeyError, SecurityKeys, key_error};
use super::webauthn::{CredentialKind, WebAuthn};
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactorRepo, UserRepo};
use kemlock_domain::{PasskeyId, UserId};
use serde_json::Value;
use subtle::ConstantTimeEq;
use time::Duration;

/// How long a proof challenge may take to be answered.
pub const PROOF_TTL: Duration = Duration::minutes(2);

/// A proof by assertion over its ports. `keys` holds the account's security keys and the
/// challenges; `passkeys` its passkeys.
#[derive(Debug)]
pub struct AssertionProof<U, F, C, W, S, E, P> {
    pub keys: SecurityKeys<U, F, C, W, S, E>,
    pub passkeys: P,
}

/// A credential the account may answer with.
struct Held {
    credential_id: Vec<u8>,
    credential: Vec<u8>,
    /// The passkey it is, when it is one.
    passkey: Option<PasskeyId>,
}

impl<U, F, C, W, S, E, P> AssertionProof<U, F, C, W, S, E, P>
where
    U: UserRepo,
    F: TwoFactorRepo,
    C: ChallengeRepo,
    W: WebAuthn,
    S: SecretSeal,
    E: Platform,
    P: PasskeyRepo,
{
    async fn held(&self, user: UserId) -> Result<Vec<Held>, AppError> {
        let mut held: Vec<Held> = self
            .keys
            .credentials_of(user)
            .await?
            .into_iter()
            .map(|(credential_id, credential)| Held {
                credential_id,
                credential,
                passkey: None,
            })
            .collect();
        held.extend(
            self.passkeys
                .passkeys_of(user)
                .await?
                .into_iter()
                .map(|p| Held {
                    credential_id: p.credential_id,
                    credential: p.credential,
                    passkey: Some(p.id),
                }),
        );
        Ok(held)
    }

    /// The request options for `navigator.credentials.get`, listing the account's security keys
    /// and passkeys. `NotFound` when it has none. A new challenge replaces the older one.
    pub async fn options(&self, user: UserId) -> Result<Value, AppError> {
        let held = self.held(user).await?;
        if held.is_empty() {
            return Err(AppError::NotFound);
        }
        let credentials: Vec<&[u8]> = held.iter().map(|h| h.credential.as_slice()).collect();
        let started = self
            .keys
            .webauthn
            .start_authentication(CredentialKind::SecurityKey, &credentials)
            .map_err(ceremony_error)?;
        self.keys
            .challenges
            .put_challenge(
                user,
                ChallengeKind::Proof,
                &started.state,
                self.keys.env.now() + PROOF_TTL,
            )
            .await?;
        let mut options = started.options;
        // A passkey's answer must carry user verification, so the browser is required to verify when
        // one is listed; a security key alone stays touch-only.
        if held.iter().any(|h| h.passkey.is_some()) {
            let inner = if options.get("publicKey").is_some() {
                &mut options["publicKey"]
            } else {
                &mut options
            };
            inner["userVerification"] = Value::from("required");
        }
        Ok(options)
    }

    /// Checks an answer: the signature, the counter (which must grow, and is stored), the relying
    /// party and origin, and that the credential is the account's own. The challenge is spent
    /// whatever the answer.
    pub async fn verify(&self, user: UserId, response: &[u8]) -> Result<(), SecurityKeyError> {
        let now = self.keys.env.now();
        let state = self
            .keys
            .challenges
            .take_challenge(user, ChallengeKind::Proof, now)
            .await?
            .ok_or(SecurityKeyError::NoChallenge)?;
        let ids = self
            .keys
            .webauthn
            .response_ids(response)
            .map_err(key_error)?;
        // A handle the authenticator returns names the account it was made for.
        if let Some(handle) = &ids.user_handle
            && !bool::from(handle.as_slice().ct_eq(user.as_bytes()))
        {
            return Err(SecurityKeyError::Refused);
        }
        let held = self.held(user).await?;
        let own = held
            .iter()
            .find(|h| h.credential_id == ids.credential_id)
            .ok_or(SecurityKeyError::Refused)?;
        let assertion = self
            .keys
            .webauthn
            .finish_authentication(
                CredentialKind::SecurityKey,
                &state,
                response,
                &[own.credential.as_slice()],
            )
            .map_err(key_error)?;
        // A passkey is possession plus a PIN or a body check, as at sign-in.
        if own.passkey.is_some() && !assertion.user_verified {
            return Err(SecurityKeyError::Refused);
        }
        // The authenticator's counter moved: keep it.
        match own.passkey {
            Some(id) => {
                self.passkeys
                    .record_passkey_use(id, &assertion.credential, now)
                    .await
                    .map_err(AppError::from)?;
            }
            None => {
                self.keys
                    .record_use(user, &assertion.credential_id, &assertion.credential)
                    .await?;
            }
        }
        Ok(())
    }
}
