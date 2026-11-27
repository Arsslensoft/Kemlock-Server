//! An account's passkeys: register one, list, rename, delete, and keep the PRF copy of the root
//! key each can open.
//!
//! Registration is two calls. `start_registration` makes the creation options and keeps the
//! ceremony's state; `finish_registration` takes the browser's answer, uses the state up (right
//! answer or wrong) and stores the credential. An account has at most five.

use super::ceremony_error;
use super::ports::{ChallengeKind, ChallengeRepo, PasskeyRepo};
use super::webauthn::{CredentialKind, RegistrationStart, WebAuthn};
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{Event, EventLog, UserRepo};
use kemlock_domain::{Passkey, PasskeyId, PrfWrap, User, UserId};
use serde_json::Value;

const TOO_MANY: &str = "an account may have at most five passkeys";

/// Passkey management over its ports.
#[derive(Debug)]
pub struct ManagePasskeys<U, P, C, W, E, V> {
    pub users: U,
    pub passkeys: P,
    pub challenges: C,
    pub webauthn: W,
    pub env: E,
    pub events: V,
    pub config: AuthConfig,
}

/// What the browser sent back after `navigator.credentials.create`, and what the person added.
#[derive(Clone, Debug)]
pub struct FinishRegistration {
    pub user: UserId,
    /// What the person calls this passkey.
    pub name: String,
    /// The `PublicKeyCredential` as JSON (`toJSON()`).
    pub response: Vec<u8>,
    /// The root key wrapped under the PRF output, when the client has one to give now.
    pub prf: Option<PrfWrap>,
}

/// A wrap is kept only when it is the length of a wrapped root key and names the account's
/// current key version: a copy for another version opens nothing.
fn checked_wrap(account: &User, wrap: PrfWrap) -> Result<PrfWrap, AppError> {
    if !wrap.is_well_formed() {
        return Err(AppError::Invalid("the wrapped key has the wrong length"));
    }
    if wrap.key_version != account.key_version {
        return Err(AppError::StaleKeyVersion {
            current: account.key_version,
        });
    }
    Ok(wrap)
}

impl<U, P, C, W, E, V> ManagePasskeys<U, P, C, W, E, V>
where
    U: UserRepo,
    P: PasskeyRepo,
    C: ChallengeRepo,
    W: WebAuthn,
    E: Platform,
    V: EventLog,
{
    async fn account(&self, user: UserId) -> Result<User, AppError> {
        self.users.by_id(user).await?.ok_or(AppError::Unauthorized)
    }

    async fn record(&self, action: &'static str, user: UserId, passkey: PasskeyId) {
        let event = Event {
            actor: Some(user),
            device: None,
            action,
            target: Some(passkey.to_string()),
            at: self.env.now(),
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(action, error = %e, "couldn't record an event");
        }
    }

    /// Starts a registration: the creation options for `navigator.credentials.create`. A passkey
    /// is a discoverable credential with user verification required, so one gesture signs the
    /// person in. The client adds the PRF extension to the options itself.
    pub async fn start_registration(&self, user: UserId) -> Result<Value, AppError> {
        let account = self.account(user).await?;
        let existing = self.passkeys.passkeys_of(user).await?;
        if existing.len() >= Passkey::MAX_PER_ACCOUNT {
            return Err(AppError::Invalid(TOO_MANY));
        }
        let exclude: Vec<Vec<u8>> = existing.into_iter().map(|p| p.credential_id).collect();
        let display = account
            .name
            .clone()
            .unwrap_or_else(|| account.email.as_str().to_owned());
        let started = self
            .webauthn
            .start_registration(&RegistrationStart {
                kind: CredentialKind::Passkey,
                user_handle: account.id.as_bytes(),
                user_name: account.email.as_str(),
                display_name: &display,
                exclude: &exclude,
            })
            .map_err(ceremony_error)?;
        self.challenges
            .put_challenge(
                user,
                ChallengeKind::PasskeyRegistration,
                &started.state,
                self.env.now() + self.config.challenge_ttl,
            )
            .await?;
        Ok(started.options)
    }

    /// Finishes a registration. The ceremony's state is used up whatever the answer, so a wrong
    /// answer needs a new `start_registration`.
    pub async fn finish_registration(
        &self,
        input: FinishRegistration,
    ) -> Result<Passkey, AppError> {
        let account = self.account(input.user).await?;
        let name =
            Passkey::clean_name(&input.name).ok_or(AppError::Invalid("a passkey needs a name"))?;
        let prf_wrap = input
            .prf
            .map(|wrap| checked_wrap(&account, wrap))
            .transpose()?;
        let now = self.env.now();
        let state = self
            .challenges
            .take_challenge(input.user, ChallengeKind::PasskeyRegistration, now)
            .await?
            .ok_or(AppError::Invalid(
                "no passkey registration is in progress, or it expired",
            ))?;
        let made = self
            .webauthn
            .finish_registration(CredentialKind::Passkey, &state, &input.response)
            .map_err(ceremony_error)?;
        if self.passkeys.passkeys_of(input.user).await?.len() >= Passkey::MAX_PER_ACCOUNT {
            return Err(AppError::Invalid(TOO_MANY));
        }
        if self
            .passkeys
            .passkey_by_credential(&made.credential_id)
            .await?
            .is_some()
        {
            return Err(AppError::Duplicate);
        }
        let passkey = Passkey {
            id: PasskeyId::random(),
            user: input.user,
            credential_id: made.credential_id,
            name,
            credential: made.credential,
            prf_wrap,
            created_at: now,
            last_used_at: None,
        };
        self.passkeys.insert_passkey(&passkey).await?;
        self.record("passkey.register", input.user, passkey.id)
            .await;
        Ok(passkey)
    }

    /// The account's passkeys, oldest first.
    pub async fn list(&self, user: UserId) -> Result<Vec<Passkey>, AppError> {
        Ok(self.passkeys.passkeys_of(user).await?)
    }

    pub async fn rename(&self, user: UserId, id: PasskeyId, name: &str) -> Result<(), AppError> {
        let name = Passkey::clean_name(name).ok_or(AppError::Invalid("a passkey needs a name"))?;
        self.passkeys.rename_passkey(user, id, &name).await?;
        Ok(())
    }

    /// Deletes a passkey, and with it the PRF copy of the root key it held.
    pub async fn delete(&self, user: UserId, id: PasskeyId) -> Result<(), AppError> {
        self.passkeys.delete_passkey(user, id).await?;
        self.record("passkey.delete", user, id).await;
        Ok(())
    }

    /// Stores the PRF copy of the root key under a passkey the account already has: the client
    /// can only get the PRF output with a sign-in, so a passkey is often made first and given its
    /// copy after.
    pub async fn set_wrap(
        &self,
        user: UserId,
        id: PasskeyId,
        wrap: PrfWrap,
    ) -> Result<(), AppError> {
        let account = self.account(user).await?;
        let wrap = checked_wrap(&account, wrap)?;
        self.passkeys
            .set_passkey_wrap(user, id, Some(&wrap))
            .await?;
        self.record("passkey.wrap", user, id).await;
        Ok(())
    }
}
