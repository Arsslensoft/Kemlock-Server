//! WebAuthn security keys as a two-step method (Bitwarden's type 7), shared by both APIs.
//!
//! An account's keys are one `two_factor` row of method `webauthn`: a list of at most five keys,
//! each with a slot number (1 to 5, the number Bitwarden's clients use), a name and the credential
//! as the WebAuthn library keeps it, sealed together under `server.key` (purpose `"webauthn"`).
//! The row exists, enabled, while there is a key.
//!
//! Registering and signing in are each two calls, and each call pair shares a stored state
//! ([`ChallengeKind`]). The state is taken out when its answer arrives, so an answer, right or wrong,
//! uses its challenge up, and asking again replaces the older challenge, whose answer then fails.
//! This is Vaultwarden's behaviour, which Bitwarden's clients and the Kemlock app depend on.

use super::ceremony_error;
use super::ports::{ChallengeKind, ChallengeRepo};
use super::webauthn::{CredentialKind, RegistrationStart, WebAuthn, WebAuthnError};
use crate::b64url;
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{SecretSeal, StoreError, TwoFactor, TwoFactorMethod, TwoFactorRepo, UserRepo};
use crate::sealed::{open_bound, seal_bound};
use kemlock_domain::{Passkey, UserId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// `SecretSeal` purpose of the stored list of security keys.
pub const PURPOSE_WEBAUTHN: &str = "webauthn";

/// An account may have this many security keys, in slots 1 to this number.
pub const MAX_KEYS: usize = 5;
const MAX_SLOT: u8 = 5;

#[derive(Serialize, Deserialize)]
struct StoredKey {
    id: u8,
    name: String,
    /// The WebAuthn credential id, base64url.
    credential_id: String,
    /// The credential as the WebAuthn library keeps it, base64url.
    credential: String,
}

#[derive(Serialize, Deserialize, Default)]
struct StoredKeys {
    keys: Vec<StoredKey>,
}

/// A security key registered somewhere else and carried over, as the move from Vaultwarden does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedKey {
    /// The slot, 1 to 5.
    pub slot: u8,
    pub name: String,
    pub credential_id: Vec<u8>,
    /// The credential as the relying party keeps it (`kemlock-identity`'s `WebAuthnRp`): the
    /// JSON of webauthn-rs-core's `Credential`.
    pub credential: Vec<u8>,
}

/// The list [`SecurityKeys`] keeps for an account, for these keys, ready to be sealed under
/// [`PURPOSE_WEBAUTHN`]. `None` when there are none or more than [`MAX_KEYS`], or two share a
/// slot.
pub fn encode_key_list(keys: &[ImportedKey]) -> Option<Vec<u8>> {
    let slots_ok = keys.iter().enumerate().all(|(i, k)| {
        (1..=MAX_SLOT).contains(&k.slot) && keys[..i].iter().all(|o| o.slot != k.slot)
    });
    if keys.is_empty() || keys.len() > MAX_KEYS || !slots_ok {
        return None;
    }
    let stored = StoredKeys {
        keys: keys
            .iter()
            .map(|k| StoredKey {
                id: k.slot,
                name: k.name.clone(),
                credential_id: b64url::encode(&k.credential_id),
                credential: b64url::encode(&k.credential),
            })
            .collect(),
    };
    serde_json::to_vec(&stored).ok()
}

/// A security key as listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityKeyInfo {
    /// The slot, 1 to 5.
    pub id: u8,
    pub name: String,
}

/// The account's security keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyList {
    /// Whether the account has a security key, so the method is on.
    pub enabled: bool,
    pub keys: Vec<SecurityKeyInfo>,
}

fn list_of(keys: &[StoredKey]) -> KeyList {
    KeyList {
        enabled: !keys.is_empty(),
        keys: keys
            .iter()
            .map(|k| SecurityKeyInfo {
                id: k.id,
                name: k.name.clone(),
            })
            .collect(),
    }
}

/// Why a security-key registration or answer failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecurityKeyError {
    /// There is no challenge to answer: none was asked for, it was answered already (right or
    /// wrong), a newer one replaced it, or it expired.
    #[error("there is no challenge to answer")]
    NoChallenge,
    /// The key's answer doesn't answer the challenge.
    #[error("the security key's answer was refused")]
    Refused,
    #[error("an account may have at most five security keys")]
    TooMany,
    /// This key is registered already.
    #[error("that security key is already registered")]
    Duplicate,
    #[error(transparent)]
    App(AppError),
}

impl From<AppError> for SecurityKeyError {
    fn from(e: AppError) -> Self {
        SecurityKeyError::App(e)
    }
}

impl From<StoreError> for SecurityKeyError {
    fn from(e: StoreError) -> Self {
        SecurityKeyError::App(AppError::from(e))
    }
}

/// The error a Kemlock registration call answers with.
impl From<SecurityKeyError> for AppError {
    fn from(e: SecurityKeyError) -> Self {
        match e {
            SecurityKeyError::NoChallenge => {
                AppError::Invalid("no security key registration is in progress, or it expired")
            }
            SecurityKeyError::Refused => {
                AppError::Invalid("the security key's answer wasn't accepted")
            }
            SecurityKeyError::TooMany => {
                AppError::Invalid("an account may have at most five security keys")
            }
            SecurityKeyError::Duplicate => AppError::Duplicate,
            SecurityKeyError::App(e) => e,
        }
    }
}

pub(super) fn key_error(e: WebAuthnError) -> SecurityKeyError {
    match e {
        WebAuthnError::Refused(why) => {
            tracing::debug!(%why, "a security key's answer was refused");
            SecurityKeyError::Refused
        }
        WebAuthnError::Malformed(_) => SecurityKeyError::Refused,
        WebAuthnError::Failed(message) => SecurityKeyError::App(AppError::Store(message)),
    }
}

/// What is stored now.
struct Loaded {
    /// When the row was made, kept across rewrites.
    created_at: Option<OffsetDateTime>,
    keys: Vec<StoredKey>,
}

/// The account's stored keys: the enabled `webauthn` row, opened; none when there is no row.
async fn load_keys<F: TwoFactorRepo, S: SecretSeal>(
    two_factor: &F,
    seal: &S,
    user: UserId,
) -> Result<Loaded, AppError> {
    let rows = two_factor.list(user).await?;
    let row = rows
        .into_iter()
        .find(|t| t.method == TwoFactorMethod::WebAuthn && t.enabled);
    let (created_at, keys) = match row {
        Some(row) => {
            let plain = open_bound(seal, PURPOSE_WEBAUTHN, user, &row.sealed_secret)
                .map_err(|_| {
                    AppError::Store("a stored security key list doesn't open".to_owned())
                })?
                .value;
            let stored: StoredKeys = serde_json::from_slice(&plain).map_err(|_| {
                AppError::Store("a stored security key list isn't valid".to_owned())
            })?;
            (Some(row.created_at), stored.keys)
        }
        None => (None, Vec::new()),
    };
    Ok(Loaded { created_at, keys })
}

/// Writes the list back; an empty list removes the row, so the method is off.
async fn save_keys<F: TwoFactorRepo, S: SecretSeal, E: Platform>(
    two_factor: &F,
    seal: &S,
    env: &E,
    user: UserId,
    created_at: Option<OffsetDateTime>,
    keys: Vec<StoredKey>,
) -> Result<(), AppError> {
    if keys.is_empty() {
        two_factor.remove(user, TwoFactorMethod::WebAuthn).await?;
        return Ok(());
    }
    let plain = serde_json::to_vec(&StoredKeys { keys })
        .map_err(|_| AppError::Store("couldn't encode the security key list".to_owned()))?;
    two_factor
        .put(&TwoFactor {
            user,
            method: TwoFactorMethod::WebAuthn,
            sealed_secret: seal_bound(seal, PURPOSE_WEBAUTHN, user, &plain),
            enabled: true,
            created_at: created_at.unwrap_or_else(|| env.now()),
        })
        .await?;
    Ok(())
}

/// An account's security keys as a ceremony that only reads and answers them needs them: their
/// credentials, and the counter kept after an answer. The admin console's step-up uses it, so a
/// security key confirms a change as a passkey or a code does.
#[derive(Debug, Clone)]
pub struct KeyCredentials<F, S, E> {
    pub two_factor: F,
    pub seal: S,
    pub env: E,
}

impl<F: TwoFactorRepo, S: SecretSeal, E: Platform> KeyCredentials<F, S, E> {
    /// Each key's credential id and credential.
    pub async fn credentials_of(&self, user: UserId) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AppError> {
        let invalid = || AppError::Store("a stored security key isn't valid".to_owned());
        load_keys(&self.two_factor, &self.seal, user)
            .await?
            .keys
            .iter()
            .map(|k| {
                Ok((
                    b64url::decode(&k.credential_id).ok_or_else(invalid)?,
                    b64url::decode(&k.credential).ok_or_else(invalid)?,
                ))
            })
            .collect()
    }

    /// Stores the credential after an answer (its counter moved) for the key with this id.
    pub async fn record_use(
        &self,
        user: UserId,
        credential_id: &[u8],
        credential: &[u8],
    ) -> Result<(), AppError> {
        let mut loaded = load_keys(&self.two_factor, &self.seal, user).await?;
        let id = b64url::encode(credential_id);
        if let Some(key) = loaded.keys.iter_mut().find(|k| k.credential_id == id) {
            key.credential = b64url::encode(credential);
            save_keys(
                &self.two_factor,
                &self.seal,
                &self.env,
                user,
                loaded.created_at,
                loaded.keys,
            )
            .await?;
        }
        Ok(())
    }
}

/// An account's security keys over their ports.
#[derive(Debug)]
pub struct SecurityKeys<U, F, C, W, S, E> {
    pub users: U,
    pub two_factor: F,
    pub challenges: C,
    pub webauthn: W,
    pub seal: S,
    pub env: E,
    pub config: AuthConfig,
}

impl<U, F, C, W, S, E> SecurityKeys<U, F, C, W, S, E>
where
    U: UserRepo,
    F: TwoFactorRepo,
    C: ChallengeRepo,
    W: WebAuthn,
    S: SecretSeal,
    E: Platform,
{
    async fn load(&self, user: UserId) -> Result<Loaded, AppError> {
        load_keys(&self.two_factor, &self.seal, user).await
    }

    /// Writes the list back; an empty list removes the row, so the method is off.
    async fn save(
        &self,
        user: UserId,
        created_at: Option<OffsetDateTime>,
        keys: Vec<StoredKey>,
    ) -> Result<(), AppError> {
        save_keys(
            &self.two_factor,
            &self.seal,
            &self.env,
            user,
            created_at,
            keys,
        )
        .await
    }

    /// The credentials of `keys`, as the relying party reads them.
    fn credentials(keys: &[StoredKey]) -> Result<Vec<Vec<u8>>, AppError> {
        keys.iter()
            .map(|k| {
                b64url::decode(&k.credential).ok_or_else(|| {
                    AppError::Store("a stored security key credential isn't valid".to_owned())
                })
            })
            .collect()
    }

    /// Each key's credential id and credential, for a ceremony that lists them.
    pub(super) async fn credentials_of(
        &self,
        user: UserId,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AppError> {
        let invalid = || AppError::Store("a stored security key isn't valid".to_owned());
        self.load(user)
            .await?
            .keys
            .iter()
            .map(|k| {
                Ok((
                    b64url::decode(&k.credential_id).ok_or_else(invalid)?,
                    b64url::decode(&k.credential).ok_or_else(invalid)?,
                ))
            })
            .collect()
    }

    /// Stores the credential after an answer (its counter moved) for the key with this id.
    pub(super) async fn record_use(
        &self,
        user: UserId,
        credential_id: &[u8],
        credential: &[u8],
    ) -> Result<(), AppError> {
        let mut loaded = self.load(user).await?;
        let id = b64url::encode(credential_id);
        if let Some(key) = loaded.keys.iter_mut().find(|k| k.credential_id == id) {
            key.credential = b64url::encode(credential);
            self.save(user, loaded.created_at, loaded.keys).await?;
        }
        Ok(())
    }

    /// The account's keys.
    pub async fn keys(&self, user: UserId) -> Result<KeyList, AppError> {
        Ok(list_of(&self.load(user).await?.keys))
    }

    /// Starts a registration: the creation options for `navigator.credentials.create`, which
    /// exclude the keys the account has, so a key is not enrolled twice.
    ///
    /// Whether a registration may start beside another method that is on is for the caller to
    /// decide: the Kemlock routes ask for a fresh proof before the method is turned on, and
    /// Bitwarden's check the master password.
    pub async fn start_registration(&self, user: UserId) -> Result<Value, AppError> {
        let account = self
            .users
            .by_id(user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let loaded = self.load(user).await?;
        if loaded.keys.len() >= MAX_KEYS {
            return Err(AppError::Invalid(
                "an account may have at most five security keys",
            ));
        }
        let exclude: Vec<Vec<u8>> = loaded
            .keys
            .iter()
            .filter_map(|k| b64url::decode(&k.credential_id))
            .collect();
        let display = account
            .name
            .clone()
            .unwrap_or_else(|| account.email.as_str().to_owned());
        let started = self
            .webauthn
            .start_registration(&RegistrationStart {
                kind: CredentialKind::SecurityKey,
                user_handle: account.id.as_bytes(),
                user_name: account.email.as_str(),
                display_name: &display,
                exclude: &exclude,
            })
            .map_err(ceremony_error)?;
        self.challenges
            .put_challenge(
                user,
                ChallengeKind::SecurityKeyRegistration,
                &started.state,
                self.env.now() + self.config.challenge_ttl,
            )
            .await?;
        Ok(started.options)
    }

    /// Finishes a registration with the browser's answer. `slot` is the number Bitwarden's client
    /// chose, 1 to 5, which replaces the key already there; `None` takes the lowest free slot.
    /// The challenge is used up whatever the answer.
    pub async fn finish_registration(
        &self,
        user: UserId,
        slot: Option<u8>,
        name: &str,
        response: &[u8],
    ) -> Result<KeyList, SecurityKeyError> {
        if let Some(slot) = slot
            && !(1..=MAX_SLOT).contains(&slot)
        {
            return Err(AppError::Invalid("the key slot must be 1 to 5").into());
        }
        let name = Passkey::clean_name(name).unwrap_or_else(|| "Security key".to_owned());
        let now = self.env.now();
        let state = self
            .challenges
            .take_challenge(user, ChallengeKind::SecurityKeyRegistration, now)
            .await?
            .ok_or(SecurityKeyError::NoChallenge)?;
        let made = self
            .webauthn
            .finish_registration(CredentialKind::SecurityKey, &state, response)
            .map_err(key_error)?;

        let mut loaded = self.load(user).await?;
        let credential_id = b64url::encode(&made.credential_id);
        if loaded.keys.iter().any(|k| k.credential_id == credential_id) {
            return Err(SecurityKeyError::Duplicate);
        }
        let slot = match slot {
            Some(slot) => slot,
            None => (1..=MAX_SLOT)
                .find(|s| !loaded.keys.iter().any(|k| k.id == *s))
                .ok_or(SecurityKeyError::TooMany)?,
        };
        let key = StoredKey {
            id: slot,
            name,
            credential_id,
            credential: b64url::encode(&made.credential),
        };
        let taken = loaded.keys.iter().position(|k| k.id == slot);
        match taken {
            Some(index) => loaded.keys[index] = key,
            None => {
                if loaded.keys.len() >= MAX_KEYS {
                    return Err(SecurityKeyError::TooMany);
                }
                loaded.keys.push(key);
            }
        }
        let list = list_of(&loaded.keys);
        self.save(user, loaded.created_at, loaded.keys).await?;
        Ok(list)
    }

    /// Removes the key in `slot`; `NotFound` when the slot is empty. With the last key gone the
    /// method is off.
    pub async fn remove(&self, user: UserId, slot: u8) -> Result<KeyList, AppError> {
        let mut loaded = self.load(user).await?;
        let before = loaded.keys.len();
        loaded.keys.retain(|k| k.id != slot);
        if loaded.keys.len() == before {
            return Err(AppError::NotFound);
        }
        let list = list_of(&loaded.keys);
        self.save(user, loaded.created_at, loaded.keys).await?;
        Ok(list)
    }

    /// Starts a sign-in: the request options for `navigator.credentials.get`, listing the
    /// account's keys. The state it keeps replaces any earlier one, so an answer to an older
    /// challenge fails. `NotFound` when the account has no key.
    pub async fn start_login(&self, user: UserId) -> Result<Value, AppError> {
        let loaded = self.load(user).await?;
        if loaded.keys.is_empty() {
            return Err(AppError::NotFound);
        }
        let credentials = Self::credentials(&loaded.keys)?;
        let refs: Vec<&[u8]> = credentials.iter().map(Vec::as_slice).collect();
        let started = self
            .webauthn
            .start_authentication(CredentialKind::SecurityKey, &refs)
            .map_err(ceremony_error)?;
        self.challenges
            .put_challenge(
                user,
                ChallengeKind::SecurityKeyLogin,
                &started.state,
                self.env.now() + self.config.challenge_ttl,
            )
            .await?;
        Ok(started.options)
    }

    /// Checks a key's answer. The challenge is taken out first, so a refused answer uses it up
    /// and the same challenge answered correctly afterwards finds none. A signature counter that
    /// didn't grow is refused; one that did is stored.
    pub async fn finish_login(
        &self,
        user: UserId,
        response: &[u8],
    ) -> Result<(), SecurityKeyError> {
        let now = self.env.now();
        let state = self
            .challenges
            .take_challenge(user, ChallengeKind::SecurityKeyLogin, now)
            .await?
            .ok_or(SecurityKeyError::NoChallenge)?;
        let mut loaded = self.load(user).await?;
        let credentials = Self::credentials(&loaded.keys)?;
        let refs: Vec<&[u8]> = credentials.iter().map(Vec::as_slice).collect();
        let assertion = self
            .webauthn
            .finish_authentication(CredentialKind::SecurityKey, &state, response, &refs)
            .map_err(key_error)?;
        let credential_id = b64url::encode(&assertion.credential_id);
        let key = loaded
            .keys
            .iter_mut()
            .find(|k| k.credential_id == credential_id)
            .ok_or(SecurityKeyError::Refused)?;
        key.credential = b64url::encode(&assertion.credential);
        self.save(user, loaded.created_at, loaded.keys).await?;
        Ok(())
    }
}
