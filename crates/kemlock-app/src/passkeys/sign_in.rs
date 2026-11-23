//! Signing in with a passkey: a challenge, then the authenticator's signature over it, then
//! tokens.
//!
//! The server keeps no state for the challenge. The WebAuthn state goes to the client sealed under
//! `server.key` (purpose `"passkey-challenge"`) with a 5-minute expiry and the thumbprint of the
//! DPoP key that asked, and comes back with the answer; the API remembers a returned challenge as
//! used, so it is good once. A passkey is a discoverable credential, so the challenge lists no
//! credentials and names no account: nobody learns whether an address has passkeys.
//!
//! A passkey signs in and, when it has a PRF copy of the root key, hands that copy back so the
//! client can open the vault. User verification is required, so the sign-in skips the second step:
//! the gesture was already possession and a PIN or a body check.
//!
//! A disabled account is refused (`AppError::AccountDisabled`) once the passkey checks out, and
//! "Require SSO" blocks the sign-in for members it binds ([`RequireSso::check`]), after the
//! signature checks, so nobody can probe an account's spaces without holding its passkey.

use super::ceremony_error;
use super::ports::PasskeyRepo;
use super::webauthn::{CredentialKind, WebAuthn};
use crate::b64url;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{
    DeviceRepo, EventLog, SecretSeal, TokenRepo, TokenSigner, TwoFactorRepo, UserRepo,
};
use crate::privacy::ensure_not_pending;
use crate::session::{DeviceInfo, Sessions, TokenPair};
use crate::sso::{MembershipFacts, RequireSso, SignInMethod, SsoError};
use kemlock_domain::{PasskeyId, PrfWrap};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;

/// `SecretSeal` purpose of the passkey sign-in challenge.
pub const PURPOSE_PASSKEY_CHALLENGE: &str = "passkey-challenge";

const CHALLENGE_VERSION: u8 = 1;

/// What a sealed challenge remembers.
#[derive(Serialize, Deserialize)]
struct SignInChallenge {
    v: u8,
    /// Unix seconds.
    exp: i64,
    /// The DPoP key that asked: only the same key may answer.
    jkt: String,
    /// The WebAuthn state, base64url.
    state: String,
}

/// Passkey sign-in over its ports.
#[derive(Debug)]
pub struct PasskeySignIn<U, P, W, S, D, T, K, E, V, F, M> {
    pub users: U,
    pub passkeys: P,
    pub webauthn: W,
    pub seal: S,
    pub sso: RequireSso<M>,
    pub sessions: Sessions<D, T, K, E, V, F>,
}

/// The first half of a sign-in.
#[derive(Clone, Debug, PartialEq)]
pub struct PasskeyChallenge {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`.
    pub options: Value,
    /// The sealed state; the client sends it back unread with the authenticator's answer.
    pub challenge: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PasskeyVerifyInput {
    /// The sealed challenge from `options`.
    pub challenge: Vec<u8>,
    /// The `PublicKeyCredential` as JSON (`toJSON()`).
    pub response: Vec<u8>,
    pub device: DeviceInfo,
    /// The thumbprint of the DPoP key that signed this request; must be the one that asked.
    pub jkt: String,
}

/// A passkey sign-in that succeeded.
#[derive(Clone, Debug)]
pub struct PasskeySignedIn {
    pub tokens: TokenPair,
    /// The passkey used.
    pub passkey: PasskeyId,
    /// The root key wrapped under the PRF output, when this passkey has a copy for the account's
    /// current key version. Without one the sign-in opens no vault: a device or the password does.
    pub prf_wrap: Option<PrfWrap>,
    /// The account's key version now.
    pub key_version: u32,
}

impl<U, P, W, S, D, T, K, E, V, F, M> PasskeySignIn<U, P, W, S, D, T, K, E, V, F, M>
where
    U: UserRepo,
    P: PasskeyRepo,
    W: WebAuthn,
    S: SecretSeal,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    F: TwoFactorRepo,
    M: MembershipFacts,
{
    /// The options for a sign-in, for the DPoP key `jkt` that asked. Anyone may ask: nothing in
    /// the answer depends on an account.
    pub fn options(&self, jkt: &str) -> Result<PasskeyChallenge, AppError> {
        let started = self
            .webauthn
            .start_authentication(CredentialKind::Passkey, &[])
            .map_err(ceremony_error)?;
        let exp = (self.sessions.env.now() + self.sessions.config.challenge_ttl).unix_timestamp();
        let plain = serde_json::to_vec(&SignInChallenge {
            v: CHALLENGE_VERSION,
            exp,
            jkt: jkt.to_owned(),
            state: b64url::encode(&started.state),
        })
        .map_err(|_| AppError::Store("couldn't encode a passkey challenge".to_owned()))?;
        Ok(PasskeyChallenge {
            options: started.options,
            challenge: self.seal.seal(PURPOSE_PASSKEY_CHALLENGE, &plain),
        })
    }

    fn open_challenge(&self, sealed: &[u8]) -> Result<SignInChallenge, AppError> {
        let plain = self
            .seal
            .open(PURPOSE_PASSKEY_CHALLENGE, sealed)
            .map_err(|_| AppError::Invalid("the passkey challenge is invalid"))?;
        let challenge: SignInChallenge = serde_json::from_slice(&plain)
            .map_err(|_| AppError::Invalid("the passkey challenge is invalid"))?;
        if challenge.v != CHALLENGE_VERSION
            || self.sessions.env.now().unix_timestamp() >= challenge.exp
        {
            return Err(AppError::Invalid("the passkey challenge has expired"));
        }
        Ok(challenge)
    }

    /// Whether `sealed` is a genuine, unexpired challenge. The API checks this before it
    /// remembers the challenge as used, so made-up ones take no room in that memory.
    pub fn check_challenge(&self, sealed: &[u8]) -> Result<(), AppError> {
        self.open_challenge(sealed).map(|_| ())
    }

    /// The second half: checks the authenticator's answer and signs the device in.
    ///
    /// A wrong challenge, key, credential, signature or counter is `Unauthorized` and says no
    /// more. `SsoError::SsoRequired` means the passkey was right but a space the account belongs to
    /// requires single sign-on.
    pub async fn verify(&self, input: PasskeyVerifyInput) -> Result<PasskeySignedIn, SsoError> {
        let challenge = self
            .open_challenge(&input.challenge)
            .map_err(|_| AppError::Unauthorized)?;
        if !bool::from(challenge.jkt.as_bytes().ct_eq(input.jkt.as_bytes())) {
            return Err(AppError::Unauthorized.into());
        }
        let state = b64url::decode(&challenge.state).ok_or(AppError::Unauthorized)?;

        let ids = self
            .webauthn
            .response_ids(&input.response)
            .map_err(|_| AppError::Unauthorized)?;
        let passkey = self
            .passkeys
            .passkey_by_credential(&ids.credential_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        // A discoverable credential answers with the user handle it was made for; one that names
        // another account is not this passkey's.
        if let Some(handle) = &ids.user_handle
            && !bool::from(handle.as_slice().ct_eq(passkey.user.as_bytes()))
        {
            return Err(AppError::Unauthorized.into());
        }
        let user = self
            .users
            .by_id(passkey.user)
            .await?
            .ok_or(AppError::Unauthorized)?;

        let assertion = self
            .webauthn
            .finish_authentication(
                CredentialKind::Passkey,
                &state,
                &input.response,
                &[passkey.credential.as_slice()],
            )
            .map_err(|e| {
                tracing::debug!(error = %e, "a passkey sign-in was refused");
                AppError::Unauthorized
            })?;
        if !assertion.user_verified {
            return Err(AppError::Unauthorized.into());
        }
        // The authenticator's counter moved whatever happens next, so keep it.
        let now = self.sessions.env.now();
        self.passkeys
            .record_passkey_use(passkey.id, &assertion.credential, now)
            .await?;

        // The passkey is proved, so the account may be told it is disabled.
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled.into());
        }
        ensure_not_pending(&self.users, user.id).await?;
        self.sso.check(&user, SignInMethod::Passkey).await?;

        let device = self
            .sessions
            .register_device(user.id, &input.device, &input.jkt)
            .await?;
        let tokens = self
            .sessions
            .issue(&user, &device, &input.jkt, None)
            .await?;
        self.sessions
            .record("auth.passkey_sign_in", user.id, Some(device.id))
            .await;
        let prf_wrap = passkey
            .prf_wrap
            .filter(|wrap| wrap.key_version == user.key_version);
        Ok(PasskeySignedIn {
            tokens,
            passkey: passkey.id,
            prf_wrap,
            key_version: user.key_version,
        })
    }
}
