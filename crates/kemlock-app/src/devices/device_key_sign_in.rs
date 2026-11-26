//! Signing in on a replica with the device key: a challenge, then a proof of the key the device
//! registered at its home, then tokens.
//!
//! A federated vault's members are copied to each replica with their device registrations (the
//! thumbprint of each device's DPoP key), but never their OPAQUE record, so no password can be
//! typed there. A device signs in with the key its tokens are bound to instead: it asks for a
//! challenge with a DPoP-signed call naming its device id, and sends the challenge back in a second
//! DPoP-signed call. The registration copied from the home is what says the key may sign in.
//!
//! The challenge is sealed under `server.key` with a random nonce, the device id and the key's
//! thumbprint, so the server keeps no state for it and it only opens for the key it was made for.
//! The sign-in skips the password and the two-step check: the device passed both when the home
//! registered it, and a copied account has no password here to check.
//!
//! Whether an account may use this route at all (it must be a copy, not an account that lives on
//! this server) is the API's check, made with the federation view before a challenge is sealed.

use super::approvals::same;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{
    DeviceRepo, EventLog, SecretSeal, TokenRepo, TokenSigner, TwoFactorRepo, UserRepo,
};
use crate::privacy::ensure_not_pending;
use crate::session::{Sessions, TokenPair};
use crate::sso::{MembershipFacts, RequireSso, SignInMethod};
use kemlock_domain::{Device, DeviceId, User};
use uuid::Uuid;

/// `SecretSeal` purpose of the device-key sign-in challenge.
pub const PURPOSE_DEVICE_KEY_CHALLENGE: &str = "device-key-sign-in-challenge";

const CHALLENGE_VERSION: u8 = 1;
const NONCE_LEN: usize = 32;

/// What a device-key challenge remembers.
#[derive(Debug, PartialEq, Eq)]
struct KeyChallenge {
    expires_at: i64,
    device: DeviceId,
    nonce: [u8; NONCE_LEN],
    jkt: String,
}

impl KeyChallenge {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![CHALLENGE_VERSION];
        out.extend_from_slice(&self.expires_at.max(0).to_be_bytes());
        out.extend_from_slice(self.device.0.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(self.jkt.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (&version, rest) = bytes.split_first()?;
        if version != CHALLENGE_VERSION || rest.len() < 8 + 16 + NONCE_LEN + 1 {
            return None;
        }
        let (expires, rest) = rest.split_at(8);
        let (id, rest) = rest.split_at(16);
        let (nonce, jkt) = rest.split_at(NONCE_LEN);
        Some(KeyChallenge {
            expires_at: i64::from_be_bytes(expires.try_into().ok()?),
            device: DeviceId(Uuid::from_bytes(id.try_into().ok()?)),
            nonce: nonce.try_into().ok()?,
            jkt: String::from_utf8(jkt.to_vec()).ok()?,
        })
    }
}

/// A device that holds a copied registration signs in with its key.
/// `sso` is the Require SSO check: a space that requires single sign-on closes this way in to its
/// members, a copied account included.
#[derive(Debug)]
pub struct DeviceKeySignIn<U, S, D, T, K, E, V, W, M> {
    pub users: U,
    pub seal: S,
    pub sessions: Sessions<D, T, K, E, V, W>,
    pub sso: RequireSso<M>,
}

impl<U, S, D, T, K, E, V, W, M> DeviceKeySignIn<U, S, D, T, K, E, V, W, M>
where
    U: UserRepo,
    S: SecretSeal,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    W: TwoFactorRepo,
    M: MembershipFacts,
{
    /// Whether the account of a device that proved its key may sign in: not disabled, not being deleted, and
    /// not closed to this way in by a space that requires single sign-on.
    async fn account_allows(&self, user: &User) -> Result<(), AppError> {
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled);
        }
        ensure_not_pending(&self.users, user.id).await?;
        self.sso
            .check(user, SignInMethod::DeviceKey)
            .await
            .map_err(AppError::from)
    }

    /// The registered device, if `jkt` (the thumbprint of the key that signed this call) is the
    /// key it was registered with. Anything else is `Unauthorized`, so the answer says nothing
    /// more about which device ids exist.
    pub async fn registered(&self, device: DeviceId, jkt: &str) -> Result<Device, AppError> {
        let device = self
            .sessions
            .devices
            .get(device)
            .await?
            .ok_or(AppError::Unauthorized)?;
        match device.dpop_jkt.as_deref() {
            Some(registered) if same(registered, jkt) => Ok(device),
            _ => Err(AppError::Unauthorized),
        }
    }

    /// The challenge for a registered device. `jkt` is the thumbprint of the DPoP key that signed
    /// this call: it must be the key the device was registered with.
    pub async fn challenge(&self, device: DeviceId, jkt: &str) -> Result<Vec<u8>, AppError> {
        let now = self.sessions.env.now();
        let device = self.registered(device, jkt).await?;
        let user = self
            .users
            .by_id(device.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.account_allows(&user).await?;
        let challenge = KeyChallenge {
            expires_at: (now + self.sessions.config.challenge_ttl).unix_timestamp(),
            device: device.id,
            nonce: self.sessions.env.bytes::<NONCE_LEN>(),
            jkt: jkt.to_owned(),
        };
        Ok(self
            .seal
            .seal(PURPOSE_DEVICE_KEY_CHALLENGE, &challenge.encode()))
    }

    /// Checks the challenge came back from the same key, re-reads the registration (a device
    /// signed out since has none) and signs the device in.
    pub async fn verify(&self, challenge: &[u8], jkt: &str) -> Result<TokenPair, AppError> {
        let now = self.sessions.env.now();
        let plain = self
            .seal
            .open(PURPOSE_DEVICE_KEY_CHALLENGE, challenge)
            .map_err(|_| AppError::Unauthorized)?;
        let challenge = KeyChallenge::decode(&plain).ok_or(AppError::Unauthorized)?;
        if now.unix_timestamp() >= challenge.expires_at || !same(&challenge.jkt, jkt) {
            return Err(AppError::Unauthorized);
        }
        let device = self.registered(challenge.device, jkt).await?;
        let user = self
            .users
            .by_id(device.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.account_allows(&user).await?;
        // Only the time is written, and only while the device still has this key: sessions may
        // have been ended since it was read, and writing the whole row back would put its key back.
        if !self.sessions.devices.touch_seen(device.id, jkt, now).await? {
            return Err(AppError::Unauthorized);
        }
        let device = Device {
            last_seen_at: now,
            ..device
        };
        let tokens = self.sessions.issue(&user, &device, jkt, None).await?;
        self.sessions
            .record("auth.device_key", user.id, Some(device.id))
            .await;
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_round_trips() {
        let c = KeyChallenge {
            expires_at: 1_800_000_000,
            device: DeviceId(Uuid::from_bytes([3; 16])),
            nonce: [7; NONCE_LEN],
            jkt: "thumbprint".to_owned(),
        };
        assert_eq!(KeyChallenge::decode(&c.encode()), Some(c));
    }

    #[test]
    fn a_truncated_or_unknown_version_challenge_is_refused() {
        let c = KeyChallenge {
            expires_at: 5,
            device: DeviceId(Uuid::from_bytes([1; 16])),
            nonce: [1; NONCE_LEN],
            jkt: "k".to_owned(),
        };
        let bytes = c.encode();
        assert_eq!(KeyChallenge::decode(&bytes[..bytes.len() - 1]), None);
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(KeyChallenge::decode(&bad), None);
        assert_eq!(KeyChallenge::decode(&[]), None);
    }
}
