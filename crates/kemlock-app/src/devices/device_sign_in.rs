//! Signing in as an approved device: a challenge, then a proof of the key registered with the
//! request, then tokens.
//!
//! The device registered a DPoP key with its approval request. To sign in it asks for a challenge
//! (a DPoP-signed call, so the server knows the key) and sends the challenge back in a second
//! DPoP-signed call. The challenge is sealed under `server.key` with a random nonce, the request id
//! and the key's thumbprint, so the server keeps no state for it, and it only opens for the key it
//! was made for. The approval is used up by the sign-in: a replayed challenge finds it consumed.
//!
//! The sign-in skips the password and the two-step check: an open device that already passed both
//! approved it, and the phrase check is the person's proof they are at the new device.

use super::approvals::same;
use super::ports::ApprovalRepo;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{
    DeviceRepo, EventLog, SecretSeal, TokenRepo, TokenSigner, TwoFactorRepo, UserRepo,
};
use crate::privacy::ensure_not_pending;
use crate::session::{DeviceInfo, Sessions, TokenPair};
use crate::sso::{MembershipFacts, RequireSso, SignInMethod};
use kemlock_domain::unlock::{ApprovalId, ApprovalState, AuthRequest};
use uuid::Uuid;

/// `SecretSeal` purpose of the device sign-in challenge.
pub const PURPOSE_DEVICE_CHALLENGE: &str = "device-sign-in-challenge";

const CHALLENGE_VERSION: u8 = 1;
const NONCE_LEN: usize = 32;

/// What a device challenge remembers.
#[derive(Debug, PartialEq, Eq)]
struct DeviceChallenge {
    expires_at: i64,
    request: ApprovalId,
    nonce: [u8; NONCE_LEN],
    jkt: String,
}

impl DeviceChallenge {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![CHALLENGE_VERSION];
        out.extend_from_slice(&self.expires_at.max(0).to_be_bytes());
        out.extend_from_slice(self.request.0.as_bytes());
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
        Some(DeviceChallenge {
            expires_at: i64::from_be_bytes(expires.try_into().ok()?),
            request: ApprovalId(Uuid::from_bytes(id.try_into().ok()?)),
            nonce: nonce.try_into().ok()?,
            jkt: String::from_utf8(jkt.to_vec()).ok()?,
        })
    }
}

/// An approved device signs in.
/// `sso` is the Require SSO check: a space that requires single sign-on closes this way in to its
/// members, whoever approved it.
#[derive(Debug)]
pub struct DeviceSignIn<U, A, S, D, T, K, E, V, W, M> {
    pub users: U,
    pub approvals: A,
    pub seal: S,
    pub sessions: Sessions<D, T, K, E, V, W>,
    pub sso: RequireSso<M>,
}

impl<U, A, S, D, T, K, E, V, W, M> DeviceSignIn<U, A, S, D, T, K, E, V, W, M>
where
    U: UserRepo,
    A: ApprovalRepo,
    S: SecretSeal,
    D: DeviceRepo,
    T: TokenRepo,
    K: TokenSigner,
    E: Platform,
    V: EventLog,
    W: TwoFactorRepo,
    M: MembershipFacts,
{
    /// The challenge for an approved request. `jkt` is the thumbprint of the DPoP key that signed
    /// this call: it must be the key registered with the request. Anything else (unknown request,
    /// another key, not approved, expired) is `Unauthorized`, so the answer says nothing more.
    pub async fn challenge(&self, id: ApprovalId, jkt: &str) -> Result<Vec<u8>, AppError> {
        let now = self.sessions.env.now();
        let request = self.redeemable(id, jkt).await?;
        self.require_sso_allows(&request).await?;
        let nonce = self.sessions.env.bytes::<NONCE_LEN>();
        // A challenge never outlives the approval it is for.
        let expires_at = (now + self.sessions.config.challenge_ttl)
            .min(request.expires_at)
            .unix_timestamp();
        let challenge = DeviceChallenge {
            expires_at,
            request: id,
            nonce,
            jkt: jkt.to_owned(),
        };
        Ok(self
            .seal
            .seal(PURPOSE_DEVICE_CHALLENGE, &challenge.encode()))
    }

    /// Checks the challenge came back from the same key, uses the approval up, registers the device
    /// and signs it in.
    pub async fn verify(&self, challenge: &[u8], jkt: &str) -> Result<TokenPair, AppError> {
        let now = self.sessions.env.now();
        let plain = self
            .seal
            .open(PURPOSE_DEVICE_CHALLENGE, challenge)
            .map_err(|_| AppError::Unauthorized)?;
        let challenge = DeviceChallenge::decode(&plain).ok_or(AppError::Unauthorized)?;
        if now.unix_timestamp() >= challenge.expires_at || !same(&challenge.jkt, jkt) {
            return Err(AppError::Unauthorized);
        }
        let mut request = self.redeemable(challenge.request, jkt).await?;
        // Before the approval is used up: a refusal leaves it for a way in that isn't closed.
        self.require_sso_allows(&request).await?;
        let from = request.state;
        request.consume(now).map_err(|_| AppError::Unauthorized)?;
        if !self.approvals.save_request(&request, from).await? {
            // Another call used the approval first.
            return Err(AppError::Unauthorized);
        }
        let user = self
            .users
            .by_id(request.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let device = self
            .sessions
            .register_device(
                user.id,
                &DeviceInfo {
                    id: Some(request.device),
                    name: request.device_name,
                    kind: request.device_kind,
                    bitwarden_identifier: None,
                },
                jkt,
            )
            .await?;
        let tokens = self.sessions.issue(&user, &device, jkt, None).await?;
        self.sessions
            .record("auth.device_approval", user.id, Some(device.id))
            .await;
        Ok(tokens)
    }

    /// Whether the request's account may sign in at all: not disabled, and not closed to this way
    /// in by a space that requires single sign-on. The caller has already shown the approved
    /// request's key, so the answer may say which.
    async fn require_sso_allows(&self, request: &AuthRequest) -> Result<(), AppError> {
        let user = self
            .users
            .by_id(request.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if self.users.account_disabled(user.id).await? {
            return Err(AppError::AccountDisabled);
        }
        ensure_not_pending(&self.users, user.id).await?;
        self.sso
            .check(&user, SignInMethod::PhoneApproval)
            .await
            .map_err(AppError::from)
    }

    /// The request, if it is approved, unexpired and belongs to this key.
    async fn redeemable(&self, id: ApprovalId, jkt: &str) -> Result<AuthRequest, AppError> {
        let now = self.sessions.env.now();
        let request = self
            .approvals
            .request(id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if !same(&request.jkt, jkt)
            || request.state != ApprovalState::Approved
            || request.is_expired(now)
        {
            return Err(AppError::Unauthorized);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_round_trips() {
        let c = DeviceChallenge {
            expires_at: 1_800_000_000,
            request: ApprovalId::random(),
            nonce: [7; NONCE_LEN],
            jkt: "thumbprint".to_owned(),
        };
        assert_eq!(DeviceChallenge::decode(&c.encode()), Some(c));
    }

    #[test]
    fn a_truncated_or_unknown_version_challenge_is_refused() {
        let c = DeviceChallenge {
            expires_at: 5,
            request: ApprovalId::random(),
            nonce: [1; NONCE_LEN],
            jkt: "k".to_owned(),
        };
        let bytes = c.encode();
        assert_eq!(DeviceChallenge::decode(&bytes[..bytes.len() - 1]), None);
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(DeviceChallenge::decode(&bad), None);
        assert_eq!(DeviceChallenge::decode(&[]), None);
    }
}
