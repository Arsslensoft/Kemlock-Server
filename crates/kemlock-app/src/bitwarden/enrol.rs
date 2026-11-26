//! A Compatible account moves to OPAQUE in one exchange.
//!
//! A copied Vaultwarden account has no OPAQUE record yet, only the Bitwarden master password hash
//! the Bitwarden API checks. The Kemlock app sends that hash once, to `start`, which checks it the
//! way the Bitwarden API does and answers OPAQUE's first registration message with a sealed ticket.
//! `finish` takes the ticket, OPAQUE's last registration message and the keys the app made, and
//! stores them. The account stays Compatible: its Bitwarden record, its security stamp (so Bitwarden
//! apps stay signed in) and its root key are untouched, and the app signs in again through OPAQUE
//! on `/kem/v1`.
//!
//! The hash alone proves the password, not the second step. An account with a two-step method
//! therefore also needs a current code at `finish`, or anyone who guessed the password could replace
//! the account's published keys.

use super::ports::{BwAccount, BwAccountRepo};
use crate::config::AuthConfig;
use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{
    Event, EventLog, PasswordAuth, SecretSeal, Totp, TwoFactorMethod, TwoFactorRepo, UserRepo,
};
use crate::register::{RegisterInput, check_keys};
use crate::sealed::{PURPOSE_TOTP, open_bound};
use kemlock_domain::{AccountMode, Email, KdfParams, User, UserId};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// `SecretSeal` purpose of the ticket `start` hands out.
pub const PURPOSE_BW_ENROL: &str = "bitwarden-enrol";

/// The longest `masterPasswordHash` accepted. Bitwarden's is 44 characters of base64.
pub const MAX_PASSWORD_HASH_LEN: usize = 256;

/// The Bitwarden API's password check (PBKDF2-HMAC-SHA-256 over the hash's text), which the
/// server wires to the same code `kemlock-api-bw` uses.
pub trait BwPasswordCheck: Send + Sync {
    /// Whether `stored` is the hash of `secret` under `salt` and `iterations`, in constant time.
    /// An empty `stored` (an account with no password) never matches.
    fn matches(&self, secret: &[u8], salt: &[u8], stored: &[u8], iterations: u32) -> bool;
}

#[derive(Debug)]
pub struct BitwardenEnrol<U, B, H, P, S, F, O, V, E> {
    pub users: U,
    pub accounts: B,
    pub check: H,
    pub auth: P,
    pub seal: S,
    pub two_factor: F,
    pub totp: O,
    pub events: V,
    pub env: E,
    pub config: AuthConfig,
}

#[derive(Clone, Debug)]
pub struct EnrolStartInput {
    pub email: String,
    /// The text of the client's `masterPasswordHash`.
    pub master_password_hash: String,
    /// OPAQUE's `RegistrationRequest`.
    pub request: Vec<u8>,
    /// The thumbprint of the DPoP key that signed the request; the ticket is bound to it.
    pub jkt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolStarted {
    /// The account being enrolled.
    pub user: UserId,
    /// The account's Bitwarden user key wrapped under its master key, as the Bitwarden API's
    /// `key` (`akey`) carries it, so the client can build the finish upload without a sync.
    pub key: String,
    /// OPAQUE's `RegistrationResponse`.
    pub response: Vec<u8>,
    /// The sealed ticket to send back with the last message.
    pub ticket: Vec<u8>,
    /// The second-step methods the account has; `finish` needs a code when any is there.
    pub two_factor: Vec<TwoFactorMethod>,
}

#[derive(Clone, Debug)]
pub struct EnrolFinishInput {
    pub ticket: Vec<u8>,
    /// OPAQUE's `RegistrationUpload`.
    pub upload: Vec<u8>,
    pub kdf: KdfParams,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    pub wrapped_root_key: Vec<u8>,
    /// A current TOTP code, for an account that has the method.
    pub two_factor_code: Option<String>,
    /// The thumbprint of the DPoP key that signed the request.
    pub jkt: String,
}

/// What the ticket remembers: whose password was proven, for which key, until when.
struct Ticket {
    expires_at: i64,
    user: UserId,
    jkt: String,
}

impl Ticket {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&self.expires_at.max(0).to_be_bytes());
        out.extend_from_slice(self.user.as_bytes());
        out.extend_from_slice(self.jkt.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Ticket> {
        let (&version, rest) = bytes.split_first()?;
        if version != 1 || rest.len() < 8 + 16 {
            return None;
        }
        let (expires, rest) = rest.split_at(8);
        let (user, jkt) = rest.split_at(16);
        let mut expires_bytes = [0u8; 8];
        expires_bytes.copy_from_slice(expires);
        let mut user_bytes = [0u8; 16];
        user_bytes.copy_from_slice(user);
        Some(Ticket {
            expires_at: i64::from_be_bytes(expires_bytes),
            user: UserId(Uuid::from_bytes(user_bytes)),
            jkt: String::from_utf8(jkt.to_vec()).ok()?,
        })
    }
}

fn same(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

impl<U, B, H, P, S, F, O, V, E> BitwardenEnrol<U, B, H, P, S, F, O, V, E>
where
    U: UserRepo,
    B: BwAccountRepo,
    H: BwPasswordCheck,
    P: PasswordAuth,
    S: SecretSeal,
    F: TwoFactorRepo,
    O: Totp,
    V: EventLog,
    E: Platform,
{
    /// Checks the Bitwarden hash and answers OPAQUE's first registration message. An unknown
    /// email, an account that isn't Compatible and a wrong hash all answer `Unauthorized`, so the
    /// route can't be used to find accounts; a right hash on an account that has enrolled already
    /// is `Duplicate`.
    pub async fn start(&self, input: EnrolStartInput) -> Result<EnrolStarted, AppError> {
        if input.master_password_hash.is_empty()
            || input.master_password_hash.len() > MAX_PASSWORD_HASH_LEN
        {
            return Err(AppError::Invalid("the master password hash is malformed"));
        }
        let email = Email::parse(&input.email).map_err(|_| AppError::Unauthorized)?;
        let (user, account) = self.compatible(&email).await?;
        if !self.check.matches(
            input.master_password_hash.as_bytes(),
            &account.salt,
            &account.password_hash,
            account.password_iterations,
        ) {
            return Err(AppError::Unauthorized);
        }
        if user.opaque_record.is_some() || !user.public_bundle.is_empty() {
            return Err(AppError::Duplicate);
        }
        let response = self
            .auth
            .registration_response(email.as_str().as_bytes(), &input.request)?;
        let expires_at = (self.env.now() + self.config.challenge_ttl).unix_timestamp();
        let ticket = Ticket {
            expires_at,
            user: user.id,
            jkt: input.jkt,
        };
        let methods = self.two_step_methods(user.id).await?;
        Ok(EnrolStarted {
            user: user.id,
            key: account.akey,
            response,
            ticket: self.seal.seal(PURPOSE_BW_ENROL, &ticket.encode()),
            two_factor: methods,
        })
    }

    /// Stores the OPAQUE record and the account's keys, after the same checks a registration
    /// makes. The account's mode, security stamp and Bitwarden record stay as they were.
    pub async fn finish(&self, input: EnrolFinishInput) -> Result<UserId, AppError> {
        let ticket = self.open_ticket(&input.ticket)?;
        let now = self.env.now();
        if !same(&ticket.jkt, &input.jkt) {
            return Err(AppError::Unauthorized);
        }
        let mut user = self
            .users
            .by_id(ticket.user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if user.mode != AccountMode::Compatible || self.accounts.get(user.id).await?.is_none() {
            return Err(AppError::Unauthorized);
        }
        if user.opaque_record.is_some() || !user.public_bundle.is_empty() {
            return Err(AppError::Duplicate);
        }
        self.require_second_step(user.id, input.two_factor_code.as_deref())
            .await?;
        check_keys(&RegisterInput {
            user: user.id,
            email: user.email.as_str().to_owned(),
            name: None,
            upload: input.upload.clone(),
            kdf: input.kdf.clone(),
            public_bundle: input.public_bundle.clone(),
            bundle_signature: input.bundle_signature.clone(),
            sealed_private_keys: input.sealed_private_keys.clone(),
            wrapped_root_key: input.wrapped_root_key.clone(),
            setup_grant: None,
        })?;
        let record = self.auth.registration_record(&input.upload)?;

        user.opaque_record = Some(record);
        user.kdf = input.kdf;
        user.wrapped_root_key = input.wrapped_root_key;
        user.public_bundle = input.public_bundle;
        user.bundle_signature = input.bundle_signature;
        user.sealed_private_keys = input.sealed_private_keys;
        user.key_version = crate::register::FIRST_KEY_VERSION;
        user.updated_at = now;
        self.users.update(&user).await?;

        let event = Event {
            actor: Some(user.id),
            device: None,
            action: "auth.bitwarden_enrol",
            target: None,
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(error = %e, "could not record an OPAQUE enrolment");
        }
        Ok(user.id)
    }

    /// The account a genuine, unexpired ticket is for. The API counts second-step failures per
    /// account with it, before any code is looked at.
    pub fn ticket_user(&self, ticket: &[u8]) -> Result<UserId, AppError> {
        Ok(self.open_ticket(ticket)?.user)
    }

    fn open_ticket(&self, sealed: &[u8]) -> Result<Ticket, AppError> {
        let plain = self
            .seal
            .open(PURPOSE_BW_ENROL, sealed)
            .map_err(|_| AppError::Invalid("the ticket is invalid"))?;
        let ticket = Ticket::decode(&plain).ok_or(AppError::Invalid("the ticket is invalid"))?;
        if self.env.now().unix_timestamp() >= ticket.expires_at {
            return Err(AppError::Invalid("the ticket has expired"));
        }
        Ok(ticket)
    }

    /// The Compatible account behind an email, with its Bitwarden record. Anything else is
    /// `Unauthorized`.
    async fn compatible(&self, email: &Email) -> Result<(User, BwAccount), AppError> {
        let user = self
            .users
            .by_email(email)
            .await?
            .filter(|u| u.mode == AccountMode::Compatible)
            .ok_or(AppError::Unauthorized)?;
        let account = self
            .accounts
            .get(user.id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        Ok((user, account))
    }

    async fn two_step_methods(&self, user: UserId) -> Result<Vec<TwoFactorMethod>, AppError> {
        Ok(self
            .two_factor
            .list(user)
            .await?
            .into_iter()
            .filter(|t| t.enabled)
            .map(|t| t.method)
            .collect())
    }

    /// An account with a two-step method needs a current code for it. A security key can't be
    /// used here, so such an account signs in to the web vault first.
    async fn require_second_step(&self, user: UserId, code: Option<&str>) -> Result<(), AppError> {
        let enabled: Vec<_> = self
            .two_factor
            .list(user)
            .await?
            .into_iter()
            .filter(|t| t.enabled)
            .collect();
        if enabled.is_empty() {
            return Ok(());
        }
        let Some(totp) = enabled.iter().find(|t| t.method == TwoFactorMethod::Totp) else {
            return Err(AppError::Forbidden);
        };
        let code = code.ok_or(AppError::Unauthorized)?;
        let secret = open_bound(&self.seal, PURPOSE_TOTP, user, &totp.sealed_secret)
            .map_err(|_| AppError::Store("a stored TOTP secret does not open".to_owned()))?;
        let step = self
            .totp
            .verify_step(&secret.value, code.trim(), self.env.now())
            .ok_or(AppError::Unauthorized)?;
        if !self.two_factor.accept_totp_step(user, step).await? {
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_round_trips_and_refuses_damage() {
        let ticket = Ticket {
            expires_at: 1_700_000_000,
            user: UserId::random(),
            jkt: "thumb".to_owned(),
        };
        let bytes = ticket.encode();
        let back = Ticket::decode(&bytes).expect("decodes");
        assert_eq!(back.expires_at, ticket.expires_at);
        assert_eq!(back.user, ticket.user);
        assert_eq!(back.jkt, "thumb");
        assert!(Ticket::decode(&bytes[..20]).is_none());
        let mut other_version = bytes.clone();
        other_version[0] = 2;
        assert!(Ticket::decode(&other_version).is_none());
        assert!(Ticket::decode(&[]).is_none());
    }
}
