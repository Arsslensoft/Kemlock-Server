//! Prelogin: the KDF settings and salt a client needs before it can make its master key.
//!
//! An unknown email gets settings and a salt derived from an HMAC of the email under a server
//! secret, so the answer is the same every time and looks like a real account's (docs/crypto.md,
//! "Master key"). An unknown account can't be told from a known one by asking.

use crate::error::AppError;
use crate::platform::Hasher;
use crate::ports::UserRepo;
use kemlock_domain::{Email, KdfParams};

const FAKE_SALT_LABEL: &[u8] = b"kemlock/v1/prelogin-salt";

#[derive(Debug)]
pub struct Prelogin<U, H> {
    pub users: U,
    pub hasher: H,
    /// A server secret for fake salts, derived from `server.key`.
    pub secret: [u8; 32],
}

impl<U: UserRepo, H: Hasher> Prelogin<U, H> {
    pub async fn execute(&self, email: &str) -> Result<KdfParams, AppError> {
        if email.len() > Email::MAX_LEN * 2 {
            return Err(AppError::Invalid("the email is too long"));
        }
        if let Ok(parsed) = Email::parse(email)
            && let Some(user) = self.users.by_email(&parsed).await?
        {
            return Ok(user.kdf);
        }
        Ok(self.fake(email))
    }

    /// Settings for an email with no account (or none that parses): the defaults and a salt that
    /// depends only on the email and the server secret.
    pub fn fake(&self, email: &str) -> KdfParams {
        let normalised = email.trim().to_lowercase();
        let mut data = Vec::with_capacity(FAKE_SALT_LABEL.len() + normalised.len());
        data.extend_from_slice(FAKE_SALT_LABEL);
        data.extend_from_slice(normalised.as_bytes());
        let mac = self.hasher.hmac_sha256(&self.secret, &data);
        let mut salt = [0u8; KdfParams::SALT_LEN];
        salt.copy_from_slice(&mac[..KdfParams::SALT_LEN]);
        KdfParams::new_account(salt)
    }
}
