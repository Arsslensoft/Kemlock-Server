//! Enrol TOTP: makes an authenticator-app secret for the signed-in account and stores it sealed
//! (purpose `"totp"`, bound to the account's id), not yet enabled. `confirm_totp` enables it once a
//! code from the app checks.

use crate::error::AppError;
use crate::platform::Platform;
use crate::ports::{SecretSeal, TwoFactor, TwoFactorMethod, TwoFactorRepo, UserRepo, Zeroizing};
use crate::sealed::{PURPOSE_TOTP, seal_bound};
use kemlock_domain::UserId;

/// The secret as RFC 6238 apps take it.
pub const SECRET_LEN: usize = 20;
const ISSUER: &str = "Kemlock";

#[derive(Debug)]
pub struct EnrolTotp<U, F, S, E> {
    pub users: U,
    pub two_factor: F,
    pub seal: S,
    pub env: E,
}

/// What the account's owner scans or types into an authenticator app.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpEnrolment {
    /// The secret in RFC 4648 base32 without padding.
    pub secret: String,
    /// An `otpauth://totp/…` URI for a QR code.
    pub uri: String,
}

impl std::fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrolment").finish_non_exhaustive()
    }
}

impl<U: UserRepo, F: TwoFactorRepo, S: SecretSeal, E: Platform> EnrolTotp<U, F, S, E> {
    /// Starts (or restarts) an enrolment. An enrolment that is already confirmed is refused with
    /// `Duplicate`, so a stolen session can't swap a second step for one it controls.
    pub async fn execute(&self, user: UserId) -> Result<TotpEnrolment, AppError> {
        let account = self
            .users
            .by_id(user)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let existing = self.two_factor.list(user).await?;
        if existing
            .iter()
            .any(|t| t.method == TwoFactorMethod::Totp && t.enabled)
        {
            return Err(AppError::Duplicate);
        }
        // Wiped when this call ends, like every opened copy of it.
        let secret = Zeroizing::new(self.env.bytes::<SECRET_LEN>());
        self.two_factor
            .put(&TwoFactor {
                user,
                method: TwoFactorMethod::Totp,
                sealed_secret: seal_bound(&self.seal, PURPOSE_TOTP, user, &secret[..]),
                enabled: false,
                created_at: self.env.now(),
            })
            .await?;
        let secret = base32(&secret[..]);
        let uri = format!(
            "otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
            issuer = percent_encode(ISSUER),
            label = percent_encode(account.email.as_str()),
        );
        Ok(TotpEnrolment { secret, uri })
    }
}

/// RFC 4648 base32, upper case, no padding.
pub fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn percent_encoding_keeps_unreserved_and_escapes_the_rest() {
        assert_eq!(percent_encode("a.b-c_d~e"), "a.b-c_d~e");
        assert_eq!(percent_encode("a+b@c.co"), "a%2Bb%40c.co");
    }
}
