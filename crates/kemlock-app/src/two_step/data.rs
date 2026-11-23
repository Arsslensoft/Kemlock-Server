// Partly ported from Vaultwarden 1.37.5 (https://github.com/dani-garcia/vaultwarden, tag 1.37.5):
//   src/api/core/two_factor/email.rs (EmailTokenData, as EmailData; obscure_email).
// Copyright (C) Daniel García and the Vaultwarden contributors. Licensed AGPL-3.0-only, the licence
// of this repository. See NOTICE item 6.

//! What each two-step method keeps in its `two_factor` row, in Vaultwarden's own JSON, so a
//! setup moved from Vaultwarden is read as it was written.
//!
//! The row's `sealed_secret` is that JSON sealed under `server.key`, with a purpose per method.

use crate::ports::{Random, SecretSeal, TwoFactorMethod};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// `SecretSeal` purpose of an email setup's row.
pub const PURPOSE_EMAIL: &str = "two-step-email";
/// `SecretSeal` purpose of a YubiKey setup's row.
pub const PURPOSE_YUBIKEY: &str = "two-step-yubikey";
/// `SecretSeal` purpose of a Duo setup's row.
pub const PURPOSE_DUO: &str = "two-step-duo";
/// `SecretSeal` purpose of an email address waiting for its first code.
pub(crate) const PURPOSE_EMAIL_SETUP: &str = "two-step-email-setup";
/// `SecretSeal` purpose of a Duo prompt waiting for its answer.
pub(crate) const PURPOSE_DUO_PROMPT: &str = "two-step-duo-prompt";

/// Bitwarden's number for an email code.
pub const PROVIDER_EMAIL: i32 = 1;
/// Bitwarden's number for Duo.
pub const PROVIDER_DUO: i32 = 2;
/// Bitwarden's number for a YubiKey.
pub const PROVIDER_YUBIKEY: i32 = 3;

/// Bitwarden's number for a method: 0 an authenticator app, 1 email, 2 Duo, 3 a YubiKey, 7 a
/// security key.
pub fn provider_type(method: TwoFactorMethod) -> i32 {
    match method {
        TwoFactorMethod::Totp => 0,
        TwoFactorMethod::Email => PROVIDER_EMAIL,
        TwoFactorMethod::Duo => PROVIDER_DUO,
        TwoFactorMethod::YubiKey => PROVIDER_YUBIKEY,
        TwoFactorMethod::WebAuthn => 7,
    }
}

/// The method Bitwarden's number names, for the numbers that are two-step methods.
pub fn method_of_provider(provider: i32) -> Option<TwoFactorMethod> {
    match provider {
        0 => Some(TwoFactorMethod::Totp),
        PROVIDER_EMAIL => Some(TwoFactorMethod::Email),
        PROVIDER_DUO => Some(TwoFactorMethod::Duo),
        PROVIDER_YUBIKEY => Some(TwoFactorMethod::YubiKey),
        7 => Some(TwoFactorMethod::WebAuthn),
        _ => None,
    }
}

/// What an email setup keeps: Vaultwarden's `EmailTokenData`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailData {
    /// Where the codes go. It can be another address than the account's.
    pub email: String,
    /// The last code sent and not yet entered; `None` once it was used.
    pub last_token: Option<String>,
    /// When it was sent, in Unix seconds.
    pub token_sent: i64,
    /// Wrong entries of `last_token`.
    pub attempts: u64,
}

impl EmailData {
    pub(crate) fn new(email: String, token: Option<String>, now: i64) -> Self {
        EmailData {
            email,
            last_token: token,
            token_sent: now,
            attempts: 0,
        }
    }

    pub(crate) fn set_token(&mut self, token: String, now: i64) {
        self.last_token = Some(token);
        self.token_sent = now;
    }

    pub(crate) fn reset_token(&mut self) {
        self.last_token = None;
        self.attempts = 0;
    }
}

/// What a YubiKey setup keeps: Vaultwarden's `YubikeyMetadata`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct YubikeyData {
    /// The public ids (the first 12 characters of an OTP) of the registered keys.
    #[serde(rename = "keys", alias = "Keys")]
    pub keys: Vec<String>,
    /// Whether the keys are read over NFC.
    #[serde(rename = "nfc", alias = "Nfc")]
    pub nfc: bool,
}

/// A Duo integration: its API host and the integration key and secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuoKeys {
    pub host: String,
    /// The integration key (client id).
    pub ik: String,
    /// The secret key (client secret).
    pub sk: String,
}

impl std::fmt::Debug for DuoKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuoKeys")
            .field("host", &self.host)
            .field("ik", &self.ik)
            .field("sk", &"<redacted>")
            .finish()
    }
}

impl DuoKeys {
    /// Whether every part is there.
    pub fn is_complete(&self) -> bool {
        !self.host.trim().is_empty() && !self.ik.trim().is_empty() && !self.sk.trim().is_empty()
    }

    /// The first four characters of each part, as the web vault shows them.
    pub fn obscured(&self) -> DuoKeys {
        let hide = |s: &str| format!("{}************", s.chars().take(4).collect::<String>());
        DuoKeys {
            host: hide(&self.host),
            ik: hide(&self.ik),
            sk: hide(&self.sk),
        }
    }
}

/// What the web vault shows in place of the global keys.
pub const GLOBAL_KEYS_MARK: &str = "<global_secret>";

/// An address with all but its first two characters (none, up to three) hidden, as Vaultwarden
/// shows it before a code is asked for.
pub fn obscure_email(email: &str) -> String {
    let Some((name, domain)) = email.rsplit_once('@') else {
        return email.to_owned();
    };
    let size = name.chars().count();
    let shown = if (1..=3).contains(&size) {
        "*".repeat(size)
    } else {
        let head: String = name.chars().take(2).collect();
        format!("{head}{}", "*".repeat(size.saturating_sub(2)))
    };
    format!("{shown}@{domain}")
}

/// Whether two texts are equal, in time that doesn't depend on where they differ.
pub(crate) fn same(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// `size` random digits, as Vaultwarden makes an email code.
pub(crate) fn numeric_code<R: Random>(random: &R, size: u8) -> String {
    random_text(random, usize::from(size), b"0123456789")
}

/// `size` random letters and digits.
pub(crate) fn alphanumeric<R: Random>(random: &R, size: usize) -> String {
    random_text(
        random,
        size,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}

/// Characters of `alphabet` drawn without modulo bias.
fn random_text<R: Random>(random: &R, size: usize, alphabet: &[u8]) -> String {
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(size);
    while out.len() < size {
        let mut buf = [0u8; 32];
        random.fill(&mut buf);
        for byte in buf {
            if out.len() == size {
                break;
            }
            if usize::from(byte) < limit {
                out.push(char::from(alphabet[usize::from(byte) % alphabet.len()]));
            }
        }
    }
    out
}

/// Opens a row's sealed JSON as `T`.
pub(crate) fn open<T: for<'de> Deserialize<'de>, S: SecretSeal>(
    seal: &S,
    purpose: &str,
    sealed: &[u8],
) -> Option<T> {
    let plain = seal.open(purpose, sealed).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// Seals `value` as JSON.
pub(crate) fn sealed<T: Serialize, S: SecretSeal>(seal: &S, purpose: &str, value: &T) -> Vec<u8> {
    // These types are plain structs of text and numbers: encoding them can't fail.
    let json = serde_json::to_vec(value).unwrap_or_default();
    seal.seal(purpose, &json)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(std::sync::atomic::AtomicU8);

    impl Random for Counter {
        fn fill(&self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn addresses_are_obscured_as_vaultwarden_does() {
        assert_eq!(obscure_email("bytes@example.ext"), "by***@example.ext");
        assert_eq!(obscure_email("byt@example.ext"), "***@example.ext");
        assert_eq!(obscure_email("a@b.c"), "*@b.c");
        assert_eq!(obscure_email("no-at-sign"), "no-at-sign");
        // Only the last `@` splits, like `rsplitn`.
        assert_eq!(obscure_email("a@b@example.ext"), "***@example.ext");
    }

    #[test]
    fn duo_keys_show_four_characters() {
        let keys = DuoKeys {
            host: "api-1234.duosecurity.com".to_owned(),
            ik: "DIXXXXXXXXXXXXXXXXXX".to_owned(),
            sk: "ab".to_owned(),
        };
        let shown = keys.obscured();
        assert_eq!(shown.host, "api-************");
        assert_eq!(shown.ik, "DIXX************");
        assert_eq!(shown.sk, "ab************");
        assert!(!format!("{keys:?}").contains("ab"));
    }

    #[test]
    fn codes_are_digits_of_the_size_asked() {
        let random = Counter(std::sync::atomic::AtomicU8::new(1));
        let code = numeric_code(&random, 8);
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(alphanumeric(&random, 64).len(), 64);
    }

    #[test]
    fn email_data_is_vaultwardens_json() {
        let json = r#"{"email":"a@b.c","last_token":null,"token_sent":1700000000,"attempts":2}"#;
        let data: EmailData = serde_json::from_str(json).expect("reads");
        assert_eq!(data.email, "a@b.c");
        assert_eq!(data.last_token, None);
        assert_eq!(data.attempts, 2);
        assert_eq!(serde_json::to_string(&data).expect("writes"), json);
    }

    #[test]
    fn yubikey_data_reads_both_spellings() {
        let lower: YubikeyData =
            serde_json::from_str(r#"{"keys":["cccccccccccc"],"nfc":true}"#).expect("reads");
        let upper: YubikeyData =
            serde_json::from_str(r#"{"Keys":["cccccccccccc"],"Nfc":true}"#).expect("reads");
        assert_eq!(lower, upper);
    }
}
