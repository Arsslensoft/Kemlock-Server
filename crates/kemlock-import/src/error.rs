//! Why an export could not be read.

use thiserror::Error;

/// Why an export could not be read. [`ImportError::PasswordRequired`] and
/// [`ImportError::BadPassword`] are the two the caller answers by asking again; the rest end the
/// import, and their text is safe to show (it never holds a secret from the file).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImportError {
    /// The input is over a size limit.
    #[error("the file is larger than Kemlock reads ({limit} bytes)")]
    TooLarge {
        /// The limit that was passed.
        limit: usize,
    },
    /// Some other limit (entries, nesting, ZIP contents, inflated size) was passed.
    #[error("the export is beyond a limit: {0}")]
    LimitExceeded(&'static str),
    /// Not a format this crate reads.
    #[error("not an export Kemlock can read")]
    Unsupported,
    /// A known format with nothing in it.
    #[error("the export has no entries")]
    Empty,
    /// A known format, damaged or not shaped as expected.
    #[error("the export is damaged: {0}")]
    Malformed(String),
    /// An encrypted export and no password was given.
    #[error("the export is encrypted and needs its password")]
    PasswordRequired,
    /// The password (or key file) does not open the export, or its encrypted part is damaged.
    #[error("the password or key file does not open the export")]
    BadPassword,
    /// The export asks for key derivation work above the limits.
    #[error("the export's key derivation settings are outside what Kemlock accepts")]
    KdfOutOfBounds,
    /// A Bitwarden export encrypted with an account's own key: sign in to that account instead.
    #[error("the export is encrypted with an account key; export it again with a password")]
    AccountRestricted,
    /// An encrypted form this crate does not open.
    #[error("this kind of encryption is not supported: {0}")]
    UnsupportedEncryption(String),
}

impl ImportError {
    /// A [`ImportError::Malformed`] from any text.
    pub fn malformed(why: impl Into<String>) -> ImportError {
        ImportError::Malformed(why.into())
    }
}

/// `Result` with [`ImportError`].
pub type Result<T> = std::result::Result<T, ImportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_never_carry_file_content() {
        let e = ImportError::malformed("bad header");
        assert_eq!(e.to_string(), "the export is damaged: bad header");
        assert!(ImportError::TooLarge { limit: 5 }.to_string().contains('5'));
    }
}
