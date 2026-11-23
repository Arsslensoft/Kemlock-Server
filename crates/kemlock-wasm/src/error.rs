//! The two ways an operation fails. Neither says why: a wrong password, a wrong key and a
//! tampered byte all look the same, so the page cannot be used as an oracle.

use core::fmt;

/// An operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The input is malformed, a handle is stale, or a key did not open what it was given.
    Invalid,
    /// No account is unlocked, or the keys the operation needs are not loaded.
    Locked,
}

impl Error {
    /// The short code the worker turns into an error class.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Error::Invalid => "invalid",
            Error::Locked => "locked",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl From<kemlock_crypto::Error> for Error {
    fn from(_: kemlock_crypto::Error) -> Error {
        Error::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(Error::Invalid.code(), "invalid");
        assert_eq!(Error::Locked.code(), "locked");
        assert_eq!(Error::Locked.to_string(), "locked");
    }

    #[test]
    fn crypto_errors_become_invalid() {
        let failure = kemlock_crypto::password_wrap::open(&[0; 32], &[0; 64], &[], &[0; 16], 1)
            .map(|_| ())
            .expect_err("an empty wrap never opens");
        assert_eq!(Error::from(failure), Error::Invalid);
    }
}
