use core::fmt;

/// The one error this crate returns. It says nothing about why: a wrong key, a wrong label, a
/// tampered byte and a malformed input all look the same, so callers can't build an oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(());

impl Error {
    pub(crate) const fn invalid() -> Error {
        Error(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid")
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_invalid() {
        assert_eq!(Error::invalid().to_string(), "invalid");
    }

    #[test]
    fn is_a_std_error() {
        fn takes(_: &dyn std::error::Error) {}
        takes(&Error::invalid());
    }
}
