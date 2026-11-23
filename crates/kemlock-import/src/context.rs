//! What every parser is given besides the bytes.

use std::fmt;

use crate::limits::Limits;

/// The limits, and the secrets the person typed or picked for an encrypted export. Each format's
/// `parse(bytes, &Context)` takes one.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The caps to apply.
    pub limits: &'a Limits,
    /// The password for an encrypted export (Bitwarden, Proton Pass, KDBX).
    pub password: Option<&'a str>,
    /// A KDBX key file.
    pub key_file: Option<&'a [u8]>,
}

// Not derived: the password and the key file stay out of logs.
impl fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("limits", self.limits)
            .field("password", &self.password.map(|_| ".."))
            .field("key_file", &self.key_file.map(|_| ".."))
            .finish()
    }
}

impl<'a> Context<'a> {
    /// A context with `limits` and no secrets.
    pub fn new(limits: &'a Limits) -> Context<'a> {
        Context {
            limits,
            password: None,
            key_file: None,
        }
    }

    /// The same, with a password.
    #[must_use]
    pub fn with_password(mut self, password: &'a str) -> Context<'a> {
        self.password = Some(password);
        self
    }

    /// The same, with a key file.
    #[must_use]
    pub fn with_key_file(mut self, key_file: &'a [u8]) -> Context<'a> {
        self.key_file = Some(key_file);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_up() {
        let limits = Limits::default();
        let ctx = Context::new(&limits)
            .with_password("pw")
            .with_key_file(b"k");
        assert_eq!(ctx.password, Some("pw"));
        assert_eq!(ctx.key_file, Some(&b"k"[..]));
        assert!(Context::new(&limits).password.is_none());
    }
}
