//! The passkey PRF wrap of the root key (`docs/crypto.md`, "The passkey PRF wrap of the root
//! key"), for the browser.
//!
//! The page gets the PRF output from `navigator.credentials` (evaluated with
//! `first = SHA-256("kemlock/v1/prf-salt")`) and hands it here with the credential's raw id. An
//! unlocked session wraps its root key under it for the server to keep; a locked one opens a
//! wrap the server returned and keeps the root key behind a handle, which `unlock_with_root` turns
//! into an open vault. The root key never reaches JavaScript.

use kemlock_crypto::prf_wrap;
use zeroize::Zeroizing;

use crate::{
    error::Error,
    session::{Session, Slot},
};

/// The PRF output is exactly 32 bytes.
fn prf_output(bytes: &[u8]) -> Result<&[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::Invalid)
}

impl Session {
    /// The open account's root key wrapped under the passkey's PRF output:
    /// `nonce(12) ‖ ciphertext(64) ‖ tag(16)`, for `PUT /kem/v1/account/passkeys/{id}/prf` and for
    /// the registration's `prf` field. The wrap is for the account's current key version.
    pub(crate) fn prf_wrap_root(
        &self,
        prf: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, u32), Error> {
        let unlocked = self.unlocked()?;
        let wrapped = prf_wrap::seal(
            prf_output(prf)?,
            credential_id,
            &unlocked.root,
            &unlocked.account_id,
            unlocked.key_version,
        )?;
        Ok((wrapped, unlocked.key_version))
    }

    /// Opens a PRF wrap of the root key and keeps the root key behind a new handle for
    /// `unlock_with_root`. Fails for another PRF output, credential, account or key version.
    pub(crate) fn prf_open_root_key(
        &mut self,
        prf: &[u8],
        credential_id: &[u8],
        account: &[u8; 16],
        key_version: u32,
        wrapped: &[u8],
    ) -> Result<u32, Error> {
        let root = prf_wrap::open(
            prf_output(prf)?,
            credential_id,
            wrapped,
            account,
            key_version,
        )?;
        self.insert(Slot::Root(Zeroizing::new(*root.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_session_wraps_nothing() {
        let session = Session::new();
        assert_eq!(
            session.prf_wrap_root(&[7; 32], b"credential"),
            Err(Error::Locked)
        );
    }

    #[test]
    fn a_prf_output_of_another_length_is_refused() {
        let mut session = Session::new();
        assert_eq!(
            session.prf_open_root_key(&[7; 31], b"credential", &[1; 16], 1, &[0; 92]),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn a_wrap_that_does_not_open_leaves_no_handle() {
        let mut session = Session::new();
        assert_eq!(
            session.prf_open_root_key(&[7; 32], b"credential", &[1; 16], 1, &[0; 92]),
            Err(Error::Invalid)
        );
        assert!(!session.is_unlocked());
    }
}
