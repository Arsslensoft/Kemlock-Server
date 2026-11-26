//! The new-device side of a device approval (`docs/crypto.md`, sealed box context
//! `"device-approval"` and "Device-approval phrase").
//!
//! A browser that asks to sign in with another device makes a one-time `kx1` key pair here. The
//! private half stays in a handle; the public half goes to the server in the approval request and
//! the five-word phrase is worked out from it. When an open device approves, the server relays the
//! root key sealed to that public key with `aad = account id (16) ‖ request id (16)`. This module
//! opens it under that aad (so an answer can't be replayed onto another request or account) and
//! keeps the root key behind a handle, which `unlock_with_root` turns into an open vault. The
//! root key never reaches JavaScript.

use kemlock_crypto::{
    kx1,
    sealed_box::{self, context},
};
use zeroize::Zeroizing;

use crate::{
    error::Error,
    session::{Session, Slot},
};

/// The `aad` of a device-approval box: the account id, then the approval request id.
pub(crate) fn approval_aad(account: &[u8; 16], request: &[u8; 16]) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(account);
    aad[16..].copy_from_slice(request);
    aad
}

impl Session {
    /// Makes a one-time exchange key pair for an approval request. The private key is kept behind
    /// the returned handle; the public key (1,600 bytes) is returned to go in the request.
    pub(crate) fn new_device_key(&mut self) -> Result<(u32, Vec<u8>), Error> {
        let (private, public) = kx1::generate()?;
        let handle = self.insert(Slot::DeviceKey(private))?;
        Ok((handle, public.as_bytes().to_vec()))
    }

    /// Opens the root key an approving device sealed to the one-time key behind `device_key`, and
    /// keeps it behind a new handle. The one-time key is spent whether or not the box opens: a
    /// request is answered once.
    pub(crate) fn open_approved_root_key(
        &mut self,
        device_key: u32,
        account: &[u8; 16],
        request: &[u8; 16],
        sealed: &[u8],
    ) -> Result<u32, Error> {
        let opened = {
            let private = self.device_key(device_key)?;
            sealed_box::open(
                private,
                context::DEVICE_APPROVAL,
                &approval_aad(account, request),
                sealed,
            )
        };
        self.release(device_key);
        let plain = opened?;
        let mut root = Zeroizing::new([0u8; 64]);
        if plain.len() != root.len() {
            return Err(Error::Invalid);
        }
        root.copy_from_slice(&plain);
        self.insert(Slot::Root(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_aad_is_the_account_then_the_request() {
        let aad = approval_aad(&[1; 16], &[2; 16]);
        assert_eq!(&aad[..16], &[1; 16]);
        assert_eq!(&aad[16..], &[2; 16]);
    }

    #[test]
    fn an_unknown_device_key_opens_nothing() {
        let mut session = Session::new();
        assert_eq!(
            session.open_approved_root_key(7, &[1; 16], &[2; 16], &[0; 1700]),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn unlocking_with_an_unknown_root_handle_is_refused() {
        let mut session = Session::new();
        assert_eq!(
            session.unlock_with_root(&[1; 16], 9, 1, None, None),
            Err(Error::Invalid)
        );
        assert!(!session.is_unlocked());
    }
}
