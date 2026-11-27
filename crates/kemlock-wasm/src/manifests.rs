//! The signed manifest (`docs/crypto.md`, "Signed manifest") in the worker: signing one with the
//! unlocked account's `sig1` key and checking one, so the page never holds a signing key.
//!
//! - **Signing** takes a manifest's exact bytes. It signs only bytes that parse as a manifest (sorted,
//!   canonical), under context `"manifest"`, and only for the account's own vault or a space: the
//!   account can't sign another person's manifest, and the key that signs the account's bundle can't
//!   be driven to sign arbitrary bytes.
//! - **Checking an account's own manifest** uses the public key of the account's own `sig1` private
//!   key, never a bundle the server served, so a server can't vouch for a manifest it made.
//! - **Checking a space's manifest** uses the signer's bundle, which the page has already checked
//!   against what the space knows of its members (the space chain once that is verified). A
//!   personal manifest is never accepted this way.

use kemlock_crypto::{
    bundle::Bundle,
    manifest::Manifest,
    owner::{Owner, OwnerKind},
    sig1::context::MANIFEST,
};

use crate::{error::Error, session::Session};

impl Session {
    /// Signs the manifest `manifest` (its exact bytes) with the unlocked account's `sig1` key.
    /// Fails unless the bytes are a manifest, and its owner is this account's own vault or a space.
    pub(crate) fn sign_manifest(&self, manifest: &[u8]) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        let parsed = Manifest::from_bytes(manifest)?;
        if parsed.owner.kind() == OwnerKind::User
            && parsed.owner != Owner::user(unlocked.account_id)
        {
            return Err(Error::Invalid);
        }
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        Ok(sig_private.sign(MANIFEST, manifest)?)
    }

    /// Checks that `signature` is this account's own `sig1` signature of `manifest`, and that the
    /// manifest is of this account's own vault. The key is the one of the account's own private
    /// key, so the unlock has to have opened it.
    pub(crate) fn verify_own_manifest(
        &self,
        manifest: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let unlocked = self.unlocked()?;
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let public = sig_private.public_key()?;
        let parsed = Manifest::open_signed(&public, manifest, signature)?;
        if parsed.owner != Owner::user(unlocked.account_id) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Checks that `signature` is the `sig1` signature of `manifest` under the key in `signer_bundle`,
/// and that the manifest is a space's. Public data only, so it needs no session.
pub(crate) fn verify_space_manifest(
    signer_bundle: &[u8],
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let bundle = Bundle::from_bytes(signer_bundle)?;
    let parsed = Manifest::open_signed(&bundle.sig1_public, manifest, signature)?;
    if parsed.owner.kind() != OwnerKind::Space {
        return Err(Error::Invalid);
    }
    Ok(())
}
