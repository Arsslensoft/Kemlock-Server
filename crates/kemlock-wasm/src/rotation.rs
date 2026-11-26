//! Rotating the root key (`docs/crypto.md`, "Rotating the root key"), in the worker.
//!
//! The session holds, beside the open account, a **pending** rotation: the new root key `R′`, its
//! `item-wrap` key, the new `kx1` and `sig1` pair and the next key version. The page asks for each
//! piece of the rotation in turn (the new bundle, every item and Send moved, every wrap of `R′`)
//! and only ever receives what the server stores: the new root key leaves WebAssembly only inside
//! a wrap, a box or this device's own sealed copy. `commit` makes `R′` the account's root key and
//! keeps the old private keys, which a `rekey` in a space still needs; `abort` forgets it all.

use kemlock_crypto::{
    bundle::Bundle,
    kem1,
    keys::{ITEM_WRAP_LABEL, RootKey, SecretKey},
    kx1,
    owner::Owner,
    password_wrap, private_keys, recovery_kit,
    rotation::{self, ResealedItem, ResealedSend},
    sealed_box::{self, context},
    send::Kind,
    sig1,
};
use zeroize::Zeroizing;

use crate::{
    chain::{LOCAL_KIND, LOCAL_STORE_LABEL, local_id},
    error::Error,
    kit::{MadeKit, PIECES, THRESHOLD},
    session::{SealedItemRef, Session},
};

/// A rotation that has been started and not yet committed.
pub(crate) struct Pending {
    root: RootKey,
    item_wrap: SecretKey,
    private: (kx1::PrivateKey, sig1::SigningKey),
    key_version: u32,
}

/// The account's keys before the last rotation, kept until the spaces have moved on.
pub(crate) struct Previous {
    pub(crate) private: (kx1::PrivateKey, sig1::SigningKey),
}

/// What the server stores of the new keys, and the fingerprint to show.
pub(crate) struct Started {
    pub(crate) key_version: u32,
    pub(crate) public_bundle: Vec<u8>,
    pub(crate) bundle_signature: Vec<u8>,
    pub(crate) sealed_private_keys: Vec<u8>,
    pub(crate) sealed_previous_private_keys: Vec<u8>,
    pub(crate) fingerprint: String,
}

/// An item moved, with the key version it is now wrapped under and the account's signature of the
/// write the move makes, by the new keys.
pub(crate) struct MovedItem {
    pub(crate) moved: ResealedItem,
    pub(crate) key_version: u32,
    pub(crate) signature: crate::item_writes::WriteSigned,
}

/// The PRF output is exactly 32 bytes.
fn prf_output(bytes: &[u8]) -> Result<&[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::Invalid)
}

impl Session {
    fn pending(&self) -> Result<&Pending, Error> {
        self.pending.as_ref().ok_or(Error::Invalid)
    }

    /// Starts a rotation of the open account: a new root key, a new `kx1` and `sig1` pair, the
    /// bundle at the next key version signed by the new `sig1` key, both pairs sealed under the new
    /// user key (the new pair at the new version, the old one at the old version). Needs the
    /// private keys, so the account must have been unlocked with them. A pending rotation is
    /// replaced.
    pub(crate) fn rotation_start(&mut self) -> Result<Started, Error> {
        let unlocked = self.unlocked()?;
        let (old_kx, old_sig) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let account_id = unlocked.account_id;
        let old_version = unlocked.key_version;
        let new_version = old_version.checked_add(1).ok_or(Error::Invalid)?;

        let root = RootKey::generate();
        let user_key = root.user_key()?;
        let item_wrap = user_key.child(ITEM_WRAP_LABEL)?;
        let (kx_private, kx_public) = kx1::generate()?;
        let sig_private = sig1::SigningKey::generate();
        let sig_public = sig_private.public_key()?;
        let bundle = Bundle {
            account_id,
            key_version: new_version,
            kx1_public: kx_public,
            sig1_public: sig_public,
        };
        let bundle_signature = bundle.sign(&sig_private)?;
        let sealed_private_keys = private_keys::seal(
            &user_key,
            &kx_private,
            &sig_private,
            &account_id,
            new_version,
        )?;
        let sealed_previous_private_keys =
            private_keys::seal(&user_key, old_kx, old_sig, &account_id, old_version)?;
        let started = Started {
            key_version: new_version,
            public_bundle: bundle.to_bytes(),
            bundle_signature,
            sealed_private_keys,
            sealed_previous_private_keys,
            fingerprint: bundle.fingerprint_text(),
        };
        self.pending = Some(Pending {
            root,
            item_wrap,
            private: (kx_private, sig_private),
            key_version: new_version,
        });
        Ok(started)
    }

    /// Moves one item of the account's own vault from the old keys to the new: a fresh item key,
    /// the next revision, the new `item-wrap` key and key version.
    pub(crate) fn rotation_reseal_item(
        &self,
        item: &SealedItemRef<'_>,
    ) -> Result<MovedItem, Error> {
        let unlocked = self.unlocked()?;
        let pending = self.pending()?;
        if *item.owner != kemlock_crypto::owner::Owner::user(unlocked.account_id) {
            return Err(Error::Invalid);
        }
        let moved = rotation::reseal_item(
            &unlocked.item_wrap,
            item.key_version.unwrap_or(unlocked.key_version),
            &pending.item_wrap,
            pending.key_version,
            item.id,
            item.owner,
            item.kind,
            item.revision,
            item.ciphertext,
            item.item_key,
        )?;
        // The re-encrypted item is a write like any other, so the account signs it, with the key of
        // the version the server installs it under: the new one.
        let signature = crate::item_writes::sign_rotated(
            item.owner,
            item.id,
            item.kind,
            moved.revision,
            pending.key_version,
            &moved.ciphertext,
            &moved.item_key,
            unlocked.account_id,
            &pending.private.1,
        )?;
        Ok(MovedItem {
            moved,
            key_version: pending.key_version,
            signature,
        })
    }

    /// Moves one Send's sealed key and meta to the new `item-wrap` key and key version.
    pub(crate) fn rotation_reseal_send(
        &self,
        send_id: &[u8; 16],
        kind: Kind,
        sealed_key: &[u8],
        meta: &[u8],
    ) -> Result<ResealedSend, Error> {
        let unlocked = self.unlocked()?;
        let pending = self.pending()?;
        Ok(rotation::reseal_send(
            &unlocked.item_wrap,
            &pending.item_wrap,
            pending.key_version,
            send_id,
            kind,
            sealed_key,
            meta,
        )?)
    }

    /// The new root key wrapped under a master key and OPAQUE export key (the handles of a fresh
    /// sign-in): the password wrap at the new key version. Consumes both handles on success.
    pub(crate) fn rotation_wrap_password(
        &mut self,
        master: u32,
        export: u32,
    ) -> Result<Vec<u8>, Error> {
        let account_id = self.unlocked()?.account_id;
        let master_key = self.master(master)?;
        let export_key = self.export(export)?;
        let pending = self.pending()?;
        let wrapped = password_wrap::seal(
            &master_key,
            &export_key,
            &pending.root,
            &account_id,
            pending.key_version,
        )?;
        self.release(master);
        self.release(export);
        Ok(wrapped)
    }

    /// The new root key wrapped under a passkey's PRF output and credential id, at the new key
    /// version: `(wrap, key version)`.
    pub(crate) fn rotation_prf_wrap(
        &self,
        prf: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, u32), Error> {
        let account_id = self.unlocked()?.account_id;
        let pending = self.pending()?;
        let wrapped = kemlock_crypto::prf_wrap::seal(
            prf_output(prf)?,
            credential_id,
            &pending.root,
            &account_id,
            pending.key_version,
        )?;
        Ok((wrapped, pending.key_version))
    }

    /// A new Recovery Kit for the new root key, at the new key version.
    pub(crate) fn rotation_kit_make(&self) -> Result<MadeKit, Error> {
        let account_id = self.unlocked()?.account_id;
        let pending = self.pending()?;
        let (kit_id, key, pieces) = recovery_kit::make_kit(THRESHOLD, PIECES)?;
        let wrapped = recovery_kit::seal(
            &key,
            &kit_id,
            &pending.root,
            &account_id,
            pending.key_version,
        )?;
        Ok(MadeKit {
            kit_id,
            pieces,
            wrapped,
            key_version: pending.key_version,
        })
    }

    /// The new root key's bytes, for the worker to seal as this device's own copy. They go no
    /// further than the worker.
    pub(crate) fn rotation_export_root(&self) -> Result<Zeroizing<[u8; 64]>, Error> {
        Ok(Zeroizing::new(*self.pending()?.root.as_bytes()))
    }

    /// The new root key sealed to `recipient_kx1` under `"emergency-access"` (`aad`: the contact's
    /// account id, 16 bytes) or `"account-recovery"` (`aad`: space id, this account's id and
    /// `u64be(keySeq)`, 40 bytes). No other context.
    pub(crate) fn rotation_seal_root_key(
        &self,
        recipient_kx1: &[u8],
        box_context: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let account_id = self.unlocked()?.account_id;
        let pending = self.pending()?;
        match box_context {
            context::EMERGENCY_ACCESS => {
                if aad.len() != 16 {
                    return Err(Error::Invalid);
                }
            }
            context::ACCOUNT_RECOVERY => {
                if aad.len() != 40 || aad[16..32] != account_id {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
        let public = kx1::PublicKey::from_bytes(recipient_kx1)?;
        Ok(sealed_box::seal(
            &public,
            box_context,
            aad,
            pending.root.as_bytes(),
        )?)
    }

    /// Makes the new keys the account's: the root key, the `item-wrap` key, the private keys and
    /// the key version. The old private keys are kept (see [`Previous`]); the space and collection
    /// keys already opened stay. Returns the key version and the new fingerprint.
    pub(crate) fn rotation_commit(&mut self) -> Result<(u32, String), Error> {
        // Everything that can fail is done before anything is taken: a failure leaves the rotation
        // pending and the old private keys where they are.
        let account_id = self.unlocked()?.account_id;
        if self.unlocked()?.private.is_none() {
            return Err(Error::Locked);
        }
        let pending = self.pending.as_ref().ok_or(Error::Invalid)?;
        let bundle = Bundle {
            account_id,
            key_version: pending.key_version,
            kx1_public: pending.private.0.public_key()?,
            sig1_public: pending.private.1.public_key()?,
        };
        let fingerprint = bundle.fingerprint_text();
        let pending = self.pending.take().ok_or(Error::Invalid)?;
        let Some(unlocked) = self.unlocked.as_mut() else {
            self.pending = Some(pending);
            return Err(Error::Locked);
        };
        let Some(old_private) = unlocked.private.take() else {
            self.pending = Some(pending);
            return Err(Error::Locked);
        };
        let previous = Previous {
            private: old_private,
        };
        unlocked.root = pending.root;
        unlocked.item_wrap = pending.item_wrap;
        unlocked.private = Some(pending.private);
        unlocked.key_version = pending.key_version;
        let key_version = unlocked.key_version;
        self.previous = Some(previous);
        Ok((key_version, fingerprint))
    }

    /// Moves one value this browser keeps for the account (`seal_local`) from the key it is sealed
    /// under now to the new one, bound to the same label. Fails for a value that does not open now.
    pub(crate) fn rotation_reseal_local(
        &self,
        label: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let account_id = self.unlocked()?.account_id;
        let pending = self.pending()?;
        let plain = Zeroizing::new(self.open_local(label, sealed)?);
        let key = pending.root.user_key()?.child(LOCAL_STORE_LABEL)?;
        Ok(kem1::seal_item(
            &key,
            &local_id(label),
            1,
            LOCAL_KIND,
            &Owner::user(account_id),
            &plain,
        )?)
    }

    /// Forgets a pending rotation.
    pub(crate) fn rotation_abort(&mut self) {
        self.pending = None;
    }

    /// Signs `message` under `context` with the account's previous `sig1` key, kept after a
    /// rotation for the `rekey` records of its spaces, or with the new one when `previous` is
    /// false. Only a space chain record's signing input may be signed this way, and the web layer
    /// that builds it is the one that calls this.
    pub(crate) fn rotation_sign(
        &self,
        previous: bool,
        context: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if context != kemlock_crypto::sig1::context::SPACE_CHAIN {
            return Err(Error::Invalid);
        }
        let key = if previous {
            &self.previous.as_ref().ok_or(Error::Invalid)?.private.1
        } else {
            &self.unlocked()?.private.as_ref().ok_or(Error::Locked)?.1
        };
        Ok(key.sign(context, message)?)
    }
}
