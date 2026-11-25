//! The vault's state, in plain Rust: handles to secrets, and the unlocked account.
//!
//! Nothing here knows about JavaScript, so the logic reads on its own and the tests drive it
//! directly. `wasm.rs` is the thin skin that turns it into the worker's API.
//!
//! Every secret lives in a slot of this table, or in [`Unlocked`], and is wiped when it drops:
//!
//! - a master key and an OPAQUE export key are handed out as handles; `unlock` consumes both,
//!   `new_account` only the export key (the sign-in right after a new account still needs the
//!   master key, and the page wipes it when that is done);
//! - a half-finished OPAQUE registration or login is a handle too, consumed by its finish;
//! - an unlocked account holds the root key (to seal it to a new device or an emergency contact),
//!   the item-wrap key and, when asked, the `kx1` and `sig1` private keys, plus the space and
//!   collection keys it has opened or made (`spaces.rs`). The user key is derived, used and
//!   dropped inside `unlock`;
//! - a released emergency key is a handle too: another account's root key, opened with this
//!   account's `kx1` key (`sharing.rs`).
//!
//! `lock` drops all of it.

use core::fmt;
use std::collections::HashMap;

use kemlock_crypto::{
    argon2id,
    bundle::Bundle,
    kem1,
    keys::{ITEM_WRAP_LABEL, RootKey, SecretKey},
    kx1,
    opaque::{self, ClientLogin, ClientRegistration},
    owner::Owner,
    password_wrap, private_keys,
    send::{self, Kind},
    sig1,
};
use zeroize::Zeroizing;

use crate::{error::Error, spaces::SpaceKeys};

/// The key version of a new account.
pub(crate) const FIRST_KEY_VERSION: u32 = 1;

/// Argon2id settings the vault accepts, the same bounds the server enforces (`KdfParams`): a
/// server, or a man in the middle, can't talk the client into a cheap hash or an enormous one.
const ITERATIONS: core::ops::RangeInclusive<u32> = 2..=10;
const MEMORY_KIB: core::ops::RangeInclusive<u32> = 16 * 1024..=1024 * 1024;
const PARALLELISM: core::ops::RangeInclusive<u32> = 1..=16;
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 64;

pub(crate) enum Slot {
    Master(Zeroizing<[u8; 32]>),
    Export(Zeroizing<[u8; 64]>),
    Registration(Box<ClientRegistration>),
    Login(Box<ClientLogin>),
    /// Another account's root key, opened from an emergency-access box.
    Root(Zeroizing<[u8; 64]>),
    /// A new device's one-time exchange key, waiting for the root key to be sealed to it
    /// (`approval.rs`).
    DeviceKey(kx1::PrivateKey),
}

/// An account whose keys are open.
pub(crate) struct Unlocked {
    pub(crate) account_id: [u8; 16],
    pub(crate) key_version: u32,
    /// The root key, kept so it can be sealed to a device or an emergency contact. It never leaves
    /// WebAssembly memory except inside such a box.
    pub(crate) root: RootKey,
    /// The user key's `"kemlock/v1/item-wrap"` child: wraps and unwraps item keys.
    item_wrap: SecretKey,
    /// The `kx1` and `sig1` private keys, when the caller handed over the sealed blob.
    pub(crate) private: Option<(kx1::PrivateKey, sig1::SigningKey)>,
    /// The space and collection keys opened or made in this unlock.
    pub(crate) spaces: SpaceKeys,
}

/// What the server stores for a new account (the register route's fields) and the fingerprint to
/// show its owner.
pub(crate) struct NewAccount {
    pub(crate) public_bundle: Vec<u8>,
    pub(crate) bundle_signature: Vec<u8>,
    pub(crate) sealed_private_keys: Vec<u8>,
    pub(crate) wrapped_root_key: Vec<u8>,
    pub(crate) key_version: u32,
    pub(crate) fingerprint: String,
}

/// An item sealed for the server.
pub(crate) struct SealedItem {
    pub(crate) ciphertext: Vec<u8>,
    /// The item key, wrapped under the owner's item-wrap key.
    pub(crate) item_key: Vec<u8>,
    pub(crate) key_version: u32,
}

/// An item as the server stores it, to be opened.
#[derive(Clone, Copy)]
pub(crate) struct SealedItemRef<'a> {
    pub(crate) id: &'a [u8; 16],
    pub(crate) owner: &'a Owner,
    pub(crate) kind: &'a str,
    pub(crate) revision: u64,
    pub(crate) ciphertext: &'a [u8],
    /// The wrapped item key.
    pub(crate) item_key: &'a [u8],
    /// The key version the item key was wrapped under, when the item says.
    pub(crate) key_version: Option<u32>,
}

pub(crate) struct Session {
    next: u32,
    slots: HashMap<u32, Slot>,
    unlocked: Option<Unlocked>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("handles", &self.slots.len())
            .field("unlocked", &self.unlocked.is_some())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new() -> Session {
        Session {
            next: 1,
            slots: HashMap::new(),
            unlocked: None,
        }
    }

    pub(crate) fn insert(&mut self, slot: Slot) -> Result<u32, Error> {
        let handle = self.next;
        self.next = handle.checked_add(1).ok_or(Error::Invalid)?;
        self.slots.insert(handle, slot);
        Ok(handle)
    }

    pub(crate) fn insert_master(&mut self, key: [u8; 32]) -> Result<u32, Error> {
        self.insert(Slot::Master(Zeroizing::new(key)))
    }

    pub(crate) fn insert_export(&mut self, key: [u8; 64]) -> Result<u32, Error> {
        self.insert(Slot::Export(Zeroizing::new(key)))
    }

    fn master(&self, handle: u32) -> Result<Zeroizing<[u8; 32]>, Error> {
        match self.slots.get(&handle) {
            Some(Slot::Master(key)) => Ok(Zeroizing::new(**key)),
            _ => Err(Error::Invalid),
        }
    }

    fn export(&self, handle: u32) -> Result<Zeroizing<[u8; 64]>, Error> {
        match self.slots.get(&handle) {
            Some(Slot::Export(key)) => Ok(Zeroizing::new(**key)),
            _ => Err(Error::Invalid),
        }
    }

    fn take_registration(&mut self, handle: u32) -> Result<ClientRegistration, Error> {
        match self.slots.remove(&handle) {
            Some(Slot::Registration(state)) => Ok(*state),
            Some(other) => {
                self.slots.insert(handle, other);
                Err(Error::Invalid)
            }
            None => Err(Error::Invalid),
        }
    }

    fn take_login(&mut self, handle: u32) -> Result<ClientLogin, Error> {
        match self.slots.remove(&handle) {
            Some(Slot::Login(state)) => Ok(*state),
            Some(other) => {
                self.slots.insert(handle, other);
                Err(Error::Invalid)
            }
            None => Err(Error::Invalid),
        }
    }

    /// Drops one handle. A stale or unknown handle is not an error.
    pub(crate) fn release(&mut self, handle: u32) {
        self.slots.remove(&handle);
    }

    /// Whether an account is unlocked.
    pub(crate) fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Wipes every secret: all handles and the unlocked account.
    pub(crate) fn lock(&mut self) {
        // Dropping a slot or an `Unlocked` wipes its keys (`Zeroizing`, `ZeroizeOnDrop`). The
        // counter is not reset, so a handle from before the lock can never name a new secret.
        self.slots.clear();
        self.unlocked = None;
    }

    /// The master key: `Argon2id(password, salt, m, t, p, L = 32)`. The password is the UTF-8 of
    /// its NFC form (the worker normalises it). Settings outside the bounds the server enforces
    /// are refused. Returns a handle.
    pub(crate) fn master_key(
        &mut self,
        password: &[u8],
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: &[u8],
    ) -> Result<u32, Error> {
        if !MEMORY_KIB.contains(&memory_kib)
            || !ITERATIONS.contains(&iterations)
            || !PARALLELISM.contains(&parallelism)
            || !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len())
        {
            return Err(Error::Invalid);
        }
        let key = argon2id::master_key(password, salt, memory_kib, iterations, parallelism)?;
        self.insert_master(key)
    }

    /// OPAQUE registration, first message. Returns the state's handle and the 32-byte request.
    pub(crate) fn opaque_register_start(&mut self, master: u32) -> Result<(u32, Vec<u8>), Error> {
        let master_key = self.master(master)?;
        let (state, request) = opaque::client_registration_start(master_key.as_slice())?;
        Ok((self.insert(Slot::Registration(Box::new(state)))?, request))
    }

    /// OPAQUE registration, last message. Consumes the state. Returns the 192-byte upload and the
    /// export key's handle.
    pub(crate) fn opaque_register_finish(
        &mut self,
        state: u32,
        master: u32,
        response: &[u8],
    ) -> Result<(Vec<u8>, u32), Error> {
        let state = self.take_registration(state)?;
        let master_key = self.master(master)?;
        let (upload, export_key) =
            opaque::client_registration_finish(state, master_key.as_slice(), response)?;
        Ok((upload, self.insert_export(export_key)?))
    }

    /// OPAQUE login, first message. Returns the state's handle and the 96-byte request.
    pub(crate) fn opaque_login_start(&mut self, master: u32) -> Result<(u32, Vec<u8>), Error> {
        let master_key = self.master(master)?;
        let (state, request) = opaque::client_login_start(master_key.as_slice())?;
        Ok((self.insert(Slot::Login(Box::new(state)))?, request))
    }

    /// OPAQUE login, last message. Consumes the state; fails when the password was wrong or the
    /// server's answer was a fake one. Returns the 64-byte finalization and the export key's
    /// handle. The session key is dropped: the server proves nothing more with it here.
    pub(crate) fn opaque_login_finish(
        &mut self,
        state: u32,
        master: u32,
        response: &[u8],
    ) -> Result<(Vec<u8>, u32), Error> {
        let state = self.take_login(state)?;
        let master_key = self.master(master)?;
        let (finalization, session_key, export_key) =
            opaque::client_login_finish(state, master_key.as_slice(), response)?;
        drop(Zeroizing::new(session_key));
        Ok((finalization, self.insert_export(export_key)?))
    }

    /// Makes a Kemlock-only account's keys: a root key, the user key, `kx1` and `sig1` key pairs,
    /// the signed public bundle, the sealed private keys and the password wrap of the root key.
    /// Consumes the export handle and keeps the master one, which the sign-in that follows uses.
    /// Nothing is left unlocked.
    pub(crate) fn new_account(
        &mut self,
        account_id: &[u8; 16],
        master: u32,
        export: u32,
    ) -> Result<NewAccount, Error> {
        let master_key = self.master(master)?;
        let export_key = self.export(export)?;

        let root = RootKey::generate();
        let user_key = root.user_key()?;
        let (kx_private, kx_public) = kx1::generate()?;
        let sig_private = sig1::SigningKey::generate();
        let sig_public = sig_private.public_key()?;

        let bundle = Bundle {
            account_id: *account_id,
            key_version: FIRST_KEY_VERSION,
            kx1_public: kx_public,
            sig1_public: sig_public,
        };
        let bundle_signature = bundle.sign(&sig_private)?;
        let sealed_private_keys = private_keys::seal(
            &user_key,
            &kx_private,
            &sig_private,
            account_id,
            FIRST_KEY_VERSION,
        )?;
        let wrapped_root_key = password_wrap::seal(
            &master_key,
            &export_key,
            &root,
            account_id,
            FIRST_KEY_VERSION,
        )?;

        self.slots.remove(&export);
        Ok(NewAccount {
            public_bundle: bundle.to_bytes(),
            bundle_signature,
            sealed_private_keys,
            wrapped_root_key,
            key_version: FIRST_KEY_VERSION,
            fingerprint: bundle.fingerprint_text(),
        })
    }

    /// Wraps the open account's root key under a new master key and OPAQUE export key, for a
    /// change of master password or of sign-in address (docs/crypto.md, "Changing the master
    /// password and the sign-in address"). The root key stays, and so do the key version and the
    /// wrap's associated data: only the key that wraps it is new. Consumes both handles on
    /// success, and keeps them when it fails, so the page can try again or release them.
    pub(crate) fn rewrap_root(&mut self, master: u32, export: u32) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        let master_key = self.master(master)?;
        let export_key = self.export(export)?;
        let wrapped = password_wrap::seal(
            &master_key,
            &export_key,
            &unlocked.root,
            &unlocked.account_id,
            unlocked.key_version,
        )?;
        self.slots.remove(&master);
        self.slots.remove(&export);
        Ok(wrapped)
    }

    /// Opens the password wrap of the root key and keeps what items need in memory: the root key
    /// opens the wrap only if both the master key and the export key are right. With the sealed
    /// private keys it opens those too. Consumes the master and export handles on success.
    pub(crate) fn unlock(
        &mut self,
        account_id: &[u8; 16],
        wrapped_root_key: &[u8],
        master: u32,
        export: u32,
        key_version: u32,
        sealed_private_keys: Option<&[u8]>,
    ) -> Result<(), Error> {
        let master_key = self.master(master)?;
        let export_key = self.export(export)?;
        let root = password_wrap::open(
            &master_key,
            &export_key,
            wrapped_root_key,
            account_id,
            key_version,
        )?;
        let user_key = root.user_key()?;
        let item_wrap = user_key.child(ITEM_WRAP_LABEL)?;
        let private = match sealed_private_keys {
            Some(sealed) => Some(private_keys::open(
                &user_key,
                sealed,
                account_id,
                key_version,
            )?),
            None => None,
        };

        self.slots.remove(&master);
        self.slots.remove(&export);
        self.unlocked = Some(Unlocked {
            account_id: *account_id,
            key_version,
            root,
            item_wrap,
            private,
            spaces: SpaceKeys::default(),
        });
        Ok(())
    }

    /// Makes the keys of an account that has no password (one single sign-on made): the same keys
    /// as `new_account`, with no password wrap of the root key, and leaves the account unlocked,
    /// because this device made the root key and holds it. `wrapped_root_key` of the result is
    /// empty: the device keeps its own copy (`export_root`, sealed by the worker) instead.
    pub(crate) fn new_sso_account(&mut self, account_id: &[u8; 16]) -> Result<NewAccount, Error> {
        let root = RootKey::generate();
        let user_key = root.user_key()?;
        let item_wrap = user_key.child(ITEM_WRAP_LABEL)?;
        let (kx_private, kx_public) = kx1::generate()?;
        let sig_private = sig1::SigningKey::generate();
        let sig_public = sig_private.public_key()?;

        let bundle = Bundle {
            account_id: *account_id,
            key_version: FIRST_KEY_VERSION,
            kx1_public: kx_public,
            sig1_public: sig_public,
        };
        let bundle_signature = bundle.sign(&sig_private)?;
        let sealed_private_keys = private_keys::seal(
            &user_key,
            &kx_private,
            &sig_private,
            account_id,
            FIRST_KEY_VERSION,
        )?;
        let fingerprint = bundle.fingerprint_text();
        let public_bundle = bundle.to_bytes();

        self.unlocked = Some(Unlocked {
            account_id: *account_id,
            key_version: FIRST_KEY_VERSION,
            root,
            item_wrap,
            private: Some((kx_private, sig_private)),
            spaces: SpaceKeys::default(),
        });
        Ok(NewAccount {
            public_bundle,
            bundle_signature,
            sealed_private_keys,
            wrapped_root_key: Vec::new(),
            key_version: FIRST_KEY_VERSION,
            fingerprint,
        })
    }

    /// The open account's root key bytes, for the worker to seal under this device's own key
    /// (docs/crypto.md, "The trusted-device copy of the root key"). They go no further than the
    /// worker: the page only ever receives the sealed copy.
    pub(crate) fn export_root(&self) -> Result<Zeroizing<[u8; 64]>, Error> {
        Ok(Zeroizing::new(*self.unlocked()?.root.as_bytes()))
    }

    /// Keeps a root key the worker opened from this device's copy behind a handle, for
    /// `unlock_with_root`.
    pub(crate) fn import_root(&mut self, bytes: &[u8]) -> Result<u32, Error> {
        let mut root = Zeroizing::new([0u8; 64]);
        if bytes.len() != root.len() {
            return Err(Error::Invalid);
        }
        root.copy_from_slice(bytes);
        self.insert(Slot::Root(root))
    }

    pub(crate) fn unlocked(&self) -> Result<&Unlocked, Error> {
        self.unlocked.as_ref().ok_or(Error::Locked)
    }

    pub(crate) fn unlocked_mut(&mut self) -> Result<&mut Unlocked, Error> {
        self.unlocked.as_mut().ok_or(Error::Locked)
    }

    /// The one-time exchange key behind a device-key handle.
    pub(crate) fn device_key(&self, handle: u32) -> Result<&kx1::PrivateKey, Error> {
        match self.slots.get(&handle) {
            Some(Slot::DeviceKey(key)) => Ok(key),
            _ => Err(Error::Invalid),
        }
    }

    /// Opens the vault with a root key already in hand (an approved device's), exactly as
    /// `unlock` does with the one its password wrap opened. `root_handle` is a `Slot::Root` and is
    /// consumed on success.
    pub(crate) fn unlock_with_root(
        &mut self,
        account_id: &[u8; 16],
        root_handle: u32,
        key_version: u32,
        sealed_private_keys: Option<&[u8]>,
    ) -> Result<(), Error> {
        let slot = self.root_slot(root_handle)?;
        let root = RootKey::from_bytes(&slot);
        let user_key = root.user_key()?;
        let item_wrap = user_key.child(ITEM_WRAP_LABEL)?;
        let private = match sealed_private_keys {
            Some(sealed) => Some(private_keys::open(
                &user_key,
                sealed,
                account_id,
                key_version,
            )?),
            None => None,
        };
        self.slots.remove(&root_handle);
        self.unlocked = Some(Unlocked {
            account_id: *account_id,
            key_version,
            root,
            item_wrap,
            private,
            spaces: SpaceKeys::default(),
        });
        Ok(())
    }

    /// The root key behind an emergency-key handle.
    pub(crate) fn root_slot(&self, handle: u32) -> Result<Zeroizing<[u8; 64]>, Error> {
        match self.slots.get(&handle) {
            Some(Slot::Root(key)) => Ok(Zeroizing::new(**key)),
            _ => Err(Error::Invalid),
        }
    }

    /// Seals an item: a fresh item key encrypts the JSON, and the user's item-wrap key wraps the
    /// item key. Only the account's own vault is open for sealing; a space has a key of its own.
    pub(crate) fn seal_item(
        &self,
        id: &[u8; 16],
        owner: &Owner,
        kind: &str,
        revision: u64,
        json: &[u8],
    ) -> Result<SealedItem, Error> {
        let unlocked = self.unlocked()?;
        if *owner != Owner::user(unlocked.account_id) {
            return Err(Error::Invalid);
        }
        let item_key = SecretKey::generate();
        let ciphertext = kem1::seal_item(&item_key, id, revision, kind, owner, json)?;
        let wrapped = kem1::wrap_item_key(
            &unlocked.item_wrap,
            &item_key,
            id,
            owner,
            unlocked.key_version,
        )?;
        Ok(SealedItem {
            ciphertext,
            item_key: wrapped,
            key_version: unlocked.key_version,
        })
    }

    /// Opens an item. `key_version` is the one the item says it was wrapped under; without it the
    /// account's current one is used. Fails for another item, revision, kind or owner than the
    /// one sealed, and for any altered byte.
    pub(crate) fn open_item(&self, item: &SealedItemRef<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        let unlocked = self.unlocked()?;
        let item_key = kem1::unwrap_item_key(
            &unlocked.item_wrap,
            item.item_key,
            item.id,
            item.owner,
            item.key_version.unwrap_or(unlocked.key_version),
        )?;
        Ok(kem1::open_item(
            &item_key,
            item.id,
            item.revision,
            item.kind,
            item.owner,
            item.ciphertext,
        )?)
    }

    /// Wraps a Send's link key for its owner: under the user's item-wrap key at the account's key
    /// version, bound to the Send's id (`docs/crypto.md`, Sends). The 64 bytes begin with the
    /// version.
    pub(crate) fn wrap_send_key(
        &self,
        send_id: &[u8; 16],
        link_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        Ok(send::wrap_link_key(
            &unlocked.item_wrap,
            link_key,
            send_id,
            unlocked.key_version,
        )?)
    }

    /// Opens a Send's sealed link key. Fails for another Send or account, for any altered byte and
    /// for a key wrapped under a key version this session doesn't hold.
    pub(crate) fn unwrap_send_key(
        &self,
        send_id: &[u8; 16],
        sealed_key: &[u8],
    ) -> Result<SecretKey, Error> {
        let unlocked = self.unlocked()?;
        let (link_key, _version) = send::unwrap_link_key(&unlocked.item_wrap, sealed_key, send_id)?;
        Ok(link_key)
    }

    /// Seals a Send's meta (the owner's name and notes) under the key from the account's item-wrap
    /// key, the Send's id and the account's key version, the version `wrap_send_key` names too.
    /// The link key plays no part, so whoever holds the link can't open it.
    pub(crate) fn seal_send_meta(
        &self,
        send_id: &[u8; 16],
        kind: Kind,
        meta_json: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        Ok(send::seal_meta(
            &unlocked.item_wrap,
            send_id,
            unlocked.key_version,
            kind,
            meta_json,
        )?)
    }

    /// Opens a Send's meta. The key version is the one the Send's `sealed_key` names, read without
    /// opening the link key.
    pub(crate) fn open_send_meta(
        &self,
        send_id: &[u8; 16],
        kind: Kind,
        sealed_key: &[u8],
        meta: &[u8],
    ) -> Result<String, Error> {
        let unlocked = self.unlocked()?;
        let key_version = send::sealed_key_version(sealed_key)?;
        let plain = send::open_meta(&unlocked.item_wrap, send_id, key_version, kind, meta)?;
        String::from_utf8(plain.to_vec()).map_err(|_| Error::Invalid)
    }

    /// The unlocked account's own fingerprint, as 12 groups of 5 digits. Needs the private keys
    /// to have been opened by `unlock`.
    pub(crate) fn own_fingerprint(&self) -> Result<String, Error> {
        let unlocked = self.unlocked()?;
        let (kx_private, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let bundle = Bundle {
            account_id: unlocked.account_id,
            key_version: unlocked.key_version,
            kx1_public: kx_private.public_key()?,
            sig1_public: sig_private.public_key()?,
        };
        Ok(bundle.fingerprint_text())
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    pub(crate) fn master_bytes(&self, handle: u32) -> Result<Zeroizing<[u8; 32]>, Error> {
        self.master(handle)
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    pub(crate) fn export_bytes(&self, handle: u32) -> Result<Zeroizing<[u8; 64]>, Error> {
        self.export(handle)
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    pub(crate) fn item_wrap_bytes(&self) -> Result<[u8; 32], Error> {
        Ok(*self.unlocked()?.item_wrap.as_bytes())
    }
}

/// A bundle's fingerprint as 12 groups of 5 digits joined by spaces. Public data, so it needs no
/// session.
pub(crate) fn fingerprint(bundle: &[u8]) -> Result<String, Error> {
    Ok(Bundle::from_bytes(bundle)?.fingerprint_text())
}

/// Whether `signature` is the bundle's own `sig1` signature (`"bundle"` context) under the `sig1`
/// public key the bundle carries. It proves the owner of that key published the bundle, not that
/// the key is the right person's: comparing fingerprints does that.
pub(crate) fn verify_bundle(bundle: &[u8], signature: &[u8]) -> bool {
    Bundle::from_bytes(bundle)
        .and_then(|bundle| bundle.verify_self_signature(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Native `cargo test --workspace` unifies kemlock-crypto's features with the server's, which
    // turns on aws-lc-rs, and that backend can't derive `kx1` keys. So everything that touches
    // `kx1` runs in WebAssembly (src/tests.rs); what is left here is backend-independent.

    #[test]
    fn weak_and_absurd_kdf_settings_are_refused() {
        let mut session = Session::new();
        let salt = [7u8; 16];
        for (m, t, p, salt) in [
            (16 * 1024, 1, 1, &salt[..]),
            (16 * 1024, 11, 1, &salt[..]),
            (16 * 1024 - 1, 2, 1, &salt[..]),
            (1024 * 1024 + 1, 2, 1, &salt[..]),
            (16 * 1024, 2, 0, &salt[..]),
            (16 * 1024, 2, 17, &salt[..]),
            (16 * 1024, 2, 1, &salt[..15]),
            (16 * 1024, 2, 1, &[0u8; 65][..]),
        ] {
            assert_eq!(
                session.master_key(b"pw", m, t, p, salt),
                Err(Error::Invalid),
                "{m} {t} {p} {}",
                salt.len()
            );
        }
        assert!(session.slots.is_empty());
    }

    #[test]
    fn handles_are_checked_by_kind_and_never_reused() {
        let mut session = Session::new();
        let master = session.insert_master([1; 32]).expect("handle");
        let export = session.insert_export([2; 64]).expect("handle");
        assert_ne!(master, export);
        assert!(session.master(master).is_ok());
        assert!(session.master(export).is_err());
        assert!(session.export(master).is_err());
        assert!(session.master(99).is_err());

        session.release(master);
        session.release(master);
        assert!(session.master(master).is_err());
        let again = session.insert_master([1; 32]).expect("handle");
        assert_ne!(again, master);

        session.lock();
        assert!(session.export(export).is_err());
        let after = session.insert_master([1; 32]).expect("handle");
        assert!(after > again);
    }

    #[test]
    fn a_locked_session_refuses_item_work() {
        let session = Session::new();
        let owner = Owner::user([1; 16]);
        assert!(!session.is_unlocked());
        assert!(matches!(
            session.seal_item(&[2; 16], &owner, "login", 1, b"{}"),
            Err(Error::Locked)
        ));
        let item = SealedItemRef {
            id: &[2; 16],
            owner: &owner,
            kind: "login",
            revision: 1,
            ciphertext: &[0; 40],
            item_key: &[0; 60],
            key_version: None,
        };
        assert!(matches!(session.open_item(&item), Err(Error::Locked)));
        assert_eq!(session.own_fingerprint(), Err(Error::Locked));
    }

    #[test]
    fn a_stale_opaque_handle_fails_without_side_effects() {
        let mut session = Session::new();
        let master = session.insert_master([1; 32]).expect("handle");
        assert_eq!(
            session
                .opaque_register_finish(55, master, &[0; 64])
                .map(|_| ()),
            Err(Error::Invalid)
        );
        assert_eq!(
            session
                .opaque_login_finish(56, master, &[0; 320])
                .map(|_| ()),
            Err(Error::Invalid)
        );
        assert!(session.master(master).is_ok());
    }

    #[test]
    fn debug_shows_no_secrets() {
        let mut session = Session::new();
        session.insert_master([0xAB; 32]).expect("handle");
        let text = format!("{session:?}");
        assert!(text.contains("handles"), "{text}");
        assert!(!text.contains("171"), "{text}");
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;

    fn unlocked_session(item_wrap: [u8; 32], key_version: u32) -> Session {
        let mut session = Session::new();
        session.unlocked = Some(Unlocked {
            account_id: [1; 16],
            key_version,
            root: RootKey::from_bytes(&[0x44; 64]),
            item_wrap: SecretKey::from_bytes(&item_wrap),
            private: None,
            spaces: SpaceKeys::default(),
        });
        session
    }

    #[test]
    fn a_send_key_is_wrapped_under_the_account_and_opens_again() {
        let session = unlocked_session([2; 32], 3);
        let link_key = SecretKey::from_bytes(&[9; 32]);
        let sealed = session.wrap_send_key(&[4; 16], &link_key).expect("wrap");
        assert_eq!(sealed.len(), send::SEALED_KEY_LEN);
        assert_eq!(sealed[..4], [0, 0, 0, 3]);
        let opened = session.unwrap_send_key(&[4; 16], &sealed).expect("unwrap");
        assert_eq!(opened.as_bytes(), link_key.as_bytes());
    }

    #[test]
    fn a_send_key_stays_with_its_send_and_its_account() {
        let session = unlocked_session([2; 32], 1);
        let sealed = session
            .wrap_send_key(&[4; 16], &SecretKey::from_bytes(&[9; 32]))
            .expect("wrap");
        assert!(session.unwrap_send_key(&[5; 16], &sealed).is_err());
        let other = unlocked_session([3; 32], 1);
        assert!(other.unwrap_send_key(&[4; 16], &sealed).is_err());
        assert!(session.unwrap_send_key(&[4; 16], &sealed[1..]).is_err());
    }

    #[test]
    fn a_meta_opens_in_its_account_and_not_with_the_link_key() {
        let session = unlocked_session([2; 32], 3);
        let link_key = SecretKey::from_bytes(&[9; 32]);
        let id = [4; 16];
        let sealed_key = session.wrap_send_key(&id, &link_key).expect("wrap");
        let json = br#"{"name":"n","notes":"private"}"#;
        let meta = session.seal_send_meta(&id, Kind::Text, json).expect("seal");
        let opened = session
            .open_send_meta(&id, Kind::Text, &sealed_key, &meta)
            .expect("open");
        assert_eq!(opened.as_bytes(), json);
        // Another Send, another kind, another account: nothing opens.
        assert!(
            session
                .open_send_meta(&[5; 16], Kind::Text, &sealed_key, &meta)
                .is_err()
        );
        assert!(
            session
                .open_send_meta(&id, Kind::File, &sealed_key, &meta)
                .is_err()
        );
        let other = unlocked_session([3; 32], 3);
        assert!(
            other
                .open_send_meta(&id, Kind::Text, &sealed_key, &meta)
                .is_err()
        );
        // A holder of the link key alone has only K to use as a wrap key.
        let from_link = unlocked_session(*link_key.as_bytes(), 3);
        assert!(
            from_link
                .open_send_meta(&id, Kind::Text, &sealed_key, &meta)
                .is_err()
        );
    }

    #[test]
    fn a_locked_session_wraps_no_send_key() {
        let session = Session::new();
        let key = SecretKey::from_bytes(&[9; 32]);
        assert_eq!(session.wrap_send_key(&[4; 16], &key), Err(Error::Locked));
        assert!(matches!(
            session.unwrap_send_key(&[4; 16], &[0; 64]),
            Err(Error::Locked)
        ));
        assert_eq!(
            session.seal_send_meta(&[4; 16], Kind::Text, b"{}"),
            Err(Error::Locked)
        );
        assert_eq!(
            session.open_send_meta(&[4; 16], Kind::Text, &[0; 64], &[0; 40]),
            Err(Error::Locked)
        );
    }
}

#[cfg(test)]
mod rewrap_tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [0x61; 16];

    fn unlocked_session(key_version: u32) -> Session {
        let mut session = Session::new();
        session.unlocked = Some(Unlocked {
            account_id: ACCOUNT,
            key_version,
            root: RootKey::from_bytes(&[0x44; 64]),
            item_wrap: SecretKey::from_bytes(&[2; 32]),
            private: None,
            spaces: SpaceKeys::default(),
        });
        session
    }

    #[test]
    fn a_locked_session_wraps_nothing_and_keeps_the_handles() {
        let mut session = Session::new();
        let master = session.insert_master([1; 32]).expect("handle");
        let export = session.insert_export([2; 64]).expect("handle");
        assert_eq!(session.rewrap_root(master, export), Err(Error::Locked));
        assert!(session.master(master).is_ok());
        assert!(session.export(export).is_ok());
    }

    #[test]
    fn the_wrap_opens_under_the_new_keys_and_only_them() {
        let mut session = unlocked_session(3);
        let master = session.insert_master([7; 32]).expect("handle");
        let export = session.insert_export([8; 64]).expect("handle");

        let wrapped = session.rewrap_root(master, export).expect("wraps");

        assert_eq!(wrapped.len(), password_wrap::WRAPPED_LEN);
        // The same root key, for the same account and key version.
        let opened = password_wrap::open(&[7; 32], &[8; 64], &wrapped, &ACCOUNT, 3).expect("opens");
        assert_eq!(opened.as_bytes(), &[0x44u8; 64]);
        // Another master key, export key, account or key version opens nothing.
        let wrong_master = password_wrap::open(&[9; 32], &[8; 64], &wrapped, &ACCOUNT, 3);
        assert!(wrong_master.is_err());
        let wrong_export = password_wrap::open(&[7; 32], &[9; 64], &wrapped, &ACCOUNT, 3);
        assert!(wrong_export.is_err());
        let wrong_account = password_wrap::open(&[7; 32], &[8; 64], &wrapped, &[0x62; 16], 3);
        assert!(wrong_account.is_err());
        let wrong_version = password_wrap::open(&[7; 32], &[8; 64], &wrapped, &ACCOUNT, 4);
        assert!(wrong_version.is_err());
    }

    #[test]
    fn the_next_sign_in_unlocks_with_the_new_keys() {
        let mut session = unlocked_session(1);
        let master = session.insert_master([7; 32]).expect("handle");
        let export = session.insert_export([8; 64]).expect("handle");
        let wrapped = session.rewrap_root(master, export).expect("wraps");

        // The open session carries on: the root key is the same one.
        assert!(session.is_unlocked());
        let mut next = Session::new();
        let m = next.insert_master([7; 32]).expect("handle");
        let e = next.insert_export([8; 64]).expect("handle");
        next.unlock(&ACCOUNT, &wrapped, m, e, 1, None)
            .expect("unlocks");
        assert!(next.is_unlocked());
        // The old keys no longer unlock with this wrap.
        let mut old = Session::new();
        let m = old.insert_master([1; 32]).expect("handle");
        let e = old.insert_export([2; 64]).expect("handle");
        assert!(old.unlock(&ACCOUNT, &wrapped, m, e, 1, None).is_err());
        assert!(!old.is_unlocked());
    }

    #[test]
    fn both_handles_are_spent_and_a_wrong_handle_spends_nothing() {
        let mut session = unlocked_session(1);
        let master = session.insert_master([7; 32]).expect("handle");
        let export = session.insert_export([8; 64]).expect("handle");

        // A handle of the other kind, or none at all.
        assert_eq!(session.rewrap_root(export, master), Err(Error::Invalid));
        assert_eq!(session.rewrap_root(master, 9_999), Err(Error::Invalid));
        assert!(session.master(master).is_ok());
        assert!(session.export(export).is_ok());

        session.rewrap_root(master, export).expect("wraps");
        assert!(session.master(master).is_err());
        assert!(session.export(export).is_err());
        assert_eq!(session.rewrap_root(master, export), Err(Error::Invalid));
    }
}
