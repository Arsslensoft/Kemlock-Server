//! A space's keys and names, inside the unlocked session.
//!
//! A space has one random 32-byte space key per key version, and each of its collections one random
//! 32-byte collection key per key version (`docs/crypto.md`: the server holds each sealed to the
//! members who may have it, as a `kx1` sealed box under context `"space-key"` or
//! `"collection-key"`). Nothing here leaves this module as a key: only boxes and ciphertexts do.
//!
//! **What a box is bound to.** The box's `aad` names what the key is for, so a server can't serve
//! one space's (or collection's) box as another's to a member who holds both:
//!
//! ```text
//! space-key:      aad = space id (16) ‖ u32be(space key version) ‖ recipient account id (16)
//! collection-key: aad = space id (16) ‖ collection id (16) ‖ u32be(collection key version)
//!                       ‖ recipient account id (16)
//! ```
//!
//! **Names.** The names of a space, its collections and its groups are encrypted under the space
//! key, which `docs/crypto.md` states but does not lay out. They use the `kem1` envelope on a
//! child key of the space key, so no new construction is added:
//!
//! ```text
//! name key   = HKDF(ikm = space key, salt = absent, info = "kemlock/v1/space-name", L = 32)
//! ciphertext = kem1.seal_item(name key, id = the space's, collection's or group's id,
//!                             revision = the space key version, kind = "space-name",
//!                             "collection-name" or "group-name", owner = space:<space id>,
//!                             json = the name's UTF-8)
//! ```
//!
//! So a name opens only under the space, id, kind and key version it was sealed with, and a rename
//! under the same key version is a fresh nonce, not a new key.

use std::collections::{HashMap, HashSet};

use kemlock_crypto::{
    bundle::{Bundle, FINGERPRINT_LEN, fingerprint_groups},
    kem1, key_box,
    keys::{ITEM_WRAP_LABEL, SecretKey},
    kx1,
    owner::Owner,
    sealed_box::{self, context},
    sig1,
    space_chain::{
        State,
        client::{ItemRefusal, check_item_revision},
    },
};
use zeroize::Zeroizing;

use crate::{
    chain::HeldChain,
    error::Error,
    session::{SealedItem, SealedItemRef, Session},
};

/// The label of the space key's child that encrypts names.
pub(crate) const NAME_KEY_LABEL: &str = "kemlock/v1/space-name";

/// An encrypted name must fit `kemlock-domain`'s 4 KiB sealed-name limit.
const MAX_SEALED_NAME_LEN: usize = 4096;
/// What sealing adds to a name: a 12-byte nonce and a 16-byte tag.
const SEAL_OVERHEAD: usize = 28;

/// What a name names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameKind {
    Space,
    Collection,
    Group,
}

impl NameKind {
    pub(crate) fn parse(text: &str) -> Result<NameKind, Error> {
        match text {
            "space" => Ok(NameKind::Space),
            "collection" => Ok(NameKind::Collection),
            "group" => Ok(NameKind::Group),
            _ => Err(Error::Invalid),
        }
    }

    /// The `kem1` kind the name is sealed under.
    fn item_kind(self) -> &'static str {
        match self {
            NameKind::Space => "space-name",
            NameKind::Collection => "collection-name",
            NameKind::Group => "group-name",
        }
    }
}

/// The space and collection keys this unlock holds, by id and key version. Every key is wiped when
/// it drops (`SecretKey`), so `lock` wipes them with the rest of the session.
#[derive(Default)]
pub(crate) struct SpaceKeys {
    pub(crate) spaces: HashMap<([u8; 16], u32), SecretKey>,
    pub(crate) collections: HashMap<([u8; 16], [u8; 16], u32), SecretKey>,
    /// The verified chains of the spaces that have one (`chain.rs`). A space in here opens and
    /// seals keys only through its chain.
    pub(crate) chains: HashMap<[u8; 16], HeldChain>,
    /// Spaces whose served chain was refused: they have a chain, so they stay closed too.
    pub(crate) refused: HashSet<[u8; 16]>,
    /// Spaces the account's own signed record names as chained (the page tells the worker before it
    /// reads a chain). A space in here has a chain even when the server serves none: it stays closed
    /// to the unchained operations, so keys the server names can't stand in for the chain's.
    pub(crate) expected_chained: HashSet<[u8; 16]>,
    /// Spaces with a key opened from a box that carried no signature and that this browser had not
    /// accepted before (the server's own word, on first sight). Nothing is sealed or written under
    /// the keys of such a space until a person has compared their fingerprint
    /// ([`Session::accept_provisional_keys`]).
    pub(crate) provisional: HashSet<[u8; 16]>,
}

impl SpaceKeys {
    /// Forgets every key held for a space.
    pub(crate) fn drop_keys(&mut self, space: &[u8; 16]) {
        self.spaces.retain(|(held, _), _| held != space);
        self.collections.retain(|(held, _, _), _| held != space);
        self.provisional.remove(space);
    }

    /// The verified state of a space that has a chain, when this unlock has verified it.
    fn chain_state(&self, space: &[u8; 16]) -> Option<&State> {
        self.chains.get(space).map(|held| &held.state)
    }

    /// Refuses an operation that opens, seals or names keys outside the chain, for a space that
    /// has one: the page can't skip the chain by calling the older operations.
    pub(crate) fn require_unchained(&self, space: &[u8; 16]) -> Result<(), Error> {
        if self.chains.contains_key(space)
            || self.refused.contains(space)
            || self.expected_chained.contains(space)
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }

    /// Refuses sealing or writing under the keys of a space whose keys this browser took on the
    /// server's word (an unsigned box on first sight) and no person has compared yet.
    pub(crate) fn require_settled(&self, space: &[u8; 16]) -> Result<(), Error> {
        if self.provisional.contains(space) {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }

    /// Whether an item of `collection` may be written under `version`: for a chained space, only
    /// once first contact is done, under the collection's current key version, and while neither
    /// it nor the space key is marked ("Using the state", "Items"). For a space with no chain,
    /// only once its keys are settled ([`SpaceKeys::require_settled`]).
    fn allow_item_write(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
        version: u32,
    ) -> Result<(), Error> {
        if self.refused.contains(space) {
            return Err(Error::Invalid);
        }
        self.require_settled(space)?;
        let Some(held) = self.chains.get(space) else {
            return Ok(());
        };
        if !held.trusted {
            return Err(Error::Invalid);
        }
        check_item_revision(&held.state, collection, version).map_err(|_| Error::Invalid)
    }

    /// Whether an item of `collection` may be opened under `version`: for a chained space, the
    /// collection is one the chain has, at a key version it has made. A marked key doesn't hide
    /// what was accepted before it was marked.
    fn allow_item_open(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
        version: u32,
    ) -> Result<(), Error> {
        if self.refused.contains(space) {
            return Err(Error::Invalid);
        }
        let Some(held) = self.chains.get(space) else {
            return Ok(());
        };
        if !held.trusted {
            return Err(Error::Invalid);
        }
        match check_item_revision(&held.state, collection, version) {
            Ok(()) | Err(ItemRefusal::KeyMarked) => Ok(()),
            Err(_) => Err(Error::Invalid),
        }
    }

    fn space(&self, space: &[u8; 16], version: u32) -> Result<&SecretKey, Error> {
        self.spaces.get(&(*space, version)).ok_or(Error::Invalid)
    }

    /// The space key of the newest version held.
    fn newest_space(&self, space: &[u8; 16]) -> Result<(u32, &SecretKey), Error> {
        self.spaces
            .iter()
            .filter(|((id, _), _)| id == space)
            .max_by_key(|((_, version), _)| *version)
            .map(|((_, version), key)| (*version, key))
            .ok_or(Error::Invalid)
    }

    /// The collection key of exactly this version.
    fn collection(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
        version: u32,
    ) -> Result<&SecretKey, Error> {
        self.collections
            .get(&(*space, *collection, version))
            .ok_or(Error::Invalid)
    }

    /// The collection key of the newest version held.
    fn newest_collection(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
    ) -> Result<(u32, &SecretKey), Error> {
        self.collections
            .iter()
            .filter(|((s, c, _), _)| s == space && c == collection)
            .max_by_key(|((_, _, version), _)| *version)
            .map(|((_, _, version), key)| (*version, key))
            .ok_or(Error::Invalid)
    }
}

/// One key of a provisional space, as a person compares it: which key, its version and its
/// fingerprint, 12 groups of 5 digits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProvisionalKey {
    /// `None` for the space key.
    pub(crate) collection: Option<[u8; 16]>,
    pub(crate) version: u32,
    pub(crate) fingerprint: String,
}

/// The text of a key's fingerprint: 12 groups of 5 digits worked out from two one-way children of
/// the key, bound to the space, the collection and the key version, so the digits can be shown and
/// read aloud without giving the key away, and one key's can't be passed for another's.
pub(crate) fn key_fingerprint(
    key: &SecretKey,
    space: &[u8; 16],
    collection: Option<&[u8; 16]>,
    version: u32,
) -> Result<String, Error> {
    fn hex(bytes: &[u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    let scope = match collection {
        None => format!("kemlock/v1/key-fingerprint/{}/space/{version}", hex(space)),
        Some(collection) => format!(
            "kemlock/v1/key-fingerprint/{}/collection/{}/{version}",
            hex(space),
            hex(collection)
        ),
    };
    let mut digest = Zeroizing::new([0u8; FINGERPRINT_LEN]);
    digest[..32].copy_from_slice(key.child(&format!("{scope}/a"))?.as_bytes());
    digest[32..].copy_from_slice(key.child(&format!("{scope}/b"))?.as_bytes());
    Ok(fingerprint_groups(&digest).join(" "))
}

/// The `aad` of a space key's box: the space, the key version and the recipient.
pub(crate) fn space_key_aad(space: &[u8; 16], version: u32, recipient: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(space);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(recipient);
    out
}

/// The `aad` of a collection key's box: the space, the collection, the key version and the
/// recipient.
pub(crate) fn collection_key_aad(
    space: &[u8; 16],
    collection: &[u8; 16],
    version: u32,
    recipient: &[u8; 16],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    out.extend_from_slice(space);
    out.extend_from_slice(collection);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(recipient);
    out
}

/// A new space's names and sealed keys, all sealed to its maker.
pub(crate) struct NewSpace {
    pub(crate) name: Vec<u8>,
    pub(crate) sealed_space_key: Vec<u8>,
    /// The maker's `sig1` signature over `sealed_space_key` (docs/crypto.md, "Signed key boxes").
    pub(crate) sealed_space_key_signature: Vec<u8>,
    pub(crate) collection: NewCollection,
}

/// A new collection's name and its key sealed to its maker.
pub(crate) struct NewCollection {
    pub(crate) name: Vec<u8>,
    pub(crate) sealed_key: Vec<u8>,
    /// The maker's `sig1` signature over `sealed_key`.
    pub(crate) sealed_key_signature: Vec<u8>,
}

/// The first key version of a collection: a collection's key has versions of its own, not its
/// space's.
const FIRST_COLLECTION_KEY_VERSION: u32 = 1;

/// The first key version of a space.
const FIRST_SPACE_KEY_VERSION: u32 = 1;

/// A key box sealed to someone, with the sealer's signature over it (docs/crypto.md, "Signed key
/// boxes").
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SignedBox {
    pub(crate) sealed: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// The signature of the unlocked account over a key box it sealed: the sealer is the account and
/// the key version its own.
fn sign_key_box(
    sig_private: &sig1::SigningKey,
    account: [u8; 16],
    key_version: u32,
    kind: key_box::Kind,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    Ok(key_box::Statement {
        kind,
        aad,
        sealed_box: sealed,
        sealer: account,
        sealer_key_version: key_version,
    }
    .sign(sig_private)?)
}

pub(crate) fn seal_name_under(
    space_key: &SecretKey,
    space: &[u8; 16],
    version: u32,
    kind: NameKind,
    id: &[u8; 16],
    name: &str,
) -> Result<Vec<u8>, Error> {
    if name.len() + SEAL_OVERHEAD > MAX_SEALED_NAME_LEN {
        return Err(Error::Invalid);
    }
    let key = space_key.child(NAME_KEY_LABEL)?;
    Ok(kem1::seal_item(
        &key,
        id,
        u64::from(version),
        kind.item_kind(),
        &Owner::space(*space),
        name.as_bytes(),
    )?)
}

fn key_from(plain: &[u8]) -> Result<SecretKey, Error> {
    let bytes: &[u8; 32] = plain.try_into().map_err(|_| Error::Invalid)?;
    Ok(SecretKey::from_bytes(bytes))
}

impl Session {
    /// A fresh space key and first collection key (both version 1), the names of both under the
    /// space key, and each key sealed to the unlocked account's own `kx1` key. Both keys are kept
    /// for sealing to members. Refused for a space already held.
    pub(crate) fn new_space(
        &mut self,
        space: &[u8; 16],
        collection: &[u8; 16],
        space_name: &str,
        collection_name: &str,
    ) -> Result<NewSpace, Error> {
        let unlocked = self.unlocked_mut()?;
        let (kx_private, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        if unlocked.spaces.newest_space(space).is_ok() {
            return Err(Error::Invalid);
        }
        unlocked.spaces.require_unchained(space)?;
        let own_public = kx_private.public_key()?;
        let own_id = unlocked.account_id;
        let own_version = unlocked.key_version;

        let space_key = SecretKey::generate();
        let collection_key = SecretKey::generate();
        let version = FIRST_SPACE_KEY_VERSION;
        // Both boxes are sealed to this account and signed by it, so a client that opens them later
        // finds a box its own account made.
        let space_aad = space_key_aad(space, version, &own_id);
        let sealed_space_key = sealed_box::seal(
            &own_public,
            context::SPACE_KEY,
            &space_aad,
            space_key.as_bytes(),
        )?;
        let sealed_space_key_signature = sign_key_box(
            sig_private,
            own_id,
            own_version,
            key_box::Kind::Space,
            &space_aad,
            &sealed_space_key,
        )?;
        let collection_aad = collection_key_aad(space, collection, version, &own_id);
        let sealed_key = sealed_box::seal(
            &own_public,
            context::COLLECTION_KEY,
            &collection_aad,
            collection_key.as_bytes(),
        )?;
        let sealed_key_signature = sign_key_box(
            sig_private,
            own_id,
            own_version,
            key_box::Kind::Collection,
            &collection_aad,
            &sealed_key,
        )?;
        let made = NewSpace {
            name: seal_name_under(
                &space_key,
                space,
                version,
                NameKind::Space,
                space,
                space_name,
            )?,
            sealed_space_key,
            sealed_space_key_signature,
            collection: NewCollection {
                name: seal_name_under(
                    &space_key,
                    space,
                    version,
                    NameKind::Collection,
                    collection,
                    collection_name,
                )?,
                sealed_key,
                sealed_key_signature,
            },
        };
        unlocked.spaces.spaces.insert((*space, version), space_key);
        unlocked
            .spaces
            .collections
            .insert((*space, *collection, version), collection_key);
        Ok(made)
    }

    /// Opens the space key sealed to this account and keeps it for `space` at `key_version`.
    pub(crate) fn open_space(
        &mut self,
        space: &[u8; 16],
        key_version: u32,
        sealed: &[u8],
    ) -> Result<(), Error> {
        let unlocked = self.unlocked_mut()?;
        // A space with a chain opens its keys through the chain (`open_chain_key`) only.
        unlocked.spaces.require_unchained(space)?;
        let (kx_private, _) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let plain = sealed_box::open(
            kx_private,
            context::SPACE_KEY,
            &space_key_aad(space, key_version, &unlocked.account_id),
            sealed,
        )?;
        let key = key_from(&plain)?;
        unlocked.spaces.spaces.insert((*space, key_version), key);
        Ok(())
    }

    /// Opens a collection key sealed to this account and keeps it.
    pub(crate) fn open_collection(
        &mut self,
        space: &[u8; 16],
        collection: &[u8; 16],
        key_version: u32,
        sealed: &[u8],
    ) -> Result<(), Error> {
        let unlocked = self.unlocked_mut()?;
        unlocked.spaces.require_unchained(space)?;
        let (kx_private, _) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let plain = sealed_box::open(
            kx_private,
            context::COLLECTION_KEY,
            &collection_key_aad(space, collection, key_version, &unlocked.account_id),
            sealed,
        )?;
        let key = key_from(&plain)?;
        unlocked
            .spaces
            .collections
            .insert((*space, *collection, key_version), key);
        Ok(())
    }

    /// As [`Session::open_space`], for a box that carried no signature and that this browser had not
    /// accepted before: the key is kept for reading, and the space is marked so that nothing is
    /// sealed or written under its keys until a person has compared them
    /// ([`Session::accept_provisional_keys`]).
    pub(crate) fn open_space_unsigned(
        &mut self,
        space: &[u8; 16],
        key_version: u32,
        sealed: &[u8],
    ) -> Result<(), Error> {
        self.open_space(space, key_version, sealed)?;
        self.unlocked_mut()?.spaces.provisional.insert(*space);
        Ok(())
    }

    /// As [`Session::open_collection`], for an unsigned box not accepted before (see
    /// [`Session::open_space_unsigned`]).
    pub(crate) fn open_collection_unsigned(
        &mut self,
        space: &[u8; 16],
        collection: &[u8; 16],
        key_version: u32,
        sealed: &[u8],
    ) -> Result<(), Error> {
        self.open_collection(space, collection, key_version, sealed)?;
        self.unlocked_mut()?.spaces.provisional.insert(*space);
        Ok(())
    }

    /// Tells the worker the account's own signed record names `space` as chained: until a verified
    /// chain is held for it, the unchained operations refuse it and an empty chain is a refusal
    /// (a chain the server withheld), not "no chain".
    pub(crate) fn expect_chained(&mut self, space: &[u8; 16]) -> Result<(), Error> {
        let unlocked = self.unlocked_mut()?;
        unlocked.spaces.expected_chained.insert(*space);
        Ok(())
    }

    /// The fingerprints of the keys of a space marked provisional, for a person to compare with a
    /// member who holds them: first the space key (newest version), then each collection key held
    /// (newest version of each, in collection id order). `None` when the space is not provisional.
    pub(crate) fn provisional_fingerprints(
        &self,
        space: &[u8; 16],
    ) -> Result<Option<Vec<ProvisionalKey>>, Error> {
        let unlocked = self.unlocked()?;
        if !unlocked.spaces.provisional.contains(space) {
            return Ok(None);
        }
        let (version, key) = unlocked.spaces.newest_space(space)?;
        let mut out = vec![ProvisionalKey {
            collection: None,
            version,
            fingerprint: key_fingerprint(key, space, None, version)?,
        }];
        let mut collections: Vec<[u8; 16]> = unlocked
            .spaces
            .collections
            .keys()
            .filter(|(held, _, _)| held == space)
            .map(|(_, collection, _)| *collection)
            .collect();
        collections.sort_unstable();
        collections.dedup();
        for collection in collections {
            let (version, key) = unlocked.spaces.newest_collection(space, &collection)?;
            out.push(ProvisionalKey {
                collection: Some(collection),
                version,
                fingerprint: key_fingerprint(key, space, Some(&collection), version)?,
            });
        }
        Ok(Some(out))
    }

    /// The person compared the fingerprints of a provisional space's keys and typed the last group
    /// of the space key's: when it is right the space is settled, and sealing and writing under
    /// its keys are allowed again. Anything else leaves it as it was.
    pub(crate) fn accept_provisional_keys(
        &mut self,
        space: &[u8; 16],
        typed_last_group: &str,
    ) -> Result<(), Error> {
        let shown = self
            .provisional_fingerprints(space)?
            .ok_or(Error::Invalid)?;
        let space_key = shown.first().ok_or(Error::Invalid)?;
        let want = space_key.fingerprint.rsplit(' ').next().unwrap_or_default();
        let typed: String = typed_last_group.split_whitespace().collect();
        if want.is_empty() || !kemlock_crypto::hash::ct_eq(typed.as_bytes(), want.as_bytes()) {
            return Err(Error::Invalid);
        }
        self.unlocked_mut()?.spaces.provisional.remove(space);
        Ok(())
    }

    /// Decrypts a name. Fails for another space, id, kind or key version than it was sealed with.
    pub(crate) fn open_name(
        &self,
        space: &[u8; 16],
        key_version: u32,
        kind: NameKind,
        id: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<String, Error> {
        let unlocked = self.unlocked()?;
        if unlocked.spaces.refused.contains(space) {
            return Err(Error::Invalid);
        }
        // A name of a chained space is shown only when it is the one the chain committed, at the
        // name version it recorded ("Using the state", "Names").
        if let Some(state) = unlocked.spaces.chain_state(space) {
            if !unlocked
                .spaces
                .chains
                .get(space)
                .is_some_and(|held| held.trusted)
            {
                return Err(Error::Invalid);
            }
            let committed = match kind {
                NameKind::Space if id == space => {
                    Some((state.space.name_hash, state.space.name_version))
                }
                NameKind::Space => None,
                NameKind::Collection => state
                    .collections
                    .get(id)
                    .map(|c| (c.name_hash, c.name_version)),
                NameKind::Group => state.groups.get(id).map(|g| (g.name_hash, g.name_version)),
            };
            match committed {
                Some((hash, version))
                    if version == key_version
                        && hash == kemlock_crypto::hash::sha256(ciphertext) => {}
                _ => return Err(Error::Invalid),
            }
        }
        let key = unlocked
            .spaces
            .space(space, key_version)?
            .child(NAME_KEY_LABEL)?;
        let plain: Zeroizing<Vec<u8>> = kem1::open_item(
            &key,
            id,
            u64::from(key_version),
            kind.item_kind(),
            &Owner::space(*space),
            ciphertext,
        )?;
        String::from_utf8(plain.to_vec()).map_err(|_| Error::Invalid)
    }

    /// Encrypts a name under the space key of `key_version`.
    pub(crate) fn seal_name(
        &self,
        space: &[u8; 16],
        key_version: u32,
        kind: NameKind,
        id: &[u8; 16],
        name: &str,
    ) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        // A chained space's names change by records, which commit their hashes.
        unlocked.spaces.require_unchained(space)?;
        unlocked.spaces.require_settled(space)?;
        let key = unlocked.spaces.space(space, key_version)?;
        seal_name_under(key, space, key_version, kind, id, name)
    }

    /// Seals an item of a space's collection. The item key is wrapped under the
    /// `"kemlock/v1/item-wrap"` child of the newest key held of that collection, so only a member
    /// granted the collection opens it; the wrap is bound to the item, the owner `space:<id>` and
    /// the collection key's version, which is the `key_version` the item carries.
    pub(crate) fn seal_space_item(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
        id: &[u8; 16],
        kind: &str,
        revision: u64,
        json: &[u8],
    ) -> Result<SealedItem, Error> {
        let unlocked = self.unlocked()?;
        let (version, key) = unlocked.spaces.newest_collection(space, collection)?;
        unlocked
            .spaces
            .allow_item_write(space, collection, version)?;
        let wrap = key.child(ITEM_WRAP_LABEL)?;
        let owner = Owner::space(*space);
        let item_key = SecretKey::generate();
        let ciphertext = kem1::seal_item(&item_key, id, revision, kind, &owner, json)?;
        let wrapped = kem1::wrap_item_key(&wrap, &item_key, id, &owner, version)?;
        Ok(SealedItem {
            ciphertext,
            item_key: wrapped,
            key_version: version,
        })
    }

    /// Opens an item of a space's collection with the collection key of the version it says.
    pub(crate) fn open_space_item(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
        item: &SealedItemRef<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if *item.owner != Owner::space(*space) {
            return Err(Error::Invalid);
        }
        let unlocked = self.unlocked()?;
        let version = item.key_version.ok_or(Error::Invalid)?;
        unlocked
            .spaces
            .allow_item_open(space, collection, version)?;
        let wrap = unlocked
            .spaces
            .collection(space, collection, version)?
            .child(ITEM_WRAP_LABEL)?;
        let item_key = kem1::unwrap_item_key(&wrap, item.item_key, item.id, item.owner, version)?;
        Ok(kem1::open_item(
            &item_key,
            item.id,
            item.revision,
            item.kind,
            item.owner,
            item.ciphertext,
        )?)
    }

    /// A new collection: a fresh key sealed to the maker, and its name under the newest space key
    /// held. The key is kept for sealing to the members the collection is granted to.
    pub(crate) fn new_collection(
        &mut self,
        space: &[u8; 16],
        collection: &[u8; 16],
        name: &str,
    ) -> Result<NewCollection, Error> {
        let unlocked = self.unlocked_mut()?;
        let (kx_private, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        unlocked.spaces.require_unchained(space)?;
        unlocked.spaces.require_settled(space)?;
        let (version, space_key) = unlocked.spaces.newest_space(space)?;
        if unlocked.spaces.collections.contains_key(&(
            *space,
            *collection,
            FIRST_COLLECTION_KEY_VERSION,
        )) {
            return Err(Error::Invalid);
        }
        let own_public = kx_private.public_key()?;
        let own_id = unlocked.account_id;
        let key = SecretKey::generate();
        let aad = collection_key_aad(space, collection, FIRST_COLLECTION_KEY_VERSION, &own_id);
        let sealed_key =
            sealed_box::seal(&own_public, context::COLLECTION_KEY, &aad, key.as_bytes())?;
        let sealed_key_signature = sign_key_box(
            sig_private,
            own_id,
            unlocked.key_version,
            key_box::Kind::Collection,
            &aad,
            &sealed_key,
        )?;
        let made = NewCollection {
            name: seal_name_under(
                space_key,
                space,
                version,
                NameKind::Collection,
                collection,
                name,
            )?,
            sealed_key,
            sealed_key_signature,
        };
        unlocked
            .spaces
            .collections
            .insert((*space, *collection, FIRST_COLLECTION_KEY_VERSION), key);
        Ok(made)
    }

    /// The newest space key held, sealed to a member's `kx1` key and signed by this account;
    /// `recipient_id` is their account id. The box is bound to the space, the key's version and the
    /// recipient.
    pub(crate) fn seal_space_key_to(
        &self,
        space: &[u8; 16],
        recipient_kx1: &[u8],
        recipient_id: &[u8; 16],
    ) -> Result<SignedBox, Error> {
        let unlocked = self.unlocked()?;
        // A chained space seals to the members its chain gives, in records, not to a key the page
        // names.
        unlocked.spaces.require_unchained(space)?;
        unlocked.spaces.require_settled(space)?;
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let (version, key) = unlocked.spaces.newest_space(space)?;
        let public = kx1::PublicKey::from_bytes(recipient_kx1)?;
        let aad = space_key_aad(space, version, recipient_id);
        let sealed = sealed_box::seal(&public, context::SPACE_KEY, &aad, key.as_bytes())?;
        let signature = sign_key_box(
            sig_private,
            unlocked.account_id,
            unlocked.key_version,
            key_box::Kind::Space,
            &aad,
            &sealed,
        )?;
        Ok(SignedBox { sealed, signature })
    }

    /// The newest key held of a collection, sealed to a member's `kx1` key and signed by this
    /// account.
    pub(crate) fn seal_collection_key_to(
        &self,
        space: &[u8; 16],
        collection: &[u8; 16],
        recipient_kx1: &[u8],
        recipient_id: &[u8; 16],
    ) -> Result<SignedBox, Error> {
        let unlocked = self.unlocked()?;
        unlocked.spaces.require_unchained(space)?;
        unlocked.spaces.require_settled(space)?;
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let (version, key) = unlocked.spaces.newest_collection(space, collection)?;
        let public = kx1::PublicKey::from_bytes(recipient_kx1)?;
        let aad = collection_key_aad(space, collection, version, recipient_id);
        let sealed = sealed_box::seal(&public, context::COLLECTION_KEY, &aad, key.as_bytes())?;
        let signature = sign_key_box(
            sig_private,
            unlocked.account_id,
            unlocked.key_version,
            key_box::Kind::Collection,
            &aad,
            &sealed,
        )?;
        Ok(SignedBox { sealed, signature })
    }
}

/// Whether `signature` is the sealer's `sig1` signature, under their bundle's key, over exactly the
/// key box statement these facts give, with the bundle's own account and key version as the
/// sealer's (docs/crypto.md, "Signed key boxes"). `collection` is `None` for a space key. Public
/// data only, so it needs no session. Anything malformed is simply `false`.
pub(crate) fn verify_key_box(
    sealer_bundle: &[u8],
    space: &[u8; 16],
    collection: Option<&[u8; 16]>,
    key_version: u32,
    recipient: &[u8; 16],
    sealed: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(bundle) = Bundle::from_bytes(sealer_bundle) else {
        return false;
    };
    let (kind, aad) = match collection {
        None => (
            key_box::Kind::Space,
            key_box::space_aad(space, key_version, recipient),
        ),
        Some(collection) => (
            key_box::Kind::Collection,
            key_box::collection_aad(space, collection, key_version, recipient),
        ),
    };
    key_box::Statement {
        kind,
        aad: &aad,
        sealed_box: sealed,
        sealer: bundle.account_id,
        sealer_key_version: bundle.key_version,
    }
    .verify(&bundle.sig1_public, signature)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Everything that touches `kx1` runs in WebAssembly (src/tests.rs); these are the parts that
    // do not.

    #[test]
    fn name_kinds_are_the_three_the_page_names() {
        assert_eq!(NameKind::parse("space"), Ok(NameKind::Space));
        assert_eq!(NameKind::parse("collection"), Ok(NameKind::Collection));
        assert_eq!(NameKind::parse("group"), Ok(NameKind::Group));
        for bad in ["", "Space", "folder", "space-name"] {
            assert_eq!(NameKind::parse(bad), Err(Error::Invalid), "{bad:?}");
        }
    }

    #[test]
    fn name_kinds_are_valid_kem1_kinds_and_differ() {
        let kinds =
            [NameKind::Space, NameKind::Collection, NameKind::Group].map(NameKind::item_kind);
        for kind in kinds {
            assert!(kem1::is_valid_kind(kind), "{kind}");
        }
        assert_ne!(kinds[0], kinds[1]);
        assert_ne!(kinds[1], kinds[2]);
        assert_ne!(kinds[0], kinds[2]);
    }

    #[test]
    fn a_locked_session_holds_no_space_keys() {
        let mut session = Session::new();
        let id = [1u8; 16];
        assert_eq!(
            session.new_space(&id, &id, "a", "b").map(|_| ()),
            Err(Error::Locked)
        );
        assert_eq!(session.open_space(&id, 1, &[0; 1661]), Err(Error::Locked));
        assert_eq!(
            session.open_collection(&id, &id, 1, &[0; 1661]),
            Err(Error::Locked)
        );
        assert_eq!(
            session.open_name(&id, 1, NameKind::Space, &id, &[0; 40]),
            Err(Error::Locked)
        );
        assert_eq!(
            session.seal_name(&id, 1, NameKind::Space, &id, "a"),
            Err(Error::Locked)
        );
        assert_eq!(
            session.new_collection(&id, &id, "a").map(|_| ()),
            Err(Error::Locked)
        );
        assert_eq!(
            session.seal_space_key_to(&id, &[0; 1600], &id),
            Err(Error::Locked)
        );
        assert_eq!(
            session.seal_collection_key_to(&id, &id, &[0; 1600], &id),
            Err(Error::Locked)
        );
    }

    #[test]
    fn box_aads_bind_the_space_collection_version_and_recipient() {
        let (s, c, r) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let space = space_key_aad(&s, 7, &r);
        assert_eq!(space.len(), 36);
        assert_eq!(&space[..16], &s);
        assert_eq!(&space[16..20], &[0, 0, 0, 7]);
        assert_eq!(&space[20..], &r);
        let collection = collection_key_aad(&s, &c, 7, &r);
        assert_eq!(collection.len(), 52);
        assert_eq!(&collection[..16], &s);
        assert_eq!(&collection[16..32], &c);
        assert_eq!(&collection[32..36], &[0, 0, 0, 7]);
        assert_eq!(&collection[36..], &r);
        assert_ne!(space_key_aad(&s, 8, &r), space);
        assert_ne!(space_key_aad(&[9; 16], 7, &r), space);
        assert_ne!(collection_key_aad(&s, &[9; 16], 7, &r), collection);
    }

    #[test]
    fn the_newest_key_wins() {
        let mut keys = SpaceKeys::default();
        let space = [1u8; 16];
        assert!(keys.newest_space(&space).is_err());
        for version in [3u32, 1, 2] {
            keys.spaces.insert(
                (space, version),
                SecretKey::from_bytes(&[u8::try_from(version).expect("small"); 32]),
            );
        }
        let (version, key) = keys.newest_space(&space).expect("a key");
        assert_eq!(version, 3);
        assert_eq!(key.as_bytes(), &[3; 32]);
        assert!(keys.newest_space(&[2; 16]).is_err());
        assert!(keys.space(&space, 2).is_ok());
        assert!(keys.space(&space, 4).is_err());
    }
}
