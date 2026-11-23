//! What a client does with a verified state that is a pure function of it: opening a key at the
//! chain's version, and picking the person to compare a fingerprint with on first contact
//! (docs/crypto.md, "Space chain": "Using the state", "First contact").

use zeroize::Zeroizing;

use crate::{
    backend::{Active, Backend},
    bundle::{self, FINGERPRINT_LEN},
    kx1, sealed_box,
};

use super::{
    model::{Hash, Id, KeyRef},
    seals::{box_context, key_check_in, seal_digest_in},
    state::{State, Status},
};

/// Why a client uses no key of a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRefusal {
    /// The server served another version than the chain's current one.
    WrongVersion,
    /// The chain committed no seal of this key version to this member.
    NotCommitted,
    /// The box's hash, or the server's hash list, isn't what the chain's digest covers.
    HashList,
    /// The box doesn't open for this member.
    WontOpen,
    /// The key that opened isn't the one whose check the chain holds.
    BadCheck,
}

/// A hash list entry the server serves for a record: `(member, bundle key version, seal hash)`.
pub type SealListEntry = (Id, u32, Hash);

/// Opens a key at **the chain's current version** only. `served_version` and `sealed` are what the
/// server serves for the member; `list` is the server's seal hash list for the record that
/// committed it (`G5`), needed when that commitment covers more than the member.
///
/// The box is accepted only when the commitment covers just this member and the digest recomputed
/// from the box is the committed one, or the list names exactly the recipients the chain derived,
/// holds this box's hash and gives the committed digest; when it opens under the member's key; and
/// when the key's check is the chain's.
#[allow(clippy::too_many_arguments)]
pub fn open_key(
    state: &State,
    space: &Id,
    me: &Id,
    private: &kx1::PrivateKey,
    key: &KeyRef,
    served_version: u32,
    sealed: &[u8],
    list: Option<&[SealListEntry]>,
) -> Result<Zeroizing<[u8; 32]>, KeyRefusal> {
    open_key_in::<Active>(state, space, me, private, key, served_version, sealed, list)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_key_in<B: Backend>(
    state: &State,
    space: &Id,
    me: &Id,
    private: &kx1::PrivateKey,
    key: &KeyRef,
    served_version: u32,
    sealed: &[u8],
    list: Option<&[SealListEntry]>,
) -> Result<Zeroizing<[u8; 32]>, KeyRefusal> {
    let current = state.key_version(key).ok_or(KeyRefusal::NotCommitted)?;
    if served_version != current {
        return Err(KeyRefusal::WrongVersion);
    }
    let seal = state
        .seals
        .get(&(*key, current, *me))
        .ok_or(KeyRefusal::NotCommitted)?;
    let committed = state
        .commitments
        .get(&(*key, current, seal.seq))
        .ok_or(KeyRefusal::NotCommitted)?;
    let own: SealListEntry = (*me, seal.bundle_version, B::sha256(sealed));

    // 1. The commitment covers just this member, or the server's list matches it.
    let alone = committed.recipients.len() == 1
        && seal_digest_in::<B>(space, key, current, &[own]) == committed.digest;
    let listed = list.is_some_and(|entries| {
        let names: Vec<(Id, u32)> = entries.iter().map(|(m, v, _)| (*m, *v)).collect();
        names == committed.recipients
            && entries.contains(&own)
            && seal_digest_in::<B>(space, key, current, entries) == committed.digest
    });
    if !alone && !listed {
        return Err(KeyRefusal::HashList);
    }

    // 2. The box opens under the member's key, with the documented aad.
    let (context, aad) = box_context(key, space, current, me);
    let opened = sealed_box::open_in::<B>(private, context, &aad, sealed)
        .map_err(|_| KeyRefusal::WontOpen)?;
    let secret: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| KeyRefusal::WontOpen)?;

    // 3. The key's check is the chain's for that version.
    let expected = state
        .key_checks
        .get(&(*key, current))
        .ok_or(KeyRefusal::NotCommitted)?;
    let check =
        key_check_in::<B>(space, key, current, &secret).map_err(|_| KeyRefusal::BadCheck)?;
    if &check != expected {
        return Err(KeyRefusal::BadCheck);
    }
    Ok(Zeroizing::new(secret))
}

/// The person a device compares a fingerprint with on first contact, and the fingerprint of their
/// bundle **as the chain records it at its head**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorPerson {
    pub person: Id,
    pub fingerprint: [u8; FINGERPRINT_LEN],
}

/// The anchor person for account `me`: the inviter of an invitee, or the confirmer of a confirmed
/// member's new device. `None` when `me` made the chain, when their own current key signed a
/// record after their confirmation (their key vouches), or when the person is no longer a
/// confirmed member and the human must pick a confirmed Owner instead.
pub fn anchor_person(state: &State, me: &Id) -> Option<AnchorPerson> {
    let member = state.members.get(me)?;
    let person = match member.status {
        Status::Removed => return None,
        Status::Invited => member.invited_by,
        Status::Confirmed => {
            if member.rekey_seq.is_some() {
                return None;
            }
            member.confirmation.as_ref()?.by
        }
    };
    if person == *me {
        return None;
    }
    let bundle = state.confirmed(&person)?.bundle.as_ref()?;
    Some(AnchorPerson {
        person,
        fingerprint: bundle::fingerprint_in::<Active>(&bundle.to_bytes()),
    })
}

/// Why a client holds an item revision instead of applying it ("Using the state", "Items").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemRefusal {
    /// The item names a collection the chain doesn't have, or one it deleted.
    UnknownCollection,
    /// The revision is wrapped under a key version older than the collection's current one.
    OldKeyVersion,
    /// The revision is wrapped under a key version the chain hasn't made yet.
    NewKeyVersion,
    /// The collection's key, or the space key, is marked and waits for its replacement: no new
    /// revision is accepted until the `keys` record that replaces it.
    KeyMarked,
}

/// Whether a client accepts an item revision it hasn't accepted yet, for the collection
/// `collection`, wrapped under `key_version`. A refused revision is held and shown, not applied.
///
/// Revisions the client accepted before a record marked the key stay as they are; this is for the
/// ones that arrive after it, and for any that arrive after the key was replaced under the old
/// version.
pub fn check_item_revision(
    state: &State,
    collection: &Id,
    key_version: u32,
) -> Result<(), ItemRefusal> {
    let current = state
        .collections
        .get(collection)
        .ok_or(ItemRefusal::UnknownCollection)?
        .key_version;
    if key_version < current {
        return Err(ItemRefusal::OldKeyVersion);
    }
    if key_version > current {
        return Err(ItemRefusal::NewKeyVersion);
    }
    if state.key_marked(&KeyRef::Collection(*collection)) || state.key_marked(&KeyRef::Space) {
        return Err(ItemRefusal::KeyMarked);
    }
    Ok(())
}
