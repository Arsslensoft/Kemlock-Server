//! The cursor a device holds between syncs: one version vector per owner.
//!
//! A device syncs its user's vault and every space its user is a confirmed member of. Each of
//! those owners has its own change history, so the cursor keeps one [`VersionVector`] per owner
//! and an owner the cursor doesn't list starts from the empty vector, which asks for its whole
//! history.
//!
//! # Why a vector per owner
//!
//! Sequence numbers belong to the server that accepted the write, not to an owner: one server
//! numbers the changes of every vault and space it holds in one run. A single vector over all of
//! a device's owners, which the first release used, therefore could not tell "I have seen this
//! owner's changes up to here" from "I have seen some other owner's changes up to there". A
//! device that joined a space later already held a high sequence number for the server from its
//! own vault, so every item the space had received before it joined looked covered and was never
//! sent. A per-owner cursor has no such blind spot: the new owner is not in it, and its first
//! delta is its full history, once.
//!
//! This is also what a replica can answer. Federation moves one vault at a time and a peer's
//! cursor is a version vector per vault (docs/federation.md), so the replica of a space has seen
//! the space's changes up to its own vector for that space and nothing else says more.
//!
//! The alternative rejected: let the server record the change id at which each member joined (and
//! at which each collection was granted), and send an owner's full history once to a cursor older
//! than that. It keeps the cursor a single vector, but the join's change id is the local
//! server's: a replica that applies the same membership at another position in its own log would
//! disagree on when "joined" was, and a device that moves between a home server and a replica
//! would be told the wrong history. It also keeps server-side state for every membership forever.
//! A vector per owner carries that knowledge in the cursor and needs none of it.
//!
//! # Forms
//!
//! A cursor is opaque to clients. The server reads two versions:
//!
//! - version 1 is a single vector, the first release's cursor: `u8(1) ‖ u16be(n) ‖ n × (server id
//!   (16) ‖ u64be(seq))`. It reads as "every owner is at this vector", which is what it meant
//!   when it was issued. The next sync converts it into a version 2 cursor. (A space the device
//!   joined while holding a version 1 cursor stays missing its earlier items: the cursor can't
//!   say which owners it was issued for. A device that finds items missing starts over with no
//!   cursor.)
//! - version 2 lists the owners: `u8(2) ‖ u16be(n) ‖ n × (owner (17) ‖ u16be(k) ‖ k × (server id
//!   (16) ‖ u64be(seq)))`, owners ascending, each vector's origins ascending, no sequence of 0,
//!   no owner with an empty vector. The server writes only this form. The cursor grows by about
//!   43 bytes per owner with one origin, and the form takes at most [`SyncCursor::MAX_OWNERS`].
//!
//! Federation's own cursors, between servers, stay version 1 vectors, one per vault.
//!
//! # Held items
//!
//! A key replacement can leave live items **held** (docs/crypto.md, I3). A held item is in no
//! owner's pages; every member of the space is sent it from a vector of its own, one
//! per collection, written in the owner slot as `u8(0x03) ‖ collection id (16)`. A collection the
//! cursor doesn't list is read from empty, so a member who joins the space later is sent
//! its held items, as an owner that is new to the device is sent its whole history. Those entries
//! sort after every owner and count toward [`SyncCursor::MAX_OWNERS`].

use crate::change::{BadCursor, VersionVector};
use crate::ids::ServerId;
use crate::owner::Owner;
use crate::spaces::CollectionId;
use std::collections::BTreeMap;

/// What a device has seen of each owner it syncs. See the module comment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncCursor {
    /// The vector of an owner this cursor doesn't list: empty, except for a version 1 cursor,
    /// which holds one vector for every owner.
    fallback: VersionVector,
    owners: BTreeMap<Owner, VersionVector>,
    /// What the device has seen of the held items of each collection of its spaces.
    held: BTreeMap<CollectionId, VersionVector>,
}

impl SyncCursor {
    /// The version this server writes.
    pub const CURSOR_VERSION: u8 = 2;
    /// The most owners a cursor lists: more than any account is a member of, so a client can't
    /// make the server parse much.
    pub const MAX_OWNERS: usize = 1024;
    /// The type byte of a held-items entry, in the place of an owner's.
    pub const TYPE_HELD: u8 = 0x03;

    /// A version 1 cursor: every owner at `vector`.
    pub fn legacy(vector: VersionVector) -> Self {
        SyncCursor {
            fallback: vector,
            owners: BTreeMap::new(),
            held: BTreeMap::new(),
        }
    }

    /// A cursor of these owners' vectors. An owner with an empty vector is left out: not listed
    /// and empty mean the same.
    pub fn from_owners(owners: impl IntoIterator<Item = (Owner, VersionVector)>) -> Self {
        Self::from_parts(owners, [])
    }

    /// A cursor of these owners' vectors and of the held items of these collections. A vector
    /// that is empty is left out of either.
    pub fn from_parts(
        owners: impl IntoIterator<Item = (Owner, VersionVector)>,
        held: impl IntoIterator<Item = (CollectionId, VersionVector)>,
    ) -> Self {
        SyncCursor {
            fallback: VersionVector::new(),
            owners: owners.into_iter().filter(|(_, v)| !v.is_empty()).collect(),
            held: held.into_iter().filter(|(_, v)| !v.is_empty()).collect(),
        }
    }

    /// Whether this cursor has seen nothing: a first sync.
    pub fn is_empty(&self) -> bool {
        self.fallback.is_empty() && self.owners.is_empty() && self.held.is_empty()
    }

    /// What this cursor has seen of the held items of `collection`: empty for one it doesn't
    /// list, a version 1 cursor's vector included, which never covered held items.
    pub fn held_since(&self, collection: CollectionId) -> VersionVector {
        self.held.get(&collection).cloned().unwrap_or_default()
    }

    /// What this cursor has seen of `owner`; empty for an owner it doesn't know.
    pub fn since(&self, owner: Owner) -> &VersionVector {
        self.owners.get(&owner).unwrap_or(&self.fallback)
    }

    /// Every vector of the cursor merged into one, for a caller that wants the newest sequence
    /// seen from each origin whatever the owner.
    pub fn merged(&self) -> VersionVector {
        let mut all = self.fallback.clone();
        for vector in self.owners.values() {
            all.merge(vector);
        }
        all
    }

    /// The cursor's binary form (see the module comment): a version 2 cursor, or the version 1
    /// form again for one that was read as such and not changed. The API layer base64url-encodes
    /// it.
    pub fn to_cursor_bytes(&self) -> Vec<u8> {
        if self.owners.is_empty() && self.held.is_empty() && !self.fallback.is_empty() {
            return self.fallback.to_cursor_bytes();
        }
        let mut out = vec![Self::CURSOR_VERSION];
        // MAX_OWNERS and MAX_ORIGINS keep both counts well inside u16.
        out.extend_from_slice(&((self.owners.len() + self.held.len()) as u16).to_be_bytes());
        for (owner, vector) in &self.owners {
            out.extend_from_slice(&owner.to_bytes());
            write_vector(&mut out, vector);
        }
        for (collection, vector) in &self.held {
            out.push(Self::TYPE_HELD);
            out.extend_from_slice(collection.as_bytes());
            write_vector(&mut out, vector);
        }
        out
    }

    /// Parses either version, refusing unknown versions, unsorted or repeated owners and origins,
    /// empty or zero entries, and trailing bytes.
    pub fn from_cursor_bytes(bytes: &[u8]) -> Result<Self, BadCursor> {
        let (&version, mut rest) = bytes.split_first().ok_or(BadCursor)?;
        match version {
            VersionVector::CURSOR_VERSION => {
                VersionVector::from_cursor_bytes(bytes).map(SyncCursor::legacy)
            }
            Self::CURSOR_VERSION => {
                let n = usize::from(u16::from_be_bytes(take(&mut rest)?));
                if n > Self::MAX_OWNERS {
                    return Err(BadCursor);
                }
                let mut owners = BTreeMap::new();
                let mut held = BTreeMap::new();
                // The 17 bytes of the entry before: entries ascend, as bytes.
                let mut last: Option<[u8; 17]> = None;
                for _ in 0..n {
                    let key = take::<17>(&mut rest)?;
                    if last.is_some_and(|l| l >= key) {
                        return Err(BadCursor);
                    }
                    last = Some(key);
                    if key[0] == Self::TYPE_HELD {
                        let mut id = [0u8; 16];
                        id.copy_from_slice(&key[1..]);
                        let collection = CollectionId(uuid::Uuid::from_bytes(id));
                        held.insert(collection, read_vector(&mut rest)?);
                    } else {
                        let owner = Owner::from_bytes(&key).ok_or(BadCursor)?;
                        owners.insert(owner, read_vector(&mut rest)?);
                    }
                }
                if !rest.is_empty() {
                    return Err(BadCursor);
                }
                Ok(SyncCursor {
                    fallback: VersionVector::new(),
                    owners,
                    held,
                })
            }
            _ => Err(BadCursor),
        }
    }
}

/// One vector: `u16be(k) ‖ k × (server id ‖ u64be(seq))`.
fn write_vector(out: &mut Vec<u8>, vector: &VersionVector) {
    let entries: Vec<(ServerId, u64)> = vector.iter().collect();
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (origin, seq) in entries {
        out.extend_from_slice(origin.as_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
    }
}

/// The next `N` bytes of `rest`, which then starts after them.
fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], BadCursor> {
    if rest.len() < N {
        return Err(BadCursor);
    }
    let (head, tail) = rest.split_at(N);
    *rest = tail;
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    Ok(out)
}

/// One owner's vector: `u16be(k) ‖ k × (server id ‖ u64be(seq))`, `k` at least 1.
fn read_vector(rest: &mut &[u8]) -> Result<VersionVector, BadCursor> {
    let k = usize::from(u16::from_be_bytes(take(rest)?));
    if k == 0 || k > VersionVector::MAX_ORIGINS {
        return Err(BadCursor);
    }
    let mut entries = Vec::with_capacity(k);
    let mut last: Option<ServerId> = None;
    for _ in 0..k {
        let origin = ServerId(uuid::Uuid::from_bytes(take(rest)?));
        let seq = u64::from_be_bytes(take(rest)?);
        if seq == 0 || last.is_some_and(|l| l >= origin) {
            return Err(BadCursor);
        }
        last = Some(origin);
        entries.push((origin, seq));
    }
    Ok(entries.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{SpaceId, UserId};

    fn vector(entries: &[(ServerId, u64)]) -> VersionVector {
        entries.iter().copied().collect()
    }

    fn user() -> Owner {
        Owner::User(UserId::random())
    }

    fn space() -> Owner {
        Owner::Space(SpaceId::random())
    }

    #[test]
    fn an_owner_the_cursor_does_not_list_starts_empty() {
        let server = ServerId::random();
        let (mine, joined) = (user(), space());
        let cursor = SyncCursor::from_owners([(mine, vector(&[(server, 9)]))]);
        assert_eq!(cursor.since(mine).get(server), 9);
        assert!(cursor.since(joined).is_empty());
    }

    #[test]
    fn a_version_1_cursor_is_every_owner_at_that_vector() {
        let server = ServerId::random();
        let old = vector(&[(server, 4)]);
        let cursor = SyncCursor::from_cursor_bytes(&old.to_cursor_bytes()).expect("version 1");
        assert_eq!(cursor, SyncCursor::legacy(old.clone()));
        assert_eq!(cursor.since(user()), &old);
        assert_eq!(cursor.since(space()), &old);
        // Left as it was, it is written as it was.
        assert_eq!(cursor.to_cursor_bytes(), old.to_cursor_bytes());
        assert!(!cursor.is_empty());
        assert_eq!(cursor.merged(), old);
    }

    #[test]
    fn an_empty_version_1_cursor_is_a_first_sync() {
        let cursor =
            SyncCursor::from_cursor_bytes(&VersionVector::new().to_cursor_bytes()).expect("v1");
        assert!(cursor.is_empty());
    }

    #[test]
    fn a_cursor_round_trips_and_drops_empty_vectors() {
        let (a, b) = (ServerId::random(), ServerId::random());
        let owners = [user(), space(), space()];
        let cursor = SyncCursor::from_owners([
            (owners[0], vector(&[(a, 7), (b, 1)])),
            (owners[1], vector(&[(a, 2)])),
            (owners[2], VersionVector::new()),
        ]);
        let bytes = cursor.to_cursor_bytes();
        assert_eq!(bytes[0], SyncCursor::CURSOR_VERSION);
        let back = SyncCursor::from_cursor_bytes(&bytes).expect("reads back");
        assert_eq!(back, cursor);
        assert_eq!(back.since(owners[0]).get(b), 1);
        assert!(back.since(owners[2]).is_empty());
        assert_eq!(back.merged(), vector(&[(a, 7), (b, 1)]));
    }

    #[test]
    fn an_empty_cursor_round_trips() {
        let empty = SyncCursor::default();
        assert!(empty.is_empty());
        let bytes = empty.to_cursor_bytes();
        assert_eq!(SyncCursor::from_cursor_bytes(&bytes), Ok(empty));
    }

    #[test]
    fn a_cursor_refuses_malformed_input() {
        let server = ServerId::random();
        let one = user();
        let two = space();
        let cursor =
            SyncCursor::from_owners([(one, vector(&[(server, 5)])), (two, vector(&[(server, 3)]))]);
        let good = cursor.to_cursor_bytes();
        // Layout: version, count (2), then per owner 17 + 2 + 24 = 43 bytes.
        let mut trailing = good.clone();
        trailing.push(0);
        let mut version = good.clone();
        version[0] = 3;
        let mut zero_seq = good.clone();
        zero_seq[3 + 17 + 2 + 16..3 + 43].fill(0);
        let mut no_origins = good.clone();
        no_origins[3 + 17..3 + 19].fill(0);
        let mut bad_owner = good.clone();
        bad_owner[3] = 9;
        let mut swapped = good.clone();
        let (first, second) = swapped[3..].split_at_mut(43);
        first.swap_with_slice(second);
        let mut repeated = good.clone();
        let (first, second) = repeated[3..].split_at_mut(43);
        second.copy_from_slice(first);
        let mut too_many = vec![SyncCursor::CURSOR_VERSION];
        too_many.extend_from_slice(&((SyncCursor::MAX_OWNERS as u16) + 1).to_be_bytes());
        for bad in [
            &[][..],
            &trailing,
            &version,
            &zero_seq,
            &no_origins,
            &bad_owner,
            &swapped,
            &repeated,
            &too_many,
            &good[..good.len() - 1],
            &good[..2],
        ] {
            assert_eq!(
                SyncCursor::from_cursor_bytes(bad),
                Err(BadCursor),
                "{bad:?}"
            );
        }
    }
}

#[cfg(test)]
mod held_tests {
    use super::*;
    use crate::ids::{SpaceId, UserId};

    fn vector(entries: &[(ServerId, u64)]) -> VersionVector {
        entries.iter().copied().collect()
    }

    #[test]
    fn held_entries_round_trip_after_the_owners_and_start_empty_when_not_listed() {
        let server = ServerId::random();
        let mine = Owner::User(UserId::random());
        let space = Owner::Space(SpaceId::random());
        let (one, two) = (CollectionId::random(), CollectionId::random());
        let cursor = SyncCursor::from_parts(
            [
                (mine, vector(&[(server, 4)])),
                (space, vector(&[(server, 9)])),
            ],
            [(one, vector(&[(server, 6)])), (two, VersionVector::new())],
        );
        let bytes = cursor.to_cursor_bytes();
        let back = SyncCursor::from_cursor_bytes(&bytes).expect("reads back");
        assert_eq!(back, cursor);
        assert_eq!(back.held_since(one).get(server), 6);
        // A collection the cursor doesn't list reads from empty: it is sent its held items.
        assert!(back.held_since(two).is_empty());
        assert!(back.held_since(CollectionId::random()).is_empty());
        // Entries follow the owners: 3 + 2 owners of 43 bytes, then the held one.
        assert_eq!(bytes[3 + 2 * 43], SyncCursor::TYPE_HELD);
        assert!(!SyncCursor::from_parts([], [(one, vector(&[(server, 1)]))]).is_empty());
    }

    #[test]
    fn a_held_entry_before_an_owner_or_repeated_is_refused() {
        let server = ServerId::random();
        let space = Owner::Space(SpaceId::random());
        let held = CollectionId::random();
        let good = SyncCursor::from_parts(
            [(space, vector(&[(server, 1)]))],
            [(held, vector(&[(server, 2)]))],
        )
        .to_cursor_bytes();
        let mut swapped = good.clone();
        let (first, second) = swapped[3..].split_at_mut(43);
        first.swap_with_slice(second);
        let mut repeated = good.clone();
        let (first, second) = repeated[3..].split_at_mut(43);
        second.copy_from_slice(first);
        for bad in [&swapped, &repeated] {
            assert_eq!(SyncCursor::from_cursor_bytes(bad), Err(BadCursor));
        }
    }
}
