//! The change log's identities: every accepted write gets a change id, and a device's sync cursor
//! holds a version vector of the last change it saw from each server for each owner it syncs (see
//! `sync_cursor`).
//!
//! These exist from the first release so federation needs no migration of items: one server has a
//! one-entry vector, and a replica answers the same cursor (design, "How changes travel").

use crate::ids::ServerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A hybrid logical clock time: milliseconds since the Unix epoch in the high 48 bits, a logical
/// counter in the low 16. It orders changes across servers whose clocks drift.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct Hlc(pub u64);

impl Hlc {
    const LOGICAL_BITS: u32 = 16;
    const LOGICAL_MASK: u64 = (1 << Self::LOGICAL_BITS) - 1;

    pub fn from_parts(millis: u64, logical: u16) -> Self {
        Hlc((millis << Self::LOGICAL_BITS) | u64::from(logical))
    }

    pub fn millis(self) -> u64 {
        self.0 >> Self::LOGICAL_BITS
    }

    pub fn logical(self) -> u16 {
        // Masked to 16 bits, so the cast never truncates.
        (self.0 & Self::LOGICAL_MASK) as u16
    }

    /// The next time for a local event, given the wall clock now (ms). Never goes backwards, even
    /// when the wall clock does.
    pub fn tick(self, now_millis: u64) -> Hlc {
        if now_millis > self.millis() {
            Hlc::from_parts(now_millis, 0)
        } else {
            Hlc(self.0 + 1)
        }
    }

    /// The next time after receiving `remote`, given the wall clock now (ms).
    pub fn receive(self, remote: Hlc, now_millis: u64) -> Hlc {
        let latest = self.max(remote);
        if now_millis > latest.millis() {
            Hlc::from_parts(now_millis, 0)
        } else {
            Hlc(latest.0 + 1)
        }
    }
}

/// One accepted write: the server that accepted it, that server's next sequence number, and the
/// HLC time it was accepted at. Sequence numbers start at 1 and never repeat for one origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChangeId {
    pub origin: ServerId,
    pub seq: u64,
    pub hlc: Hlc,
}

/// The last sequence number seen from each origin server. A device's sync cursor holds one of these
/// per owner, encoded opaquely; an empty vector asks for everything.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionVector(BTreeMap<ServerId, u64>);

/// A cursor that can't be read: a client must start a full sync.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the sync cursor is not valid")]
pub struct BadCursor;

impl VersionVector {
    pub const CURSOR_VERSION: u8 = 1;
    /// More origins than any federation will have; bounds what a client can make us parse.
    pub const MAX_ORIGINS: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// The last sequence seen from `origin`, 0 when none.
    pub fn get(&self, origin: ServerId) -> u64 {
        self.0.get(&origin).copied().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (ServerId, u64)> + '_ {
        self.0.iter().map(|(k, v)| (*k, *v))
    }

    /// Whether a device holding this vector has already seen `change`.
    pub fn covers(&self, change: &ChangeId) -> bool {
        self.get(change.origin) >= change.seq
    }

    /// Whether this vector has seen everything `other` has.
    pub fn dominates(&self, other: &VersionVector) -> bool {
        other
            .0
            .iter()
            .all(|(origin, seq)| self.get(*origin) >= *seq)
    }

    /// Records `change` as seen.
    pub fn observe(&mut self, change: &ChangeId) {
        let seen = self.0.entry(change.origin).or_insert(0);
        if change.seq > *seen {
            *seen = change.seq;
        }
    }

    /// The pointwise maximum of both vectors.
    pub fn merge(&mut self, other: &VersionVector) {
        for (origin, seq) in &other.0 {
            let seen = self.0.entry(*origin).or_insert(0);
            if *seq > *seen {
                *seen = *seq;
            }
        }
    }

    /// The cursor's binary form: `u8(1) ‖ u16be(n) ‖ n × (server id (16) ‖ u64be(seq))`, origins
    /// in ascending order. The API layer base64url-encodes it; clients treat it as opaque.
    pub fn to_cursor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.0.len() * 24);
        out.push(Self::CURSOR_VERSION);
        // MAX_ORIGINS keeps the count well inside u16.
        out.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        for (origin, seq) in &self.0 {
            out.extend_from_slice(origin.as_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
        }
        out
    }

    /// Parses a cursor's binary form, refusing unknown versions, unsorted or repeated origins,
    /// zero sequences and trailing bytes.
    pub fn from_cursor_bytes(bytes: &[u8]) -> Result<Self, BadCursor> {
        let (&version, rest) = bytes.split_first().ok_or(BadCursor)?;
        if version != Self::CURSOR_VERSION || rest.len() < 2 {
            return Err(BadCursor);
        }
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let body = &rest[2..];
        if n > Self::MAX_ORIGINS || body.len() != n * 24 {
            return Err(BadCursor);
        }
        let mut map = BTreeMap::new();
        let mut last: Option<ServerId> = None;
        for chunk in body.as_chunks::<24>().0 {
            let mut id = [0u8; 16];
            id.copy_from_slice(&chunk[..16]);
            let origin = ServerId(uuid::Uuid::from_bytes(id));
            let mut seq = [0u8; 8];
            seq.copy_from_slice(&chunk[16..]);
            let seq = u64::from_be_bytes(seq);
            if seq == 0 || last.is_some_and(|l| l >= origin) {
                return Err(BadCursor);
            }
            last = Some(origin);
            map.insert(origin, seq);
        }
        Ok(VersionVector(map))
    }
}

impl FromIterator<(ServerId, u64)> for VersionVector {
    fn from_iter<T: IntoIterator<Item = (ServerId, u64)>>(iter: T) -> Self {
        let mut v = VersionVector::new();
        for (origin, seq) in iter {
            if seq > 0 {
                v.merge(&VersionVector(BTreeMap::from([(origin, seq)])));
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(origin: ServerId, seq: u64) -> ChangeId {
        ChangeId {
            origin,
            seq,
            hlc: Hlc::default(),
        }
    }

    #[test]
    fn hlc_never_goes_backwards() {
        let t = Hlc::from_parts(1_000, 0);
        let next = t.tick(900);
        assert!(next > t);
        assert_eq!(next.millis(), 1_000);
        assert_eq!(next.logical(), 1);
        assert_eq!(t.tick(2_000), Hlc::from_parts(2_000, 0));
        let remote = Hlc::from_parts(5_000, 7);
        assert_eq!(t.receive(remote, 1_000), Hlc::from_parts(5_000, 8));
    }

    #[test]
    fn covers_what_it_observed() {
        let a = ServerId::random();
        let mut v = VersionVector::new();
        assert!(!v.covers(&change(a, 1)));
        v.observe(&change(a, 3));
        assert!(v.covers(&change(a, 2)));
        assert!(!v.covers(&change(a, 4)));
        v.observe(&change(a, 1));
        assert_eq!(v.get(a), 3);
    }

    #[test]
    fn cursor_round_trips() {
        let v: VersionVector = [(ServerId::random(), 7), (ServerId::random(), 1)]
            .into_iter()
            .collect();
        let bytes = v.to_cursor_bytes();
        assert_eq!(VersionVector::from_cursor_bytes(&bytes), Ok(v));
        assert_eq!(
            VersionVector::from_cursor_bytes(&VersionVector::new().to_cursor_bytes()),
            Ok(VersionVector::new())
        );
    }

    #[test]
    fn cursor_refuses_malformed_input() {
        let v: VersionVector = [(ServerId::random(), 7), (ServerId::random(), 2)]
            .into_iter()
            .collect();
        let good = v.to_cursor_bytes();
        let mut trailing = good.clone();
        trailing.push(0);
        let mut version = good.clone();
        version[0] = 2;
        let mut swapped = good.clone();
        let (a, b) = swapped[3..].split_at_mut(24);
        a.swap_with_slice(b);
        let mut zero = good.clone();
        zero[19..27].fill(0);
        for bad in [
            &[][..],
            &trailing,
            &version,
            &swapped,
            &zero,
            &good[..good.len() - 1],
        ] {
            assert_eq!(
                VersionVector::from_cursor_bytes(bad),
                Err(BadCursor),
                "{bad:?}"
            );
        }
    }
}
