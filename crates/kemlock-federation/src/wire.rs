//! Small helpers for the byte formats: ids, owners, change keys and big-endian integers.

use crate::error::{FedError, Result};
use kemlock_domain::{ChangeId, ItemId, Owner, ServerId};

/// A server id from its 16 raw bytes.
pub fn server_id(bytes: [u8; 16]) -> ServerId {
    ServerId(uuid::Uuid::from_bytes(bytes))
}

/// An item id from its 16 raw bytes.
pub fn item_id(bytes: [u8; 16]) -> ItemId {
    ItemId(uuid::Uuid::from_bytes(bytes))
}

/// An owner from its 17-byte form (`u8(type) ‖ uuid`).
pub fn owner(bytes: [u8; 17]) -> Result<Owner> {
    Owner::from_bytes(&bytes).ok_or(FedError::Malformed("unknown owner type"))
}

/// The identity of one change: the server that accepted it and that server's sequence number.
/// A version of an item is named by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeKey {
    pub origin: ServerId,
    pub seq: u64,
}

impl ChangeKey {
    pub const LEN: usize = 24;

    pub fn of(change: &ChangeId) -> ChangeKey {
        ChangeKey {
            origin: change.origin,
            seq: change.seq,
        }
    }

    /// `origin (16) ‖ u64be(seq)`.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..16].copy_from_slice(self.origin.as_bytes());
        out[16..].copy_from_slice(&self.seq.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ChangeKey> {
        let bytes: &[u8; 24] = bytes
            .try_into()
            .map_err(|_| FedError::Malformed("a change key has the wrong length"))?;
        let mut origin = [0u8; 16];
        origin.copy_from_slice(&bytes[..16]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&bytes[16..]);
        Ok(ChangeKey {
            origin: server_id(origin),
            seq: u64::from_be_bytes(seq),
        })
    }
}

/// Concatenated change keys, as the database and signed lineages hold them.
pub fn pack_keys(keys: &[ChangeKey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(keys.len() * ChangeKey::LEN);
    for key in keys {
        out.extend_from_slice(&key.to_bytes());
    }
    out
}

pub fn unpack_keys(bytes: &[u8]) -> Result<Vec<ChangeKey>> {
    if !bytes.len().is_multiple_of(ChangeKey::LEN) {
        return Err(FedError::Malformed(
            "a change key list has the wrong length",
        ));
    }
    bytes
        .as_chunks::<{ ChangeKey::LEN }>()
        .0
        .iter()
        .map(|c| ChangeKey::from_bytes(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_keys_round_trip() {
        let keys = vec![
            ChangeKey {
                origin: ServerId::random(),
                seq: 7,
            },
            ChangeKey {
                origin: ServerId::random(),
                seq: u64::MAX,
            },
        ];
        assert_eq!(unpack_keys(&pack_keys(&keys)), Ok(keys));
        assert!(unpack_keys(&[0; 25]).is_err());
        assert_eq!(unpack_keys(&[]), Ok(vec![]));
    }

    #[test]
    fn owners_parse_or_fail() {
        let o = Owner::User(kemlock_domain::UserId::random());
        assert_eq!(owner(o.to_bytes()), Ok(o));
        let mut bad = o.to_bytes();
        bad[0] = 9;
        assert!(owner(bad).is_err());
    }
}
