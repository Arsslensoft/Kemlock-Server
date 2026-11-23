//! The signed manifest: item ids and revisions a device has seen, so a deleted or reverted item
//! shows as tampering rather than as a quiet change.
//!
//! ```text
//! manifest = "kemlock/v1/manifest" ‖ owner (17) ‖ u64be(counter) ‖ u32be(n)
//!            ‖ n × (item id (16) ‖ u64be(revision) ‖ SHA-256(ciphertext) (32) ‖ u8(deleted))
//! ```
//!
//! Entries are sorted by item id bytes. A tombstone's hash is 32 zero bytes. The writer signs it
//! with `sig1` under context `"manifest"`. The counter only goes up; a device keeps the highest it
//! has seen.

use crate::{
    Error,
    hash::sha256,
    owner::{self, Owner},
    sig1::{self, context::MANIFEST},
    wire::Reader,
};

const LABEL: &[u8] = b"kemlock/v1/manifest";
const HEADER_LEN: usize = 19 + owner::LEN + 8 + 4;
/// The length of one entry.
pub const ENTRY_LEN: usize = 16 + 8 + 32 + 1;

/// One item the manifest vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub item_id: [u8; 16],
    pub revision: u64,
    /// SHA-256 of the item's ciphertext; 32 zero bytes for a tombstone.
    pub ciphertext_hash: [u8; 32],
    pub deleted: bool,
}

impl Entry {
    /// A live item: the hash is taken from its ciphertext.
    pub fn live(item_id: [u8; 16], revision: u64, ciphertext: &[u8]) -> Entry {
        Entry {
            item_id,
            revision,
            ciphertext_hash: sha256(ciphertext),
            deleted: false,
        }
    }

    /// A deleted item: its revision still moves on, and its hash is all zero.
    pub fn tombstone(item_id: [u8; 16], revision: u64) -> Entry {
        Entry {
            item_id,
            revision,
            ciphertext_hash: [0; 32],
            deleted: true,
        }
    }
}

/// A manifest: an owner, a counter and the items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub owner: Owner,
    pub counter: u64,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Encodes the manifest with its entries sorted by item id. Fails on a repeated item id or a
    /// tombstone whose hash isn't zero.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|e| e.item_id);
        if entries
            .windows(2)
            .any(|pair| pair[0].item_id == pair[1].item_id)
        {
            return Err(Error::invalid());
        }
        if entries
            .iter()
            .any(|e| e.deleted && e.ciphertext_hash != [0; 32])
        {
            return Err(Error::invalid());
        }
        let count = u32::try_from(entries.len()).map_err(|_| Error::invalid())?;
        let mut out = Vec::with_capacity(HEADER_LEN + entries.len() * ENTRY_LEN);
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.owner.to_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &entries {
            out.extend_from_slice(&entry.item_id);
            out.extend_from_slice(&entry.revision.to_be_bytes());
            out.extend_from_slice(&entry.ciphertext_hash);
            out.push(u8::from(entry.deleted));
        }
        Ok(out)
    }

    /// Parses a manifest. Refuses another label, a count that doesn't match the length, entries
    /// out of order or repeated, a deleted flag other than 0 or 1, a tombstone with a hash, and
    /// trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Manifest, Error> {
        let mut reader = Reader::new(bytes);
        if reader.take(LABEL.len())? != LABEL {
            return Err(Error::invalid());
        }
        let owner = Owner::from_bytes(&reader.array::<{ owner::LEN }>()?)?;
        let counter = reader.u64()?;
        let count = usize::try_from(reader.u32()?).map_err(|_| Error::invalid())?;
        // The length is checked before anything is allocated for the entries.
        let expected = count
            .checked_mul(ENTRY_LEN)
            .and_then(|n| n.checked_add(HEADER_LEN))
            .ok_or_else(Error::invalid)?;
        if bytes.len() != expected {
            return Err(Error::invalid());
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(count);
        for _ in 0..count {
            let item_id = reader.array::<16>()?;
            let revision = reader.u64()?;
            let ciphertext_hash = reader.array::<32>()?;
            let deleted = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::invalid()),
            };
            if deleted && ciphertext_hash != [0; 32] {
                return Err(Error::invalid());
            }
            if let Some(previous) = entries.last()
                && previous.item_id >= item_id
            {
                return Err(Error::invalid());
            }
            entries.push(Entry {
                item_id,
                revision,
                ciphertext_hash,
                deleted,
            });
        }
        reader.finish()?;
        Ok(Manifest {
            owner,
            counter,
            entries,
        })
    }

    /// Signs the encoded manifest with the writer's `sig1` key under context `"manifest"`.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Vec<u8>, Error> {
        key.sign(MANIFEST, &self.to_bytes()?)
    }

    /// Checks a signature over `encoded` and, only if it is good, parses it.
    pub fn open_signed(
        public: &sig1::PublicKey,
        encoded: &[u8],
        signature: &[u8],
    ) -> Result<Manifest, Error> {
        public.verify(MANIFEST, encoded, signature)?;
        Manifest::from_bytes(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            owner: Owner::user([7; 16]),
            counter: 9,
            entries: vec![
                Entry::live([3; 16], 2, b"cipher three"),
                Entry::tombstone([1; 16], 5),
                Entry::live([2; 16], 1, b"cipher two"),
            ],
        }
    }

    #[test]
    fn layout_matches_the_doc() {
        let bytes = manifest().to_bytes().expect("encode");
        assert_eq!(bytes.len(), 48 + 3 * 57);
        assert_eq!(&bytes[..19], b"kemlock/v1/manifest");
        assert_eq!(bytes[19], 1);
        assert_eq!(&bytes[20..36], &[7; 16]);
        assert_eq!(&bytes[36..44], &[0, 0, 0, 0, 0, 0, 0, 9]);
        assert_eq!(&bytes[44..48], &[0, 0, 0, 3]);
        // The first entry is the tombstone of item 1 (sorted by id).
        assert_eq!(&bytes[48..64], &[1; 16]);
        assert_eq!(&bytes[64..72], &[0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&bytes[72..104], &[0; 32]);
        assert_eq!(bytes[104], 1);
        // The second is item 2, live, with the SHA-256 of its ciphertext.
        assert_eq!(&bytes[105..121], &[2; 16]);
        assert_eq!(&bytes[129..161], &sha256(b"cipher two"));
        assert_eq!(bytes[161], 0);
    }

    #[test]
    fn entries_are_sorted_and_the_input_order_does_not_matter() {
        let a = manifest();
        let mut b = manifest();
        b.entries.reverse();
        assert_eq!(a.to_bytes().expect("encode"), b.to_bytes().expect("encode"));
    }

    #[test]
    fn round_trips() {
        let decoded =
            Manifest::from_bytes(&manifest().to_bytes().expect("encode")).expect("decode");
        let mut expected = manifest();
        expected.entries.sort_by_key(|e| e.item_id);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn an_empty_manifest_round_trips() {
        let m = Manifest {
            owner: Owner::space([1; 16]),
            counter: 0,
            entries: vec![],
        };
        let bytes = m.to_bytes().expect("encode");
        assert_eq!(bytes.len(), 48);
        assert_eq!(Manifest::from_bytes(&bytes), Ok(m));
    }

    #[test]
    fn encoding_refuses_repeated_ids_and_dirty_tombstones() {
        let mut m = manifest();
        m.entries.push(Entry::live([1; 16], 9, b"again"));
        assert!(m.to_bytes().is_err());
        let mut m = manifest();
        m.entries[1].ciphertext_hash = [1; 32];
        assert!(m.to_bytes().is_err());
    }

    #[test]
    fn decoding_is_strict() {
        let bytes = manifest().to_bytes().expect("encode");
        // Trailing byte, missing byte, wrong label.
        let mut long = bytes.clone();
        long.push(0);
        assert!(Manifest::from_bytes(&long).is_err());
        assert!(Manifest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut label = bytes.clone();
        label[0] ^= 1;
        assert!(Manifest::from_bytes(&label).is_err());
        // A count that doesn't match the length, in both directions.
        let mut count = bytes.clone();
        count[47] = 4;
        assert!(Manifest::from_bytes(&count).is_err());
        count[47] = 2;
        assert!(Manifest::from_bytes(&count).is_err());
        // A huge count must fail on length without allocating.
        let mut huge = bytes.clone();
        huge[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Manifest::from_bytes(&huge).is_err());
        // A deleted flag of 2, a tombstone with a hash, an unknown owner type.
        let mut flag = bytes.clone();
        flag[104] = 2;
        assert!(Manifest::from_bytes(&flag).is_err());
        let mut hash = bytes.clone();
        hash[80] = 1;
        assert!(Manifest::from_bytes(&hash).is_err());
        let mut owner = bytes.clone();
        owner[19] = 9;
        assert!(Manifest::from_bytes(&owner).is_err());
    }

    #[test]
    fn decoding_refuses_unsorted_or_repeated_entries() {
        let bytes = manifest().to_bytes().expect("encode");
        // Swap the first two entries (57 bytes each, from offset 48).
        let mut swapped = bytes.clone();
        let (first, second) = (bytes[48..105].to_vec(), bytes[105..162].to_vec());
        swapped[48..105].copy_from_slice(&second);
        swapped[105..162].copy_from_slice(&first);
        assert!(Manifest::from_bytes(&swapped).is_err());
        // Repeat the first entry in place of the second.
        let mut repeated = bytes.clone();
        repeated[105..162].copy_from_slice(&first);
        assert!(Manifest::from_bytes(&repeated).is_err());
    }

    #[test]
    fn a_signed_manifest_opens_and_a_changed_one_does_not() {
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let public = key.public_key().expect("public key");
        let m = manifest();
        let signature = m.sign(&key).expect("sign");
        let encoded = m.to_bytes().expect("encode");
        assert_eq!(
            Manifest::open_signed(&public, &encoded, &signature)
                .expect("open")
                .counter,
            9
        );

        // A rolled-back counter, a dropped entry and another signer all fail.
        let mut changed = m.clone();
        changed.counter = 8;
        assert!(
            Manifest::open_signed(&public, &changed.to_bytes().expect("encode"), &signature)
                .is_err()
        );
        let mut dropped = m.clone();
        dropped.entries.pop();
        assert!(
            Manifest::open_signed(&public, &dropped.to_bytes().expect("encode"), &signature)
                .is_err()
        );
        let other = sig1::SigningKey::from_bytes(&[6; 64])
            .public_key()
            .expect("public key");
        assert!(Manifest::open_signed(&other, &encoded, &signature).is_err());
    }
}
