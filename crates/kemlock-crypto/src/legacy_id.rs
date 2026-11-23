//! Legacy ids: the stable UUIDs Kemlock gives spaces and items that other systems named with
//! something that isn't a UUID (an import, or the app's older ids).
//!
//! ```text
//! space uuid = uuidv8(SHA-256("kemlock/v1/legacy-id" ‖ lp("space") ‖ lp(old space id)))
//! item uuid  = uuidv8(SHA-256("kemlock/v1/legacy-id" ‖ lp("item") ‖ owner(17) ‖ lp(old item id)))
//! ```
//!
//! `uuidv8(h)` takes `h[0..16]` and sets `b[6] = b[6] & 0x0f | 0x80` and
//! `b[8] = b[8] & 0x3f | 0x80`. Old ids are their UTF-8 bytes. An id that already is a hyphenated
//! lower-case UUID is never mapped: callers check [`is_uuid`] first and keep it as it is.

use crate::{
    backend::{Active, Backend},
    owner,
};

const LABEL: &[u8] = b"kemlock/v1/legacy-id";

/// Whether `s` is a hyphenated lower-case UUID (`8-4-4-4-12` hex digits), the form that is never
/// mapped. The version and variant bits aren't checked: any such string counts.
pub fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, &b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// The UUID of a space whose old id was `old`.
pub fn space_uuid(old: &str) -> [u8; 16] {
    space_uuid_in::<Active>(old)
}

/// The UUID of an item whose old id was `old`, under the owner `owner` (`u8(type) ‖ uuid`, with
/// a space owner's uuid being the mapped one).
pub fn item_uuid(owner: &[u8; owner::LEN], old: &str) -> [u8; 16] {
    item_uuid_in::<Active>(owner, old)
}

fn push_lp(out: &mut Vec<u8>, x: &[u8]) {
    // An id of 4 GiB or more can't exist in practice; saturating keeps this infallible.
    let len = u32::try_from(x.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

pub(crate) fn space_uuid_in<B: Backend>(old: &str) -> [u8; 16] {
    let mut input = Vec::with_capacity(LABEL.len() + 4 + 5 + 4 + old.len());
    input.extend_from_slice(LABEL);
    push_lp(&mut input, b"space");
    push_lp(&mut input, old.as_bytes());
    uuidv8(&B::sha256(&input))
}

pub(crate) fn item_uuid_in<B: Backend>(owner: &[u8; owner::LEN], old: &str) -> [u8; 16] {
    let mut input = Vec::with_capacity(LABEL.len() + 4 + 4 + owner::LEN + 4 + old.len());
    input.extend_from_slice(LABEL);
    push_lp(&mut input, b"item");
    input.extend_from_slice(owner);
    push_lp(&mut input, old.as_bytes());
    uuidv8(&B::sha256(&input))
}

/// The first 16 bytes of a hash with the version (8) and variant (10) bits set.
fn uuidv8(hash: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out[6] = (out[6] & 0x0f) | 0x80;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::Owner;

    #[test]
    fn is_uuid_accepts_only_hyphenated_lower_case() {
        assert!(is_uuid("0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b"));
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
        for bad in [
            "",
            "acc-1",
            "3f2c9a71e4b0d856",
            "0190A1B2-C3D4-8E5F-9A0B-1C2D3E4F5A6B",
            "0190a1b2c3d48e5f9a0b1c2d3e4f5a6b",
            "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6",
            "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6bb",
            "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6g",
            "{0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b}",
            "0190a1b2_c3d4_8e5f_9a0b_1c2d3e4f5a6b",
            "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6\u{e9}",
        ] {
            assert!(!is_uuid(bad), "{bad:?}");
        }
    }

    #[test]
    fn uuidv8_sets_version_and_variant() {
        let mut hash = [0xFFu8; 32];
        let id = uuidv8(&hash);
        assert_eq!(id[6], 0x8F);
        assert_eq!(id[8], 0xBF);
        hash.fill(0);
        let id = uuidv8(&hash);
        assert_eq!(id[6], 0x80);
        assert_eq!(id[8], 0x80);
        assert_eq!(id[0], 0);
    }

    #[test]
    fn space_uuid_is_the_documented_hash() {
        for_backends!(B => {
            let mut input = b"kemlock/v1/legacy-id".to_vec();
            input.extend_from_slice(&[0, 0, 0, 5]);
            input.extend_from_slice(b"space");
            input.extend_from_slice(&[0, 0, 0, 13]);
            input.extend_from_slice(b"team_Alpha-01");
            assert_eq!(space_uuid_in::<B>("team_Alpha-01"), uuidv8(&B::sha256(&input)), "{}", B::NAME);
        });
    }

    #[test]
    fn item_uuid_is_the_documented_hash() {
        for_backends!(B => {
            let owner = Owner::space([9; 16]).to_bytes();
            let mut input = b"kemlock/v1/legacy-id".to_vec();
            input.extend_from_slice(&[0, 0, 0, 4]);
            input.extend_from_slice(b"item");
            input.extend_from_slice(&owner);
            input.extend_from_slice(&[0, 0, 0, 5]);
            input.extend_from_slice(b"acc-1");
            assert_eq!(item_uuid_in::<B>(&owner, "acc-1"), uuidv8(&B::sha256(&input)), "{}", B::NAME);
        });
    }

    #[test]
    fn results_look_like_version_8_uuids() {
        for old in ["acc-1", "svc-1", "3f2c9a71e4b0d856", "team_Alpha-01", ""] {
            let id = space_uuid(old);
            assert_eq!(id[6] >> 4, 8, "{old}");
            assert_eq!(id[8] >> 6, 0b10, "{old}");
        }
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        assert_eq!(space_uuid("acc-1"), space_uuid("acc-1"));
        assert_ne!(space_uuid("acc-1"), space_uuid("acc-2"));
        assert_ne!(space_uuid("acc-1"), space_uuid("ACC-1"));
    }

    #[test]
    fn items_are_bound_to_their_owner_and_kind_of_id() {
        let user = Owner::user([1; 16]).to_bytes();
        let space = Owner::space([1; 16]).to_bytes();
        let other = Owner::user([2; 16]).to_bytes();
        let id = item_uuid(&user, "x");
        assert_eq!(id, item_uuid(&user, "x"));
        assert_ne!(id, item_uuid(&space, "x"));
        assert_ne!(id, item_uuid(&other, "x"));
        assert_ne!(id, item_uuid(&user, "y"));
        // The same text as a space id and as an item id never collides.
        assert_ne!(space_uuid("x"), item_uuid(&user, "x"));
    }

    #[test]
    fn a_mapped_id_is_not_a_legacy_id_again() {
        // Callers keep UUIDs as they are, and a mapped id formats as one.
        let id = space_uuid("acc-1");
        let text = format!(
            "{}-{}-{}-{}-{}",
            hex::encode(&id[..4]),
            hex::encode(&id[4..6]),
            hex::encode(&id[6..8]),
            hex::encode(&id[8..10]),
            hex::encode(&id[10..])
        );
        assert!(is_uuid(&text));
    }
}
