//! The hash link, the signing of records, and the commitments' digests and key checks
//! (docs/crypto.md, "Space chain": "Signature", "Hash link", "Seal commitments").

use crate::{
    Error,
    backend::{Active, Backend},
    sealed_box,
    sig1::{self, context::SPACE_CHAIN},
};

use super::model::{Hash, Id, KeyRef};

const LINK_LABEL: &[u8] = b"kemlock/v1/space-chain/link";
const SEALS_LABEL: &[u8] = b"kemlock/v1/space-chain/seals";
const CHECK_LABEL: &[u8] = b"kemlock/v1/space-chain/key-check";

/// The label of a hash link.
pub const LINK_CONTEXT: &[u8] = LINK_LABEL;

/// `SHA-256("kemlock/v1/space-chain/link" ‖ record bytes)`: what the next record holds as `prev`.
pub fn link(entry: &[u8]) -> Hash {
    link_in::<Active>(entry)
}

pub(crate) fn link_in<B: Backend>(entry: &[u8]) -> Hash {
    let mut input = Vec::with_capacity(LINK_LABEL.len() + entry.len());
    input.extend_from_slice(LINK_LABEL);
    input.extend_from_slice(entry);
    B::sha256(&input)
}

/// Signs a record's bytes with the signer's `sig1` key under context `"space-chain"`.
pub fn sign_record(key: &sig1::SigningKey, entry: &[u8]) -> Result<Vec<u8>, Error> {
    key.sign(SPACE_CHAIN, entry)
}

/// Checks a record's signature against a `sig1` public key.
pub fn verify_record_signature(
    public: &sig1::PublicKey,
    entry: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    public.verify(SPACE_CHAIN, entry, signature)
}

/// `SHA-256` of a sealed box: the hash a commitment's digest covers.
pub fn seal_hash(sealed: &[u8]) -> Hash {
    Active::sha256(sealed)
}

/// The digest of a commitment: `SHA-256("kemlock/v1/space-chain/seals" ‖ space id ‖ key ref ‖
/// u32be(key version) ‖ u32be(n) ‖ n × (account id ‖ u32be(bundle key version) ‖ seal hash))`,
/// the entries in ascending order of account id bytes.
pub fn seal_digest(space: &Id, key: &KeyRef, version: u32, entries: &[(Id, u32, Hash)]) -> Hash {
    seal_digest_in::<Active>(space, key, version, entries)
}

pub(crate) fn seal_digest_in<B: Backend>(
    space: &Id,
    key: &KeyRef,
    version: u32,
    entries: &[(Id, u32, Hash)],
) -> Hash {
    let mut input = Vec::with_capacity(SEALS_LABEL.len() + 40 + entries.len() * 52);
    input.extend_from_slice(SEALS_LABEL);
    input.extend_from_slice(space);
    input.extend_from_slice(&key.bytes());
    input.extend_from_slice(&version.to_be_bytes());
    input.extend_from_slice(
        &u32::try_from(entries.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for (account, bundle_version, hash) in entries {
        input.extend_from_slice(account);
        input.extend_from_slice(&bundle_version.to_be_bytes());
        input.extend_from_slice(hash);
    }
    B::sha256(&input)
}

/// The check of a key version: `HKDF(ikm = key, salt = absent, info =
/// "kemlock/v1/space-chain/key-check" ‖ space id ‖ key ref ‖ u32be(key version), L = 32)`.
pub fn key_check(space: &Id, key: &KeyRef, version: u32, secret: &[u8; 32]) -> Result<Hash, Error> {
    key_check_in::<Active>(space, key, version, secret)
}

pub(crate) fn key_check_in<B: Backend>(
    space: &Id,
    key: &KeyRef,
    version: u32,
    secret: &[u8; 32],
) -> Result<Hash, Error> {
    let mut info = Vec::with_capacity(CHECK_LABEL.len() + 37);
    info.extend_from_slice(CHECK_LABEL);
    info.extend_from_slice(space);
    info.extend_from_slice(&key.bytes());
    info.extend_from_slice(&version.to_be_bytes());
    let mut out = [0u8; 32];
    B::hkdf_sha256(secret, None, &info, &mut out)?;
    Ok(out)
}

/// The sealed-box context and `aad` of a key's box for one recipient: context `"space-key"` with
/// `space id ‖ u32be(space key version) ‖ recipient`, or `"collection-key"` with
/// `space id ‖ collection id ‖ u32be(collection key version) ‖ recipient`.
pub fn box_context(
    key: &KeyRef,
    space: &Id,
    version: u32,
    recipient: &Id,
) -> (&'static str, Vec<u8>) {
    let mut aad = Vec::with_capacity(52);
    aad.extend_from_slice(space);
    match key {
        KeyRef::Space => {
            aad.extend_from_slice(&version.to_be_bytes());
            aad.extend_from_slice(recipient);
            (sealed_box::context::SPACE_KEY, aad)
        }
        KeyRef::Collection(id) => {
            aad.extend_from_slice(id);
            aad.extend_from_slice(&version.to_be_bytes());
            aad.extend_from_slice(recipient);
            (sealed_box::context::COLLECTION_KEY, aad)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space_chain::b64;

    #[test]
    fn links_are_labelled() {
        let entry = b"abc";
        let mut labelled = LINK_LABEL.to_vec();
        labelled.extend_from_slice(entry);
        assert_eq!(link(entry), crate::hash::sha256(&labelled));
        assert_ne!(link(entry), crate::hash::sha256(entry));
    }

    /// The two examples of the spec, computed by hand with `openssl dgst -sha256`.
    #[test]
    fn the_spec_links_are_these() {
        let promotion = b64::encode(&crate::hash::sha256(b"example promotion record"));
        assert_eq!(promotion, "QTHxrde9FN788OzrLL4TpaPmaC2O0E5WgPn8_Ws-K0Q");
        let fence = format!(
            "{{\"at\":1700000700,\"body\":{{\"home\":\"{}\",\"promotion\":\"{promotion}\"}},\
             \"by\":\"{}\",\"epoch\":2,\"kind\":\"fence\",\"prev\":\"{}\",\"seq\":7,\
             \"space\":\"{}\",\"v\":1}}",
            "00000000-0000-4000-8000-0000000000f2",
            "00000000-0000-4000-8000-000000000002",
            b64::encode(&[0x11; 32]),
            "00000000-0000-4000-8000-000000000001",
        );
        assert_eq!(fence.len(), 313);
        let fence_link = link(fence.as_bytes());
        assert_eq!(
            hex_text(&fence_link),
            "baf5fdb659e027e88cfe5f2a68f05e1fb2537ad9c99ea2b37869ff5924536947"
        );
        assert_eq!(
            b64::encode(&fence_link),
            "uvX9tlngJ-iM_l8qaPBeH7JTetnJnqKzeGn_WSRTaUc"
        );
        assert!(hex_text(&crate::hash::sha256(fence.as_bytes())).starts_with("04cce6ca"));
        assert!(hex_text(&crate::hash::sha256(fence.as_bytes())).ends_with("7016608a"));

        let role = format!(
            "{{\"at\":1700000800,\"body\":{{\"custom\":[\"create-collections\",\"manage-users\"],\
             \"member\":\"{}\",\"role\":\"custom\"}},\"by\":\"{}\",\"epoch\":2,\"kind\":\"role\",\
             \"prev\":\"{}\",\"seq\":8,\"space\":\"{}\",\"v\":1}}",
            "00000000-0000-4000-8000-000000000003",
            "00000000-0000-4000-8000-000000000002",
            b64::encode(&fence_link),
            "00000000-0000-4000-8000-000000000001",
        );
        assert_eq!(role.len(), 319);
        let role_link = link(role.as_bytes());
        assert_eq!(
            hex_text(&role_link),
            "8aa6fb9d20088eeb1cbb86b48f0ded3b0aa2120cc7ebdbbc5f288e7b637336af"
        );
        assert_eq!(
            b64::encode(&role_link),
            "iqb7nSAIjuscu4a0jw3tOwqiEgzH69u8XyiOe2NzNq8"
        );
    }

    fn hex_text(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn digests_cover_every_field() {
        let space = [1u8; 16];
        let entries = [([2u8; 16], 1u32, [3u8; 32]), ([4u8; 16], 2u32, [5u8; 32])];
        let base = seal_digest(&space, &KeyRef::Space, 3, &entries);
        assert_ne!(base, seal_digest(&[9; 16], &KeyRef::Space, 3, &entries));
        assert_ne!(
            base,
            seal_digest(&space, &KeyRef::Collection([7; 16]), 3, &entries)
        );
        assert_ne!(base, seal_digest(&space, &KeyRef::Space, 4, &entries));
        assert_ne!(base, seal_digest(&space, &KeyRef::Space, 3, &entries[..1]));
        let mut other = entries;
        other[1].1 = 3;
        assert_ne!(base, seal_digest(&space, &KeyRef::Space, 3, &other));
        other = entries;
        other[0].2 = [6; 32];
        assert_ne!(base, seal_digest(&space, &KeyRef::Space, 3, &other));

        // The layout, rebuilt by hand.
        let mut input = b"kemlock/v1/space-chain/seals".to_vec();
        input.extend_from_slice(&space);
        input.push(1);
        input.extend_from_slice(&3u32.to_be_bytes());
        input.extend_from_slice(&2u32.to_be_bytes());
        for (a, v, h) in &entries {
            input.extend_from_slice(a);
            input.extend_from_slice(&v.to_be_bytes());
            input.extend_from_slice(h);
        }
        assert_eq!(base, crate::hash::sha256(&input));
    }

    #[test]
    fn key_checks_bind_the_key_and_its_name() {
        let space = [1u8; 16];
        let secret = [8u8; 32];
        let base = key_check(&space, &KeyRef::Space, 1, &secret).expect("check");
        assert_ne!(
            base,
            key_check(&space, &KeyRef::Space, 2, &secret).expect("check")
        );
        assert_ne!(
            base,
            key_check(&space, &KeyRef::Collection([2; 16]), 1, &secret).expect("check")
        );
        assert_ne!(
            base,
            key_check(&space, &KeyRef::Space, 1, &[9; 32]).expect("check")
        );
        assert_ne!(
            base,
            key_check(&[2; 16], &KeyRef::Space, 1, &secret).expect("check")
        );
    }

    #[test]
    fn box_contexts_match_the_documented_aad() {
        let (ctx, aad) = box_context(&KeyRef::Space, &[1; 16], 3, &[2; 16]);
        assert_eq!(ctx, "space-key");
        assert_eq!(aad.len(), 16 + 4 + 16);
        assert_eq!(&aad[16..20], &3u32.to_be_bytes());
        let (ctx, aad) = box_context(&KeyRef::Collection([5; 16]), &[1; 16], 3, &[2; 16]);
        assert_eq!(ctx, "collection-key");
        assert_eq!(aad.len(), 16 + 16 + 4 + 16);
        assert_eq!(&aad[16..32], &[5; 16]);
    }

    #[test]
    fn records_are_signed_under_their_own_context() {
        let key = sig1::SigningKey::from_bytes(&[3; 64]);
        let public = key.public_key().expect("public");
        let signature = sign_record(&key, b"entry").expect("sign");
        verify_record_signature(&public, b"entry", &signature).expect("verifies");
        assert!(verify_record_signature(&public, b"other", &signature).is_err());
        for context in ["bundle", "manifest", "confirm"] {
            let other = key.sign(context, b"entry").expect("sign");
            assert!(verify_record_signature(&public, b"entry", &other).is_err());
            assert!(public.verify(context, b"entry", &signature).is_err());
        }
    }
}
