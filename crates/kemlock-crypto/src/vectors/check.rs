//! Checks vector files against the formats on every compiled-in backend: the committed files in
//! `test-vectors/` when they exist, and (with the RustCrypto backend) freshly generated ones.
//!
//! The checks recompute what they can independently of the code under test: lengths, labels and
//! AEAD seals are rebuilt from the documented layout, and every vector must verify or open under
//! the format functions. aws-lc-rs can't expand an ML-KEM seed itself, so the crate does that one
//! step on RustCrypto on every backend (see the crate docs) and the checks run on all of them.

use std::path::PathBuf;

use serde_json::Value;

use super::{FILES, ScriptedRng, VERSION, b64url};
use crate::{
    argon2id,
    backend::Backend,
    bundle::{self, Bundle},
    confirm::{STATEMENT_LEN, Statement},
    key_box::{self, Kind as KeyBoxKind, Statement as KeyBoxStatement},
    dedup, ed25519, kem1,
    keys::{ITEM_WRAP_LABEL, RootKey, SecretKey},
    kma1, kx1, legacy_id,
    manifest::{Entry, Manifest},
    opaque::{self, OpaqueServer},
    owner::Owner,
    password_wrap, prf_wrap, private_keys, seal, sealed_box, send,
    sig1::{self, context::BUNDLE, context::MANIFEST},
    wire::lp,
};

// ---- reading values ---------------------------------------------------------------------------

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` is missing or not a string in {v}"))
}

fn bytes(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("`{key}` is not hex: {e}"))
}

fn arr<const N: usize>(v: &Value, key: &str) -> [u8; N] {
    bytes(v, key)
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("`{key}` is {} bytes, not {N}", b.len()))
}

fn int(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("`{key}` is missing or not an integer in {v}"))
}

fn list<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("`{key}` is missing or not a list"))
}

fn cases(doc: &Value) -> &Vec<Value> {
    list(doc, "cases")
}

fn flip(mut b: Vec<u8>, index: usize) -> Vec<u8> {
    let last = b.len() - 1;
    b[index.min(last)] ^= 1;
    b
}

/// The header every file carries.
fn check_header(name: &str, doc: &Value) {
    assert!(!s(doc, "format").is_empty(), "{name}: format");
    assert_eq!(int(doc, "version"), VERSION, "{name}: version");
    assert!(!s(doc, "description").is_empty(), "{name}: description");
    assert!(!cases(doc).is_empty(), "{name}: cases");
}

// ---- the formats ------------------------------------------------------------------------------

fn account_keys<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let root = RootKey::from_bytes(&arr(case, "root_key"));
        assert_eq!(s(case, "user_label"), "kemlock/v1/user");
        let user = root.user_key_in::<B>().expect("user key");
        assert_eq!(
            user.as_bytes().as_slice(),
            bytes(case, "user_key"),
            "{}",
            B::NAME
        );
        assert_eq!(list(case, "children").len(), 3);
        for child in list(case, "children") {
            let got = user.child_in::<B>(s(child, "label")).expect("child");
            assert_eq!(
                got.as_bytes().as_slice(),
                bytes(child, "key"),
                "{}",
                B::NAME
            );
        }
    }
}

fn password_wrap_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let master: [u8; 32] = arr(case, "master_key");
        let export: [u8; 64] = arr(case, "export_key");
        let root: [u8; 64] = arr(case, "root_key");
        let account: [u8; 16] = arr(case, "account_id");
        let version = u32::try_from(int(case, "key_version")).expect("u32");
        let wrapped = bytes(case, "wrapped");

        let key = password_wrap::wrap_key_in::<B>(&master, &export).expect("wrap key");
        assert_eq!(
            key.as_bytes().as_slice(),
            bytes(case, "wrap_key"),
            "{}",
            B::NAME
        );
        let aad = password_wrap::aad(&account, version);
        assert_eq!(aad, bytes(case, "aad"));
        // The seal, rebuilt from its documented layout with the vector's own nonce.
        let nonce: [u8; 12] = wrapped[..12].try_into().expect("nonce");
        let resealed = B::aes256gcm_seal(key.as_bytes(), &nonce, &aad, &root).expect("seal");
        assert_eq!(resealed, wrapped[12..], "{}", B::NAME);

        let opened = password_wrap::open_in::<B>(&master, &export, &wrapped, &account, version)
            .expect("open");
        assert_eq!(opened.as_bytes().as_slice(), root);
        assert!(
            password_wrap::open_in::<B>(&master, &export, &wrapped, &account, version + 1).is_err()
        );
        let mut other = account;
        other[0] ^= 1;
        assert!(password_wrap::open_in::<B>(&master, &export, &wrapped, &other, version).is_err());
        assert!(
            password_wrap::open_in::<B>(
                &master,
                &export,
                &flip(wrapped.clone(), 40),
                &account,
                version
            )
            .is_err()
        );
    }
}

fn argon2id_file(doc: &Value) {
    for case in cases(doc) {
        let key = argon2id::master_key(
            &bytes(case, "password"),
            &bytes(case, "salt"),
            u32::try_from(int(case, "memory_kib")).expect("u32"),
            u32::try_from(int(case, "iterations")).expect("u32"),
            u32::try_from(int(case, "parallelism")).expect("u32"),
        )
        .expect("argon2id");
        assert_eq!(
            key.as_slice(),
            bytes(case, "master_key"),
            "{}",
            s(case, "name")
        );
        assert_eq!(s(case, "password_text").as_bytes(), bytes(case, "password"));
    }
}

fn kx1_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let private_bytes: [u8; 96] = arr(case, "private_key");
        assert_eq!(&private_bytes[..64], bytes(case, "mlkem_seed"));
        assert_eq!(&private_bytes[64..], bytes(case, "x25519_secret"));
        let private = kx1::PrivateKey::from_bytes(&private_bytes);
        let public = kx1::PublicKey::from_bytes(&bytes(case, "public_key")).expect("public key");
        let ciphertext = bytes(case, "ciphertext");
        assert_eq!(ciphertext.len(), kx1::CIPHERTEXT_LEN);

        // Every backend can encapsulate to the vector's public key.
        let (fresh, secret) = kx1::encapsulate_in::<B>(&public).expect("encaps");
        assert_eq!(fresh.len(), kx1::CIPHERTEXT_LEN);
        assert_ne!(secret.as_bytes().as_slice(), bytes(case, "shared_secret"));

        assert_eq!(
            kx1::public_key_in::<B>(&private).expect("public"),
            public,
            "{}",
            B::NAME
        );
        let got = kx1::decapsulate_in::<B>(&private, &ciphertext).expect("decaps");
        assert_eq!(
            got.as_bytes().as_slice(),
            bytes(case, "shared_secret"),
            "{}",
            B::NAME
        );
        // And decapsulates what this backend just made.
        let again = kx1::decapsulate_in::<B>(&private, &fresh).expect("decaps");
        assert_eq!(again.as_bytes(), secret.as_bytes());
        for changed in list(case, "changed_ciphertexts") {
            let got =
                kx1::decapsulate_in::<B>(&private, &bytes(changed, "ciphertext")).expect("decaps");
            assert_eq!(
                got.as_bytes().as_slice(),
                bytes(changed, "shared_secret"),
                "{}",
                s(changed, "description")
            );
        }
        assert!(kx1::decapsulate_in::<B>(&private, &ciphertext[1..]).is_err());
    }
}

fn sealed_box_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let private = kx1::PrivateKey::from_bytes(&arr(case, "private_key"));
        let public = kx1::PublicKey::from_bytes(&bytes(case, "public_key")).expect("public key");
        let context = s(case, "context");
        let aad = bytes(case, "aad");
        let secret = bytes(case, "secret");
        let boxed = bytes(case, "sealed_box");
        assert_eq!(boxed.len(), sealed_box::OVERHEAD + secret.len());
        assert_eq!(boxed[0], 1);

        // The aad is the one docs/crypto.md fixes for the context, rebuilt from its parts.
        let parts = &case["aad_parts"];
        let version = |key: &str| u32::try_from(int(parts, key)).expect("u32").to_be_bytes();
        let rebuilt: Vec<u8> = match context {
            sealed_box::context::DEVICE_APPROVAL => {
                [bytes(parts, "account_id"), bytes(parts, "request_id")].concat()
            }
            sealed_box::context::SPACE_KEY => [
                bytes(parts, "space_id"),
                version("key_version").to_vec(),
                bytes(parts, "recipient_id"),
            ]
            .concat(),
            sealed_box::context::COLLECTION_KEY => [
                bytes(parts, "space_id"),
                bytes(parts, "collection_id"),
                version("key_version").to_vec(),
                bytes(parts, "recipient_id"),
            ]
            .concat(),
            sealed_box::context::EMERGENCY_ACCESS => bytes(parts, "contact_id"),
            sealed_box::context::ACCOUNT_RECOVERY => [
                bytes(parts, "space_id"),
                bytes(parts, "account_id"),
                int(parts, "key_seq").to_be_bytes().to_vec(),
            ]
            .concat(),
            other => panic!("no aad is fixed for {other}"),
        };
        assert_eq!(aad, rebuilt, "{}", s(case, "name"));
        let expected_len = match context {
            sealed_box::context::DEVICE_APPROVAL => 32,
            sealed_box::context::SPACE_KEY => 36,
            sealed_box::context::COLLECTION_KEY => 52,
            sealed_box::context::ACCOUNT_RECOVERY => 40,
            _ => 16,
        };
        assert_eq!(aad.len(), expected_len, "{}", s(case, "name"));

        // A box made on this backend opens on this backend.
        let fresh = sealed_box::seal_in::<B>(&public, context, &aad, &secret).expect("seal");
        assert_eq!(fresh.len(), boxed.len());

        let opened = sealed_box::open_in::<B>(&private, context, &aad, &boxed).expect("open");
        assert_eq!(opened.as_slice(), secret, "{}", B::NAME);
        assert_eq!(
            sealed_box::open_in::<B>(&private, context, &aad, &fresh)
                .expect("open")
                .as_slice(),
            secret
        );

        // The documented construction, rebuilt: key from the kx1 secret, then the seal.
        let shared =
            kx1::decapsulate_in::<B>(&private, &boxed[1..1 + kx1::CIPHERTEXT_LEN]).expect("decaps");
        let mut info = b"kemlock/v1/seal".to_vec();
        lp(&mut info, context.as_bytes()).expect("lp");
        let mut key = [0u8; 32];
        B::hkdf_sha256(shared.as_bytes(), None, &info, &mut key).expect("hkdf");
        let mut full_aad = Vec::new();
        lp(&mut full_aad, context.as_bytes()).expect("lp");
        lp(&mut full_aad, &aad).expect("lp");
        let tail = &boxed[1 + kx1::CIPHERTEXT_LEN..];
        let nonce: [u8; 12] = tail[..12].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_seal(&key, &nonce, &full_aad, &secret).expect("seal"),
            tail[12..]
        );

        for wrong in list(case, "wrong_contexts") {
            let wrong = wrong.as_str().expect("context");
            assert!(
                sealed_box::open_in::<B>(&private, wrong, &aad, &boxed).is_err(),
                "{wrong}"
            );
        }
        let mut other_aad = aad.clone();
        other_aad.push(0);
        assert!(sealed_box::open_in::<B>(&private, context, &other_aad, &boxed).is_err());
        // Any one byte of the aad changed (a space, a collection, a key version, a recipient)
        // opens nothing.
        for index in [0usize, 15, 16, aad.len() / 2, aad.len() - 1] {
            assert!(
                sealed_box::open_in::<B>(&private, context, &flip(aad.clone(), index), &boxed)
                    .is_err(),
                "aad byte {index}"
            );
        }
        for index in [0usize, 1, 800, 1600, 1601, boxed.len() - 1] {
            assert!(
                sealed_box::open_in::<B>(&private, context, &aad, &flip(boxed.clone(), index))
                    .is_err(),
                "byte {index}"
            );
        }
    }
}

fn sig1_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let private_bytes: [u8; 64] = arr(case, "private_key");
        assert_eq!(&private_bytes[..32], bytes(case, "mldsa_seed"));
        assert_eq!(&private_bytes[32..], bytes(case, "ed25519_seed"));
        let key = sig1::SigningKey::from_bytes(&private_bytes);
        let public = sig1::PublicKey::from_bytes(&bytes(case, "public_key")).expect("public key");
        let context = s(case, "context");
        let message = bytes(case, "message");
        let signature = bytes(case, "signature");

        assert_eq!(
            sig1::public_key_in::<B>(&key).expect("public"),
            public,
            "{}",
            B::NAME
        );
        sig1::verify_in::<B>(&public, context, &message, &signature).expect("the vector verifies");
        let other_context = if context == "bundle" {
            "manifest"
        } else {
            "bundle"
        };
        assert!(sig1::verify_in::<B>(&public, other_context, &message, &signature).is_err());
        assert!(
            sig1::verify_in::<B>(
                &public,
                context,
                &[message.clone(), vec![0]].concat(),
                &signature
            )
            .is_err()
        );
        for index in [0usize, 3308, 3309, 3372] {
            assert!(
                sig1::verify_in::<B>(&public, context, &message, &flip(signature.clone(), index))
                    .is_err(),
                "byte {index}"
            );
        }
        // This backend's own signature verifies too; the RustCrypto one is deterministic, so
        // there it is the vector itself.
        let own = sig1::sign_in::<B>(&key, context, &message).expect("sign");
        sig1::verify_in::<B>(&public, context, &message, &own).expect("own signature");
        if B::NAME == "rustcrypto" {
            assert_eq!(own, signature);
        }
    }
}

/// The Ed25519 verification rule's edge cases: every backend gives the file's verdicts, for the
/// key at parse time and for the whole check.
fn sig1_edge_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let name = s(case, "name");
        let public: [u8; 32] = arr(case, "public_key");
        let message = bytes(case, "message");
        let signature = bytes(case, "signature");
        let flag = |key: &str| {
            case[key]
                .as_bool()
                .unwrap_or_else(|| panic!("`{key}` is missing or not a boolean in {name}"))
        };

        assert_eq!(
            ed25519::check_public_key(&public).is_ok(),
            flag("key_ok"),
            "{} key_ok of {name}",
            B::NAME
        );
        assert_eq!(
            B::ed25519_verify(&public, &message, &signature).is_ok(),
            flag("valid"),
            "{} valid of {name}",
            B::NAME
        );
        // A refused key never verifies, whatever the signature.
        if !flag("key_ok") {
            assert!(!flag("valid"), "{name}");
        }
    }
}

fn bundle_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let encoded = bytes(case, "bundle");
        let parsed = Bundle::from_bytes(&encoded).expect("parse");
        assert_eq!(parsed.account_id.as_slice(), bytes(case, "account_id"));
        assert_eq!(u64::from(parsed.key_version), int(case, "key_version"));
        assert_eq!(
            parsed.kx1_public.as_bytes().as_slice(),
            bytes(case, "kx1_public_key")
        );
        assert_eq!(
            parsed.sig1_public.as_bytes().as_slice(),
            bytes(case, "sig1_public_key")
        );
        assert_eq!(parsed.to_bytes(), encoded);

        let fingerprint = bundle::fingerprint_in::<B>(&encoded);
        assert_eq!(
            fingerprint.as_slice(),
            bytes(case, "fingerprint"),
            "{}",
            B::NAME
        );
        let groups = bundle::fingerprint_groups(&fingerprint);
        let expected: Vec<&str> = list(case, "fingerprint_groups")
            .iter()
            .map(|g| g.as_str().expect("group"))
            .collect();
        assert_eq!(
            groups.iter().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(groups.join(" "), s(case, "fingerprint_text"));
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit()))
        );

        let signature = bytes(case, "signature");
        sig1::verify_in::<B>(&parsed.sig1_public, BUNDLE, &encoded, &signature).expect("signature");
        assert!(
            sig1::verify_in::<B>(
                &parsed.sig1_public,
                BUNDLE,
                &flip(encoded.clone(), 40),
                &signature
            )
            .is_err()
        );

        let private = kx1::PrivateKey::from_bytes(&arr(case, "kx1_private_key"));
        assert_eq!(
            kx1::public_key_in::<B>(&private).expect("public"),
            parsed.kx1_public
        );
        let signing = sig1::SigningKey::from_bytes(&arr(case, "sig1_private_key"));
        assert_eq!(
            sig1::public_key_in::<B>(&signing).expect("public"),
            parsed.sig1_public
        );
    }
}

fn owner_of(v: &Value, key: &str) -> Owner {
    Owner::from_bytes(&arr(v, key)).expect("owner")
}

fn kem1_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let user = RootKey::from_bytes(&arr(case, "root_key"))
            .user_key_in::<B>()
            .expect("user key");
        assert_eq!(user.as_bytes().as_slice(), bytes(case, "user_key"));
        let wrap = user.child_in::<B>(ITEM_WRAP_LABEL).expect("wrap key");
        assert_eq!(wrap.as_bytes().as_slice(), bytes(case, "wrap_key"));
        let item_key = SecretKey::from_bytes(&arr(case, "item_key"));
        let item_id: [u8; 16] = arr(case, "item_id");
        let owner = owner_of(case, "owner");
        let revision = int(case, "revision");
        let kind = s(case, "kind");
        let key_version = u32::try_from(int(case, "key_version")).expect("u32");
        let json = s(case, "item_json");
        let ciphertext = bytes(case, "ciphertext");
        let wrapped = bytes(case, "wrapped_item_key");

        let aad = kem1::item_aad(&item_id, revision, kind, &owner).expect("aad");
        assert_eq!(aad, bytes(case, "aad"));
        let nonce: [u8; 12] = ciphertext[..12].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_seal(item_key.as_bytes(), &nonce, &aad, json.as_bytes()).expect("seal"),
            ciphertext[12..]
        );
        let opened =
            kem1::open_item_in::<B>(&item_key, &item_id, revision, kind, &owner, &ciphertext)
                .expect("open");
        assert_eq!(opened.as_slice(), json.as_bytes(), "{}", B::NAME);
        assert!(
            kem1::open_item_in::<B>(&item_key, &item_id, revision + 1, kind, &owner, &ciphertext)
                .is_err()
        );
        assert!(
            kem1::open_item_in::<B>(&item_key, &item_id, revision, "other", &owner, &ciphertext)
                .is_err()
        );
        assert!(
            kem1::open_item_in::<B>(&item_key, &[0; 16], revision, kind, &owner, &ciphertext)
                .is_err()
        );

        let wrap_aad = kem1::item_key_aad(&item_id, &owner, key_version);
        assert_eq!(wrap_aad, bytes(case, "wrap_aad"));
        let nonce: [u8; 12] = wrapped[..12].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_seal(wrap.as_bytes(), &nonce, &wrap_aad, item_key.as_bytes())
                .expect("seal"),
            wrapped[12..]
        );
        let unwrapped =
            kem1::unwrap_item_key_in::<B>(&wrap, &wrapped, &item_id, &owner, key_version)
                .expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), item_key.as_bytes());
        assert!(
            kem1::unwrap_item_key_in::<B>(&wrap, &wrapped, &item_id, &owner, key_version + 1)
                .is_err()
        );
    }
}

/// The label of the space key's child that encrypts names, as docs/crypto.md writes it.
const SPACE_NAME_LABEL: &str = "kemlock/v1/space-name";

fn space_names_file<B: Backend>(doc: &Value) {
    let kinds = ["space-name", "collection-name", "group-name"];
    for case in cases(doc) {
        let name = s(case, "name");
        let space_key = SecretKey::from_bytes(&arr(case, "space_key"));
        let name_key = space_key.child_in::<B>(SPACE_NAME_LABEL).expect("name key");
        assert_eq!(
            name_key.as_bytes().as_slice(),
            bytes(case, "name_key"),
            "{name} {}",
            B::NAME
        );
        let space: [u8; 16] = arr(case, "space_id");
        let id: [u8; 16] = arr(case, "id");
        let owner = owner_of(case, "owner");
        assert_eq!(owner, Owner::space(space), "{name}");
        assert_eq!(owner.to_bytes()[0], 0x02, "{name}");
        let kind = s(case, "kind");
        assert!(kinds.contains(&kind), "{name}");
        if kind == "space-name" {
            // A space's own name has the space's id.
            assert_eq!(id, space, "{name}");
        }
        let version = int(case, "key_version");
        let text = s(case, "text");
        let ciphertext = bytes(case, "ciphertext");
        assert!(ciphertext.len() >= kem1::MIN_SEALED_LEN, "{name}");
        assert!(ciphertext.len() <= 4096, "{name}");
        assert_eq!(ciphertext.len(), 12 + text.len() + 16, "{name}");

        // The aad is rebuilt from the documented layout, not from kem1::item_aad.
        let mut aad = b"kemlock/v1/item".to_vec();
        aad.extend_from_slice(&id);
        aad.extend_from_slice(&version.to_be_bytes());
        lp(&mut aad, kind.as_bytes()).expect("lp");
        aad.extend_from_slice(&owner.to_bytes());
        assert_eq!(aad, bytes(case, "aad"), "{name}");
        assert_eq!(
            kem1::item_aad(&id, version, kind, &owner).expect("aad"),
            aad,
            "{name}"
        );

        let nonce: [u8; 12] = ciphertext[..12].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_seal(name_key.as_bytes(), &nonce, &aad, text.as_bytes()).expect("seal"),
            ciphertext[12..],
            "{name} {}",
            B::NAME
        );
        let opened = kem1::open_item_in::<B>(&name_key, &id, version, kind, &owner, &ciphertext)
            .expect("open");
        assert_eq!(opened.as_slice(), text.as_bytes(), "{name} {}", B::NAME);

        // It opens only under the space, id, kind, key version and key it was sealed with.
        let other_kind = kinds.iter().find(|k| **k != kind).expect("another kind");
        assert!(
            kem1::open_item_in::<B>(&name_key, &id, version, other_kind, &owner, &ciphertext)
                .is_err(),
            "{name}: another kind"
        );
        assert!(
            kem1::open_item_in::<B>(&name_key, &[0; 16], version, kind, &owner, &ciphertext)
                .is_err(),
            "{name}: another id"
        );
        assert!(
            kem1::open_item_in::<B>(&name_key, &id, version + 1, kind, &owner, &ciphertext)
                .is_err(),
            "{name}: another key version"
        );
        assert!(
            kem1::open_item_in::<B>(
                &name_key,
                &id,
                version,
                kind,
                &Owner::space([0; 16]),
                &ciphertext
            )
            .is_err(),
            "{name}: another space"
        );
        assert!(
            kem1::open_item_in::<B>(
                &name_key,
                &id,
                version,
                kind,
                &Owner::user(space),
                &ciphertext
            )
            .is_err(),
            "{name}: a vault instead of a space"
        );
        // The space key itself is not the name key.
        assert!(
            kem1::open_item_in::<B>(&space_key, &id, version, kind, &owner, &ciphertext).is_err(),
            "{name}: the space key"
        );
        for index in [0usize, 12, ciphertext.len() - 1] {
            assert!(
                kem1::open_item_in::<B>(
                    &name_key,
                    &id,
                    version,
                    kind,
                    &owner,
                    &flip(ciphertext.clone(), index)
                )
                .is_err(),
                "{name}: byte {index}"
            );
        }
    }
}

fn manifest_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let owner = owner_of(case, "owner");
        let mut entries = Vec::new();
        for e in list(case, "entries") {
            let item_id: [u8; 16] = arr(e, "item_id");
            let revision = int(e, "revision");
            let deleted = e["deleted"].as_bool().expect("deleted");
            let entry = if deleted {
                Entry::tombstone(item_id, revision)
            } else {
                Entry::live(item_id, revision, &bytes(e, "ciphertext"))
            };
            assert_eq!(
                entry.ciphertext_hash.as_slice(),
                bytes(e, "ciphertext_hash")
            );
            entries.push(entry);
        }
        let manifest = Manifest {
            owner,
            counter: int(case, "counter"),
            entries,
        };
        let encoded = bytes(case, "manifest");
        assert_eq!(manifest.to_bytes().expect("encode"), encoded);
        let parsed = Manifest::from_bytes(&encoded).expect("decode");
        assert_eq!(parsed.owner, owner);
        assert_eq!(parsed.counter, manifest.counter);
        assert_eq!(parsed.entries.len(), manifest.entries.len());

        let public =
            sig1::PublicKey::from_bytes(&bytes(case, "signing_public_key")).expect("public key");
        let signature = bytes(case, "signature");
        sig1::verify_in::<B>(&public, MANIFEST, &encoded, &signature).expect("signature");
        assert!(sig1::verify_in::<B>(&public, BUNDLE, &encoded, &signature).is_err());
        assert!(
            sig1::verify_in::<B>(&public, MANIFEST, &flip(encoded.clone(), 47), &signature)
                .is_err()
        );
        let signing = sig1::SigningKey::from_bytes(&arr(case, "signing_private_key"));
        assert_eq!(sig1::public_key_in::<B>(&signing).expect("public"), public);
    }
}

fn dedup_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let owner = owner_of(case, "owner");
        let version = u32::try_from(int(case, "key_version")).expect("u32");
        let key = dedup::dedup_key_in::<B>(
            &SecretKey::from_bytes(&arr(case, "owner_key")),
            &owner,
            version,
        )
        .expect("dedup key");
        assert_eq!(
            key.as_bytes().as_slice(),
            bytes(case, "dedup_key"),
            "{}",
            B::NAME
        );
        for tag in list(case, "tags") {
            let values: Vec<&str> = list(tag, "values")
                .iter()
                .map(|v| v.as_str().expect("value"))
                .collect();
            let input = dedup::canonical_input(s(tag, "name"), &values);
            assert_eq!(input, bytes(tag, "canonical_input_hex"));
            assert_eq!(String::from_utf8_lossy(&input), s(tag, "canonical_input"));
            assert_eq!(
                B::hmac_sha256(key.as_bytes(), &input).as_slice(),
                bytes(tag, "tag"),
                "{}",
                B::NAME
            );
            assert_eq!(dedup::tag(&key, &input).len(), 32);
        }
    }
}

fn server_seal_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let server_key: [u8; 32] = arr(case, "server_key");
        let purpose = s(case, "purpose");
        let value = bytes(case, "value");
        let sealed = bytes(case, "sealed");
        assert_eq!(sealed[0], 1);

        let opened = seal::open_in::<B>(&server_key, purpose, &sealed).expect("open");
        assert_eq!(opened.as_slice(), value, "{}", B::NAME);
        assert!(seal::open_in::<B>(&server_key, "another-purpose", &sealed).is_err());
        assert!(seal::open_in::<B>(&server_key, purpose, &flip(sealed.clone(), 20)).is_err());

        let mut info = b"kemlock/v1/server-seal".to_vec();
        lp(&mut info, purpose.as_bytes()).expect("lp");
        let mut key = [0u8; 32];
        B::hkdf_sha256(&server_key, None, &info, &mut key).expect("hkdf");
        let mut aad = Vec::new();
        lp(&mut aad, purpose.as_bytes()).expect("lp");
        let nonce: [u8; 12] = sealed[1..13].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_seal(&key, &nonce, &aad, &value).expect("seal"),
            sealed[13..]
        );
    }
}

fn opaque_file(doc: &Value) {
    for case in cases(doc) {
        let server = OpaqueServer::from_bytes(&bytes(case, "server_setup")).expect("setup");
        assert_eq!(server.to_bytes(), bytes(case, "server_setup"));
        let id = bytes(case, "credential_identifier");
        assert_eq!(
            id,
            opaque::credential_id(s(case, "credential_identifier_text"))
        );
        let context = bytes(case, "context");
        assert_eq!(context, opaque::CONTEXT);
        assert_eq!(context, s(case, "context_text").as_bytes());
        let password = bytes(case, "password");
        let random = &case["random_inputs"];
        let wide = |key: &str| {
            let mut v = bytes(random, key);
            v.extend_from_slice(&[0u8; 32]);
            v
        };
        let reg = &case["registration"];
        let login = &case["login"];

        let (state, request) = opaque::client_registration_start_with(
            &mut ScriptedRng::new(vec![wide("blind_registration")]),
            &password,
        )
        .expect("start");
        assert_eq!(request, bytes(reg, "request"));
        let response = server
            .registration_response(&id, &request)
            .expect("response");
        assert_eq!(response, bytes(reg, "response"));
        assert_eq!(response[32..], bytes(case, "server_public_key"));
        let (upload, export) = opaque::client_registration_finish_with(
            &mut ScriptedRng::new(vec![bytes(random, "envelope_nonce")]),
            state,
            &password,
            &response,
        )
        .expect("finish");
        assert_eq!(upload, bytes(reg, "upload"));
        assert_eq!(export.as_slice(), bytes(reg, "export_key"));
        let record = OpaqueServer::registration_record(&upload).expect("record");
        assert_eq!(record, bytes(reg, "record"));

        let (client, ke1) = opaque::client_login_start_with(
            &mut ScriptedRng::new(vec![
                wide("blind_login"),
                bytes(random, "client_keyshare_seed"),
                bytes(random, "client_nonce"),
            ]),
            &password,
        )
        .expect("start");
        assert_eq!(ke1, bytes(login, "ke1"));
        let (state, ke2) = server
            .login_start_with(
                &mut ScriptedRng::new(vec![
                    vec![0u8; 64],
                    bytes(random, "masking_nonce"),
                    bytes(random, "server_keyshare_seed"),
                    bytes(random, "server_nonce"),
                ]),
                &context,
                &id,
                Some(&record),
                &ke1,
            )
            .expect("server start");
        assert_eq!(ke2, bytes(login, "ke2"));
        let (ke3, client_session, login_export) = opaque::client_login_finish_with(
            &mut ScriptedRng::new(Vec::new()),
            &context,
            client,
            &password,
            &ke2,
        )
        .expect("client finish");
        assert_eq!(ke3, bytes(login, "ke3"));
        assert_eq!(client_session, bytes(login, "client_session_key"));
        assert_eq!(login_export.as_slice(), bytes(login, "export_key"));
        let server_session =
            OpaqueServer::login_finish_with(&context, &state, &ke3).expect("server finish");
        assert_eq!(server_session, bytes(login, "server_session_key"));
        assert_eq!(client_session, server_session);

        // A wrong password and a wrong context fail.
        let (wrong_client, _) = opaque::client_login_start_with(
            &mut ScriptedRng::new(vec![
                wide("blind_login"),
                bytes(random, "client_keyshare_seed"),
                bytes(random, "client_nonce"),
            ]),
            b"not the master key",
        )
        .expect("start");
        assert!(
            opaque::client_login_finish_with(
                &mut ScriptedRng::new(Vec::new()),
                &context,
                wrong_client,
                b"not the master key",
                &ke2
            )
            .is_err()
        );
    }
}

fn legacy_ids_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        match s(case, "type") {
            "space" => {
                let got = legacy_id::space_uuid_in::<B>(s(case, "old"));
                assert_eq!(got.as_slice(), bytes(case, "uuid"), "{}", B::NAME);
                assert_eq!(super::uuid_text(&got), s(case, "uuid_text"));
                assert!(legacy_id::is_uuid(s(case, "uuid_text")));
            }
            "item" => {
                let got = legacy_id::item_uuid_in::<B>(&arr(case, "owner"), s(case, "old"));
                assert_eq!(got.as_slice(), bytes(case, "uuid"), "{}", B::NAME);
                assert_eq!(super::uuid_text(&got), s(case, "uuid_text"));
            }
            "is_uuid" => {
                let expected = case["is_uuid"].as_bool().expect("bool");
                assert_eq!(
                    legacy_id::is_uuid(s(case, "input")),
                    expected,
                    "{:?}",
                    s(case, "input")
                );
            }
            other => panic!("unknown legacy-ids case type {other}"),
        }
    }
}

/// The canonical inputs of the headline cases, written out by hand from `docs/crypto.md`, so the
/// normaliser is held to the document and not only to what it produced.
const PINNED: &[(&str, &[&str])] = &[
    (
        "cred-url-with-www-and-path",
        &[r#"["cred","example.com","alice","Hunter2 "]"#],
    ),
    (
        "cred-istanbul",
        &[r#"["cred","istanbul.example","istanbul","pw"]"#],
    ),
    (
        "cred-final-sigma-is-always-sigma",
        &["[\"cred\",\"example.com\",\"\u{3c3}\u{3b1}\u{3c3}\",\"pw\"]"],
    ),
    (
        "cred-sharp-s-stays",
        &["[\"cred\",\"example.com\",\"stra\u{df}e\",\"pw\"]"],
    ),
    (
        "cred-strasse-is-another-name",
        &[r#"["cred","example.com","strasse","pw"]"#],
    ),
    (
        "cred-capital-sharp-s",
        &["[\"cred\",\"example.com\",\"\u{df}\",\"pw\"]"],
    ),
    (
        "cred-decomposed-e",
        &["[\"cred\",\"example.com\",\"caf\u{e9}\",\"pw\"]"],
    ),
    (
        "cred-several-websites",
        &[
            r#"["cred","alice.github.io","bob","pw"]"#,
            r#"["cred","example.co.uk","bob","pw"]"#,
            r#"["cred","shop.xn--55qx5d.cn","bob","pw"]"#,
        ],
    ),
    ("cred-no-site", &[]),
    (
        "cred-internationalised-host",
        &[r#"["cred","xn--mnchen-3ya.de","bob","pw"]"#],
    ),
    (
        "cred-addresses-and-shared-hosts",
        &[
            r#"["cred","192.168.0.1","bob","pw"]"#,
            r#"["cred","2001:db8::1","bob","pw"]"#,
            r#"["cred","example.net","bob","pw"]"#,
            r#"["cred","mysite.sites.example.net","bob","pw"]"#,
        ],
    ),
    (
        "account-the-same-login",
        &[r#"["account","example.com","alice"]"#],
    ),
    (
        "account-two-websites-one-site",
        &[r#"["account","example.org","alice"]"#],
    ),
    (
        "secret-spaces-and-lower-case",
        &[r#"["secret","JBSWY3DPEHPK3PXP"]"#],
    ),
    ("secret-padding", &[r#"["secret","JBSWY3DPEHPK3PXP"]"#]),
    ("secret-short", &[r#"["secret","MFRGG"]"#]),
    ("secret-not-base32", &[]),
    (
        "passkey-case-and-padding",
        &[r#"["passkey","example.com","dGVzdA"]"#],
    ),
    (
        "passkey-standard-alphabet",
        &[r#"["passkey","example.com","-__-"]"#],
    ),
    (
        "card-digits-and-expiry",
        &[r#"["card","4111111111111111","2030-09"]"#],
    ),
    (
        "card-unknown-expiry",
        &[r#"["card","4111111111111111",""]"#],
    ),
    ("card-without-digits", &[]),
    (
        "note-crlf-and-trailing-blanks",
        &[r#"["note","line one\nline two"]"#],
    ),
    (
        "note-lone-cr-and-decomposed-e",
        &["[\"note\",\"caf\u{e9}\\nx\"]"],
    ),
    ("note-blank", &[]),
    (
        "key-ssh",
        &[r#"["key","SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"]"#],
    ),
    (
        "key-pgp-v4",
        &[r#"["key","9F3A77C10B2E45D68A19C0DE12F45B6A77889900"]"#],
    ),
    ("key-unknown", &[]),
    (
        "codes-duplicates",
        &[r#"["codes","11111111","22222222","33333333"]"#],
    ),
    ("codes-none", &[]),
    (
        "identity-trimmed-composed-lower",
        &["[\"identity\",\"zo\u{eb} m\u{fc}ller\",\"zoe@example.com\"]"],
    ),
    (
        "key-certificate-sha256-colons",
        &[r#"["key","ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"]"#],
    ),
    (
        "key-certificate-sha256-lower-case-no-colons",
        &[r#"["key","ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"]"#],
    ),
    (
        "key-certificate-sha1-colons",
        &[r#"["key","0F1E2D3C4B5A69788796A5B4C3D2E1F001122334"]"#],
    ),
    (
        "key-certificate-0x-prefix",
        &[r#"["key","0F1E2D3C4B5A69788796A5B4C3D2E1F001122334"]"#],
    ),
    ("key-certificate-too-short", &[]),
    (
        "contact-email-and-phone",
        &[r#"["contact","alex.chen@example.org","15550142"]"#],
    ),
    (
        "contact-email-only",
        &["[\"contact\",\"caf\u{e9}@x.example\",\"\"]"],
    ),
    ("contact-phone-only", &[r#"["contact","","15550142"]"#]),
    ("contact-nothing-to-hash", &[]),
    (
        "document-spaces-and-dashes",
        &[r#"["document","x1234567"]"#],
    ),
    ("document-decomposed-e", &["[\"document\",\"caf\u{e9}9\"]"]),
    ("document-too-short", &[]),
    (
        "file-upper-case-hash",
        &[r#"["file","0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]"#],
    ),
    ("file-not-a-hash", &[]),
];

fn dedup_normalise_file<B: Backend>(doc: &Value) {
    use super::normalise_cases;
    for case in cases(doc) {
        let name = s(case, "name");
        let key = SecretKey::from_bytes(&arr(case, "dedup_key"));
        assert_eq!(key.as_bytes(), &normalise_cases::key_bytes());
        let shared: Vec<String> = case["shared_hosts"]
            .as_array()
            .map(|hosts| {
                hosts
                    .iter()
                    .map(|h| h.as_str().expect("a host").to_owned())
                    .collect()
            })
            .unwrap_or_default();
        let got = normalise_cases::inputs(s(case, "tag"), &case["raw"], &shared);
        let texts = list(case, "canonical_inputs");
        let hexes = list(case, "canonical_inputs_hex");
        let tags = list(case, "tags");
        assert_eq!(got.len(), texts.len(), "{name}");
        assert_eq!(got.len(), hexes.len(), "{name}");
        assert_eq!(got.len(), tags.len(), "{name}");
        for (i, input) in got.iter().enumerate() {
            let text = texts[i].as_str().expect("text");
            assert_eq!(String::from_utf8_lossy(input), text, "{name}");
            assert_eq!(
                hex::decode(hexes[i].as_str().expect("hex")).expect("hex"),
                *input,
                "{name}"
            );
            assert_eq!(
                B::hmac_sha256(key.as_bytes(), input).as_slice(),
                hex::decode(tags[i].as_str().expect("tag")).expect("hex"),
                "{} {name}",
                B::NAME
            );
        }
        if let Some((_, expected)) = PINNED.iter().find(|(pinned, _)| *pinned == name) {
            let written: Vec<&str> = texts.iter().map(|t| t.as_str().expect("text")).collect();
            assert_eq!(&written, expected, "{name}");
        }
    }
    // The file holds every pinned case, and two spellings that must not match don't.
    for (pinned, _) in PINNED {
        assert!(
            cases(doc).iter().any(|c| s(c, "name") == *pinned),
            "{pinned} is missing"
        );
    }
    let first = |name: &str| {
        let case = cases(doc)
            .iter()
            .find(|c| s(c, "name") == name)
            .expect("the case");
        list(case, "canonical_inputs")[0].clone()
    };
    assert_ne!(
        first("cred-sharp-s-stays"),
        first("cred-strasse-is-another-name")
    );
}

/// EFF's large word list, as the domain bundles it.
const WORDLIST: &str = include_str!("../../../kemlock-domain/src/unlock/eff_large_wordlist.txt");
const WORDLIST_SHA256: &str = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522";

fn phrase_file<B: Backend>(doc: &Value) {
    assert_eq!(
        hex::encode(B::sha256(WORDLIST.as_bytes())),
        WORDLIST_SHA256,
        "{}",
        B::NAME
    );
    let words: Vec<&str> = WORDLIST.lines().collect();
    assert_eq!(words.len(), 7776);
    assert_eq!(words[0], "abacus");
    let mut wrapped = false;
    for case in cases(doc) {
        let public_key = bytes(case, "public_key");
        assert_eq!(public_key.len(), kx1::PUBLIC_KEY_LEN);
        let mut input = b"kemlock approval v1".to_vec();
        input.extend_from_slice(&public_key);
        let digest = B::sha256(&input);
        assert_eq!(digest.as_slice(), bytes(case, "digest"), "{}", B::NAME);

        // The first 65 bits, 13 at a time, most significant first.
        let mut phrase = Vec::new();
        for (i, group) in list(case, "groups").iter().enumerate() {
            let mut value = 0u64;
            for j in 0..13 {
                let bit = 13 * i + j;
                value = (value << 1) | u64::from((digest[bit / 8] >> (7 - bit % 8)) & 1);
            }
            assert_eq!(group.as_u64(), Some(value), "group {i}");
            wrapped |= value >= 7776;
            let index = value % 7776;
            assert_eq!(list(case, "indexes")[i].as_u64(), Some(index), "index {i}");
            phrase.push(words[usize::try_from(index).expect("small")]);
        }
        assert_eq!(phrase.join(" "), s(case, "phrase"), "{}", s(case, "name"));
    }
    assert!(wrapped, "no case has a group that wraps the list");
}

fn private_keys_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let user_key = SecretKey::from_bytes(&arr(case, "user_key"));
        let account: [u8; 16] = arr(case, "account_id");
        let version = u32::try_from(int(case, "key_version")).expect("u32");
        let sealed = bytes(case, "sealed");
        let plaintext = bytes(case, "plaintext");
        assert_eq!(sealed.len(), private_keys::SEALED_LEN);
        assert_eq!(plaintext.len(), private_keys::PLAINTEXT_LEN);

        let child = user_key
            .child_in::<B>(s(case, "child_label"))
            .expect("child key");
        assert_eq!(child.as_bytes().as_slice(), bytes(case, "child_key"));
        assert_eq!(s(case, "child_label"), "kemlock/v1/private-keys");

        let mut aad = b"kemlock/v1/private-keys".to_vec();
        aad.extend_from_slice(&account);
        aad.extend_from_slice(&version.to_be_bytes());
        assert_eq!(aad, bytes(case, "aad"));
        let mut expected_plain = vec![1u8];
        expected_plain.extend_from_slice(&bytes(case, "kx1_private_key"));
        expected_plain.extend_from_slice(&bytes(case, "sig1_private_key"));
        assert_eq!(expected_plain, plaintext);

        let nonce: [u8; 12] = sealed[..12].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_open(child.as_bytes(), &nonce, &aad, &sealed[12..]).expect("open"),
            plaintext,
            "{}",
            B::NAME
        );
        assert_eq!(
            B::aes256gcm_seal(child.as_bytes(), &nonce, &aad, &plaintext).expect("seal"),
            sealed[12..]
        );

        let (kx, sig) = private_keys::open_in::<B>(&user_key, &sealed, &account, version)
            .expect("open the sealed keys");
        assert_eq!(kx.as_bytes().as_slice(), bytes(case, "kx1_private_key"));
        assert_eq!(sig.as_bytes().as_slice(), bytes(case, "sig1_private_key"));

        assert!(private_keys::open_in::<B>(&user_key, &sealed, &[0; 16], version).is_err());
        assert!(private_keys::open_in::<B>(&user_key, &sealed, &account, version + 1).is_err());
        let other = SecretKey::from_bytes(&[5; 32]);
        assert!(private_keys::open_in::<B>(&other, &sealed, &account, version).is_err());
        assert!(
            private_keys::open_in::<B>(&user_key, &flip(sealed.clone(), 40), &account, version)
                .is_err()
        );
        assert!(private_keys::open_in::<B>(&user_key, &sealed[1..], &account, version).is_err());
    }
}

fn confirm_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let space: [u8; 16] = arr(case, "space");
        let member: [u8; 16] = arr(case, "member");
        let confirmer: [u8; 16] = arr(case, "confirmer");
        let version = u32::try_from(int(case, "member_key_version")).expect("u32");

        // The fingerprint is the one of the member's bundle at that key version.
        let member_bundle = bytes(case, "member_bundle");
        let parsed = Bundle::from_bytes(&member_bundle).expect("the member's bundle parses");
        assert_eq!(parsed.account_id, member);
        assert_eq!(parsed.key_version, version);
        let fingerprint = bundle::fingerprint_in::<B>(&member_bundle);
        assert_eq!(
            fingerprint.as_slice(),
            bytes(case, "fingerprint"),
            "{}",
            B::NAME
        );

        // The statement, rebuilt by hand from the documented layout.
        let mut expected = b"kemlock/v1/confirm".to_vec();
        expected.extend_from_slice(&space);
        expected.extend_from_slice(&member);
        expected.extend_from_slice(&version.to_be_bytes());
        expected.extend_from_slice(&fingerprint);
        expected.extend_from_slice(&confirmer);
        let statement = bytes(case, "statement");
        assert_eq!(statement.len(), 134);
        assert_eq!(statement.len(), STATEMENT_LEN);
        assert_eq!(statement, expected);
        let rebuilt = Statement {
            space,
            member,
            member_key_version: version,
            fingerprint: &fingerprint,
            confirmer,
        };
        assert_eq!(rebuilt.to_bytes(), statement);

        let public =
            sig1::PublicKey::from_bytes(&bytes(case, "confirmer_public_key")).expect("public key");
        let signing = sig1::SigningKey::from_bytes(&arr(case, "confirmer_private_key"));
        assert_eq!(
            sig1::public_key_in::<B>(&signing).expect("public"),
            public,
            "{}",
            B::NAME
        );
        let signature = bytes(case, "signature");
        assert_eq!(signature.len(), sig1::SIGNATURE_LEN);
        sig1::verify_in::<B>(&public, "confirm", &statement, &signature)
            .expect("the confirmation verifies");
        rebuilt
            .verify(&public, &statement, &signature)
            .expect("the crate's own verification agrees");

        for context in list(case, "wrong_contexts") {
            let context = context.as_str().expect("a context");
            assert_ne!(context, "confirm");
            assert!(
                sig1::verify_in::<B>(&public, context, &statement, &signature).is_err(),
                "{context}"
            );
        }
        for changed in list(case, "changed_statements") {
            let other = bytes(changed, "statement");
            assert_eq!(other.len(), STATEMENT_LEN);
            assert_ne!(other, statement, "{}", s(changed, "name"));
            assert!(
                sig1::verify_in::<B>(&public, "confirm", &other, &signature).is_err(),
                "{}",
                s(changed, "name")
            );
        }
        assert!(
            sig1::verify_in::<B>(&public, "confirm", &flip(statement.clone(), 60), &signature)
                .is_err()
        );
        for index in [0usize, 3308, 3309, 3372] {
            assert!(
                sig1::verify_in::<B>(
                    &public,
                    "confirm",
                    &statement,
                    &flip(signature.clone(), index)
                )
                .is_err(),
                "byte {index}"
            );
        }
        let own = sig1::sign_in::<B>(&signing, "confirm", &statement).expect("sign");
        sig1::verify_in::<B>(&public, "confirm", &statement, &own).expect("own signature");
        if B::NAME == "rustcrypto" {
            assert_eq!(own, signature);
        }
    }
}

fn key_box_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let name = s(case, "name");
        let context = s(case, "context");
        let kind = match context {
            "space-key" => KeyBoxKind::Space,
            "collection-key" => KeyBoxKind::Collection,
            other => panic!("{name}: no key box for {other}"),
        };
        let space: [u8; 16] = arr(case, "space");
        let recipient: [u8; 16] = arr(case, "recipient");
        let sealer: [u8; 16] = arr(case, "sealer");
        let key_version = u32::try_from(int(case, "key_version")).expect("u32");
        let sealer_version = u32::try_from(int(case, "sealer_key_version")).expect("u32");

        // The aad is the one of the sealed-box contexts.
        let aad = bytes(case, "aad");
        let rebuilt = match kind {
            KeyBoxKind::Space => key_box::space_aad(&space, key_version, &recipient),
            KeyBoxKind::Collection => {
                let collection: [u8; 16] = arr(case, "collection");
                key_box::collection_aad(&space, &collection, key_version, &recipient)
            }
        };
        assert_eq!(aad, rebuilt, "{name}");
        assert_eq!(
            aad.len(),
            match kind {
                KeyBoxKind::Space => 36,
                KeyBoxKind::Collection => 52,
            },
            "{name}"
        );

        // The box is a real box of the key, and opens for the recipient.
        let boxed = bytes(case, "box");
        assert_eq!(boxed.len(), key_box::BOX_LEN, "{name}");
        assert_eq!(boxed[0], 1, "{name}");
        let private = kx1::PrivateKey::from_bytes(&arr(case, "recipient_private_key"));
        let opened = sealed_box::open_in::<B>(&private, context, &aad, &boxed).expect("open");
        assert_eq!(opened.as_slice(), bytes(case, "secret"), "{} {name}", B::NAME);

        // The statement, rebuilt by hand from the documented layout.
        let mut expected = b"kemlock/v1/key-box".to_vec();
        lp(&mut expected, context.as_bytes()).expect("lp");
        lp(&mut expected, &aad).expect("lp");
        lp(&mut expected, &boxed).expect("lp");
        expected.extend_from_slice(&sealer);
        expected.extend_from_slice(&sealer_version.to_be_bytes());
        let statement = bytes(case, "statement");
        assert_eq!(
            statement.len(),
            match kind {
                KeyBoxKind::Space => 1756,
                KeyBoxKind::Collection => 1777,
            },
            "{name}"
        );
        assert_eq!(statement, expected, "{name}");
        let rebuilt = KeyBoxStatement {
            kind,
            aad: &aad,
            sealed_box: &boxed,
            sealer,
            sealer_key_version: sealer_version,
        };
        assert_eq!(rebuilt.to_bytes().expect("statement"), statement, "{name}");

        let public =
            sig1::PublicKey::from_bytes(&bytes(case, "sealer_public_key")).expect("public key");
        let signing = sig1::SigningKey::from_bytes(&arr(case, "sealer_private_key"));
        assert_eq!(
            sig1::public_key_in::<B>(&signing).expect("public"),
            public,
            "{} {name}",
            B::NAME
        );
        let signature = bytes(case, "signature");
        assert_eq!(signature.len(), sig1::SIGNATURE_LEN, "{name}");
        sig1::verify_in::<B>(&public, "key-box", &statement, &signature)
            .expect("the box signature verifies");
        rebuilt
            .verify(&public, &signature)
            .expect("the crate's own verification agrees");

        for wrong in list(case, "wrong_contexts") {
            let wrong = wrong.as_str().expect("a context");
            assert_ne!(wrong, "key-box");
            assert!(
                sig1::verify_in::<B>(&public, wrong, &statement, &signature).is_err(),
                "{name} {wrong}"
            );
        }
        for changed in list(case, "changed_statements") {
            let other = bytes(changed, "statement");
            assert_eq!(other.len(), statement.len(), "{name}");
            assert_ne!(other, statement, "{name} {}", s(changed, "name"));
            assert!(
                sig1::verify_in::<B>(&public, "key-box", &other, &signature).is_err(),
                "{name} {}",
                s(changed, "name")
            );
        }
        assert!(
            sig1::verify_in::<B>(&public, "key-box", &flip(statement.clone(), 700), &signature)
                .is_err()
        );
        for index in [0usize, 3308, 3309, 3372] {
            assert!(
                sig1::verify_in::<B>(
                    &public,
                    "key-box",
                    &statement,
                    &flip(signature.clone(), index)
                )
                .is_err(),
                "{name} byte {index}"
            );
        }
        let own = sig1::sign_in::<B>(&signing, "key-box", &statement).expect("sign");
        sig1::verify_in::<B>(&public, "key-box", &statement, &own).expect("own signature");
        if B::NAME == "rustcrypto" {
            assert_eq!(own, signature, "{name}");
        }
    }
}

fn prf_wrap_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let prf_output: [u8; 32] = arr(case, "prf_output");
        let credential = bytes(case, "credential_id");
        let account: [u8; 16] = arr(case, "account_id");
        let root: [u8; 64] = arr(case, "root_key");
        let version = u32::try_from(int(case, "key_version")).expect("u32");
        let wrapped = bytes(case, "wrapped");
        assert_eq!(wrapped.len(), prf_wrap::WRAPPED_LEN);
        assert_eq!(
            B::sha256(b"kemlock/v1/prf-salt").as_slice(),
            bytes(case, "prf_salt"),
            "{}",
            B::NAME
        );

        let mut info = b"kemlock/v1/prf-wrap".to_vec();
        lp(&mut info, &credential).expect("lp");
        let mut wrap_key = [0u8; 32];
        B::hkdf_sha256(&prf_output, None, &info, &mut wrap_key).expect("hkdf");
        assert_eq!(wrap_key.as_slice(), bytes(case, "wrap_key"), "{}", B::NAME);
        assert_eq!(
            prf_wrap::wrap_key_in::<B>(&prf_output, &credential)
                .expect("wrap key")
                .as_bytes(),
            &wrap_key
        );

        let mut aad = b"kemlock/v1/root-wrap/prf".to_vec();
        aad.extend_from_slice(&account);
        aad.extend_from_slice(&version.to_be_bytes());
        lp(&mut aad, &credential).expect("lp");
        assert_eq!(aad, bytes(case, "aad"));

        let nonce: [u8; 12] = wrapped[..12].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_open(&wrap_key, &nonce, &aad, &wrapped[12..]).expect("open"),
            root,
            "{}",
            B::NAME
        );
        assert_eq!(
            B::aes256gcm_seal(&wrap_key, &nonce, &aad, &root).expect("seal"),
            wrapped[12..]
        );

        let opened = prf_wrap::open_in::<B>(&prf_output, &credential, &wrapped, &account, version)
            .expect("open the wrap");
        assert_eq!(opened.as_bytes().as_slice(), root);
        assert!(
            prf_wrap::open_in::<B>(&[0; 32], &credential, &wrapped, &account, version).is_err()
        );
        assert!(
            prf_wrap::open_in::<B>(&prf_output, &credential[1..], &wrapped, &account, version)
                .is_err()
        );
        assert!(
            prf_wrap::open_in::<B>(&prf_output, &credential, &wrapped, &[0; 16], version).is_err()
        );
        assert!(
            prf_wrap::open_in::<B>(&prf_output, &credential, &wrapped, &account, version + 1)
                .is_err()
        );
        assert!(
            prf_wrap::open_in::<B>(
                &prf_output,
                &credential,
                &flip(wrapped.clone(), 30),
                &account,
                version
            )
            .is_err()
        );
    }
}

fn send_file<B: Backend>(doc: &Value) {
    for case in cases(doc) {
        let name = s(case, "name");
        let kind = send::Kind::parse(s(case, "kind")).expect("a known kind");
        let other_kind = match kind {
            send::Kind::Text => send::Kind::File,
            send::Kind::File => send::Kind::Text,
        };
        let id: [u8; 16] = arr(case, "send_id");
        let link_key = SecretKey::from_bytes(&arr(case, "link_key"));
        let mut other_id = id;
        other_id[0] ^= 1;
        let other_key = SecretKey::from_bytes(&[0x5a; 32]);

        // The id is a version 4 UUID, and the link is built from it and the key.
        assert_eq!(id[6] >> 4, 4, "{name}");
        assert_eq!(id[8] >> 6, 0b10, "{name}");
        assert_eq!(s(case, "access_id"), b64url(&id), "{name}");
        assert_eq!(
            s(case, "link"),
            format!(
                "https://example.org/#/send/{}/{}",
                b64url(&id),
                b64url(link_key.as_bytes())
            ),
            "{name}"
        );

        // The payload key and the salt come from the link key by their labels; the meta key comes
        // from the owner's item-wrap key, the Send's id and the key version, never from the link
        // key.
        let wrap_key = SecretKey::from_bytes(&arr(case, "wrap_key"));
        let version = u32::try_from(int(case, "key_version")).expect("u32");
        let derive = |info: &[u8], out: &mut [u8]| {
            B::hkdf_sha256(link_key.as_bytes(), None, info, out).expect("hkdf");
        };
        let mut payload_key = [0u8; 32];
        derive(b"kemlock/v1/send-payload", &mut payload_key);
        assert_eq!(payload_key.as_slice(), bytes(case, "payload_key"), "{name}");
        let mut meta_info = b"kemlock/v1/send-meta".to_vec();
        meta_info.extend_from_slice(&id);
        meta_info.extend_from_slice(&version.to_be_bytes());
        let mut meta_key = [0u8; 32];
        B::hkdf_sha256(wrap_key.as_bytes(), None, &meta_info, &mut meta_key).expect("hkdf");
        assert_eq!(meta_key.as_slice(), bytes(case, "meta_key"), "{name}");
        let mut from_link = [0u8; 32];
        derive(b"kemlock/v1/send-meta", &mut from_link);
        assert_ne!(
            from_link, meta_key,
            "{name}: the link key must not give the meta key"
        );
        let mut proof_info = b"kemlock/v1/send-proof".to_vec();
        proof_info.extend_from_slice(&id);
        let mut salt = [0u8; 16];
        derive(&proof_info, &mut salt);
        assert_eq!(salt.as_slice(), bytes(case, "proof_salt"), "{name}");

        // The payload and the meta: rebuild the aad, open, seal again with the same nonce.
        let kind_text = kind.as_str().as_bytes();
        let aad_of = |label: &[u8]| {
            let mut aad = label.to_vec();
            aad.extend_from_slice(&id);
            aad.extend_from_slice(&u32::try_from(kind_text.len()).expect("short").to_be_bytes());
            aad.extend_from_slice(kind_text);
            aad
        };
        for (label, key, json_field, sealed_field, aad_field) in [
            (
                "kemlock/v1/send-payload",
                &payload_key,
                "payload_json",
                "payload",
                "payload_aad",
            ),
            (
                "kemlock/v1/send-meta",
                &meta_key,
                "meta_json",
                "meta",
                "meta_aad",
            ),
        ] {
            let aad = aad_of(label.as_bytes());
            assert_eq!(aad, bytes(case, aad_field), "{name} {aad_field}");
            let json = s(case, json_field).as_bytes();
            let sealed = bytes(case, sealed_field);
            assert_eq!(sealed.len(), json.len() + 28, "{name} {sealed_field}");
            let nonce: [u8; 12] = sealed[..12].try_into().expect("nonce");
            assert_eq!(
                B::aes256gcm_open(key, &nonce, &aad, &sealed[12..]).expect("open"),
                json,
                "{} {name} {sealed_field}",
                B::NAME
            );
            assert_eq!(
                B::aes256gcm_seal(key, &nonce, &aad, json).expect("seal"),
                sealed[12..],
                "{name} {sealed_field}"
            );
        }

        // The format's own functions open them, and refuse another id, kind, key or purpose.
        let payload = bytes(case, "payload");
        let meta = bytes(case, "meta");
        let opened = send::open_payload_in::<B>(&link_key, &id, kind, &payload).expect("payload");
        assert_eq!(opened.as_slice(), s(case, "payload_json").as_bytes());
        let opened = send::open_meta_in::<B>(&wrap_key, &id, version, kind, &meta).expect("meta");
        assert_eq!(opened.as_slice(), s(case, "meta_json").as_bytes());
        for (other, label) in [(&other_id, "id"), (&id, "kind")] {
            let wrong_kind = if label == "kind" { other_kind } else { kind };
            assert!(send::open_payload_in::<B>(&link_key, other, wrong_kind, &payload).is_err());
            let meta_open = send::open_meta_in::<B>(&wrap_key, other, version, wrong_kind, &meta);
            assert!(meta_open.is_err());
        }
        assert!(send::open_payload_in::<B>(&other_key, &id, kind, &payload).is_err());
        assert!(send::open_meta_in::<B>(&other_key, &id, version, kind, &meta).is_err());
        assert!(send::open_meta_in::<B>(&wrap_key, &id, version + 1, kind, &meta).is_err());
        // The link key alone, whoever holds it, opens no meta.
        assert!(send::open_meta_in::<B>(&link_key, &id, version, kind, &meta).is_err());
        assert!(send::open_meta_in::<B>(&wrap_key, &id, version, kind, &payload).is_err());
        assert!(send::open_payload_in::<B>(&link_key, &id, kind, &meta).is_err());
        assert!(
            send::open_payload_in::<B>(&link_key, &id, kind, &flip(payload.clone(), 20)).is_err()
        );
        assert!(send::open_payload_in::<B>(&link_key, &id, kind, &payload[1..]).is_err());

        // The sealed link key: version, nonce, key, tag.
        let sealed_key = bytes(case, "sealed_key");
        assert_eq!(send::sealed_key_version(&sealed_key), Ok(version), "{name}");
        assert_eq!(sealed_key.len(), send::SEALED_KEY_LEN, "{name}");
        assert_eq!(sealed_key[..4], version.to_be_bytes(), "{name}");
        let mut key_aad = b"kemlock/v1/send-key".to_vec();
        key_aad.extend_from_slice(&id);
        key_aad.extend_from_slice(&version.to_be_bytes());
        assert_eq!(key_aad, bytes(case, "key_aad"), "{name}");
        let nonce: [u8; 12] = sealed_key[4..16].try_into().expect("nonce");
        assert_eq!(
            B::aes256gcm_open(wrap_key.as_bytes(), &nonce, &key_aad, &sealed_key[16..])
                .expect("open"),
            link_key.as_bytes().as_slice(),
            "{} {name}",
            B::NAME
        );
        assert_eq!(
            B::aes256gcm_seal(wrap_key.as_bytes(), &nonce, &key_aad, link_key.as_bytes())
                .expect("seal"),
            sealed_key[16..],
            "{name}"
        );
        let (unwrapped, unwrapped_version) =
            send::unwrap_link_key_in::<B>(&wrap_key, &sealed_key, &id).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), link_key.as_bytes(), "{name}");
        assert_eq!(unwrapped_version, version, "{name}");
        assert!(send::unwrap_link_key_in::<B>(&wrap_key, &sealed_key, &other_id).is_err());
        assert!(send::unwrap_link_key_in::<B>(&other_key, &sealed_key, &id).is_err());
        let mut other_version = sealed_key.clone();
        other_version[3] ^= 1;
        assert!(send::unwrap_link_key_in::<B>(&wrap_key, &other_version, &id).is_err());
        assert!(send::unwrap_link_key_in::<B>(&wrap_key, &sealed_key[1..], &id).is_err());

        // The password proof, when the Send has one.
        if case.get("password").is_some() {
            let typed = s(case, "password");
            let nfc = crate::dedup::normalise::nfc(typed);
            assert_eq!(nfc, s(case, "password_nfc"), "{name}");
            let proof = argon2id::master_key(nfc.as_bytes(), &salt, 19456, 2, 1).expect("argon2");
            assert_eq!(proof.as_slice(), bytes(case, "proof"), "{name}");
            let derived = send::password_proof_in::<B>(&link_key, &id, typed).expect("proof");
            assert_eq!(derived.as_slice(), proof.as_slice(), "{} {name}", B::NAME);
            let other = send::password_proof_in::<B>(&link_key, &other_id, typed).expect("proof");
            assert_ne!(other.as_slice(), proof.as_slice(), "{name}");
        } else {
            assert!(case.get("proof").is_none(), "{name}");
        }

        // A file Send: the KMA1 file under the payload key, and a payload that names it.
        assert_eq!(
            case.get("file").is_some(),
            kind == send::Kind::File,
            "{name}"
        );
        if case.get("file").is_some() {
            let plain = bytes(case, "file_plain");
            let file = bytes(case, "file");
            assert_eq!(file.len(), kma1::sealed_len(plain.len()), "{name}");
            let key = SecretKey::from_bytes(&payload_key);
            let opened = kma1::open_in::<B>(&key, &file).expect("the file opens");
            assert_eq!(opened.as_slice(), plain.as_slice(), "{} {name}", B::NAME);
            let prefix: [u8; kma1::PREFIX_LEN] =
                file[4..kma1::HEADER_LEN].try_into().expect("a prefix");
            assert_eq!(
                kma1::seal_with_prefix_in::<B>(&key, &prefix, &plain).expect("seal"),
                file,
                "{name}"
            );
            assert!(kma1::open_in::<B>(&other_key, &file).is_err(), "{name}");
            let described: Value = serde_json::from_str(s(case, "payload_json")).expect("JSON");
            assert_eq!(described["size"], plain.len(), "{name}");
        }
    }
}

// ---- running them -----------------------------------------------------------------------------

/// Checks one file on one backend; the backend-independent files are left to [`check_slow`].
pub(crate) fn check_on<B: Backend>(name: &str, doc: &Value) {
    check_header(name, doc);
    match name {
        "account-keys" => account_keys::<B>(doc),
        "password-wrap" => password_wrap_file::<B>(doc),
        "kx1" => kx1_file::<B>(doc),
        "sealed-box" => sealed_box_file::<B>(doc),
        "sig1" => sig1_file::<B>(doc),
        "sig1-edge" => sig1_edge_file::<B>(doc),
        "bundle" => bundle_file::<B>(doc),
        "kem1" => kem1_file::<B>(doc),
        "manifest" => manifest_file::<B>(doc),
        "dedup" => dedup_file::<B>(doc),
        "server-seal" => server_seal_file::<B>(doc),
        "legacy-ids" => legacy_ids_file::<B>(doc),
        "dedup-normalise" => dedup_normalise_file::<B>(doc),
        "phrase" => phrase_file::<B>(doc),
        "private-keys" => private_keys_file::<B>(doc),
        "prf-wrap" => prf_wrap_file::<B>(doc),
        "confirm" => confirm_file::<B>(doc),
        "key-box" => key_box_file::<B>(doc),
        "send" => send_file::<B>(doc),
        "space-names" => space_names_file::<B>(doc),
        "space-chain" => super::space_chain::check::<B>(doc),
        "argon2id" | "opaque" => {}
        other => panic!("no check for {other}"),
    }
}

/// The files that don't depend on a backend: Argon2id and OPAQUE.
pub(crate) fn check_slow(name: &str, doc: &Value) {
    match name {
        "argon2id" => argon2id_file(doc),
        "opaque" => opaque_file(doc),
        _ => {}
    }
}

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn load(name: &str) -> Option<Value> {
    let path = vector_dir().join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).ok()?;
    Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

#[test]
fn every_vector_file_is_known() {
    // A file in test-vectors/ that no check covers would be pinning nothing.
    let Ok(entries) = std::fs::read_dir(vector_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        if let Some(name) = file.strip_suffix(".json") {
            // kemlock-federation generates and checks its own federation-*.json files, and
            // kemlock-api-kem's tests check openapi.json against the served document.
            if name.starts_with("federation-") || name == "openapi" {
                continue;
            }
            assert!(FILES.contains(&name), "test-vectors/{file} has no check");
        }
    }
}

#[test]
fn committed_vectors_pass_on_every_backend() {
    for_backends!(B => {
        for name in FILES {
            if let Some(doc) = load(name) {
                check_on::<B>(name, &doc);
            }
        }
    });
}

#[test]
fn committed_argon2id_and_opaque_vectors_pass() {
    for name in ["argon2id", "opaque"] {
        if let Some(doc) = load(name) {
            check_header(name, &doc);
            check_slow(name, &doc);
        }
    }
}

#[test]
fn committed_checksums_match_the_files() {
    let Ok(sums) = std::fs::read_to_string(vector_dir().join("SHA256SUMS")) else {
        return;
    };
    for line in sums.lines() {
        let (digest, file) = line.split_once("  ").expect("`hash  file` lines");
        let text = std::fs::read(vector_dir().join(file)).expect("a listed file exists");
        assert_eq!(hex::encode(crate::hash::sha256(&text)), digest, "{file}");
    }
}

#[cfg(test)]
mod generated {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = super::super::generate::all().expect("generate");
        let b = super::super::generate::all().expect("generate");
        assert_eq!(a, b);
        assert_eq!(
            a.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            FILES.to_vec()
        );
    }

    #[test]
    fn generated_vectors_pass_their_own_checks_on_every_backend() {
        let docs = super::super::generate::all().expect("generate");
        for (name, doc) in &docs {
            for_backends!(B => {
                check_on::<B>(name, doc);
            });
            check_slow(name, doc);
        }
    }
}
