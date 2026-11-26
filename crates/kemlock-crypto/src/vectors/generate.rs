//! Generates the vector files from fixed seeds on the RustCrypto backend. Every file has its own
//! seed (the SHA-256 of `kemlock-vectors/<name>`), so changing one format never moves another's
//! bytes. ML-DSA signatures are deterministic on this backend, so the output is stable.

use serde_json::{Value, json};

use super::{ScriptedRng, b64url, document, hx, normalise_cases, uuid_text};
use crate::{
    Error, argon2id,
    backend::{Backend, rustcrypto::RustCrypto},
    bundle::{self, Bundle},
    confirm::Statement,
    dedup, kem1,
    key_box::{self, Kind as KeyBoxKind, Statement as KeyBoxStatement},
    keys::{ITEM_WRAP_LABEL, MANIFEST_LABEL, PRIVATE_KEYS_LABEL, RootKey, SecretKey, USER_LABEL},
    kma1, kx1, legacy_id,
    manifest::{Entry, Manifest},
    opaque::{self, OpaqueServer},
    owner::Owner,
    password_wrap, prf_wrap, private_keys, rand, seal, sealed_box, send,
    sig1::{self, context::BUNDLE, context::CONFIRM, context::KEY_BOX, context::MANIFEST},
};

type G = RustCrypto;

fn rnd<const N: usize>() -> Result<[u8; N], Error> {
    rand::try_bytes::<G, N>()
}

/// `0, 1, 2, …` wrapping at 256: a key a person can recognise.
fn counting<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| u8::try_from(i % 256).unwrap_or(0))
}

/// Runs `f` with this file's own seeded random stream.
fn seeded<T>(file: &str, f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    let seed = G::sha256(format!("kemlock-vectors/{file}").as_bytes());
    crate::with_seeded_random(seed, f)
}

/// Every file, in the order of [`super::FILES`].
pub(crate) fn all() -> Result<Vec<(&'static str, Value)>, Error> {
    Ok(vec![
        ("account-keys", account_keys()?),
        ("password-wrap", password_wrap_doc()?),
        ("argon2id", argon2id_doc()?),
        ("kx1", kx1_doc()?),
        ("sealed-box", sealed_box_doc()?),
        ("sig1", sig1_doc()?),
        ("sig1-edge", super::sig1_edge::generate()),
        ("bundle", bundle_doc()?),
        ("kem1", kem1_doc()?),
        ("manifest", manifest_doc()?),
        ("dedup", dedup_doc()?),
        ("server-seal", server_seal_doc()?),
        ("opaque", opaque_doc()?),
        ("legacy-ids", legacy_ids_doc()?),
        ("dedup-normalise", dedup_normalise_doc()?),
        ("phrase", phrase_doc()?),
        ("private-keys", private_keys_doc()?),
        ("prf-wrap", prf_wrap_doc()?),
        ("confirm", confirm_doc()?),
        ("key-box", key_box_doc()?),
        ("send", send_doc()?),
        ("space-names", space_names_doc()?),
        ("space-chain", super::space_chain::generate()?),
    ])
}

fn account_keys() -> Result<Value, Error> {
    seeded("account-keys", || {
        let roots: Vec<(&str, [u8; 64])> = vec![
            ("zero-root", [0u8; 64]),
            ("counting-root", counting()),
            ("random-root", rnd()?),
        ];
        let mut cases = Vec::new();
        for (name, root_bytes) in roots {
            let user = RootKey::from_bytes(&root_bytes).user_key_in::<G>()?;
            let mut children = Vec::new();
            for label in [ITEM_WRAP_LABEL, PRIVATE_KEYS_LABEL, MANIFEST_LABEL] {
                let child = user.child_in::<G>(label)?;
                children.push(json!({ "label": label, "key": hx(child.as_bytes()) }));
            }
            cases.push(json!({
                "name": name,
                "root_key": hx(&root_bytes),
                "user_label": USER_LABEL,
                "user_key": hx(user.as_bytes()),
                "children": children,
            }));
        }
        Ok(document(
            "account-keys",
            "The root key (64 bytes), the Kemlock user key HKDF-SHA256(ikm = root, salt = absent, \
             info = user_label, L = 32), and the labelled child keys HKDF-SHA256(ikm = user key, \
             salt = absent, info = label, L = 32).",
            cases,
        ))
    })
}

fn password_wrap_doc() -> Result<Value, Error> {
    seeded("password-wrap", || {
        let mut cases = Vec::new();
        for (name, key_version) in [("key-version-1", 1u32), ("key-version-2", 2u32)] {
            let master_key: [u8; 32] = rnd()?;
            let export_key: [u8; 64] = rnd()?;
            let root_key: [u8; 64] = rnd()?;
            let account_id: [u8; 16] = rnd()?;
            let wrap_key = password_wrap::wrap_key_in::<G>(&master_key, &export_key)?;
            let wrapped = password_wrap::seal_in::<G>(
                &master_key,
                &export_key,
                &RootKey::from_bytes(&root_key),
                &account_id,
                key_version,
            )?;
            cases.push(json!({
                "name": name,
                "master_key": hx(&master_key),
                "export_key": hx(&export_key),
                "root_key": hx(&root_key),
                "account_id": hx(&account_id),
                "key_version": key_version,
                "wrap_key": hx(wrap_key.as_bytes()),
                "aad": hx(&password_wrap::aad(&account_id, key_version)),
                "wrapped": hx(&wrapped),
            }));
        }
        Ok(document(
            "password-wrap",
            "wrap_key = HKDF-SHA256(ikm = master_key || export_key, salt = absent, info = \
             \"kemlock/v1/password-wrap\", L = 32); aad = \"kemlock/v1/root-wrap\" || account_id || \
             u32be(key_version); wrapped = nonce(12) || AES-256-GCM(wrap_key, nonce, root_key, aad) \
             with the 16-byte tag at the end.",
            cases,
        ))
    })
}

fn argon2id_doc() -> Result<Value, Error> {
    seeded("argon2id", || {
        let mut cases = Vec::new();
        let params: [(&str, &str, u32, u32, u32); 3] = [
            ("small", "correct horse battery staple", 64, 2, 1),
            (
                "default-parameters",
                "correct horse battery staple",
                argon2id::DEFAULT_MEMORY_KIB,
                argon2id::DEFAULT_ITERATIONS,
                argon2id::DEFAULT_PARALLELISM,
            ),
            // The password is the UTF-8 of its NFC form: this one is already normalised.
            ("nfc-password", "caf\u{e9} \u{1f511}", 64, 2, 1),
        ];
        for (name, password, memory_kib, iterations, parallelism) in params {
            let salt: [u8; 16] = rnd()?;
            let master_key = argon2id::master_key(
                password.as_bytes(),
                &salt,
                memory_kib,
                iterations,
                parallelism,
            )?;
            cases.push(json!({
                "name": name,
                "password_text": password,
                "password": hx(password.as_bytes()),
                "salt": hx(&salt),
                "memory_kib": memory_kib,
                "iterations": iterations,
                "parallelism": parallelism,
                "master_key": hx(&master_key),
            }));
        }
        Ok(document(
            "argon2id",
            "master_key = Argon2id(password, salt, m = memory_kib, t = iterations, p = \
             parallelism, L = 32), version 0x13. The password is the UTF-8 of its NFC form.",
            cases,
        ))
    })
}

fn kx1_doc() -> Result<Value, Error> {
    seeded("kx1", || {
        let mut cases = Vec::new();
        for name in ["pair-1", "pair-2"] {
            let private_bytes: [u8; 96] = rnd()?;
            let private = kx1::PrivateKey::from_bytes(&private_bytes);
            let public = kx1::public_key_in::<G>(&private)?;
            let (ciphertext, secret) = kx1::encapsulate_in::<G>(&public)?;
            // A ciphertext with one byte changed gives another secret, not an error: ML-KEM's
            // implicit rejection for the first half, a different point for the second.
            let mut implicit = Vec::new();
            for (description, index) in [
                ("first byte of the ML-KEM ciphertext flipped", 0usize),
                ("first byte of the X25519 ciphertext flipped", 1568usize),
            ] {
                let mut changed = ciphertext;
                changed[index] ^= 1;
                let got = kx1::decapsulate_in::<G>(&private, &changed)?;
                implicit.push(json!({
                    "description": description,
                    "ciphertext": hx(&changed),
                    "shared_secret": hx(got.as_bytes()),
                }));
            }
            cases.push(json!({
                "name": name,
                "private_key": hx(&private_bytes),
                "mlkem_seed": hx(&private_bytes[..64]),
                "x25519_secret": hx(&private_bytes[64..]),
                "public_key": hx(public.as_bytes()),
                "ciphertext": hx(&ciphertext),
                "shared_secret": hx(secret.as_bytes()),
                "changed_ciphertexts": implicit,
            }));
        }
        Ok(document(
            "kx1",
            "private_key = ML-KEM-1024 seed d||z (64) || X25519 secret (32); public_key = ML-KEM \
             encapsulation key (1568) || X25519 public key (32); ciphertext = ct_m (1568) || ct_x \
             (32); shared_secret = SHA3-256(\"kemlock/v1/kx1\" || ss_m || ss_x || ct_x || pk_x). \
             changed_ciphertexts pin the implicit-rejection outputs.",
            cases,
        ))
    })
}

fn sealed_box_doc() -> Result<Value, Error> {
    seeded("sealed-box", || {
        let mut cases = Vec::new();
        let all_contexts = [
            sealed_box::context::DEVICE_APPROVAL,
            sealed_box::context::SPACE_KEY,
            sealed_box::context::COLLECTION_KEY,
            sealed_box::context::EMERGENCY_ACCESS,
            sealed_box::context::ACCOUNT_RECOVERY,
        ];
        // The contexts that have an aad fixed in docs/crypto.md, each with the aad the clients
        // build for it; `aad_parts` names the pieces so a client can rebuild the aad itself.
        for (name, context) in [
            ("device-approval", all_contexts[0]),
            ("space-key", all_contexts[1]),
            ("collection-key", all_contexts[2]),
            ("emergency-access", all_contexts[3]),
            ("account-recovery", all_contexts[4]),
        ] {
            let private_bytes: [u8; 96] = rnd()?;
            let private = kx1::PrivateKey::from_bytes(&private_bytes);
            let public = kx1::public_key_in::<G>(&private)?;
            let (aad, parts) = match name {
                // account id ‖ approval request id
                "device-approval" => {
                    let account: [u8; 16] = rnd()?;
                    let request: [u8; 16] = rnd()?;
                    (
                        [account.as_slice(), &request].concat(),
                        json!({ "account_id": hx(&account), "request_id": hx(&request) }),
                    )
                }
                // space id ‖ u32be(space key version) ‖ recipient account id
                "space-key" => {
                    let space: [u8; 16] = rnd()?;
                    let recipient: [u8; 16] = rnd()?;
                    let version = 2u32;
                    (
                        [space.as_slice(), &version.to_be_bytes(), &recipient].concat(),
                        json!({
                            "space_id": hx(&space),
                            "key_version": version,
                            "recipient_id": hx(&recipient),
                        }),
                    )
                }
                // space id ‖ collection id ‖ u32be(collection key version) ‖ recipient account id
                "collection-key" => {
                    let space: [u8; 16] = rnd()?;
                    let collection: [u8; 16] = rnd()?;
                    let recipient: [u8; 16] = rnd()?;
                    let version = 3u32;
                    (
                        [
                            space.as_slice(),
                            &collection,
                            &version.to_be_bytes(),
                            &recipient,
                        ]
                        .concat(),
                        json!({
                            "space_id": hx(&space),
                            "collection_id": hx(&collection),
                            "key_version": version,
                            "recipient_id": hx(&recipient),
                        }),
                    )
                }
                // space id ‖ account id ‖ u64be(seq of the record that set the recovery key)
                "account-recovery" => {
                    let space: [u8; 16] = rnd()?;
                    let account: [u8; 16] = rnd()?;
                    let key_seq = 5u64;
                    (
                        [space.as_slice(), &account, &key_seq.to_be_bytes()].concat(),
                        json!({
                            "space_id": hx(&space),
                            "account_id": hx(&account),
                            "key_seq": key_seq,
                        }),
                    )
                }
                // the contact's account id
                _ => {
                    let contact: [u8; 16] = rnd()?;
                    (contact.to_vec(), json!({ "contact_id": hx(&contact) }))
                }
            };
            // A root key is 64 bytes, and the root key is what an account-recovery box seals.
            let secret: Vec<u8> = if name == "account-recovery" {
                rnd::<64>()?.to_vec()
            } else {
                rnd::<32>()?.to_vec()
            };
            let sealed = sealed_box::seal_in::<G>(&public, context, &aad, &secret)?;
            let wrong: Vec<&str> = all_contexts
                .iter()
                .copied()
                .filter(|c| *c != context)
                .collect();
            cases.push(json!({
                "name": name,
                "private_key": hx(&private_bytes),
                "public_key": hx(public.as_bytes()),
                "context": context,
                "aad_parts": parts,
                "aad": hx(&aad),
                "secret": hx(&secret),
                "sealed_box": hx(&sealed),
                "wrong_contexts": wrong,
            }));
        }
        Ok(document(
            "sealed-box",
            "sealed_box = u8(1) || kx1 ciphertext (1600) || nonce(12) || AES-256-GCM(key, nonce, \
             secret, aad = lp(context) || lp(aad)) with the 16-byte tag at the end, where key = \
             HKDF-SHA256(ikm = kx1 shared secret, salt = absent, info = \"kemlock/v1/seal\" || \
             lp(context), L = 32). `aad` is the caller's binding, built from `aad_parts` per \
             context: device-approval = account_id || request_id (32 bytes); space-key = \
             space_id || u32be(key_version) || recipient_id (36); collection-key = space_id || \
             collection_id || u32be(key_version) || recipient_id (52); emergency-access = \
             contact_id (16); account-recovery = space_id || account_id || u64be(key_seq) (40), \
             the secret a 64-byte root key. Opening under a wrong context or aad must fail.",
            cases,
        ))
    })
}

fn sig1_doc() -> Result<Value, Error> {
    seeded("sig1", || {
        let mut cases = Vec::new();
        for (name, context, message) in [
            (
                "bundle-context",
                sig1::context::BUNDLE,
                b"a message to sign".to_vec(),
            ),
            (
                "manifest-context",
                sig1::context::MANIFEST,
                counting::<100>().to_vec(),
            ),
            ("empty-message", sig1::context::BUNDLE, Vec::new()),
        ] {
            let private_bytes: [u8; 64] = rnd()?;
            let key = sig1::SigningKey::from_bytes(&private_bytes);
            let public = sig1::public_key_in::<G>(&key)?;
            let signature = sig1::sign_in::<G>(&key, context, &message)?;
            cases.push(json!({
                "name": name,
                "private_key": hx(&private_bytes),
                "mldsa_seed": hx(&private_bytes[..32]),
                "ed25519_seed": hx(&private_bytes[32..]),
                "public_key": hx(public.as_bytes()),
                "context": context,
                "message": hx(&message),
                "signature": hx(&signature),
            }));
        }
        Ok(document(
            "sig1",
            "m' = \"kemlock/v1/sig1\" || lp(context) || lp(message); signature = ML-DSA-65.Sign(\
             seed, m', ctx = empty) (3309) || Ed25519.Sign(seed, m') (64). The ML-DSA signature \
             here is the deterministic variant; verifiers accept either. Both halves must verify.",
            cases,
        ))
    })
}

fn bundle_doc() -> Result<Value, Error> {
    seeded("bundle", || {
        let kx1_private_bytes: [u8; 96] = rnd()?;
        let sig1_private_bytes: [u8; 64] = rnd()?;
        let account_id: [u8; 16] = rnd()?;
        let kx1_public = kx1::public_key_in::<G>(&kx1::PrivateKey::from_bytes(&kx1_private_bytes))?;
        let signing = sig1::SigningKey::from_bytes(&sig1_private_bytes);
        let sig1_public = sig1::public_key_in::<G>(&signing)?;
        let b = Bundle {
            account_id,
            key_version: 1,
            kx1_public: kx1_public.clone(),
            sig1_public: sig1_public.clone(),
        };
        let bytes = b.to_bytes();
        let fingerprint = bundle::fingerprint_in::<G>(&bytes);
        let groups = bundle::fingerprint_groups(&fingerprint);
        let signature = sig1::sign_in::<G>(&signing, BUNDLE, &bytes)?;
        let case = json!({
            "name": "bundle-1",
            "account_id": hx(&account_id),
            "key_version": 1,
            "kx1_private_key": hx(&kx1_private_bytes),
            "kx1_public_key": hx(kx1_public.as_bytes()),
            "sig1_private_key": hx(&sig1_private_bytes),
            "sig1_public_key": hx(sig1_public.as_bytes()),
            "bundle": hx(&bytes),
            "fingerprint": hx(&fingerprint),
            "fingerprint_groups": groups,
            "fingerprint_text": groups.join(" "),
            "signature": hx(&signature),
        });
        Ok(document(
            "bundle",
            "bundle = \"kemlock/v1/bundle\" || account_id || u32be(key_version) || kx1 public key \
             || sig1 public key; fingerprint = SHA-512(\"kemlock/v1/fingerprint\" || bundle); \
             group i (0 to 11) is u40be(fingerprint[5i..5i+5]) mod 100000 with leading zeros; \
             signature = sig1 signature of the bundle under context \"bundle\".",
            vec![case],
        ))
    })
}

fn kem1_doc() -> Result<Value, Error> {
    seeded("kem1", || {
        let mut cases = Vec::new();
        for (name, is_space, kind, json_text) in [
            (
                "login-in-a-vault",
                false,
                "login",
                r#"{"name":"Example","username":"alice","password":"hunter2","urls":["https://example.com"]}"#,
            ),
            (
                "note-in-a-space",
                true,
                "note",
                "{\"name\":\"R\u{e9}sum\u{e9}\",\"text\":\"line one\\nline two \u{1f511}\"}",
            ),
        ] {
            let root_bytes: [u8; 64] = rnd()?;
            let user = RootKey::from_bytes(&root_bytes).user_key_in::<G>()?;
            let wrap_key = user.child_in::<G>(ITEM_WRAP_LABEL)?;
            let item_key_bytes: [u8; 32] = rnd()?;
            let item_key = SecretKey::from_bytes(&item_key_bytes);
            let item_id: [u8; 16] = rnd()?;
            let owner_id: [u8; 16] = rnd()?;
            let owner = if is_space {
                Owner::space(owner_id)
            } else {
                Owner::user(owner_id)
            };
            let revision = 4u64;
            let key_version = 1u32;
            let aad = kem1::item_aad(&item_id, revision, kind, &owner)?;
            let ciphertext = kem1::seal_item_in::<G>(
                &item_key,
                &item_id,
                revision,
                kind,
                &owner,
                json_text.as_bytes(),
            )?;
            let wrap_aad = kem1::item_key_aad(&item_id, &owner, key_version);
            let wrapped =
                kem1::wrap_item_key_in::<G>(&wrap_key, &item_key, &item_id, &owner, key_version)?;
            cases.push(json!({
                "name": name,
                "root_key": hx(&root_bytes),
                "user_key": hx(user.as_bytes()),
                "wrap_key": hx(wrap_key.as_bytes()),
                "item_key": hx(&item_key_bytes),
                "item_id": hx(&item_id),
                "owner": hx(&owner.to_bytes()),
                "revision": revision,
                "kind": kind,
                "key_version": key_version,
                "item_json": json_text,
                "aad": hx(&aad),
                "ciphertext": hx(&ciphertext),
                "wrap_aad": hx(&wrap_aad),
                "wrapped_item_key": hx(&wrapped),
            }));
        }
        Ok(document(
            "kem1",
            "aad = \"kemlock/v1/item\" || item_id || u64be(revision) || lp(kind) || owner; \
             ciphertext = nonce(12) || AES-256-GCM(item_key, nonce, item_json UTF-8, aad) with the \
             16-byte tag at the end; wrap_aad = \"kemlock/v1/item-key\" || item_id || owner || \
             u32be(key_version); wrapped_item_key = nonce(12) || AES-256-GCM(wrap_key, nonce, \
             item_key, wrap_aad) with the tag at the end; wrap_key is the user key's \
             \"kemlock/v1/item-wrap\" child.",
            cases,
        ))
    })
}

fn manifest_doc() -> Result<Value, Error> {
    seeded("manifest", || {
        let signing_bytes: [u8; 64] = rnd()?;
        let signing = sig1::SigningKey::from_bytes(&signing_bytes);
        let public = sig1::public_key_in::<G>(&signing)?;

        let owner = Owner::user(rnd()?);
        let first: [u8; 16] = rnd()?;
        let second: [u8; 16] = rnd()?;
        let third: [u8; 16] = rnd()?;
        let cipher_a: [u8; 40] = rnd()?;
        let cipher_b: [u8; 64] = rnd()?;
        // Given in this order; the encoding sorts them by item id.
        let entries = vec![
            Entry::live(first, 3, &cipher_a),
            Entry::tombstone(second, 5),
            Entry::live(third, 1, &cipher_b),
        ];
        let ciphertexts: [Option<&[u8]>; 3] = [Some(&cipher_a), None, Some(&cipher_b)];

        let mut cases = Vec::new();
        for (name, counter, entries, ciphertexts) in [
            ("three-items", 7u64, entries, ciphertexts.to_vec()),
            ("empty", 0u64, Vec::new(), Vec::new()),
        ] {
            let manifest = Manifest {
                owner,
                counter,
                entries: entries.clone(),
            };
            let bytes = manifest.to_bytes()?;
            let signature = sig1::sign_in::<G>(&signing, MANIFEST, &bytes)?;
            let listed: Vec<Value> = entries
                .iter()
                .zip(ciphertexts.iter())
                .map(|(entry, ciphertext)| {
                    json!({
                        "item_id": hx(&entry.item_id),
                        "revision": entry.revision,
                        "ciphertext": ciphertext.map(hx),
                        "ciphertext_hash": hx(&entry.ciphertext_hash),
                        "deleted": entry.deleted,
                    })
                })
                .collect();
            cases.push(json!({
                "name": name,
                "owner": hx(&owner.to_bytes()),
                "counter": counter,
                "entries": listed,
                "manifest": hx(&bytes),
                "signing_private_key": hx(&signing_bytes),
                "signing_public_key": hx(public.as_bytes()),
                "signature": hx(&signature),
            }));
        }
        Ok(document(
            "manifest",
            "manifest = \"kemlock/v1/manifest\" || owner || u64be(counter) || u32be(n) || n x \
             (item_id || u64be(revision) || SHA-256(ciphertext) || u8(deleted)), entries sorted by \
             item_id bytes (entries here are listed unsorted), a tombstone's hash is 32 zero \
             bytes; signature = sig1 signature under context \"manifest\".",
            cases,
        ))
    })
}

fn dedup_doc() -> Result<Value, Error> {
    seeded("dedup", || {
        let mut cases = Vec::new();
        let tag_inputs: Vec<(&str, Vec<&str>)> = vec![
            (dedup::name::CRED, vec!["example.com", "alice", "hunter2"]),
            (dedup::name::ACCOUNT, vec!["example.com", "alice"]),
            (dedup::name::SECRET, vec!["JBSWY3DPEHPK3PXP"]),
            (
                dedup::name::PASSKEY,
                vec!["example.com", "dGVzdC1jcmVkZW50aWFs"],
            ),
            (dedup::name::CARD, vec!["4111111111111111", "2030-12"]),
            (dedup::name::NOTE, vec!["line one\nline two"]),
            (dedup::name::KEY, vec!["SHA256:abcdef"]),
            (dedup::name::CODES, vec!["11111111", "22222222", "33333333"]),
            // RFC 8785 string escaping: quote, backslash, control characters, non-ASCII, slash.
            (
                dedup::name::CRED,
                vec![
                    "ex\"ample\\.com",
                    "\u{1}\t\u{1f}",
                    "caf\u{e9} \u{1f600} a/b \u{2028}",
                ],
            ),
        ];
        for (name, is_space, key_version) in [
            ("user-vault-key-version-1", false, 1u32),
            ("space-key-version-2", true, 2u32),
        ] {
            let owner_key_bytes: [u8; 32] = rnd()?;
            let owner_id: [u8; 16] = rnd()?;
            let owner = if is_space {
                Owner::space(owner_id)
            } else {
                Owner::user(owner_id)
            };
            let key = dedup::dedup_key_in::<G>(
                &SecretKey::from_bytes(&owner_key_bytes),
                &owner,
                key_version,
            )?;
            let mut tags = Vec::new();
            for (tag_name, values) in &tag_inputs {
                let input = dedup::canonical_input(tag_name, values);
                tags.push(json!({
                    "name": tag_name,
                    "values": values,
                    "canonical_input": String::from_utf8_lossy(&input),
                    "canonical_input_hex": hx(&input),
                    "tag": hx(&G::hmac_sha256(key.as_bytes(), &input)),
                }));
            }
            cases.push(json!({
                "name": name,
                "owner_key": hx(&owner_key_bytes),
                "owner": hx(&owner.to_bytes()),
                "key_version": key_version,
                "dedup_key": hx(key.as_bytes()),
                "tags": tags,
            }));
        }
        Ok(document(
            "dedup",
            "dedup_key = HKDF-SHA256(ikm = owner_key, salt = absent, info = \"kemlock dedup v1\" \
             || owner || u32be(key_version), L = 32); tag = HMAC-SHA256(dedup_key, \
             canonical_input), where canonical_input is the JSON array [name, value, ...] as RFC \
             8785 text without whitespace. Values are taken as already normalised.",
            cases,
        ))
    })
}

fn server_seal_doc() -> Result<Value, Error> {
    seeded("server-seal", || {
        let server_key: [u8; 32] = rnd()?;
        let mut cases = Vec::new();
        for (purpose, value_len) in [
            ("totp", 20usize),
            ("opaque-setup", 128usize),
            ("token-signing-key", 32usize),
            ("smtp-password", 0usize),
        ] {
            let value_full: [u8; 128] = rnd()?;
            let value = &value_full[..value_len];
            let sealed = seal::seal_in::<G>(&server_key, purpose, value)?;
            cases.push(json!({
                "name": purpose,
                "server_key": hx(&server_key),
                "purpose": purpose,
                "value": hx(value),
                "sealed": hx(&sealed),
            }));
        }
        Ok(document(
            "server-seal",
            "sealed = u8(1) || nonce(12) || AES-256-GCM(key, nonce, value, aad = lp(purpose)) \
             with the 16-byte tag at the end, key = HKDF-SHA256(ikm = server_key, salt = absent, \
             info = \"kemlock/v1/server-seal\" || lp(purpose), L = 32). Another purpose must not \
             open it.",
            cases,
        ))
    })
}

/// A random 32-byte scalar below 2^252, so it is canonical in ristretto255.
fn scalar() -> Result<[u8; 32], Error> {
    let mut bytes: [u8; 32] = rnd()?;
    bytes[31] &= 0x0f;
    Ok(bytes)
}

/// The 64 bytes `opaque-ke` draws for a blinding scalar: the scalar then 32 zero bytes.
fn wide(scalar: &[u8; 32]) -> Vec<u8> {
    let mut out = scalar.to_vec();
    out.extend_from_slice(&[0u8; 32]);
    out
}

fn opaque_doc() -> Result<Value, Error> {
    seeded("opaque", || {
        let server = OpaqueServer::generate();
        let setup = server.to_bytes();
        let credential_id = opaque::credential_id("Alice@Example.com");
        let password: [u8; 32] = rnd()?;

        let blind_registration = scalar()?;
        let envelope_nonce: [u8; 32] = rnd()?;
        let blind_login = scalar()?;
        let client_keyshare_seed: [u8; 32] = rnd()?;
        let client_nonce: [u8; 32] = rnd()?;
        let dummy_masking_key: [u8; 64] = rnd()?;
        let masking_nonce: [u8; 32] = rnd()?;
        let server_keyshare_seed: [u8; 32] = rnd()?;
        let server_nonce: [u8; 32] = rnd()?;

        let (state, request) = opaque::client_registration_start_with(
            &mut ScriptedRng::new(vec![wide(&blind_registration)]),
            &password,
        )?;
        let response = server.registration_response(&credential_id, &request)?;
        let (upload, registration_export) = opaque::client_registration_finish_with(
            &mut ScriptedRng::new(vec![envelope_nonce.to_vec()]),
            state,
            &password,
            &response,
        )?;
        let record = OpaqueServer::registration_record(&upload)?;

        let (client, ke1) = opaque::client_login_start_with(
            &mut ScriptedRng::new(vec![
                wide(&blind_login),
                client_keyshare_seed.to_vec(),
                client_nonce.to_vec(),
            ]),
            &password,
        )?;
        let (server_state, ke2) = server.login_start_with(
            &mut ScriptedRng::new(vec![
                dummy_masking_key.to_vec(),
                masking_nonce.to_vec(),
                server_keyshare_seed.to_vec(),
                server_nonce.to_vec(),
            ]),
            opaque::CONTEXT,
            &credential_id,
            Some(&record),
            &ke1,
        )?;
        let (ke3, client_session, login_export) = opaque::client_login_finish_with(
            &mut ScriptedRng::new(Vec::new()),
            opaque::CONTEXT,
            client,
            &password,
            &ke2,
        )?;
        let server_session = OpaqueServer::login_finish_with(opaque::CONTEXT, &server_state, &ke3)?;

        let case = json!({
            "name": "alice",
            "server_setup": hx(&setup),
            "oprf_seed": hx(&setup[..64]),
            "server_private_key": hx(&setup[64..96]),
            "server_public_key": hx(&response[32..64]),
            "credential_identifier_text": "alice@example.com",
            "credential_identifier": hx(&credential_id),
            "context_text": "kemlock/v1/opaque",
            "context": hx(opaque::CONTEXT),
            "password": hx(&password),
            "random_inputs": {
                "blind_registration": hx(&blind_registration),
                "envelope_nonce": hx(&envelope_nonce),
                "blind_login": hx(&blind_login),
                "client_keyshare_seed": hx(&client_keyshare_seed),
                "client_nonce": hx(&client_nonce),
                "masking_nonce": hx(&masking_nonce),
                "server_keyshare_seed": hx(&server_keyshare_seed),
                "server_nonce": hx(&server_nonce),
            },
            "registration": {
                "request": hx(&request),
                "response": hx(&response),
                "upload": hx(&upload),
                "record": hx(&record),
                "export_key": hx(&registration_export),
            },
            "login": {
                "ke1": hx(&ke1),
                "ke2": hx(&ke2),
                "ke3": hx(&ke3),
                "client_session_key": hx(&client_session),
                "server_session_key": hx(&server_session),
                "export_key": hx(&login_export),
            },
        });
        Ok(document(
            "opaque1",
            "OPAQUE-3DH (RFC 9807) with ristretto255-SHA512, KSF Identity, HKDF-SHA512, \
             HMAC-SHA512, context \"kemlock/v1/opaque\", no client or server identity, the \
             lower-cased e-mail as credential identifier and the 32-byte Argon2id master key as \
             the password. server_setup = oprf_seed (64) || server_private_key (32) || a dummy \
             public key (32). random_inputs are the values opaque-ke draws, in the order of the \
             RFC 9807 appendix C vectors: blind scalars are 32-byte little-endian scalars below \
             2^252 (opaque-ke reads them as a 64-byte draw followed by 32 zero bytes), and the \
             server also draws a 64-byte dummy masking key first (ignored for a real record). \
             Messages: registration request 32, response 64, upload and record 192; KE1 96, KE2 \
             320, KE3 64.",
            vec![case],
        ))
    })
}

fn legacy_ids_doc() -> Result<Value, Error> {
    seeded("legacy-ids", || {
        let mut cases = Vec::new();
        for old in ["acc-1", "svc-1", "3f2c9a71e4b0d856", "team_Alpha-01"] {
            let id = crate::legacy_id::space_uuid_in::<G>(old);
            cases.push(json!({
                "type": "space",
                "old": old,
                "uuid": hx(&id),
                "uuid_text": uuid_text(&id),
            }));
        }
        let space = Owner::space(crate::legacy_id::space_uuid_in::<G>("team_Alpha-01"));
        let user = Owner::user([0x11; 16]);
        for (label, owner) in [("mapped-space", space), ("user", user)] {
            for old in ["item-1", "3f2c9a71e4b0d856"] {
                let id = crate::legacy_id::item_uuid_in::<G>(&owner.to_bytes(), old);
                cases.push(json!({
                    "type": "item",
                    "owner_label": label,
                    "owner": hx(&owner.to_bytes()),
                    "old": old,
                    "uuid": hx(&id),
                    "uuid_text": uuid_text(&id),
                }));
            }
        }
        for input in [
            "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b",
            "0190A1B2-C3D4-8E5F-9A0B-1C2D3E4F5A6B",
            "3f2c9a71e4b0d856",
            "acc-1",
            "",
        ] {
            cases.push(json!({
                "type": "is_uuid",
                "input": input,
                "is_uuid": legacy_id::is_uuid(input),
            }));
        }
        Ok(document(
            "legacy-ids",
            "space uuid = uuidv8(SHA-256(\"kemlock/v1/legacy-id\" || lp(\"space\") || lp(old))); \
             item uuid = uuidv8(SHA-256(\"kemlock/v1/legacy-id\" || lp(\"item\") || owner || \
             lp(old))); uuidv8 takes the first 16 bytes and sets b[6] = b[6] & 0x0f | 0x80 and \
             b[8] = b[8] & 0x3f | 0x80. Old ids are UTF-8 bytes. An id that already is a \
             hyphenated lower-case UUID is never mapped (is_uuid).",
            cases,
        ))
    })
}

fn dedup_normalise_doc() -> Result<Value, Error> {
    seeded("dedup-normalise", || {
        let key_bytes = normalise_cases::key_bytes();
        let key = SecretKey::from_bytes(&key_bytes);
        let mut cases = Vec::new();
        for case in normalise_cases::raw_cases() {
            let shared: Vec<String> = case.shared_hosts.iter().map(|h| (*h).to_owned()).collect();
            let inputs = normalise_cases::inputs(case.tag, &case.raw, &shared);
            let texts: Vec<String> = inputs
                .iter()
                .map(|i| String::from_utf8_lossy(i).into_owned())
                .collect();
            let hexes: Vec<Value> = inputs.iter().map(|i| hx(i)).collect();
            let tags: Vec<Value> = inputs
                .iter()
                .map(|i| hx(&G::hmac_sha256(key.as_bytes(), i)))
                .collect();
            let mut entry = json!({
                "name": case.name,
                "tag": case.tag,
                "raw": case.raw,
                "dedup_key": hx(&key_bytes),
                "canonical_inputs": texts,
                "canonical_inputs_hex": hexes,
                "tags": tags,
            });
            if !shared.is_empty() {
                entry["shared_hosts"] = json!(shared);
            }
            cases.push(entry);
        }
        Ok(document(
            "dedup-normalise",
            "Raw item values in, canonical inputs out (docs/crypto.md, Duplicate tags, \
             Normalisation). raw holds the values as the app stores them; for a login, websites \
             are {uri, rule} and shared_hosts the app's shared hosts. canonical_inputs are the \
             RFC 8785 arrays, one per site for a login (none when the item makes no tag); tags \
             are HMAC-SHA256(dedup_key, canonical input). The Public Suffix List is \
             test-vectors/public_suffix_list.dat.",
            cases,
        ))
    })
}

/// The 13-bit groups the phrase reads from a digest, most significant first: the first 65 bits.
fn phrase_groups(digest: &[u8; 32]) -> [u32; 5] {
    let mut groups = [0u32; 5];
    for (i, group) in groups.iter_mut().enumerate() {
        for j in 0..13 {
            let bit = 13 * i + j;
            *group = (*group << 1) | u32::from((digest[bit / 8] >> (7 - bit % 8)) & 1);
        }
    }
    groups
}

fn phrase_doc() -> Result<Value, Error> {
    use kemlock_domain::unlock::{PHRASE_LABEL, WORD_COUNT, phrase_from_digest, phrase_input};
    seeded("phrase", || {
        let generated = kx1::public_key_in::<G>(&kx1::PrivateKey::from_bytes(&rnd::<96>()?))?;
        let mut keys: Vec<(String, Vec<u8>)> = vec![
            ("zero-key".to_owned(), vec![0u8; kx1::PUBLIC_KEY_LEN]),
            ("ones-key".to_owned(), vec![0xff; kx1::PUBLIC_KEY_LEN]),
            (
                "counting-key".to_owned(),
                counting::<{ kx1::PUBLIC_KEY_LEN }>().to_vec(),
            ),
            (
                "generated-kx1-public-key".to_owned(),
                generated.as_bytes().to_vec(),
            ),
        ];
        for i in 1..=3 {
            keys.push((
                format!("random-key-{i}"),
                rnd::<{ kx1::PUBLIC_KEY_LEN }>()?.to_vec(),
            ));
        }
        // A key with a group of 7776 or more, so the modulus is pinned.
        let word_count = u32::try_from(WORD_COUNT).map_err(|_| Error::invalid())?;
        loop {
            let candidate = rnd::<{ kx1::PUBLIC_KEY_LEN }>()?;
            let digest = G::sha256(&phrase_input(&candidate));
            if phrase_groups(&digest).iter().any(|g| *g >= word_count) {
                keys.push(("a-group-wraps-the-list".to_owned(), candidate.to_vec()));
                break;
            }
        }
        let mut cases = Vec::new();
        for (name, public_key) in keys {
            let digest = G::sha256(&phrase_input(&public_key));
            let groups = phrase_groups(&digest);
            let indexes: Vec<u32> = groups.iter().map(|g| g % word_count).collect();
            cases.push(json!({
                "name": name,
                "public_key": hx(&public_key),
                "digest": hx(&digest),
                "groups": groups,
                "indexes": indexes,
                "phrase": phrase_from_digest(&digest),
            }));
        }
        Ok(document(
            "phrase",
            &format!(
                "The device-approval phrase (docs/crypto.md): digest = SHA-256(\"{}\" || the new \
                 device's one-time kx1 public key (1600)); groups are the first 65 bits of the \
                 digest as five 13-bit numbers, most significant first; index = group mod 7776; \
                 the words are the indexes into EFF's large word list \
                 (crates/kemlock-domain/src/unlock/eff_large_wordlist.txt), lower case, joined \
                 by single spaces.",
                String::from_utf8_lossy(PHRASE_LABEL)
            ),
            cases,
        ))
    })
}

fn private_keys_doc() -> Result<Value, Error> {
    seeded("private-keys", || {
        let mut cases = Vec::new();
        for (name, key_version) in [("key-version-1", 1u32), ("key-version-2", 2u32)] {
            let user_key: [u8; 32] = rnd()?;
            let account_id: [u8; 16] = rnd()?;
            let kx1_private: [u8; 96] = rnd()?;
            let sig1_private: [u8; 64] = rnd()?;
            let child = SecretKey::from_bytes(&user_key).child_in::<G>(PRIVATE_KEYS_LABEL)?;
            let sealed = private_keys::seal_in::<G>(
                &SecretKey::from_bytes(&user_key),
                &kx1::PrivateKey::from_bytes(&kx1_private),
                &sig1::SigningKey::from_bytes(&sig1_private),
                &account_id,
                key_version,
            )?;
            let mut plaintext = vec![1u8];
            plaintext.extend_from_slice(&kx1_private);
            plaintext.extend_from_slice(&sig1_private);
            cases.push(json!({
                "name": name,
                "user_key": hx(&user_key),
                "child_label": PRIVATE_KEYS_LABEL,
                "child_key": hx(child.as_bytes()),
                "account_id": hx(&account_id),
                "key_version": key_version,
                "kx1_private_key": hx(&kx1_private),
                "sig1_private_key": hx(&sig1_private),
                "plaintext": hx(&plaintext),
                "aad": hx(&private_keys::aad(&account_id, key_version)),
                "sealed": hx(&sealed),
            }));
        }
        Ok(document(
            "private-keys",
            "The account's sealed private keys (docs/crypto.md): child_key = HKDF-SHA256(ikm = \
             user_key, salt = absent, info = child_label, L = 32); plaintext = u8(1) || kx1 \
             private key (96) || sig1 private key (64); aad = \"kemlock/v1/private-keys\" || \
             account_id || u32be(key_version); sealed = nonce(12) || AES-256-GCM(child_key, \
             nonce, plaintext, aad) with the 16-byte tag at the end (189 bytes).",
            cases,
        ))
    })
}

fn prf_wrap_doc() -> Result<Value, Error> {
    seeded("prf-wrap", || {
        let mut cases = Vec::new();
        for (name, key_version, credential_len) in [
            ("short-credential-id", 1u32, 16usize),
            ("long-credential-id", 2u32, 77usize),
        ] {
            let prf_output: [u8; 32] = rnd()?;
            let mut credential_id = vec![0u8; credential_len];
            for chunk in credential_id.chunks_mut(32) {
                let bytes: [u8; 32] = rnd()?;
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            let root_key: [u8; 64] = rnd()?;
            let account_id: [u8; 16] = rnd()?;
            let wrap_key = prf_wrap::wrap_key_in::<G>(&prf_output, &credential_id)?;
            let wrapped = prf_wrap::seal_in::<G>(
                &prf_output,
                &credential_id,
                &RootKey::from_bytes(&root_key),
                &account_id,
                key_version,
            )?;
            cases.push(json!({
                "name": name,
                "prf_salt": hx(&prf_wrap::prf_salt_in::<G>()),
                "prf_output": hx(&prf_output),
                "credential_id": hx(&credential_id),
                "root_key": hx(&root_key),
                "account_id": hx(&account_id),
                "key_version": key_version,
                "wrap_key": hx(wrap_key.as_bytes()),
                "aad": hx(&prf_wrap::aad(&account_id, key_version, &credential_id)?),
                "wrapped": hx(&wrapped),
            }));
        }
        Ok(document(
            "prf-wrap",
            "The passkey PRF wrap of the root key (docs/crypto.md). prf_salt is \
             SHA-256(\"kemlock/v1/prf-salt\"), the `first` input of the PRF extension. wrap_key = \
             HKDF-SHA256(ikm = prf_output, salt = absent, info = \"kemlock/v1/prf-wrap\" || \
             lp(credential_id), L = 32); aad = \"kemlock/v1/root-wrap/prf\" || account_id || \
             u32be(key_version) || lp(credential_id); wrapped = nonce(12) || \
             AES-256-GCM(wrap_key, nonce, root_key, aad) with the 16-byte tag at the end.",
            cases,
        ))
    })
}

fn confirm_doc() -> Result<Value, Error> {
    seeded("confirm", || {
        let mut cases = Vec::new();
        for (name, key_version) in [("key-version-1", 1u32), ("key-version-2", 2u32)] {
            let space: [u8; 16] = rnd()?;
            let member: [u8; 16] = rnd()?;
            let confirmer: [u8; 16] = rnd()?;
            // The member's bundle, whose fingerprint the confirmer compared.
            let member_kx1_private: [u8; 96] = rnd()?;
            let member_sig1_private: [u8; 64] = rnd()?;
            let member_bundle = Bundle {
                account_id: member,
                key_version,
                kx1_public: kx1::public_key_in::<G>(&kx1::PrivateKey::from_bytes(
                    &member_kx1_private,
                ))?,
                sig1_public: sig1::public_key_in::<G>(&sig1::SigningKey::from_bytes(
                    &member_sig1_private,
                ))?,
            }
            .to_bytes();
            let fingerprint = bundle::fingerprint_in::<G>(&member_bundle);

            let confirmer_private: [u8; 64] = rnd()?;
            let signing = sig1::SigningKey::from_bytes(&confirmer_private);
            let confirmer_public = sig1::public_key_in::<G>(&signing)?;

            let statement = Statement {
                space,
                member,
                member_key_version: key_version,
                fingerprint: &fingerprint,
                confirmer,
            };
            let bytes = statement.to_bytes();
            let signature = sig1::sign_in::<G>(&signing, CONFIRM, &bytes)?;

            // Statements that differ from the real one in a single field: the signature covers
            // none of them.
            let mut other_space = space;
            other_space[0] ^= 1;
            let mut other_member = member;
            other_member[0] ^= 1;
            let mut other_fingerprint = fingerprint;
            other_fingerprint[0] ^= 1;
            let mut other_confirmer = confirmer;
            other_confirmer[0] ^= 1;
            let changed: Vec<Value> = [
                (
                    "another-space",
                    Statement {
                        space: other_space,
                        ..statement
                    },
                ),
                (
                    "another-member",
                    Statement {
                        member: other_member,
                        ..statement
                    },
                ),
                (
                    "another-key-version",
                    Statement {
                        member_key_version: key_version + 1,
                        ..statement
                    },
                ),
                (
                    "another-fingerprint",
                    Statement {
                        fingerprint: &other_fingerprint,
                        ..statement
                    },
                ),
                (
                    "another-confirmer",
                    Statement {
                        confirmer: other_confirmer,
                        ..statement
                    },
                ),
            ]
            .into_iter()
            .map(|(what, s)| json!({ "name": what, "statement": hx(&s.to_bytes()) }))
            .collect();

            cases.push(json!({
                "name": name,
                "space": hx(&space),
                "member": hx(&member),
                "member_key_version": key_version,
                "member_bundle": hx(&member_bundle),
                "fingerprint": hx(&fingerprint),
                "confirmer": hx(&confirmer),
                "confirmer_private_key": hx(&confirmer_private),
                "confirmer_public_key": hx(confirmer_public.as_bytes()),
                "statement": hx(&bytes),
                "signature": hx(&signature),
                "wrong_contexts": [BUNDLE, MANIFEST],
                "changed_statements": changed,
            }));
        }
        Ok(document(
            "confirm",
            "Member confirmation (docs/crypto.md): statement = \"kemlock/v1/confirm\" || space \
             id (16) || member id (16) || u32be(member key version) || fingerprint (64) || \
             confirmer id (16), 134 bytes; fingerprint = SHA-512(\"kemlock/v1/fingerprint\" || \
             member_bundle) as in bundle.json; signature = sig1 signature of the confirmer's own \
             key under context \"confirm\" over the statement (3373 bytes). The signature must \
             not verify under a wrong context or over any changed statement.",
            cases,
        ))
    })
}

fn key_box_doc() -> Result<Value, Error> {
    seeded("key-box", || {
        let mut cases = Vec::new();
        for (name, kind) in [
            ("space-key", KeyBoxKind::Space),
            ("collection-key", KeyBoxKind::Collection),
        ] {
            let space: [u8; 16] = rnd()?;
            let collection: [u8; 16] = rnd()?;
            let recipient: [u8; 16] = rnd()?;
            let sealer: [u8; 16] = rnd()?;
            let key_version = 2u32;
            let sealer_key_version = 3u32;

            // A real box of a random key, to a recipient key made for the case.
            let recipient_private: [u8; 96] = rnd()?;
            let recipient_public =
                kx1::public_key_in::<G>(&kx1::PrivateKey::from_bytes(&recipient_private))?;
            let secret: [u8; 32] = rnd()?;
            let aad = match kind {
                KeyBoxKind::Space => key_box::space_aad(&space, key_version, &recipient),
                KeyBoxKind::Collection => {
                    key_box::collection_aad(&space, &collection, key_version, &recipient)
                }
            };
            let sealed =
                sealed_box::seal_in::<G>(&recipient_public, kind.context(), &aad, &secret)?;

            let sealer_private: [u8; 64] = rnd()?;
            let signing = sig1::SigningKey::from_bytes(&sealer_private);
            let sealer_public = sig1::public_key_in::<G>(&signing)?;

            let statement = KeyBoxStatement {
                kind,
                aad: &aad,
                sealed_box: &sealed,
                sealer,
                sealer_key_version,
            };
            let bytes = statement.to_bytes()?;
            let signature = sig1::sign_in::<G>(&signing, KEY_BOX, &bytes)?;

            // Statements that differ from the real one in one field: the signature covers none.
            let mut other_box = sealed.clone();
            other_box[700] ^= 1;
            let mut other_recipient = recipient;
            other_recipient[0] ^= 1;
            let other_aad = match kind {
                KeyBoxKind::Space => key_box::space_aad(&space, key_version, &other_recipient),
                KeyBoxKind::Collection => {
                    key_box::collection_aad(&space, &collection, key_version, &other_recipient)
                }
            };
            let later_aad = match kind {
                KeyBoxKind::Space => key_box::space_aad(&space, key_version + 1, &recipient),
                KeyBoxKind::Collection => {
                    key_box::collection_aad(&space, &collection, key_version + 1, &recipient)
                }
            };
            let mut other_sealer = sealer;
            other_sealer[0] ^= 1;
            let changed: Vec<Value> = [
                (
                    "another-box",
                    KeyBoxStatement {
                        sealed_box: &other_box,
                        ..statement
                    },
                ),
                (
                    "another-recipient",
                    KeyBoxStatement {
                        aad: &other_aad,
                        ..statement
                    },
                ),
                (
                    "another-key-version",
                    KeyBoxStatement {
                        aad: &later_aad,
                        ..statement
                    },
                ),
                (
                    "another-sealer",
                    KeyBoxStatement {
                        sealer: other_sealer,
                        ..statement
                    },
                ),
                (
                    "another-sealer-key-version",
                    KeyBoxStatement {
                        sealer_key_version: sealer_key_version + 1,
                        ..statement
                    },
                ),
            ]
            .into_iter()
            .map(|(what, s)| -> Result<Value, Error> {
                Ok(json!({ "name": what, "statement": hx(&s.to_bytes()?) }))
            })
            .collect::<Result<_, Error>>()?;

            cases.push(json!({
                "name": name,
                "context": kind.context(),
                "space": hx(&space),
                "collection": (kind == KeyBoxKind::Collection).then(|| hx(&collection)),
                "key_version": key_version,
                "recipient": hx(&recipient),
                "recipient_private_key": hx(&recipient_private),
                "secret": hx(&secret),
                "aad": hx(&aad),
                "box": hx(&sealed),
                "sealer": hx(&sealer),
                "sealer_key_version": sealer_key_version,
                "sealer_private_key": hx(&sealer_private),
                "sealer_public_key": hx(sealer_public.as_bytes()),
                "statement": hx(&bytes),
                "signature": hx(&signature),
                "wrong_contexts": [BUNDLE, MANIFEST, CONFIRM],
                "changed_statements": changed,
            }));
        }
        Ok(document(
            "key-box",
            "Signed key boxes (docs/crypto.md): statement = \"kemlock/v1/key-box\" || \
             lp(context) || lp(aad) || lp(box) || sealer id (16) || u32be(sealer key version), \
             where context is \"space-key\" or \"collection-key\", aad is that box's aad as in \
             sealed-box.json and box is the 1661-byte sealed box of `secret` to the recipient \
             key of `recipient_private_key`; signature = sig1 signature of the sealer's own key \
             under context \"key-box\" over the statement (3373 bytes). The signature must not \
             verify under a wrong context or over any changed statement. `collection` is null \
             for a space key.",
            cases,
        ))
    })
}

/// A version 4 UUID from random bytes.
fn uuid_v4(mut id: [u8; 16]) -> [u8; 16] {
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

/// What one Send vector is made of.
struct SendCase {
    name: &'static str,
    kind: send::Kind,
    payload_json: &'static str,
    meta_json: &'static str,
    key_version: u32,
    /// The password as typed, when the Send has one.
    password: Option<&'static str>,
    /// The file's plaintext, for a file Send.
    file: Option<&'static [u8]>,
}

fn send_doc() -> Result<Value, Error> {
    seeded("send", || {
        let inputs = [
            SendCase {
                name: "note",
                kind: send::Kind::Text,
                payload_json: r#"{"name":"Wi-Fi","text":"the password is on the fridge"}"#,
                meta_json: r#"{"name":"Wi-Fi","notes":"for the guests"}"#,
                key_version: 1,
                password: None,
                file: None,
            },
            SendCase {
                name: "note-with-a-password",
                kind: send::Kind::Text,
                payload_json: r#"{"name":"Wi-Fi","text":"café"}"#,
                meta_json: r#"{"name":"Wi-Fi","notes":""}"#,
                key_version: 2,
                password: Some("correct horse battery staple"),
                file: None,
            },
            SendCase {
                name: "file-with-a-decomposed-password",
                kind: send::Kind::File,
                payload_json: r#"{"name":"hello.txt","mime":"text/plain","size":27}"#,
                meta_json: r#"{"name":"hello.txt","notes":"sent to Ann"}"#,
                key_version: 1,
                password: Some("cafe\u{301}"),
                file: Some(b"Kemlock attachment fixture\n"),
            },
        ];
        let mut cases = Vec::new();
        for input in inputs {
            let kind = input.kind;
            let send_id = uuid_v4(rnd()?);
            let link_key = SecretKey::from_bytes(&rnd()?);
            let wrap_key = SecretKey::from_bytes(&rnd()?);
            let payload_key = send::payload_key(&link_key)?;
            let meta_key = send::meta_key_in::<G>(&wrap_key, &send_id, input.key_version)?;
            let payload = send::seal_payload_in::<G>(
                &link_key,
                &send_id,
                kind,
                input.payload_json.as_bytes(),
            )?;
            let meta = send::seal_meta_in::<G>(
                &wrap_key,
                &send_id,
                input.key_version,
                kind,
                input.meta_json.as_bytes(),
            )?;
            let sealed_key =
                send::wrap_link_key_in::<G>(&wrap_key, &link_key, &send_id, input.key_version)?;
            let access_id = b64url(&send_id);
            let link = format!(
                "https://example.org/#/send/{access_id}/{}",
                b64url(link_key.as_bytes())
            );
            let mut case = json!({
                "name": input.name,
                "kind": kind.as_str(),
                "send_id": hx(&send_id),
                "access_id": access_id,
                "link_key": hx(link_key.as_bytes()),
                "link": link,
                "payload_key": hx(payload_key.as_bytes()),
                "meta_key": hx(meta_key.as_bytes()),
                "payload_json": input.payload_json,
                "payload_aad": hx(&send::aad(send::PAYLOAD_LABEL, &send_id, kind)?),
                "payload": hx(&payload),
                "meta_json": input.meta_json,
                "meta_aad": hx(&send::aad(send::META_LABEL, &send_id, kind)?),
                "meta": hx(&meta),
                "wrap_key": hx(wrap_key.as_bytes()),
                "key_version": input.key_version,
                "key_aad": hx(&send::key_aad(&send_id, input.key_version)),
                "sealed_key": hx(&sealed_key),
                "proof_salt": hx(&send::proof_salt_in::<G>(&link_key, &send_id)?),
            });
            if let Some(typed) = input.password {
                let proof = send::password_proof_in::<G>(&link_key, &send_id, typed)?;
                case["password"] = json!(typed);
                case["password_nfc"] = json!(crate::dedup::normalise::nfc(typed));
                case["proof"] = hx(proof.as_slice());
            }
            if let Some(plain) = input.file {
                case["file_plain"] = hx(plain);
                case["file"] = hx(&kma1::seal_in::<G>(&payload_key, plain)?);
            }
            cases.push(case);
        }
        Ok(document(
            "send",
            "Sends (docs/crypto.md): payload_key = HKDF-SHA256(link_key, salt = absent, info = \
             \"kemlock/v1/send-payload\", L = 32); meta_key = HKDF-SHA256(wrap_key, salt = \
             absent, info = \"kemlock/v1/send-meta\" || send_id || u32be(key_version), L = 32), \
             from the owner's item-wrap key and never from link_key; proof_salt = \
             HKDF-SHA256(link_key, salt = absent, info = \
             \"kemlock/v1/send-proof\" || send_id, L = 16); payload_aad = \
             \"kemlock/v1/send-payload\" || send_id || lp(kind) and meta_aad likewise with \
             \"kemlock/v1/send-meta\"; payload and meta = nonce(12) || AES-256-GCM(key, nonce, \
             JSON, aad) with the 16-byte tag at the end; sealed_key = u32be(key_version) || \
             nonce(12) || AES-256-GCM(wrap_key, nonce, link_key, key_aad) with the tag at the \
             end, key_aad = \"kemlock/v1/send-key\" || send_id || u32be(key_version) (64 \
             bytes); proof = Argon2id(NFC password, proof_salt, m = 19456 KiB, t = 2, p = 1, \
             L = 32); file = the KMA1 file of file_plain under payload_key, and a file Send's \
             payload_json names it and gives its plaintext size. access_id is the base64url of \
             send_id, and link is the Send's link.",
            cases,
        ))
    })
}

/// The label of the space key's child that encrypts names (`docs/crypto.md`).
const SPACE_NAME_LABEL: &str = "kemlock/v1/space-name";

fn space_names_doc() -> Result<Value, Error> {
    seeded("space-names", || {
        let space: [u8; 16] = [0x51; 16];
        let collection: [u8; 16] = [0xC0; 16];
        let group: [u8; 16] = [0x60; 16];
        let owner = Owner::space(space);
        let first_key: [u8; 32] = counting();
        let second_key: [u8; 32] = [0xA5; 32];
        let mut cases = Vec::new();
        // (case, space key, id, kind, space key version, the name). The second case renames the
        // first under the same key version: a fresh nonce, the same key.
        for (case, space_key_bytes, id, kind, key_version, text) in [
            ("space-name", first_key, space, "space-name", 1u32, "Family"),
            (
                "space-name-renamed",
                first_key,
                space,
                "space-name",
                1,
                "Family Home",
            ),
            (
                "collection-name",
                first_key,
                collection,
                "collection-name",
                1,
                "Shared logins",
            ),
            ("group-name", first_key, group, "group-name", 1, "Parents"),
            (
                "collection-name-key-version-2",
                second_key,
                collection,
                "collection-name",
                2,
                "Caf\u{e9} \u{1f511}",
            ),
        ] {
            let space_key = SecretKey::from_bytes(&space_key_bytes);
            let name_key = space_key.child_in::<G>(SPACE_NAME_LABEL)?;
            let aad = kem1::item_aad(&id, u64::from(key_version), kind, &owner)?;
            let ciphertext = kem1::seal_item_in::<G>(
                &name_key,
                &id,
                u64::from(key_version),
                kind,
                &owner,
                text.as_bytes(),
            )?;
            cases.push(json!({
                "name": case,
                "space_key": hx(&space_key_bytes),
                "name_key": hx(name_key.as_bytes()),
                "space_id": hx(&space),
                "owner": hx(&owner.to_bytes()),
                "id": hx(&id),
                "kind": kind,
                "key_version": key_version,
                "text": text,
                "aad": hx(&aad),
                "ciphertext": hx(&ciphertext),
            }));
        }
        Ok(document(
            "space-names",
            "The name of a space, a collection or a group is a kem1 envelope under the space \
             key's child: name_key = HKDF-SHA256(space_key, salt = absent, info = \
             \"kemlock/v1/space-name\", L = 32); ciphertext = nonce(12) || AES-256-GCM(name_key, \
             nonce, text as UTF-8, aad) with the 16-byte tag at the end; aad = \
             \"kemlock/v1/item\" || id || u64be(key_version) || lp(kind) || owner, where id is \
             the object's own id (space_id for the space's name), kind is \"space-name\", \
             \"collection-name\" or \"group-name\", owner is 0x02 || space_id and key_version is \
             the space key version. There is no item-key wrap: name_key is the item key. A name \
             must not open under another space, id, kind, key version or owner.",
            cases,
        ))
    })
}
