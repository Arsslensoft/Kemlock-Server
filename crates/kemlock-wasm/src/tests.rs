//! WebAssembly tests: they run in node (`wasm-pack test --node crates/kemlock-wasm`), through the
//! same code the worker calls, on the RustCrypto backend that is the only one in a wasm build.
//!
//! Each file in `test-vectors/` that the web vault touches is embedded at build time and checked:
//! the Argon2id master key, the password wrap, the account key chain, `kem1` items, the `kx1`,
//! `sig1` and sealed-box primitives, and the bundle with its fingerprint and signature. OPAQUE is
//! run end to end against `kemlock-crypto`'s server half (its RFC 9807 vectors are checked
//! natively, where the random inputs can be fixed).

use kemlock_crypto::{
    argon2id,
    bundle::Bundle,
    kem1,
    keys::{ITEM_WRAP_LABEL, RootKey, SecretKey},
    kx1,
    opaque::{self, OpaqueServer},
    owner::Owner,
    password_wrap, private_keys, sealed_box, sig1,
};
use kemlock_crypto::space_chain::KeyRef;
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    b64, chain,
    error::Error,
    ids,
    session::{self, FIRST_KEY_VERSION, SealedItemRef, Session},
    sharing,
    spaces::NameKind,
};

const ACCOUNT_KEYS: &str = include_str!("../../../test-vectors/account-keys.json");
const ARGON2ID: &str = include_str!("../../../test-vectors/argon2id.json");
const BUNDLE: &str = include_str!("../../../test-vectors/bundle.json");
const KEM1: &str = include_str!("../../../test-vectors/kem1.json");
const KX1: &str = include_str!("../../../test-vectors/kx1.json");
const PASSWORD_WRAP: &str = include_str!("../../../test-vectors/password-wrap.json");
const SEALED_BOX: &str = include_str!("../../../test-vectors/sealed-box.json");
const SIG1: &str = include_str!("../../../test-vectors/sig1.json");

fn cases(file: &str) -> Vec<Value> {
    let doc: Value = serde_json::from_str(file).expect("a vector file is JSON");
    doc["cases"].as_array().expect("cases").clone()
}

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a string"))
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(text(case, field)).expect("hex")
}

fn array<const N: usize>(case: &Value, field: &str) -> [u8; N] {
    bytes(case, field)
        .try_into()
        .unwrap_or_else(|_| panic!("{field} has {N} bytes"))
}

fn number(case: &Value, field: &str) -> u64 {
    case[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} is a number"))
}

fn small(case: &Value, field: &str) -> u32 {
    u32::try_from(number(case, field)).expect("fits u32")
}

/// A session unlocked with `root`, under a made-up master key and export key.
fn unlocked_with(root: &RootKey, account_id: &[u8; 16], key_version: u32) -> Session {
    let (master, export) = ([1u8; 32], [2u8; 64]);
    let wrapped =
        password_wrap::seal(&master, &export, root, account_id, key_version).expect("wrap");
    let mut session = Session::new();
    let m = session.insert_master(master).expect("handle");
    let e = session.insert_export(export).expect("handle");
    session
        .unlock(account_id, &wrapped, m, e, key_version, None)
        .expect("unlock");
    session
}

#[wasm_bindgen_test]
fn argon2id_matches_the_vectors() {
    for case in cases(ARGON2ID) {
        let key = argon2id::master_key(
            &bytes(&case, "password"),
            &bytes(&case, "salt"),
            small(&case, "memory_kib"),
            small(&case, "iterations"),
            small(&case, "parallelism"),
        )
        .expect("argon2id");
        assert_eq!(
            key.to_vec(),
            bytes(&case, "master_key"),
            "{}",
            text(&case, "name")
        );
    }
}

#[wasm_bindgen_test]
fn the_account_key_chain_matches_the_vectors() {
    for case in cases(ACCOUNT_KEYS) {
        let user = RootKey::from_bytes(&array(&case, "root_key"))
            .user_key()
            .expect("user key");
        assert_eq!(user.as_bytes().to_vec(), bytes(&case, "user_key"));
        for child in case["children"].as_array().expect("children") {
            let key = user.child(text(child, "label")).expect("child");
            assert_eq!(key.as_bytes().to_vec(), bytes(child, "key"));
        }
    }
}

#[wasm_bindgen_test]
fn the_password_wrap_opens_through_unlock() {
    for case in cases(PASSWORD_WRAP) {
        let account: [u8; 16] = array(&case, "account_id");
        let version = small(&case, "key_version");
        let wrapped = bytes(&case, "wrapped");
        let root = RootKey::from_bytes(&array(&case, "root_key"));

        let opened = password_wrap::open(
            &array(&case, "master_key"),
            &array(&case, "export_key"),
            &wrapped,
            &account,
            version,
        )
        .expect("the vector opens");
        assert_eq!(opened.as_bytes(), root.as_bytes());

        let mut session = Session::new();
        let master = session
            .insert_master(array(&case, "master_key"))
            .expect("handle");
        let export = session
            .insert_export(array(&case, "export_key"))
            .expect("handle");
        assert_eq!(
            session.unlock(&[0; 16], &wrapped, master, export, version, None),
            Err(Error::Invalid),
            "another account"
        );
        assert_eq!(
            session.unlock(&account, &wrapped, master, export, version + 1, None),
            Err(Error::Invalid),
            "another key version"
        );
        assert!(!session.is_unlocked());
        session
            .unlock(&account, &wrapped, master, export, version, None)
            .expect("unlock");
        let expected = root
            .user_key()
            .expect("user key")
            .child(ITEM_WRAP_LABEL)
            .expect("item-wrap key");
        assert_eq!(session.item_wrap_bytes(), Ok(*expected.as_bytes()));
        // Unlocking consumed both handles.
        assert_eq!(
            session.unlock(&account, &wrapped, master, export, version, None),
            Err(Error::Invalid)
        );
    }
}

#[wasm_bindgen_test]
fn kem1_items_open_through_the_session() {
    for case in cases(KEM1) {
        let root = RootKey::from_bytes(&array(&case, "root_key"));
        let owner = Owner::from_bytes(&array(&case, "owner")).expect("owner");
        let id: [u8; 16] = array(&case, "item_id");
        let kind = text(&case, "kind");
        let revision = number(&case, "revision");
        let version = small(&case, "key_version");
        let json = text(&case, "item_json");
        let ciphertext = bytes(&case, "ciphertext");
        let wrapped = bytes(&case, "wrapped_item_key");
        let name = text(&case, "name");

        let session = unlocked_with(&root, owner.id(), version);
        let item = SealedItemRef {
            id: &id,
            owner: &owner,
            kind,
            revision,
            ciphertext: &ciphertext,
            item_key: &wrapped,
            key_version: Some(version),
        };
        let opened = session.open_item(&item).expect("the vector opens");
        assert_eq!(opened.as_slice(), json.as_bytes(), "{name}");

        // The key version defaults to the account's.
        let defaulted = SealedItemRef {
            key_version: None,
            ..item
        };
        assert!(session.open_item(&defaulted).is_ok(), "{name}");

        // Every field the AAD binds.
        let moved = Owner::user([0x77; 16]);
        for tampered in [
            SealedItemRef {
                revision: revision + 1,
                ..item
            },
            SealedItemRef {
                kind: "other",
                ..item
            },
            SealedItemRef {
                id: &[0; 16],
                ..item
            },
            SealedItemRef {
                owner: &moved,
                ..item
            },
            SealedItemRef {
                key_version: Some(version + 1),
                ..item
            },
        ] {
            assert!(session.open_item(&tampered).is_err(), "{name}");
        }
        let mut flipped = ciphertext.clone();
        flipped[20] ^= 1;
        assert!(
            session
                .open_item(&SealedItemRef {
                    ciphertext: &flipped,
                    ..item
                })
                .is_err(),
            "{name}"
        );

        // What the session seals for this owner opens under the vector's own key chain.
        if owner == Owner::user(*owner.id()) {
            let sealed = session
                .seal_item(&id, &owner, kind, revision, json.as_bytes())
                .expect("seal");
            let again = SealedItemRef {
                ciphertext: &sealed.ciphertext,
                item_key: &sealed.item_key,
                ..item
            };
            assert_eq!(
                session.open_item(&again).expect("open").as_slice(),
                json.as_bytes()
            );
            assert_ne!(sealed.ciphertext, ciphertext, "a fresh item key and nonce");
        }
    }
}

#[wasm_bindgen_test]
fn kx1_matches_the_vectors() {
    for case in cases(KX1) {
        let private = kx1::PrivateKey::from_bytes(&array(&case, "private_key"));
        let public = private.public_key().expect("public key");
        assert_eq!(public.as_bytes().to_vec(), bytes(&case, "public_key"));
        let shared = private
            .decapsulate(&bytes(&case, "ciphertext"))
            .expect("decapsulate");
        assert_eq!(shared.as_bytes().to_vec(), bytes(&case, "shared_secret"));
        for changed in case["changed_ciphertexts"].as_array().expect("changed") {
            let secret = private
                .decapsulate(&bytes(changed, "ciphertext"))
                .expect("implicit rejection gives a secret, not an error");
            assert_eq!(secret.as_bytes().to_vec(), bytes(changed, "shared_secret"));
        }
        let (ciphertext, secret) = public.encapsulate().expect("encapsulate");
        let back = private.decapsulate(&ciphertext).expect("decapsulate");
        assert_eq!(back.as_bytes(), secret.as_bytes());
    }
}

#[wasm_bindgen_test]
fn sealed_boxes_match_the_vectors() {
    for case in cases(SEALED_BOX) {
        let private = kx1::PrivateKey::from_bytes(&array(&case, "private_key"));
        let context = text(&case, "context");
        let aad = bytes(&case, "aad");
        let secret = bytes(&case, "secret");
        let boxed = bytes(&case, "sealed_box");

        let opened = sealed_box::open(&private, context, &aad, &boxed).expect("the vector opens");
        assert_eq!(opened.as_slice(), secret.as_slice());
        for wrong in case["wrong_contexts"].as_array().expect("wrong contexts") {
            let wrong = wrong.as_str().expect("a context");
            assert!(
                sealed_box::open(&private, wrong, &aad, &boxed).is_err(),
                "{wrong}"
            );
        }
        assert!(sealed_box::open(&private, context, b"other", &boxed).is_err());

        let public = private.public_key().expect("public key");
        let fresh = sealed_box::seal(&public, context, &aad, &secret).expect("seal");
        assert_eq!(fresh.len(), boxed.len());
        assert_eq!(
            sealed_box::open(&private, context, &aad, &fresh)
                .expect("open")
                .as_slice(),
            secret.as_slice()
        );
    }
}

#[wasm_bindgen_test]
fn sig1_matches_the_vectors() {
    for case in cases(SIG1) {
        let key = sig1::SigningKey::from_bytes(&array(&case, "private_key"));
        let public = key.public_key().expect("public key");
        assert_eq!(public.as_bytes().to_vec(), bytes(&case, "public_key"));
        let context = text(&case, "context");
        let message = bytes(&case, "message");
        let signature = bytes(&case, "signature");
        public
            .verify(context, &message, &signature)
            .expect("the vector verifies");
        assert!(public.verify("other", &message, &signature).is_err());
        // Ed25519 and the RustCrypto ML-DSA signer are deterministic, so signing again is the
        // vector itself.
        assert_eq!(key.sign(context, &message).expect("sign"), signature);
    }
}

#[wasm_bindgen_test]
fn bundles_and_fingerprints_match_the_vectors() {
    for case in cases(BUNDLE) {
        let encoded = bytes(&case, "bundle");
        let signature = bytes(&case, "signature");

        assert_eq!(
            session::fingerprint(&encoded).expect("fingerprint"),
            text(&case, "fingerprint_text")
        );
        assert!(session::verify_bundle(&encoded, &signature));
        let mut flipped = signature.clone();
        flipped[5] ^= 1;
        assert!(!session::verify_bundle(&encoded, &flipped));
        let mut changed = encoded.clone();
        changed[40] ^= 1;
        assert!(!session::verify_bundle(&changed, &signature));
        assert!(!session::verify_bundle(&encoded[1..], &signature));

        // The bundle rebuilt from the private keys is the vector, signature included.
        let kx_private = kx1::PrivateKey::from_bytes(&array(&case, "kx1_private_key"));
        let sig_private = sig1::SigningKey::from_bytes(&array(&case, "sig1_private_key"));
        let bundle = Bundle {
            account_id: array(&case, "account_id"),
            key_version: small(&case, "key_version"),
            kx1_public: kx_private.public_key().expect("kx1 public"),
            sig1_public: sig_private.public_key().expect("sig1 public"),
        };
        assert_eq!(bundle.to_bytes(), encoded);
        assert_eq!(bundle.sign(&sig_private).expect("sign"), signature);
    }
}

#[wasm_bindgen_test]
fn a_new_account_unlocks_and_seals_items() {
    let account_id = [0x11u8; 16];
    let mut session = Session::new();
    let master = session.insert_master([1; 32]).expect("handle");
    let export = session.insert_export([2; 64]).expect("handle");
    let account = session
        .new_account(&account_id, master, export)
        .expect("account");

    // The shapes the register route checks.
    assert_eq!(account.public_bundle.len(), 17 + 16 + 4 + 1600 + 1984);
    assert!(account.public_bundle.starts_with(b"kemlock/v1/bundle"));
    assert_eq!(&account.public_bundle[17..33], &account_id);
    assert_eq!(
        &account.public_bundle[33..37],
        &FIRST_KEY_VERSION.to_be_bytes()
    );
    assert_eq!(account.bundle_signature.len(), 3309 + 64);
    assert_eq!(account.wrapped_root_key.len(), 12 + 64 + 16);
    assert_eq!(account.sealed_private_keys.len(), private_keys::SEALED_LEN);
    assert_eq!(account.key_version, FIRST_KEY_VERSION);
    assert!(session::verify_bundle(
        &account.public_bundle,
        &account.bundle_signature
    ));
    assert_eq!(
        session::fingerprint(&account.public_bundle).expect("fingerprint"),
        account.fingerprint
    );
    assert!(
        !session.is_unlocked(),
        "creating an account unlocks nothing"
    );

    // The export handle was consumed; the master one is kept for the sign-in that follows, which
    // starts OPAQUE with it.
    assert!(
        session
            .unlock(
                &account_id,
                &account.wrapped_root_key,
                master,
                export,
                1,
                None
            )
            .is_err()
    );
    assert!(
        session.opaque_login_start(master).is_ok(),
        "the master handle is still there"
    );

    // The wrong master key, the wrong export key and the wrong account all fail and leave the
    // session locked.
    let right_master = session.insert_master([1; 32]).expect("handle");
    let right_export = session.insert_export([2; 64]).expect("handle");
    let wrong_master = session.insert_master([9; 32]).expect("handle");
    let wrong_export = session.insert_export([9; 64]).expect("handle");
    let wrapped = &account.wrapped_root_key;
    assert!(
        session
            .unlock(&account_id, wrapped, wrong_master, right_export, 1, None)
            .is_err()
    );
    assert!(
        session
            .unlock(&account_id, wrapped, right_master, wrong_export, 1, None)
            .is_err()
    );
    assert!(
        session
            .unlock(&[0x12; 16], wrapped, right_master, right_export, 1, None)
            .is_err()
    );
    assert!(!session.is_unlocked());

    session
        .unlock(
            &account_id,
            wrapped,
            right_master,
            right_export,
            1,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock");
    assert!(session.is_unlocked());
    assert_eq!(
        session.own_fingerprint().expect("fingerprint"),
        account.fingerprint
    );

    // Items.
    let owner = Owner::user(account_id);
    let id = [0x22u8; 16];
    let json = r#"{"name":"Example","password":"hunter2"}"#;
    let sealed = session
        .seal_item(&id, &owner, "login", 1, json.as_bytes())
        .expect("seal");
    assert_eq!(sealed.key_version, 1);
    assert_eq!(sealed.item_key.len(), kem1::WRAPPED_KEY_LEN);
    assert_eq!(sealed.ciphertext.len(), json.len() + 28);
    let item = SealedItemRef {
        id: &id,
        owner: &owner,
        kind: "login",
        revision: 1,
        ciphertext: &sealed.ciphertext,
        item_key: &sealed.item_key,
        key_version: None,
    };
    assert_eq!(
        session.open_item(&item).expect("open").as_slice(),
        json.as_bytes()
    );
    let other_owner = Owner::user([0x33; 16]);
    for tampered in [
        SealedItemRef {
            revision: 2,
            ..item
        },
        SealedItemRef {
            kind: "note",
            ..item
        },
        SealedItemRef {
            id: &[0x23; 16],
            ..item
        },
        SealedItemRef {
            owner: &other_owner,
            ..item
        },
    ] {
        assert!(session.open_item(&tampered).is_err());
    }

    // Only the account's own vault is sealed for; a bad kind is refused.
    assert_eq!(
        session
            .seal_item(&id, &other_owner, "login", 1, b"{}")
            .map(|_| ()),
        Err(Error::Invalid)
    );
    assert_eq!(
        session
            .seal_item(&id, &Owner::space(account_id), "login", 1, b"{}")
            .map(|_| ()),
        Err(Error::Invalid)
    );
    assert_eq!(
        session
            .seal_item(&id, &owner, "Not A Kind", 1, b"{}")
            .map(|_| ()),
        Err(Error::Invalid)
    );

    // Locking wipes it all.
    session.lock();
    assert!(!session.is_unlocked());
    assert!(matches!(session.open_item(&item), Err(Error::Locked)));
    assert!(matches!(
        session.seal_item(&id, &owner, "login", 1, b"{}"),
        Err(Error::Locked)
    ));
    assert_eq!(session.own_fingerprint(), Err(Error::Locked));
}

#[wasm_bindgen_test]
fn unlock_without_the_sealed_keys_leaves_no_private_keys() {
    let account_id = [0x44u8; 16];
    let root = RootKey::generate();
    let session = unlocked_with(&root, &account_id, 1);
    assert!(session.is_unlocked());
    assert_eq!(session.own_fingerprint(), Err(Error::Locked));
}

#[wasm_bindgen_test]
fn opaque_registration_and_login_round_trip() {
    let server = OpaqueServer::generate();
    let credential = opaque::credential_id(" Alice@Example.com ");
    let mut session = Session::new();
    let master = session.insert_master([7; 32]).expect("handle");

    let (state, request) = session.opaque_register_start(master).expect("start");
    assert_eq!(request.len(), 32);
    let response = server
        .registration_response(&credential, &request)
        .expect("server response");
    let (upload, registered) = session
        .opaque_register_finish(state, master, &response)
        .expect("finish");
    assert_eq!(upload.len(), 192);
    let record = OpaqueServer::registration_record(&upload).expect("record");

    let (state, request) = session.opaque_login_start(master).expect("login start");
    assert_eq!(request.len(), 96);
    let (server_state, response) = server
        .login_start(&credential, Some(record.as_slice()), &request)
        .expect("server start");
    let (finalization, logged_in) = session
        .opaque_login_finish(state, master, &response)
        .expect("login finish");
    assert_eq!(finalization.len(), 64);
    OpaqueServer::login_finish(&server_state, &finalization).expect("server finish");
    assert_eq!(
        *session.export_bytes(registered).expect("export key"),
        *session.export_bytes(logged_in).expect("export key"),
        "registration and login give the same export key"
    );

    // A state is single-use.
    assert!(
        session
            .opaque_login_finish(state, master, &response)
            .is_err()
    );

    // A wrong password can't open the envelope; neither can the fake answer for an unknown account.
    let wrong = session.insert_master([8; 32]).expect("handle");
    let (state, request) = session.opaque_login_start(wrong).expect("login start");
    let (_, response) = server
        .login_start(&credential, Some(record.as_slice()), &request)
        .expect("server start");
    assert!(
        session
            .opaque_login_finish(state, wrong, &response)
            .is_err()
    );

    let (state, request) = session.opaque_login_start(master).expect("login start");
    let (_, fake) = server
        .login_start(&credential, None, &request)
        .expect("fake answer");
    assert_eq!(fake.len(), response.len());
    assert!(session.opaque_login_finish(state, master, &fake).is_err());
}

#[wasm_bindgen_test]
fn the_master_key_handle_holds_the_argon2id_output() {
    // The smallest settings the vault accepts, so the test stays quick.
    let mut session = Session::new();
    let salt = [3u8; 16];
    let handle = session
        .master_key("pässword".as_bytes(), 16 * 1024, 2, 1, &salt)
        .expect("master key");
    let direct =
        argon2id::master_key("pässword".as_bytes(), &salt, 16 * 1024, 2, 1).expect("argon2");
    assert_eq!(*session.master_bytes(handle).expect("master key"), direct);

    session.lock();
    assert!(
        session.master_bytes(handle).is_err(),
        "lock drops the handle"
    );
}

// ---- sharing, spaces and the confirmation ------------------------------------------------------

const CONFIRM: &str = include_str!("../../../test-vectors/confirm.json");

/// A session for a freshly made account, unlocked with its private keys, and its public bundle.
fn open_account(account_id: [u8; 16]) -> (Session, Bundle) {
    let mut session = Session::new();
    let master = session.insert_master([1; 32]).expect("handle");
    let export = session.insert_export([2; 64]).expect("handle");
    let account = session
        .new_account(&account_id, master, export)
        .expect("account");
    let master = session.insert_master([1; 32]).expect("handle");
    let export = session.insert_export([2; 64]).expect("handle");
    session
        .unlock(
            &account_id,
            &account.wrapped_root_key,
            master,
            export,
            FIRST_KEY_VERSION,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock");
    let bundle = Bundle::from_bytes(&account.public_bundle).expect("bundle");
    (session, bundle)
}

/// A session unlocked with the given private keys, as the vectors have them.
fn unlocked_with_keys(
    root: &RootKey,
    account_id: &[u8; 16],
    kx_private: &kx1::PrivateKey,
    sig_private: &sig1::SigningKey,
) -> Session {
    let (master, export) = ([1u8; 32], [2u8; 64]);
    let wrapped = password_wrap::seal(&master, &export, root, account_id, 1).expect("wrap");
    let sealed = private_keys::seal(
        &root.user_key().expect("user key"),
        kx_private,
        sig_private,
        account_id,
        1,
    )
    .expect("sealed keys");
    let mut session = Session::new();
    let m = session.insert_master(master).expect("handle");
    let e = session.insert_export(export).expect("handle");
    session
        .unlock(account_id, &wrapped, m, e, 1, Some(&sealed))
        .expect("unlock");
    session
}

/// Hands a session a space key of `version`, as a key replacement would arrive: sealed to the
/// account's own key, then opened.
fn receive_space_key(session: &mut Session, bundle: &Bundle, space: &[u8; 16], version: u32) {
    let key = SecretKey::generate();
    let boxed = sealed_box::seal(
        &bundle.kx1_public,
        "space-key",
        &bundle.account_id,
        key.as_bytes(),
    )
    .expect("seal");
    session.open_space(space, version, &boxed).expect("open");
}

#[wasm_bindgen_test]
fn the_root_key_is_sealed_to_a_device_for_one_request_only() {
    for case in cases(SEALED_BOX) {
        let recipient = kx1::PrivateKey::from_bytes(&array(&case, "private_key"));
        let public = bytes(&case, "public_key");
        let root = RootKey::generate();
        let account_id = [0x31u8; 16];
        let request_id = [0x32u8; 16];
        let session = unlocked_with(&root, &account_id, 1);

        // device-approval: aad = account id, then the approval request id.
        let aad = [account_id, request_id].concat();
        let boxed = session
            .seal_root_key(&public, "device-approval", &aad)
            .expect("seal");
        assert_eq!(boxed.len(), sealed_box::OVERHEAD + 64);
        let opened = sealed_box::open(&recipient, "device-approval", &aad, &boxed)
            .expect("the device opens");
        assert_eq!(opened.as_slice(), root.as_bytes());
        // An answer can't be replayed onto another request, another account or another context.
        let other_request = [account_id, [0x33u8; 16]].concat();
        assert!(sealed_box::open(&recipient, "device-approval", &other_request, &boxed).is_err());
        assert!(sealed_box::open(&recipient, "emergency-access", &aad, &boxed).is_err());
        assert!(sealed_box::open(&recipient, "device-approval", &account_id, &boxed).is_err());

        // The account id in the aad must be the unlocked account's, and the aad must have both
        // halves.
        let foreign = [[0x99u8; 16], request_id].concat();
        for bad in [&foreign[..], &account_id[..], &aad[..31], &[][..]] {
            assert_eq!(
                session.seal_root_key(&public, "device-approval", bad),
                Err(Error::Invalid)
            );
        }
        // Only the contexts that hand over a root key are sealed.
        for context in ["space-key", "collection-key", ""] {
            assert_eq!(
                session.seal_root_key(&public, context, &aad),
                Err(Error::Invalid),
                "{context}"
            );
        }
        // A key of the wrong length is refused.
        assert_eq!(
            session.seal_root_key(&public[..1599], "device-approval", &aad),
            Err(Error::Invalid)
        );
    }
}

#[wasm_bindgen_test]
fn the_root_key_is_sealed_to_an_emergency_contact_by_their_id() {
    let (grantor, _) = open_account([0x41; 16]);
    let (_, contact) = open_account([0x42; 16]);
    let boxed = grantor
        .seal_root_key(
            contact.kx1_public.as_bytes(),
            "emergency-access",
            &contact.account_id,
        )
        .expect("seal");
    assert_eq!(boxed.len(), sealed_box::OVERHEAD + 64);
    // 16 bytes only: the request id of a device approval has no place here.
    assert_eq!(
        grantor.seal_root_key(
            contact.kx1_public.as_bytes(),
            "emergency-access",
            &[contact.account_id, [0; 16]].concat()
        ),
        Err(Error::Invalid)
    );
    let locked = Session::new();
    assert_eq!(
        locked.seal_root_key(
            contact.kx1_public.as_bytes(),
            "emergency-access",
            &contact.account_id
        ),
        Err(Error::Locked)
    );
}

#[wasm_bindgen_test]
fn a_released_emergency_key_opens_the_grantors_items_and_nothing_else() {
    let (grantor, _) = open_account([0x51; 16]);
    let (mut grantee, grantee_bundle) = open_account([0x52; 16]);
    let item_id = [0x53u8; 16];
    let owner = Owner::user([0x51; 16]);
    let sealed = grantor
        .seal_item(&item_id, &owner, "login", 1, br#"{"name":"bank"}"#)
        .expect("seal item");
    let item = SealedItemRef {
        id: &item_id,
        owner: &owner,
        kind: "login",
        revision: 1,
        ciphertext: &sealed.ciphertext,
        item_key: &sealed.item_key,
        key_version: Some(sealed.key_version),
    };

    let released = grantor
        .seal_root_key(
            grantee_bundle.kx1_public.as_bytes(),
            "emergency-access",
            &grantee_bundle.account_id,
        )
        .expect("seal");
    let handle = grantee.open_emergency_key(&released).expect("open");
    assert_eq!(
        grantee
            .open_item_with_emergency_key(handle, &item)
            .expect("the grantee reads the grantor's item")
            .as_slice(),
        br#"{"name":"bank"}"#
    );

    // A space's items, another revision, another handle and a released handle all fail.
    let space = Owner::space([0x51; 16]);
    assert!(
        grantee
            .open_item_with_emergency_key(
                handle,
                &SealedItemRef {
                    owner: &space,
                    ..item
                }
            )
            .is_err()
    );
    assert!(
        grantee
            .open_item_with_emergency_key(
                handle,
                &SealedItemRef {
                    revision: 2,
                    ..item
                }
            )
            .is_err()
    );
    assert!(
        grantee
            .open_item_with_emergency_key(handle + 1, &item)
            .is_err()
    );
    // A box sealed for another contact does not open.
    let (_, other) = open_account([0x54; 16]);
    let not_mine = grantor
        .seal_root_key(
            other.kx1_public.as_bytes(),
            "emergency-access",
            &other.account_id,
        )
        .expect("seal");
    assert!(grantee.open_emergency_key(&not_mine).is_err());

    grantee.release(handle);
    assert!(grantee.open_item_with_emergency_key(handle, &item).is_err());
    let handle = grantee.open_emergency_key(&released).expect("open again");
    grantee.lock();
    assert!(grantee.open_item_with_emergency_key(handle, &item).is_err());
}

#[wasm_bindgen_test]
fn the_confirmation_statement_and_signature_match_the_vectors() {
    for case in cases(CONFIRM) {
        let name = text(&case, "name");
        let confirmer: [u8; 16] = array(&case, "confirmer");
        let sig_private = sig1::SigningKey::from_bytes(&array(&case, "confirmer_private_key"));
        let (kx_private, kx_public) = kx1::generate().expect("kx1");
        let session =
            unlocked_with_keys(&RootKey::generate(), &confirmer, &kx_private, &sig_private);
        let facts = sharing::Facts::new(
            array(&case, "space"),
            array(&case, "member"),
            small(&case, "member_key_version"),
            &bytes(&case, "fingerprint"),
        )
        .expect("facts");
        let statement = bytes(&case, "statement");
        let signature = bytes(&case, "signature");

        assert_eq!(
            session.confirmation_statement(&facts).expect("statement"),
            statement,
            "{name}"
        );
        assert_eq!(statement.len(), 134);
        // What the session signs verifies under the vector's key, as the vector's own does.
        let sig_public = sig_private.public_key().expect("public key");
        let signed = session.sign_statement(&statement, "confirm").expect("sign");
        assert_eq!(signed.len(), 3373);
        sig_public
            .verify("confirm", &statement, &signed)
            .expect("verifies");
        sig_public
            .verify("confirm", &statement, &signature)
            .expect("the vector verifies");

        // The confirmer's bundle carries the key the signature checks against.
        let bundle = Bundle {
            account_id: confirmer,
            key_version: 1,
            kx1_public: kx_public,
            sig1_public: sig_public,
        }
        .to_bytes();
        assert!(sharing::verify_confirmation(
            &bundle, &facts, &statement, &signature
        ));
        for changed in case["changed_statements"].as_array().expect("changed") {
            assert!(
                !sharing::verify_confirmation(
                    &bundle,
                    &facts,
                    &bytes(changed, "statement"),
                    &signature
                ),
                "{name} {}",
                text(changed, "name")
            );
        }
        let mut flipped = signature.clone();
        flipped[10] ^= 1;
        assert!(!sharing::verify_confirmation(
            &bundle, &facts, &statement, &flipped
        ));
        // Another confirmer's bundle is not the signer's.
        let (_, stranger) = open_account([0x61; 16]);
        assert!(!sharing::verify_confirmation(
            &stranger.to_bytes(),
            &facts,
            &statement,
            &signature
        ));
        assert!(!sharing::verify_confirmation(
            &bundle[1..],
            &facts,
            &statement,
            &signature
        ));

        // The key that signs the account's own bundle signs nothing else.
        for wrong in case["wrong_contexts"].as_array().expect("contexts") {
            let wrong = wrong.as_str().expect("a context");
            assert_eq!(
                session.sign_statement(&statement, wrong),
                Err(Error::Invalid),
                "{wrong}"
            );
        }
        assert_eq!(
            session.sign_statement(b"any message at all", "confirm"),
            Err(Error::Invalid)
        );
        let mut as_other = statement.clone();
        as_other[133] ^= 1;
        assert_eq!(
            session.sign_statement(&as_other, "confirm"),
            Err(Error::Invalid),
            "a statement can only name the unlocked account as the confirmer"
        );
        assert_eq!(
            session.sign_statement(&statement[..133], "confirm"),
            Err(Error::Invalid)
        );
    }
}

#[wasm_bindgen_test]
fn a_session_without_private_keys_signs_nothing() {
    let account_id = [0x71u8; 16];
    let session = unlocked_with(&RootKey::generate(), &account_id, 1);
    let facts = sharing::Facts::new([1; 16], [2; 16], 1, &[3; 64]).expect("facts");
    let statement = session.confirmation_statement(&facts).expect("statement");
    assert_eq!(&statement[118..], &account_id);
    assert_eq!(
        session.sign_statement(&statement, "confirm"),
        Err(Error::Locked)
    );
    assert!(sharing::Facts::new([1; 16], [2; 16], 1, &[3; 63]).is_err());
}

#[wasm_bindgen_test]
fn a_new_space_is_sealed_to_its_maker_and_opens_for_a_confirmed_member() {
    let space = [0x81u8; 16];
    let collection = [0x82u8; 16];
    let (mut maker, _) = open_account([0x83; 16]);
    let (mut member, member_bundle) = open_account([0x84; 16]);
    let member_kx = member_bundle.kx1_public.as_bytes();

    let made = maker
        .new_space(&space, &collection, "Family", "Everyone")
        .expect("new space");
    // The shapes the create route checks: sealed keys are 1,661 bytes, names are sealed values.
    assert_eq!(made.sealed_space_key.len(), 1 + 1600 + 12 + 32 + 16);
    assert_eq!(made.collection.sealed_key.len(), 1 + 1600 + 12 + 32 + 16);
    assert_eq!(made.sealed_space_key[0], 1);
    assert_eq!(made.name.len(), 12 + "Family".len() + 16);
    assert_eq!(made.collection.name.len(), 12 + "Everyone".len() + 16);

    // The maker reads both names back, under the key version 1 that makes them.
    assert_eq!(
        maker
            .open_name(&space, 1, NameKind::Space, &space, &made.name)
            .expect("space name"),
        "Family"
    );
    assert_eq!(
        maker
            .open_name(
                &space,
                1,
                NameKind::Collection,
                &collection,
                &made.collection.name
            )
            .expect("collection name"),
        "Everyone"
    );
    // A name opens only where it was sealed: another kind, id, key version or space fails.
    assert!(
        maker
            .open_name(&space, 1, NameKind::Group, &space, &made.name)
            .is_err()
    );
    assert!(
        maker
            .open_name(&space, 1, NameKind::Space, &collection, &made.name)
            .is_err()
    );
    assert!(
        maker
            .open_name(&space, 2, NameKind::Space, &space, &made.name)
            .is_err()
    );
    assert!(
        maker
            .open_name(&[0u8; 16], 1, NameKind::Space, &space, &made.name)
            .is_err()
    );
    let mut flipped = made.name.clone();
    flipped[13] ^= 1;
    assert!(
        maker
            .open_name(&space, 1, NameKind::Space, &space, &flipped)
            .is_err()
    );
    // The same space can't be made twice.
    assert!(maker.new_space(&space, &[9; 16], "Again", "Again").is_err());

    // A member who is not yet confirmed holds no key and reads no name.
    assert!(
        member
            .open_name(&space, 1, NameKind::Space, &space, &made.name)
            .is_err()
    );
    // After a confirmation the maker seals both keys to the member, and the member opens them.
    let for_member_space = maker
        .seal_space_key_to(&space, member_kx, &member_bundle.account_id)
        .expect("seal the space key");
    let for_member_collection = maker
        .seal_collection_key_to(&space, &collection, member_kx, &member_bundle.account_id)
        .expect("seal the collection key");
    member
        .open_space(&space, 1, &for_member_space)
        .expect("open the space key");
    member
        .open_collection(&space, &collection, 1, &for_member_collection)
        .expect("open the collection key");
    assert_eq!(
        member
            .open_name(&space, 1, NameKind::Space, &space, &made.name)
            .expect("the member reads the space name"),
        "Family"
    );
    // Contexts keep the two kinds of key apart, and a box is for its recipient alone.
    assert!(
        member
            .open_space(&space, 1, &for_member_collection)
            .is_err()
    );
    assert!(
        member
            .open_collection(&space, &collection, 1, &for_member_space)
            .is_err()
    );
    assert!(maker.open_space(&space, 1, &for_member_space).is_err());
    // The recipient's id is the box's aad: a box sealed for one account id does not open for
    // another account with the same key.
    let misaddressed = maker
        .seal_space_key_to(&space, member_kx, &[0xEE; 16])
        .expect("seal");
    assert!(member.open_space(&space, 1, &misaddressed).is_err());

    // A rename by the member is a fresh name that the maker reads.
    let renamed = member
        .seal_name(&space, 1, NameKind::Space, &space, "Family and friends")
        .expect("rename");
    assert_eq!(
        maker
            .open_name(&space, 1, NameKind::Space, &space, &renamed)
            .expect("the maker reads the rename"),
        "Family and friends"
    );
    assert_ne!(renamed, made.name);
}

#[wasm_bindgen_test]
fn a_new_collection_follows_the_newest_space_key() {
    let space = [0x91u8; 16];
    let (mut maker, bundle) = open_account([0x92; 16]);
    // No space key held yet.
    assert!(maker.new_collection(&space, &[1; 16], "Private").is_err());
    maker
        .new_space(&space, &[2; 16], "Work", "Everyone")
        .expect("new space");

    let made = maker
        .new_collection(&space, &[3; 16], "Private")
        .expect("new collection");
    assert_eq!(made.sealed_key.len(), 1 + 1600 + 12 + 32 + 16);
    assert_eq!(
        maker
            .open_name(&space, 1, NameKind::Collection, &[3; 16], &made.name)
            .expect("name"),
        "Private"
    );
    // The key is held for sealing to whoever is granted the collection, and made only once.
    assert!(
        maker
            .seal_collection_key_to(
                &space,
                &[3; 16],
                bundle.kx1_public.as_bytes(),
                &bundle.account_id
            )
            .is_ok()
    );
    assert!(maker.new_collection(&space, &[3; 16], "Private").is_err());
    // A collection the session never made or opened has no key to seal.
    assert!(
        maker
            .seal_collection_key_to(
                &space,
                &[4; 16],
                bundle.kx1_public.as_bytes(),
                &bundle.account_id
            )
            .is_err()
    );
    // A newer space key version becomes the one new names are sealed under.
    receive_space_key(&mut maker, &bundle, &space, 2);
    let later = maker
        .new_collection(&space, &[5; 16], "Archive")
        .expect("new collection");
    assert_eq!(
        maker
            .open_name(&space, 2, NameKind::Collection, &[5; 16], &later.name)
            .expect("name under version 2"),
        "Archive"
    );
    assert!(
        maker
            .open_name(&space, 1, NameKind::Collection, &[5; 16], &later.name)
            .is_err()
    );

    // Names have a ceiling: a sealed name is at most 4 KiB.
    let long = "x".repeat(4096 - 28);
    assert!(
        maker
            .seal_name(&space, 1, NameKind::Group, &[6; 16], &long)
            .is_ok()
    );
    assert!(
        maker
            .seal_name(&space, 1, NameKind::Group, &[6; 16], &format!("{long}x"))
            .is_err()
    );
    assert!(NameKind::parse("folder").is_err());
}

#[wasm_bindgen_test]
fn space_work_needs_an_unlocked_account_with_its_private_keys() {
    let space = [0xA1u8; 16];
    let mut locked = Session::new();
    assert_eq!(
        locked.new_space(&space, &[1; 16], "a", "b").map(|_| ()),
        Err(Error::Locked)
    );
    assert_eq!(locked.open_space(&space, 1, &[0; 1661]), Err(Error::Locked));
    assert_eq!(
        locked.seal_name(&space, 1, NameKind::Space, &space, "a"),
        Err(Error::Locked)
    );

    // Unlocked without the sealed private keys, there is no kx1 key to seal to or open with.
    let mut bare = unlocked_with(&RootKey::generate(), &[0xA2; 16], 1);
    assert_eq!(
        bare.new_space(&space, &[1; 16], "a", "b").map(|_| ()),
        Err(Error::Locked)
    );
    assert_eq!(bare.open_space(&space, 1, &[0; 1661]), Err(Error::Locked));

    // `lock` wipes the keys a session held.
    let (mut session, _) = open_account([0xA3; 16]);
    let made = session
        .new_space(&space, &[1; 16], "Kept", "Also kept")
        .expect("new space");
    session.lock();
    assert_eq!(
        session.open_name(&space, 1, NameKind::Space, &space, &made.name),
        Err(Error::Locked)
    );
}

#[wasm_bindgen_test]
fn a_key_box_opens_only_for_the_space_collection_and_version_it_was_sealed_for() {
    let (space_a, space_b) = ([0xB1u8; 16], [0xB2u8; 16]);
    let (coll_x, coll_y) = ([0xC1u8; 16], [0xC2u8; 16]);
    let (mut maker, _) = open_account([0xB3; 16]);
    let (mut member, bundle) = open_account([0xB4; 16]);
    let kx = bundle.kx1_public.as_bytes();

    maker
        .new_space(&space_a, &coll_x, "A", "X")
        .expect("space A");
    maker
        .new_space(&space_b, &coll_y, "B", "Y")
        .expect("space B");
    maker
        .new_collection(&space_a, &coll_y, "Y in A")
        .expect("collection Y in A");

    // The member holds both spaces; a server serves A's box as B's.
    let box_a = maker
        .seal_space_key_to(&space_a, kx, &bundle.account_id)
        .expect("seal A");
    assert!(member.open_space(&space_b, 1, &box_a).is_err());
    assert!(member.open_space(&space_a, 2, &box_a).is_err());
    member
        .open_space(&space_a, 1, &box_a)
        .expect("A opens as A");

    // The same for a collection: another collection, another space, another version.
    let box_x = maker
        .seal_collection_key_to(&space_a, &coll_x, kx, &bundle.account_id)
        .expect("seal X");
    assert!(
        member
            .open_collection(&space_a, &coll_y, 1, &box_x)
            .is_err()
    );
    assert!(
        member
            .open_collection(&space_b, &coll_x, 1, &box_x)
            .is_err()
    );
    assert!(
        member
            .open_collection(&space_a, &coll_x, 2, &box_x)
            .is_err()
    );
    member
        .open_collection(&space_a, &coll_x, 1, &box_x)
        .expect("X opens as X");

    // Not as the other kind of key, either.
    assert!(member.open_space(&space_a, 1, &box_x).is_err());
}

#[wasm_bindgen_test]
fn a_new_device_opens_the_approved_root_key_for_its_own_request_only() {
    let account_id = [0x61u8; 16];
    let request_id = [0x62u8; 16];
    // The account as an open device holds it; the sealed keys are what a new device fetches after signing in.
    let mut owner_session = Session::new();
    let master = owner_session.insert_master([1; 32]).expect("handle");
    let export = owner_session.insert_export([2; 64]).expect("handle");
    let account = owner_session
        .new_account(&account_id, master, export)
        .expect("account");
    let mut approver_session = Session::new();
    let master = approver_session.insert_master([1; 32]).expect("handle");
    let export = approver_session.insert_export([2; 64]).expect("handle");
    approver_session
        .unlock(
            &account_id,
            &account.wrapped_root_key,
            master,
            export,
            FIRST_KEY_VERSION,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock");

    let mut device = Session::new();
    let (key, public) = device.new_device_key().expect("one-time key");
    assert_eq!(public.len(), 1600);
    let aad = [account_id, request_id].concat();
    let boxed = approver_session
        .seal_root_key(&public, "device-approval", &aad)
        .expect("seal");

    // Another request id, or another account id, does not open it, and spends the one-time key.
    let (other_key, other_public) = device.new_device_key().expect("another key");
    let other_box = approver_session
        .seal_root_key(&other_public, "device-approval", &aad)
        .expect("seal");
    assert!(
        device
            .open_approved_root_key(other_key, &account_id, &[0x63; 16], &other_box)
            .is_err()
    );
    assert!(
        device
            .open_approved_root_key(other_key, &account_id, &request_id, &other_box)
            .is_err(),
        "a spent key opens nothing"
    );

    let root = device
        .open_approved_root_key(key, &account_id, &request_id, &boxed)
        .expect("the device opens its box");
    assert!(!device.is_unlocked());
    device
        .unlock_with_root(
            &account_id,
            root,
            FIRST_KEY_VERSION,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock with the approved root key");
    assert!(device.is_unlocked());

    // The device now reads what the approver sealed, and has the private keys too.
    let item_id = [0x64u8; 16];
    let owner = Owner::user(account_id);
    let sealed = approver_session
        .seal_item(&item_id, &owner, "login", 1, br#"{"name":"bank"}"#)
        .expect("seal item");
    let opened = device
        .open_item(&SealedItemRef {
            id: &item_id,
            owner: &owner,
            kind: "login",
            revision: 1,
            ciphertext: &sealed.ciphertext,
            item_key: &sealed.item_key,
            key_version: Some(sealed.key_version),
        })
        .expect("the approved device opens the account's item");
    assert_eq!(opened.as_slice(), br#"{"name":"bank"}"#);
    assert!(device.own_fingerprint().is_ok());
    // The root handle was consumed.
    assert!(device.root_slot(root).is_err());
}

#[wasm_bindgen_test]
fn a_space_item_opens_only_for_its_collection_key_version_and_owner() {
    let space = [0x71u8; 16];
    let collection = [0x72u8; 16];
    let other_collection = [0x73u8; 16];
    let (mut maker, _) = open_account([0x74; 16]);
    maker
        .new_space(&space, &collection, "Work", "Everyone")
        .expect("new space");
    maker
        .new_collection(&space, &other_collection, "Finance")
        .expect("another collection");

    let id = [0x75u8; 16];
    let sealed = maker
        .seal_space_item(&space, &collection, &id, "login", 1, br#"{"name":"vpn"}"#)
        .expect("seal");
    assert_eq!(sealed.key_version, 1, "the collection key's version");
    let owner = Owner::space(space);
    let item = SealedItemRef {
        id: &id,
        owner: &owner,
        kind: "login",
        revision: 1,
        ciphertext: &sealed.ciphertext,
        item_key: &sealed.item_key,
        key_version: Some(sealed.key_version),
    };
    assert_eq!(
        maker
            .open_space_item(&space, &collection, &item)
            .expect("opens under its collection")
            .as_slice(),
        br#"{"name":"vpn"}"#
    );
    // Not under another collection's key, another revision, another version or a user's owner.
    assert!(
        maker
            .open_space_item(&space, &other_collection, &item)
            .is_err()
    );
    assert!(
        maker
            .open_space_item(
                &space,
                &collection,
                &SealedItemRef {
                    revision: 2,
                    ..item
                }
            )
            .is_err()
    );
    assert!(
        maker
            .open_space_item(
                &space,
                &collection,
                &SealedItemRef {
                    key_version: Some(2),
                    ..item
                }
            )
            .is_err()
    );
    let user = Owner::user([0x74; 16]);
    assert!(
        maker
            .open_space_item(
                &space,
                &collection,
                &SealedItemRef {
                    owner: &user,
                    ..item
                }
            )
            .is_err()
    );
    // A user's own item key wrap is not a space's: the account's key does not open it.
    assert!(maker.open_item(&item).is_err());
    // Nothing without a collection key held, or a locked session.
    assert!(
        maker
            .seal_space_item(&space, &[0x7f; 16], &id, "login", 1, b"{}")
            .is_err()
    );
    let locked = Session::new();
    assert_eq!(
        locked
            .seal_space_item(&space, &collection, &id, "login", 1, b"{}")
            .map(|_| ()),
        Err(Error::Locked)
    );
}

#[wasm_bindgen_test]
fn a_passkey_prf_wrap_opens_the_vault_on_another_device_and_only_for_its_own_inputs() {
    let account_id = [0x71u8; 16];
    let mut owner = Session::new();
    let master = owner.insert_master([1; 32]).expect("handle");
    let export = owner.insert_export([2; 64]).expect("handle");
    let account = owner
        .new_account(&account_id, master, export)
        .expect("account");
    // Nothing is left unlocked by new_account: open it as the account's own device would.
    let master = owner.insert_master([1; 32]).expect("handle");
    let export = owner.insert_export([2; 64]).expect("handle");
    owner
        .unlock(
            &account_id,
            &account.wrapped_root_key,
            master,
            export,
            FIRST_KEY_VERSION,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock");
    let (wrapped, key_version) = owner
        .prf_wrap_root(&[3; 32], b"credential")
        .expect("the open account wraps its root key");
    assert_eq!(key_version, FIRST_KEY_VERSION);
    assert_eq!(wrapped.len(), 92);

    let mut device = Session::new();
    // Another PRF output, credential, account or key version opens nothing.
    assert!(
        device
            .prf_open_root_key(&[4; 32], b"credential", &account_id, key_version, &wrapped)
            .is_err()
    );
    assert!(
        device
            .prf_open_root_key(&[3; 32], b"other", &account_id, key_version, &wrapped)
            .is_err()
    );
    assert!(
        device
            .prf_open_root_key(&[3; 32], b"credential", &[0x72; 16], key_version, &wrapped)
            .is_err()
    );
    assert!(
        device
            .prf_open_root_key(
                &[3; 32],
                b"credential",
                &account_id,
                key_version + 1,
                &wrapped
            )
            .is_err()
    );
    let root = device
        .prf_open_root_key(&[3; 32], b"credential", &account_id, key_version, &wrapped)
        .expect("the passkey opens its wrap");
    assert!(!device.is_unlocked());
    device
        .unlock_with_root(
            &account_id,
            root,
            key_version,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock with the PRF-opened root key");
    assert!(device.is_unlocked());
}

#[wasm_bindgen_test]
fn an_account_with_no_password_is_made_unlocked_and_opens_on_a_device_from_its_root_copy() {
    let account_id = [0x73u8; 16];
    let mut maker = Session::new();
    let account = maker.new_sso_account(&account_id).expect("keys are made");
    assert!(account.wrapped_root_key.is_empty(), "no password wrap");
    assert_eq!(account.key_version, FIRST_KEY_VERSION);
    assert_eq!(account.public_bundle.len(), 17 + 16 + 4 + 1600 + 1984);
    assert!(maker.is_unlocked(), "this device made the root key");

    // What the worker seals as the device's copy, and later opens into another session.
    let root = maker.export_root().expect("the open account's root key");
    let item_id = [0x74u8; 16];
    let owner = Owner::user(account_id);
    let sealed = maker
        .seal_item(&item_id, &owner, "login", 1, br#"{"name":"vpn"}"#)
        .expect("seals");

    let mut device = Session::new();
    assert_eq!(device.export_root().err(), Some(Error::Locked));
    assert_eq!(device.import_root(&root[..63]), Err(Error::Invalid));
    let handle = device.import_root(&root[..]).expect("a handle");
    device
        .unlock_with_root(
            &account_id,
            handle,
            FIRST_KEY_VERSION,
            Some(&account.sealed_private_keys),
        )
        .expect("unlock with the device's copy");
    let item = SealedItemRef {
        id: &item_id,
        owner: &owner,
        kind: "login",
        revision: 1,
        ciphertext: &sealed.ciphertext,
        item_key: &sealed.item_key,
        key_version: None,
    };
    let opened = device
        .open_item(&item)
        .expect("the device reads what the maker sealed");
    assert_eq!(opened.as_slice(), br#"{"name":"vpn"}"#);
}

#[wasm_bindgen_test]
fn the_root_key_is_sealed_to_a_spaces_recovery_key_under_its_aad() {
    let account_id = [0x61u8; 16];
    let space = [0x62u8; 16];
    let root = RootKey::generate();
    let session = unlocked_with(&root, &account_id, 1);
    for case in cases(SEALED_BOX) {
        let recipient = kx1::PrivateKey::from_bytes(&array(&case, "private_key"));
        let public = bytes(&case, "public_key");
        let key_seq = 5u64;
        let aad = [space.as_slice(), &account_id, &key_seq.to_be_bytes()].concat();
        assert_eq!(aad.len(), 40);

        let boxed = session
            .seal_root_key_for_recovery(&space, &public, key_seq)
            .expect("seal");
        assert_eq!(boxed.len(), sealed_box::OVERHEAD + 64);
        let opened = sealed_box::open(&recipient, "account-recovery", &aad, &boxed)
            .expect("the recovery key opens it");
        assert_eq!(opened.as_slice(), root.as_bytes());

        // It is bound to the space, the account, the recovery key record and the context.
        let other_space = [[0x63u8; 16].as_slice(), &account_id, &key_seq.to_be_bytes()].concat();
        let other_account = [space.as_slice(), &[0x64u8; 16], &key_seq.to_be_bytes()].concat();
        let other_seq = [space.as_slice(), &account_id, &6u64.to_be_bytes()].concat();
        for wrong in [&other_space, &other_account, &other_seq] {
            assert!(sealed_box::open(&recipient, "account-recovery", wrong, &boxed).is_err());
        }
        assert!(sealed_box::open(&recipient, "device-approval", &aad[..32], &boxed).is_err());

        // The generic route takes the same aad, but only with this account's id in it.
        assert!(
            session
                .seal_root_key(&public, "account-recovery", &aad)
                .is_ok()
        );
        for bad in [&other_account[..], &aad[..39], &aad[..32], &[][..]] {
            assert_eq!(
                session.seal_root_key(&public, "account-recovery", bad),
                Err(Error::Invalid)
            );
        }
        assert_eq!(
            Session::new().seal_root_key_for_recovery(&space, &public, key_seq),
            Err(Error::Locked)
        );
    }
}

// ---- the space chain ---------------------------------------------------------------------------

const SPACE_CHAIN: &str = include_str!("../../../test-vectors/space-chain.json");

/// A chain of the vectors, as the server serves it.
fn vector_chain(name: &str) -> ([u8; 16], Vec<chain::WireIn>) {
    let doc: Value = serde_json::from_str(SPACE_CHAIN).expect("a vector file is JSON");
    let case = doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case named {name}"));
    let wire = |record: &Value, field: &str| {
        record[field]
            .as_str()
            .map(|hex_text| b64::encode(&hex::decode(hex_text).expect("hex")))
    };
    let records = case["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|record| chain::WireIn {
            entry: wire(record, "entry").expect("entry"),
            signature: wire(record, "signature").expect("signature"),
            cosignature: wire(record, "cosignature"),
        })
        .collect();
    (ids::parse_uuid(text(case, "space")).expect("a uuid"), records)
}

fn verdict_json(session: &mut Session, space: &[u8; 16], records: &[chain::WireIn]) -> Value {
    let verdict = session
        .verify_space_chain(space, records, None)
        .expect("a verdict");
    serde_json::to_value(&verdict).expect("json")
}

#[wasm_bindgen_test]
fn a_chain_that_verifies_is_not_trusted_until_first_contact() {
    let (space, records) = vector_chain("valid-every-kind");
    let (mut session, _) = open_account([0xD1; 16]);
    let view = verdict_json(&mut session, &space, &records);
    assert_eq!(view["ok"], true);
    assert_eq!(view["chained"], true);
    assert_eq!(view["head"]["seq"], 49);
    // The head's link is the vector's.
    let doc: Value = serde_json::from_str(SPACE_CHAIN).expect("json");
    let expected = doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == "valid-every-kind")
        .expect("case")["expect"]["head_link"]
        .as_str()
        .expect("link")
        .to_owned();
    assert_eq!(
        view["head"]["link"],
        b64::encode(&hex::decode(expected).expect("hex"))
    );
    // This account isn't in the chain: its person must pick an Owner, never "nothing to compare".
    assert_eq!(view["trusted"], false);
    assert_eq!(view["firstContact"]["kind"], "pick");
    assert!(!view["members"].as_array().expect("members").is_empty());

    // Before first contact no key opens, and the older operations don't reach the space.
    assert_eq!(
        session.open_chain_key(&space, &KeyRef::Space, 1, &[0u8; 1661], None),
        Err(Error::Invalid)
    );
    assert_eq!(
        session.new_space(&space, &[1; 16], "a", "b").map(|_| ()),
        Err(Error::Invalid)
    );
    assert_eq!(session.open_space(&space, 1, &[0; 1661]), Err(Error::Invalid));
    assert_eq!(
        session.seal_space_key_to(&space, &[0; 1600], &[1; 16]),
        Err(Error::Invalid)
    );

    session.accept_first_contact(&space).expect("accepted");
    let held = session
        .space_chain_view(&space)
        .expect("a view")
        .expect("held");
    assert_eq!(serde_json::to_value(&held).expect("json")["trusted"], true);
    // A box the chain didn't commit to for this account opens no key even now.
    assert_eq!(
        session.open_chain_key(&space, &KeyRef::Space, 1, &[0u8; 1661], None),
        Err(Error::Invalid)
    );
}

#[wasm_bindgen_test]
fn a_chain_with_an_altered_record_is_refused() {
    let (space, mut records) = vector_chain("valid-every-kind");
    let mut entry = b64::decode(&records[5].entry).expect("entry");
    let last = entry.len() - 3;
    entry[last] ^= 1;
    records[5].entry = b64::encode(&entry);
    let (mut session, _) = open_account([0xD2; 16]);
    let view = verdict_json(&mut session, &space, &records);
    assert_eq!(view["ok"], false);
    assert!(view["reason"].is_string());
    // A refused chain keeps nothing: no state, so no key.
    assert!(session.space_chain_view(&space).expect("view").is_none());
    // But the space has a chain, so the older operations stay closed to it too.
    assert_eq!(
        session.new_space(&space, &[1; 16], "a", "b").map(|_| ()),
        Err(Error::Invalid)
    );
    // A space the page never named works as before.
    assert!(session.new_space(&[0xEE; 16], &[1; 16], "a", "b").is_ok());
}

#[wasm_bindgen_test]
fn a_chain_that_ends_earlier_than_one_already_verified_is_rolled_back() {
    let (space, records) = vector_chain("valid-every-kind");
    let (mut session, _) = open_account([0xD3; 16]);
    assert_eq!(verdict_json(&mut session, &space, &records)["ok"], true);
    // The server serves a prefix, or nothing at all, to the same unlock.
    for shorter in [&records[..10], &records[..0]] {
        let view = verdict_json(&mut session, &space, shorter);
        assert_eq!(view["ok"], false);
        assert_eq!(view["reason"], "rolled back");
    }
    // The state held is still the longer chain.
    let held = session.space_chain_view(&space).expect("view").expect("held");
    assert_eq!(serde_json::to_value(&held).expect("json")["head"]["seq"], 49);
}

#[wasm_bindgen_test]
fn the_page_s_anchor_makes_first_contact_done_and_refuses_a_fork() {
    let (space, records) = vector_chain("valid-every-kind");
    let (mut first, _) = open_account([0xD4; 16]);
    let view = verdict_json(&mut first, &space, &records);
    let anchor = json!({"seq": view["head"]["seq"], "epoch": view["epoch"], "links": view["links"]});

    // Another unlock, with the anchor the page stored after first contact: trusted at once.
    let (mut again, _) = open_account([0xD5; 16]);
    let known: chain::AnchorIn = serde_json::from_value(anchor.clone()).expect("anchor");
    let verdict = again
        .verify_space_chain(&space, &records, Some(&known))
        .expect("verdict");
    let view = serde_json::to_value(&verdict).expect("json");
    assert_eq!(view["ok"], true);
    assert_eq!(view["trusted"], true);

    // An anchor with another link at seq 3 is a fork, and refused.
    let mut forked = anchor;
    forked["links"][3] = json!(b64::encode(&[0x55; 32]));
    let forked: chain::AnchorIn = serde_json::from_value(forked).expect("anchor");
    let (mut third, _) = open_account([0xD6; 16]);
    let verdict = third
        .verify_space_chain(&space, &records, Some(&forked))
        .expect("verdict");
    let view = serde_json::to_value(&verdict).expect("json");
    assert_eq!(view["ok"], false);
    assert_eq!(view["reason"], "forked");
    assert_eq!(view["seq"], 3);

    // An anchor that is not made of 32-byte links is a malformed request, not a refusal.
    let junk: chain::AnchorIn =
        serde_json::from_value(json!({"seq": 0, "epoch": 1, "links": ["AAAA"]})).expect("anchor");
    let (mut fourth, _) = open_account([0xD7; 16]);
    assert_eq!(
        fourth
            .verify_space_chain(&space, &records, Some(&junk))
            .map(|_| ()),
        Err(Error::Invalid)
    );
}

#[wasm_bindgen_test]
fn a_new_chained_space_verifies_opens_its_keys_and_names_itself() {
    let (space, collection) = ([0xE1u8; 16], [0xE2u8; 16]);
    let (mut session, bundle) = open_account([0xE3; 16]);
    let made = session
        .create_chained_space(&space, &collection, "Family", "Everyone", 1_700_000_000)
        .expect("a create record");
    let request = serde_json::to_value(&made).expect("json");

    // One record, two boxes and two names, as the append route takes them.
    assert_eq!(request["records"].as_array().expect("records").len(), 1);
    assert_eq!(request["seals"].as_array().expect("seals").len(), 2);
    assert_eq!(request["names"].as_array().expect("names").len(), 2);
    for seal in request["seals"].as_array().expect("seals") {
        assert_eq!(seal["seq"], 0);
        assert_eq!(seal["version"], 1);
        assert_eq!(b64::decode(seal["box"].as_str().expect("box")).expect("b64").len(), 1661);
    }
    let boxed = |key: &str| -> Vec<u8> {
        let seal = request["seals"]
            .as_array()
            .expect("seals")
            .iter()
            .find(|s| s["key"] == key)
            .expect("a box");
        b64::decode(seal["box"].as_str().expect("box")).expect("b64")
    };
    let named = |target: &str| -> Vec<u8> {
        let name = request["names"]
            .as_array()
            .expect("names")
            .iter()
            .find(|n| n["target"] == target)
            .expect("a name");
        b64::decode(name["name"].as_str().expect("name")).expect("b64")
    };
    let collection_key = format!("collection:{}", kemlock_crypto::space_chain::uuid_text(&collection));

    // The chain verifies, and it is this account's own: nothing to compare.
    let record = &request["records"][0];
    let wire = chain::WireIn {
        entry: record["entry"].as_str().expect("entry").to_owned(),
        signature: record["signature"].as_str().expect("signature").to_owned(),
        cosignature: None,
    };
    let verdict = session
        .verify_space_chain(&space, &[wire], None)
        .expect("a verdict");
    let view = serde_json::to_value(&verdict).expect("json");
    assert_eq!(view["ok"], true);
    assert_eq!(view["head"]["seq"], 0);
    assert_eq!(view["trusted"], true);
    assert_eq!(view["members"][0]["role"], "owner");
    assert_eq!(view["members"][0]["status"], "confirmed");
    assert_eq!(
        view["members"][0]["bundle"],
        b64::encode(&bundle.to_bytes())
    );

    // Both keys open through the chain, and a box for another version doesn't.
    assert_eq!(
        session.open_chain_key(&space, &KeyRef::Space, 2, &boxed("space"), None),
        Err(Error::Invalid)
    );
    session
        .open_chain_key(&space, &KeyRef::Space, 1, &boxed("space"), None)
        .expect("the space key opens");
    session
        .open_chain_key(&space, &KeyRef::Collection(collection), 1, &boxed(&collection_key), None)
        .expect("the collection key opens");
    // A box of the collection's is not the space's.
    assert_eq!(
        session.open_chain_key(&space, &KeyRef::Space, 1, &boxed(&collection_key), None),
        Err(Error::Invalid)
    );

    // The names are the ones the chain committed, and only at the version it recorded.
    assert_eq!(
        session.open_name(&space, 1, NameKind::Space, &space, &named("space")),
        Ok("Family".to_owned())
    );
    assert_eq!(
        session.open_name(&space, 1, NameKind::Collection, &collection, &named(&collection_key)),
        Ok("Everyone".to_owned())
    );
    assert_eq!(
        session.open_name(&space, 1, NameKind::Collection, &collection, &named("space")),
        Err(Error::Invalid)
    );

    // Items are sealed under the collection's current key; an unknown collection has none.
    session
        .seal_space_item(&space, &collection, &[7; 16], "login", 1, b"{}")
        .expect("an item seals");
    assert!(
        session
            .seal_space_item(&space, &[0x99; 16], &[7; 16], "login", 1, b"{}")
            .is_err()
    );
}
