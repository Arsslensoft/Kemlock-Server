//! The JavaScript skin over [`Session`]: one class, `Vault`, that the web vault's worker owns.
//!
//! Binary values that travel to or from the server are base64url strings (the wire form of
//! docs/crypto.md), so the worker never handles raw key bytes. Secrets that stay in the browser
//! (master keys, OPAQUE export keys, half-finished OPAQUE exchanges) are numbers: handles into the
//! session's table. Methods that return several values return one JSON string, which the worker
//! parses; every failure is a `JsError` whose message is `"invalid"` or `"locked"` and nothing
//! more.

// wasm-bindgen's generated glue is `unsafe`; nothing written by hand in this crate is.
#![allow(unsafe_code)]

use core::fmt;

use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use kemlock_crypto::space_chain::KeyRef;

use crate::{
    b64, chain, chain_build,
    error::Error,
    ids, item_writes, kit, manifests, sends,
    session::{self, SealedItemRef, Session},
    sharing::{self, Facts},
    spaces::{self, NameKind, NewCollection, SignedBox},
    totp,
};

fn fail(error: Error) -> JsError {
    JsError::new(error.code())
}

fn json<T: Serialize>(value: &T) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|_| fail(Error::Invalid))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Started {
    state: u32,
    request: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationFinished {
    upload: String,
    export_key: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginFinished {
    finalization: String,
    export_key: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeys {
    public_bundle: String,
    bundle_signature: String,
    sealed_private_keys: String,
    wrapped_root_key: String,
    key_version: u32,
    fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedOut {
    ciphertext: String,
    item_key: String,
    key_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceKeyOut {
    handle: u32,
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KitOut {
    kit_id: String,
    pieces: Vec<String>,
    wrapped_key: String,
    key_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KitPieceOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    kit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shares: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrfWrapOut {
    wrapped_key: String,
    key_version: u32,
}

#[derive(Serialize)]
struct SealedSend {
    payload: String,
    meta: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TotpOut {
    secret: String,
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectionOut {
    name: String,
    sealed_key: String,
    sealed_key_signature: String,
}

impl From<NewCollection> for CollectionOut {
    fn from(made: NewCollection) -> CollectionOut {
        CollectionOut {
            name: b64::encode(&made.name),
            sealed_key: b64::encode(&made.sealed_key),
            sealed_key_signature: b64::encode(&made.sealed_key_signature),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewSpaceOut {
    name: String,
    sealed_space_key: String,
    sealed_space_key_signature: String,
    collection: CollectionOut,
}

/// A key sealed to a member and the signature of the account that sealed it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedBoxOut {
    sealed: String,
    signature: String,
}

impl From<SignedBox> for SignedBoxOut {
    fn from(made: SignedBox) -> SignedBoxOut {
        SignedBoxOut {
            sealed: b64::encode(&made.sealed),
            signature: b64::encode(&made.signature),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationStartOut {
    key_version: u32,
    public_bundle: String,
    bundle_signature: String,
    sealed_private_keys: String,
    sealed_previous_private_keys: String,
    fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResealedItemOut {
    ciphertext: String,
    item_key: String,
    revision: u64,
    key_version: u32,
    /// The account's signature of the write, by the new keys.
    writer: String,
    writer_key_version: u32,
    write_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResealedSendOut {
    sealed_key: String,
    meta: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationCommitOut {
    key_version: u32,
    fingerprint: String,
}

/// An account id given as base64url of its 16 bytes.
fn b64_id(text: &str) -> Result<[u8; 16], JsError> {
    b64::decode(text)
        .map_err(fail)?
        .try_into()
        .map_err(|_| fail(Error::Invalid))
}

/// The facts of a confirmation: ids as UUID text, the fingerprint as base64url of its 64 bytes.
fn facts_in(
    space_id: &str,
    member_id: &str,
    member_key_version: u32,
    fingerprint: &str,
) -> Result<Facts, Error> {
    Facts::new(
        ids::parse_uuid(space_id)?,
        ids::parse_uuid(member_id)?,
        member_key_version,
        &b64::decode(fingerprint)?,
    )
}

fn facts_of(
    space_id: &str,
    member_id: &str,
    member_key_version: u32,
    fingerprint: &str,
) -> Result<Facts, JsError> {
    facts_in(space_id, member_id, member_key_version, fingerprint).map_err(fail)
}

/// The vault's keys and the operations on them. One per worker; `lock` wipes it.
#[wasm_bindgen]
pub struct Vault {
    session: Session,
}

impl Default for Vault {
    fn default() -> Vault {
        Vault {
            session: Session::new(),
        }
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl Vault {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Vault {
        Vault::default()
    }

    /// `Argon2id(password, salt, m, t, p)`: the master key, as a handle. `password` is the UTF-8 of
    /// the NFC form; this call wipes its copy. `salt` is base64url. Settings outside the bounds
    /// the server enforces are refused.
    #[wasm_bindgen(js_name = masterKey)]
    pub fn master_key(
        &mut self,
        mut password: String,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: &str,
    ) -> Result<u32, JsError> {
        let salt = b64::decode(salt);
        let result = salt.and_then(|salt| {
            self.session.master_key(
                password.as_bytes(),
                memory_kib,
                iterations,
                parallelism,
                &salt,
            )
        });
        password.zeroize();
        result.map_err(fail)
    }

    /// The Bitwarden master password hash of an account whose KDF is Argon2id, base64url: the master
    /// key is `Argon2id(password, SHA-256(email), m, t, p)` and the hash `PBKDF2-HMAC-SHA256(master
    /// key, password, 1)`. `email` is trimmed and lower-cased by the caller. The password is wiped
    /// here. No session is needed, and nothing is kept.
    #[wasm_bindgen(js_name = bitwardenArgonHash)]
    pub fn bitwarden_argon_hash(
        &self,
        mut password: String,
        email: &str,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<String, JsError> {
        let hash = session::bitwarden_argon_hash(
            password.as_bytes(),
            email.as_bytes(),
            memory_kib,
            iterations,
            parallelism,
        );
        password.zeroize();
        hash.map(|hash| b64::encode(&hash)).map_err(fail)
    }

    /// Drops a handle; unknown handles are ignored.
    pub fn release(&mut self, handle: u32) {
        self.session.release(handle);
    }

    /// OPAQUE registration, first message: `{state, request}`.
    #[wasm_bindgen(js_name = opaqueRegisterStart)]
    pub fn opaque_register_start(&mut self, master: u32) -> Result<String, JsError> {
        let (state, request) = self.session.opaque_register_start(master).map_err(fail)?;
        json(&Started {
            state,
            request: b64::encode(&request),
        })
    }

    /// OPAQUE registration, last message: `{upload, exportKey}`. Consumes `state`.
    #[wasm_bindgen(js_name = opaqueRegisterFinish)]
    pub fn opaque_register_finish(
        &mut self,
        state: u32,
        master: u32,
        response: &str,
    ) -> Result<String, JsError> {
        let response = b64::decode(response).map_err(fail)?;
        let (upload, export_key) = self
            .session
            .opaque_register_finish(state, master, &response)
            .map_err(fail)?;
        json(&RegistrationFinished {
            upload: b64::encode(&upload),
            export_key,
        })
    }

    /// OPAQUE login, first message: `{state, request}`.
    #[wasm_bindgen(js_name = opaqueLoginStart)]
    pub fn opaque_login_start(&mut self, master: u32) -> Result<String, JsError> {
        let (state, request) = self.session.opaque_login_start(master).map_err(fail)?;
        json(&Started {
            state,
            request: b64::encode(&request),
        })
    }

    /// OPAQUE login, last message: `{finalization, exportKey}`. Consumes `state`. Fails when the
    /// password is wrong or the server's answer was a fake one.
    #[wasm_bindgen(js_name = opaqueLoginFinish)]
    pub fn opaque_login_finish(
        &mut self,
        state: u32,
        master: u32,
        response: &str,
    ) -> Result<String, JsError> {
        let response = b64::decode(response).map_err(fail)?;
        let (finalization, export_key) = self
            .session
            .opaque_login_finish(state, master, &response)
            .map_err(fail)?;
        json(&LoginFinished {
            finalization: b64::encode(&finalization),
            export_key,
        })
    }

    /// Makes a new account's keys and returns the register route's fields as
    /// `{publicBundle, bundleSignature, sealedPrivateKeys, wrappedRootKey, keyVersion,
    /// fingerprint}`. Consumes the master and export handles.
    #[wasm_bindgen(js_name = newAccount)]
    pub fn new_account(
        &mut self,
        account_id: &str,
        master: u32,
        export_key: u32,
    ) -> Result<String, JsError> {
        let account_id = ids::parse_uuid(account_id).map_err(fail)?;
        let account = self
            .session
            .new_account(&account_id, master, export_key)
            .map_err(fail)?;
        json(&AccountKeys {
            public_bundle: b64::encode(&account.public_bundle),
            bundle_signature: b64::encode(&account.bundle_signature),
            sealed_private_keys: b64::encode(&account.sealed_private_keys),
            wrapped_root_key: b64::encode(&account.wrapped_root_key),
            key_version: account.key_version,
            fingerprint: account.fingerprint,
        })
    }

    /// Makes the keys of an account that has no password (single sign-on made it) and leaves it
    /// unlocked: `{publicBundle, bundleSignature, sealedPrivateKeys, wrappedRootKey: "",
    /// keyVersion, fingerprint}`. The device keeps its own copy of the root key (`exportRoot`).
    #[wasm_bindgen(js_name = newSsoAccount)]
    pub fn new_sso_account(&mut self, account_id: &str) -> Result<String, JsError> {
        let account_id = ids::parse_uuid(account_id).map_err(fail)?;
        let account = self.session.new_sso_account(&account_id).map_err(fail)?;
        json(&AccountKeys {
            public_bundle: b64::encode(&account.public_bundle),
            bundle_signature: b64::encode(&account.bundle_signature),
            sealed_private_keys: b64::encode(&account.sealed_private_keys),
            wrapped_root_key: b64::encode(&account.wrapped_root_key),
            key_version: account.key_version,
            fingerprint: account.fingerprint,
        })
    }

    /// The open account's root key (base64url, 64 bytes), for the worker to seal under this
    /// device's own key. It is never sent to the page: only the sealed copy is.
    #[wasm_bindgen(js_name = exportRoot)]
    pub fn export_root(&self) -> Result<String, JsError> {
        let root = self.session.export_root().map_err(fail)?;
        Ok(b64::encode(&*root))
    }

    /// Keeps a root key the worker opened from this device's copy behind a handle, for
    /// `unlockWithRoot`.
    #[wasm_bindgen(js_name = importRoot)]
    pub fn import_root(&mut self, root: &str) -> Result<u32, JsError> {
        let bytes = zeroize::Zeroizing::new(b64::decode(root).map_err(fail)?);
        self.session.import_root(&bytes).map_err(fail)
    }

    /// Opens the password wrap of the root key and keeps the keys in memory. With
    /// `sealed_private_keys` it opens the `kx1` and `sig1` private keys too. Consumes the master
    /// and export handles on success.
    pub fn unlock(
        &mut self,
        account_id: &str,
        wrapped_root_key: &str,
        master: u32,
        export_key: u32,
        key_version: u32,
        sealed_private_keys: Option<String>,
    ) -> Result<(), JsError> {
        let account_id = ids::parse_uuid(account_id).map_err(fail)?;
        let wrapped = b64::decode(wrapped_root_key).map_err(fail)?;
        let sealed = sealed_private_keys
            .as_deref()
            .map(b64::decode)
            .transpose()
            .map_err(fail)?;
        self.session
            .unlock(
                &account_id,
                &wrapped,
                master,
                export_key,
                key_version,
                sealed.as_deref(),
            )
            .map_err(fail)
    }

    /// Whether an account is unlocked.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.session.is_unlocked()
    }

    /// Seals an item for the server: `{ciphertext, itemKey, keyVersion}`. `owner` is
    /// `user:<uuid>`, and must be the unlocked account.
    #[wasm_bindgen(js_name = sealItem)]
    pub fn seal_item(
        &self,
        id: &str,
        owner: &str,
        kind: &str,
        revision: u64,
        item_json: &str,
    ) -> Result<String, JsError> {
        let id = ids::parse_uuid(id).map_err(fail)?;
        let owner = ids::parse_owner(owner).map_err(fail)?;
        let sealed = self
            .session
            .seal_item(&id, &owner, kind, revision, item_json.as_bytes())
            .map_err(fail)?;
        json(&SealedOut {
            ciphertext: b64::encode(&sealed.ciphertext),
            item_key: b64::encode(&sealed.item_key),
            key_version: sealed.key_version,
        })
    }

    /// Opens an item the server stored and returns its JSON.
    #[wasm_bindgen(js_name = openItem)]
    #[allow(clippy::too_many_arguments)]
    pub fn open_item(
        &self,
        id: &str,
        owner: &str,
        kind: &str,
        revision: u64,
        ciphertext: &str,
        item_key: &str,
        key_version: Option<u32>,
    ) -> Result<String, JsError> {
        let id = ids::parse_uuid(id).map_err(fail)?;
        let owner = ids::parse_owner(owner).map_err(fail)?;
        let ciphertext = b64::decode(ciphertext).map_err(fail)?;
        let item_key = b64::decode(item_key).map_err(fail)?;
        let plain = self
            .session
            .open_item(&SealedItemRef {
                id: &id,
                owner: &owner,
                kind,
                revision,
                ciphertext: &ciphertext,
                item_key: &item_key,
                key_version,
            })
            .map_err(fail)?;
        String::from_utf8(plain.to_vec()).map_err(|_| fail(Error::Invalid))
    }

    /// A fresh Send link key: 32 random bytes, base64url. It belongs in the link's fragment and
    /// nowhere else.
    #[wasm_bindgen(js_name = sendNewKey)]
    pub fn send_new_key(&self) -> String {
        sends::new_link_key()
    }

    /// Seals a Send's payload JSON and meta JSON, binding the Send's id (a UUID) and kind (`text` or
    /// `file`): `{payload, meta}`, base64url. The payload is under a key from the link key, so a
    /// recipient opens it; the meta is under one from the unlocked account's item-wrap key, so only
    /// the owner's devices do.
    #[wasm_bindgen(js_name = sendSeal)]
    pub fn send_seal(
        &self,
        id: &str,
        kind: &str,
        link_key: &str,
        payload_json: &str,
        meta_json: &str,
    ) -> Result<String, JsError> {
        let id = sends::send_id(id).map_err(fail)?;
        let kind = sends::kind(kind).map_err(fail)?;
        let link_key = sends::parse_link_key(link_key).map_err(fail)?;
        let payload =
            sends::seal_payload(&id, kind, &link_key, payload_json.as_bytes()).map_err(fail)?;
        let meta = self
            .session
            .seal_send_meta(&id, kind, meta_json.as_bytes())
            .map_err(fail)?;
        json(&SealedSend {
            payload: b64::encode(&payload),
            meta: b64::encode(&meta),
        })
    }

    /// A Send's payload JSON, opened with the link key from the link. `id` is the access id the
    /// link carries or the Send's UUID.
    #[wasm_bindgen(js_name = sendOpenPayload)]
    pub fn send_open_payload(
        &self,
        id: &str,
        kind: &str,
        link_key: &str,
        payload: &str,
    ) -> Result<String, JsError> {
        let id = sends::send_id(id).map_err(fail)?;
        let kind = sends::kind(kind).map_err(fail)?;
        let link_key = sends::parse_link_key(link_key).map_err(fail)?;
        let payload = b64::decode(payload).map_err(fail)?;
        sends::open_payload(&id, kind, &link_key, &payload).map_err(fail)
    }

    /// The owner's name and notes of a Send, as JSON, opened with the unlocked account's key. The
    /// link key is no use here: `sealed_key` only names the key version the meta key needs.
    #[wasm_bindgen(js_name = sendOpenMeta)]
    pub fn send_open_meta(
        &self,
        id: &str,
        kind: &str,
        sealed_key: &str,
        meta: &str,
    ) -> Result<String, JsError> {
        let id = sends::send_id(id).map_err(fail)?;
        let kind = sends::kind(kind).map_err(fail)?;
        let sealed_key = b64::decode(sealed_key).map_err(fail)?;
        let meta = b64::decode(meta).map_err(fail)?;
        self.session
            .open_send_meta(&id, kind, &sealed_key, &meta)
            .map_err(fail)
    }

    /// Wraps a Send's link key for its owner under the unlocked account's item-wrap key: the
    /// `sealedKey` the server stores, base64url.
    #[wasm_bindgen(js_name = sendWrapKey)]
    pub fn send_wrap_key(&self, id: &str, link_key: &str) -> Result<String, JsError> {
        let id = sends::send_id(id).map_err(fail)?;
        let link_key = sends::parse_link_key(link_key).map_err(fail)?;
        let sealed = self.session.wrap_send_key(&id, &link_key).map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// The link key of one of the unlocked account's own Sends, from its `sealedKey`.
    #[wasm_bindgen(js_name = sendOpenKey)]
    pub fn send_open_key(&self, id: &str, sealed_key: &str) -> Result<String, JsError> {
        let id = sends::send_id(id).map_err(fail)?;
        let sealed = b64::decode(sealed_key).map_err(fail)?;
        let link_key = self.session.unwrap_send_key(&id, &sealed).map_err(fail)?;
        Ok(b64::encode(link_key.as_bytes()))
    }

    /// The password proof the server checks: Argon2id of the NFC password under a salt from the
    /// link key and the Send's id, base64url. This call wipes its copy of the password.
    #[wasm_bindgen(js_name = sendProof)]
    pub fn send_proof(
        &self,
        id: &str,
        link_key: &str,
        mut password: String,
    ) -> Result<String, JsError> {
        let result = sends::send_id(id).and_then(|id| {
            let link_key = sends::parse_link_key(link_key)?;
            sends::proof(&id, &link_key, &password)
        });
        password.zeroize();
        result
            .map(|proof| b64::encode(proof.as_slice()))
            .map_err(fail)
    }

    /// A file as the `KMA1` file a file Send stores, under the link key's payload key.
    #[wasm_bindgen(js_name = sendSealFile)]
    pub fn send_seal_file(&self, link_key: &str, plain: &[u8]) -> Result<Vec<u8>, JsError> {
        let link_key = sends::parse_link_key(link_key).map_err(fail)?;
        sends::seal_file(&link_key, plain).map_err(fail)
    }

    /// The plaintext of a file Send's `KMA1` file.
    #[wasm_bindgen(js_name = sendOpenFile)]
    pub fn send_open_file(&self, link_key: &str, file: &[u8]) -> Result<Vec<u8>, JsError> {
        let link_key = sends::parse_link_key(link_key).map_err(fail)?;
        let plain = sends::open_file(&link_key, file).map_err(fail)?;
        Ok(plain.to_vec())
    }

    /// The unlocked account's own fingerprint: 12 groups of 5 digits. Needs `unlock` to have been
    /// given the sealed private keys.
    #[wasm_bindgen(js_name = ownFingerprint)]
    pub fn own_fingerprint(&self) -> Result<String, JsError> {
        self.session.own_fingerprint().map_err(fail)
    }

    /// A public bundle's fingerprint, from its base64url form.
    pub fn fingerprint(&self, public_bundle: &str) -> Result<String, JsError> {
        let bundle = b64::decode(public_bundle).map_err(fail)?;
        session::fingerprint(&bundle).map_err(fail)
    }

    /// Whether `bundle_signature` is the bundle's own `sig1` signature. Anything malformed is
    /// simply `false`.
    #[wasm_bindgen(js_name = verifyBundle)]
    pub fn verify_bundle(&self, public_bundle: &str, bundle_signature: &str) -> bool {
        match (b64::decode(public_bundle), b64::decode(bundle_signature)) {
            (Ok(bundle), Ok(signature)) => session::verify_bundle(&bundle, &signature),
            _ => false,
        }
    }

    /// TOTP enrolment: `{secret, uri}`, the base32 secret and the `otpauth://` URI. With `secret`
    /// (base32) it makes the URI for that secret; without, it makes a new 160-bit one.
    #[wasm_bindgen(js_name = totpEnrol)]
    pub fn totp_enrol(
        &self,
        secret: Option<String>,
        issuer: &str,
        account: &str,
    ) -> Result<String, JsError> {
        let enrolment = totp::enrol(secret.as_deref(), issuer, account).map_err(fail)?;
        json(&TotpOut {
            secret: enrolment.secret,
            uri: enrolment.uri,
        })
    }

    /// Seals the unlocked account's root key to a `kx1` public key (base64url, 1,600 bytes) as a
    /// sealed box. `context` is `device-approval` (`aad`: the account id then the approval
    /// request id, 32 bytes) or `account-recovery` (`aad`: space id, account id,
    /// `u64be(keySeq)`, 40 bytes; see `sealRootKeyForRecovery`); no other context is sealed, and
    /// `emergency-access` only through `sealEmergencyKey`. Returns the box, base64url.
    #[wasm_bindgen(js_name = sealRootKey)]
    pub fn seal_root_key(
        &self,
        recipient_kx1: &str,
        context: &str,
        aad: &str,
    ) -> Result<String, JsError> {
        let recipient = b64::decode(recipient_kx1).map_err(fail)?;
        let aad = b64::decode(aad).map_err(fail)?;
        let sealed = self
            .session
            .seal_root_key(&recipient, context, &aad)
            .map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// Seals the unlocked account's root key to an emergency contact under `emergency-access`, with
    /// the contact's account id (`granteeId`, a UUID) as the aad. The key sealed to is the one in
    /// `publicBundle` (base64url), which must carry a valid self-signature (`bundleSignature`,
    /// base64url) and name `granteeId` as its account. Returns the box, base64url.
    #[wasm_bindgen(js_name = sealEmergencyKey)]
    pub fn seal_emergency_key(
        &self,
        public_bundle: &str,
        bundle_signature: &str,
        grantee_id: &str,
    ) -> Result<String, JsError> {
        let bundle = b64::decode(public_bundle).map_err(fail)?;
        let signature = b64::decode(bundle_signature).map_err(fail)?;
        let grantee = ids::parse_uuid(grantee_id).map_err(fail)?;
        let sealed = self
            .session
            .seal_emergency_key(&bundle, &signature, &grantee)
            .map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// Seals the unlocked account's root key to a space's recovery key (`recoveryKx1`, base64url,
    /// 1,600 bytes) under `account-recovery`, with the aad `space id ‖ account id ‖ u64be(keySeq)`.
    /// `spaceId` is the space's UUID and `keySeq` the `seq` of the chain record that set the
    /// recovery key. Returns the box, base64url.
    #[wasm_bindgen(js_name = sealRootKeyForRecovery)]
    pub fn seal_root_key_for_recovery(
        &self,
        space_id: &str,
        recovery_kx1: &str,
        key_seq: u32,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let recovery = b64::decode(recovery_kx1).map_err(fail)?;
        let sealed = self
            .session
            .seal_root_key_for_recovery(&space, &recovery, u64::from(key_seq))
            .map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// The member-confirmation statement (134 bytes, base64url) for a member of a space, with the
    /// unlocked account as the confirmer. `fingerprint` is the 64 bytes the confirmer compared.
    #[wasm_bindgen(js_name = confirmationStatement)]
    pub fn confirmation_statement(
        &self,
        space_id: &str,
        member_id: &str,
        member_key_version: u32,
        fingerprint: &str,
    ) -> Result<String, JsError> {
        let facts = facts_of(space_id, member_id, member_key_version, fingerprint)?;
        let statement = self.session.confirmation_statement(&facts).map_err(fail)?;
        Ok(b64::encode(&statement))
    }

    /// A `sig1` signature (base64url, 3,373 bytes) over a confirmation statement of the unlocked
    /// account. Only context `confirm` and a statement of that shape are signed.
    #[wasm_bindgen(js_name = signStatement)]
    pub fn sign_statement(&self, statement: &str, context: &str) -> Result<String, JsError> {
        let statement = b64::decode(statement).map_err(fail)?;
        let signature = self
            .session
            .sign_statement(&statement, context)
            .map_err(fail)?;
        Ok(b64::encode(&signature))
    }

    /// Whether `signature` is the confirmer's `sig1` signature over exactly the statement of
    /// these facts, under the key in the confirmer's bundle (base64url). Anything malformed is
    /// simply `false`.
    #[wasm_bindgen(js_name = verifyConfirmation)]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_confirmation(
        &self,
        confirmer_bundle: &str,
        space_id: &str,
        member_id: &str,
        member_key_version: u32,
        fingerprint: &str,
        statement: &str,
        signature: &str,
    ) -> bool {
        let (Ok(bundle), Ok(statement), Ok(signature), Ok(facts)) = (
            b64::decode(confirmer_bundle),
            b64::decode(statement),
            b64::decode(signature),
            facts_in(space_id, member_id, member_key_version, fingerprint),
        ) else {
            return false;
        };
        sharing::verify_confirmation(&bundle, &facts, &statement, &signature)
    }

    /// Opens a root key sealed to this account for emergency access and keeps it behind a handle
    /// (release it with `release`). The key itself never leaves.
    #[wasm_bindgen(js_name = openEmergencyKey)]
    pub fn open_emergency_key(&mut self, sealed: &str) -> Result<u32, JsError> {
        let sealed = b64::decode(sealed).map_err(fail)?;
        self.session.open_emergency_key(&sealed).map_err(fail)
    }

    /// Opens an item of the account an emergency key came from, and returns its JSON.
    #[wasm_bindgen(js_name = openEmergencyItem)]
    #[allow(clippy::too_many_arguments)]
    pub fn open_emergency_item(
        &self,
        handle: u32,
        id: &str,
        owner: &str,
        kind: &str,
        revision: u64,
        ciphertext: &str,
        item_key: &str,
        key_version: Option<u32>,
    ) -> Result<String, JsError> {
        let id = ids::parse_uuid(id).map_err(fail)?;
        let owner = ids::parse_owner(owner).map_err(fail)?;
        let ciphertext = b64::decode(ciphertext).map_err(fail)?;
        let item_key = b64::decode(item_key).map_err(fail)?;
        let plain = self
            .session
            .open_item_with_emergency_key(
                handle,
                &SealedItemRef {
                    id: &id,
                    owner: &owner,
                    kind,
                    revision,
                    ciphertext: &ciphertext,
                    item_key: &item_key,
                    key_version,
                },
            )
            .map_err(fail)?;
        String::from_utf8(plain.to_vec()).map_err(|_| fail(Error::Invalid))
    }

    /// A new device's one-time exchange key for an approval request: `{handle, publicKey}`. The
    /// private key stays behind `handle`; `publicKey` (base64url, 1,600 bytes) goes in the request
    /// and the five-word phrase is worked out from it.
    #[wasm_bindgen(js_name = newDeviceKey)]
    pub fn new_device_key(&mut self) -> Result<String, JsError> {
        let (handle, public) = self.session.new_device_key().map_err(fail)?;
        json(&DeviceKeyOut {
            handle,
            public_key: b64::encode(&public),
        })
    }

    /// Opens the root key an approving device sealed to the one-time key behind `device_key`
    /// (`aad` is the account id then the request id, both UUIDs) and keeps it behind a handle for
    /// `unlockWithRoot`. The one-time key is spent either way.
    #[wasm_bindgen(js_name = openApprovedKey)]
    pub fn open_approved_key(
        &mut self,
        device_key: u32,
        account_id: &str,
        request_id: &str,
        sealed: &str,
    ) -> Result<u32, JsError> {
        let account = ids::parse_uuid(account_id).map_err(fail)?;
        let request = ids::parse_uuid(request_id).map_err(fail)?;
        let sealed = b64::decode(sealed).map_err(fail)?;
        self.session
            .open_approved_root_key(device_key, &account, &request, &sealed)
            .map_err(fail)
    }

    /// Opens the vault with an approved root key (from `openApprovedKey`). With
    /// `sealed_private_keys` it opens the `kx1` and `sig1` private keys too. With `public_bundle`
    /// (base64url, the account's bundle) it also requires those keys to be the bundle's, and
    /// refuses to unlock otherwise: the page passes it whenever the root key came from an
    /// approving device, which nothing on the new device authenticates. Consumes the handle on
    /// success.
    #[wasm_bindgen(js_name = unlockWithRoot)]
    pub fn unlock_with_root(
        &mut self,
        account_id: &str,
        root_handle: u32,
        key_version: u32,
        sealed_private_keys: Option<String>,
        public_bundle: Option<String>,
    ) -> Result<(), JsError> {
        let account = ids::parse_uuid(account_id).map_err(fail)?;
        let sealed = sealed_private_keys
            .as_deref()
            .map(b64::decode)
            .transpose()
            .map_err(fail)?;
        let bundle = public_bundle
            .as_deref()
            .map(b64::decode)
            .transpose()
            .map_err(fail)?;
        self.session
            .unlock_with_root(
                &account,
                root_handle,
                key_version,
                sealed.as_deref(),
                bundle.as_deref(),
            )
            .map_err(fail)
    }

    /// Wraps the open account's root key under a passkey's PRF output (base64url, 32 bytes) and
    /// the credential's raw id (base64url): `{wrappedKey, keyVersion}`, for the server to keep
    /// (docs/crypto.md, "The passkey PRF wrap of the root key").
    #[wasm_bindgen(js_name = prfWrapRoot)]
    pub fn prf_wrap_root(&self, prf_output: &str, credential_id: &str) -> Result<String, JsError> {
        let prf = b64::decode(prf_output).map_err(fail)?;
        let credential = b64::decode(credential_id).map_err(fail)?;
        let (wrapped, key_version) = self
            .session
            .prf_wrap_root(&prf, &credential)
            .map_err(fail)?;
        json(&PrfWrapOut {
            wrapped_key: b64::encode(&wrapped),
            key_version,
        })
    }

    /// Wraps the open account's root key under a new master key and OPAQUE export key (the
    /// handles `masterKey` and `opaqueRegisterFinish` made), for a change of master password or
    /// of sign-in address: base64url of the 92-byte wrap, for the server to keep. The root key
    /// stays, and so do the key version and the associated data (docs/crypto.md, "Changing the
    /// master password and the sign-in address"). Consumes both handles on success.
    #[wasm_bindgen(js_name = rewrapRoot)]
    pub fn rewrap_root(&mut self, master: u32, export_key: u32) -> Result<String, JsError> {
        let wrapped = self.session.rewrap_root(master, export_key).map_err(fail)?;
        Ok(b64::encode(&wrapped))
    }

    /// Opens a passkey's PRF wrap of the root key and keeps the root key behind a handle for
    /// `unlockWithRoot`. Fails for another PRF output, credential, account or key version.
    #[wasm_bindgen(js_name = prfOpenRoot)]
    pub fn prf_open_root(
        &mut self,
        prf_output: &str,
        credential_id: &str,
        account_id: &str,
        key_version: u32,
        wrapped: &str,
    ) -> Result<u32, JsError> {
        let prf = b64::decode(prf_output).map_err(fail)?;
        let credential = b64::decode(credential_id).map_err(fail)?;
        let account = ids::parse_uuid(account_id).map_err(fail)?;
        let wrapped = b64::decode(wrapped).map_err(fail)?;
        self.session
            .prf_open_root_key(&prf, &credential, &account, key_version, &wrapped)
            .map_err(fail)
    }

    /// Makes a Recovery Kit for the open account (docs/crypto.md, "The Recovery Kit"):
    /// `{kitId, pieces, wrappedKey, keyVersion}`. The pieces are text for the page to show once;
    /// the wrap is for the server to keep.
    #[wasm_bindgen(js_name = kitMake)]
    pub fn kit_make(&self) -> Result<String, JsError> {
        let made = self.session.kit_make().map_err(fail)?;
        json(&KitOut {
            kit_id: made.kit_id,
            pieces: made.pieces,
            wrapped_key: b64::encode(&made.wrapped),
            key_version: made.key_version,
        })
    }

    /// Reads one piece, however it was typed: `{kitId, threshold, shares, index}`, or
    /// `{problem}` with `format` or `checksum`.
    #[wasm_bindgen(js_name = kitReadPiece)]
    pub fn kit_read_piece(&self, text: &str) -> Result<String, JsError> {
        match kit::read_piece(text) {
            Ok(piece) => json(&KitPieceOut {
                kit_id: Some(piece.kit_id),
                threshold: Some(piece.threshold),
                shares: Some(piece.shares),
                index: Some(piece.index),
                problem: None,
            }),
            Err(problem) => json(&KitPieceOut {
                kit_id: None,
                threshold: None,
                shares: None,
                index: None,
                problem: Some(problem.code()),
            }),
        }
    }

    /// Whether the pieces (a JSON array of their text) are of one kit with none twice:
    /// `{problem}`, or `{}` when they are.
    #[wasm_bindgen(js_name = kitCheckPieces)]
    pub fn kit_check_pieces(&self, pieces_json: &str) -> Result<String, JsError> {
        let pieces: Vec<String> =
            serde_json::from_str(pieces_json).map_err(|_| fail(Error::Invalid))?;
        json(&KitPieceOut {
            kit_id: None,
            threshold: None,
            shares: None,
            index: None,
            problem: kit::check_set(&pieces).err().map(|p| p.code()),
        })
    }

    /// Opens a Recovery Kit's wrap of the root key with enough pieces (a JSON array of their text)
    /// and keeps the root key behind a handle for `unlockWithRoot`. Fails for pieces that are not
    /// enough of the kit, and for another kit, account or key version than the wrap's.
    #[wasm_bindgen(js_name = kitOpenRoot)]
    pub fn kit_open_root(
        &mut self,
        pieces_json: &str,
        kit_id: &str,
        account_id: &str,
        key_version: u32,
        wrapped: &str,
    ) -> Result<u32, JsError> {
        let pieces: Vec<String> =
            serde_json::from_str(pieces_json).map_err(|_| fail(Error::Invalid))?;
        let account = ids::parse_uuid(account_id).map_err(fail)?;
        let wrapped = b64::decode(wrapped).map_err(fail)?;
        self.session
            .kit_open_root(&pieces, kit_id, &account, key_version, &wrapped)
            .map_err(fail)
    }

    /// Seals an item of a space's collection: `{ciphertext, itemKey, keyVersion}`, the item key
    /// wrapped under the collection's newest key held and `keyVersion` that key's version.
    #[wasm_bindgen(js_name = sealSpaceItem)]
    pub fn seal_space_item(
        &self,
        space_id: &str,
        collection_id: &str,
        id: &str,
        kind: &str,
        revision: u64,
        item_json: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let id = ids::parse_uuid(id).map_err(fail)?;
        let sealed = self
            .session
            .seal_space_item(
                &space,
                &collection,
                &id,
                kind,
                revision,
                item_json.as_bytes(),
            )
            .map_err(fail)?;
        json(&SealedOut {
            ciphertext: b64::encode(&sealed.ciphertext),
            item_key: b64::encode(&sealed.item_key),
            key_version: sealed.key_version,
        })
    }

    /// Opens an item of a space's collection and returns its JSON. `accepted` says the revision is one
    /// this browser accepted before its key was marked (default true): without it an item under a
    /// marked key is held, not opened. `key_version` is the
    /// collection key version the item says.
    #[wasm_bindgen(js_name = openSpaceItem)]
    #[allow(clippy::too_many_arguments)]
    pub fn open_space_item(
        &self,
        space_id: &str,
        collection_id: &str,
        id: &str,
        kind: &str,
        revision: u64,
        ciphertext: &str,
        item_key: &str,
        key_version: u32,
        accepted: Option<bool>,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let id = ids::parse_uuid(id).map_err(fail)?;
        let ciphertext = b64::decode(ciphertext).map_err(fail)?;
        let item_key = b64::decode(item_key).map_err(fail)?;
        let owner = kemlock_crypto::owner::Owner::space(space);
        let plain = self
            .session
            .open_space_item_as(
                &space,
                &collection,
                &SealedItemRef {
                    id: &id,
                    owner: &owner,
                    kind,
                    revision,
                    ciphertext: &ciphertext,
                    item_key: &item_key,
                    key_version: Some(key_version),
                },
                accepted.unwrap_or(true),
            )
            .map_err(fail)?;
        String::from_utf8(plain.to_vec()).map_err(|_| fail(Error::Invalid))
    }

    /// A new space: `{name, sealedSpaceKey, collection: {name, sealedKey}}`. A fresh space key and
    /// first collection key, both sealed to the unlocked account's own `kx1` key, with both names
    /// under the space key. Needs `unlock` to have been given the sealed private keys.
    #[wasm_bindgen(js_name = newSpace)]
    pub fn new_space(
        &mut self,
        space_id: &str,
        collection_id: &str,
        space_name: &str,
        collection_name: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let made = self
            .session
            .new_space(&space, &collection, space_name, collection_name)
            .map_err(fail)?;
        json(&NewSpaceOut {
            name: b64::encode(&made.name),
            sealed_space_key: b64::encode(&made.sealed_space_key),
            sealed_space_key_signature: b64::encode(&made.sealed_space_key_signature),
            collection: made.collection.into(),
        })
    }

    /// Opens the space key sealed to this account and keeps it for the space at `key_version`.
    /// `unsigned` is for a box that carried no signature: the key then opens names and items only,
    /// and nothing is sealed or written under it.
    #[wasm_bindgen(js_name = openSpace)]
    pub fn open_space(
        &mut self,
        space_id: &str,
        key_version: u32,
        sealed: &str,
        unsigned: Option<bool>,
    ) -> Result<(), JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let sealed = b64::decode(sealed).map_err(fail)?;
        let opened = if unsigned == Some(true) {
            self.session
                .open_space_unsigned(&space, key_version, &sealed)
        } else {
            self.session.open_space(&space, key_version, &sealed)
        };
        opened.map_err(fail)
    }

    /// Opens a collection key sealed to this account and keeps it. `unsigned` as for `openSpace`.
    #[wasm_bindgen(js_name = openCollection)]
    pub fn open_collection(
        &mut self,
        space_id: &str,
        collection_id: &str,
        key_version: u32,
        sealed: &str,
        unsigned: Option<bool>,
    ) -> Result<(), JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let sealed = b64::decode(sealed).map_err(fail)?;
        let opened = if unsigned == Some(true) {
            self.session
                .open_collection_unsigned(&space, &collection, key_version, &sealed)
        } else {
            self.session
                .open_collection(&space, &collection, key_version, &sealed)
        };
        opened.map_err(fail)
    }

    /// Decrypts the name of a space (`kind` `space`), a collection or a group under the space
    /// key of `key_version`, which `openSpace` or `newSpace` must have loaded.
    #[wasm_bindgen(js_name = openName)]
    pub fn open_name(
        &self,
        space_id: &str,
        key_version: u32,
        kind: &str,
        id: &str,
        ciphertext: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let id = ids::parse_uuid(id).map_err(fail)?;
        let ciphertext = b64::decode(ciphertext).map_err(fail)?;
        self.session
            .open_name(
                &space,
                key_version,
                NameKind::parse(kind).map_err(fail)?,
                &id,
                &ciphertext,
            )
            .map_err(fail)
    }

    /// Encrypts a name under the space key of `key_version` (base64url out).
    #[wasm_bindgen(js_name = sealName)]
    pub fn seal_name(
        &self,
        space_id: &str,
        key_version: u32,
        kind: &str,
        id: &str,
        name: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let id = ids::parse_uuid(id).map_err(fail)?;
        let sealed = self
            .session
            .seal_name(
                &space,
                key_version,
                NameKind::parse(kind).map_err(fail)?,
                &id,
                name,
            )
            .map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// A new collection: `{name, sealedKey}`, its key sealed to the unlocked account and its name
    /// under the newest space key held.
    #[wasm_bindgen(js_name = newCollection)]
    pub fn new_collection(
        &mut self,
        space_id: &str,
        collection_id: &str,
        name: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let made = self
            .session
            .new_collection(&space, &collection, name)
            .map_err(fail)?;
        json(&CollectionOut::from(made))
    }

    /// The space key sealed to a member's `kx1` key, context `space-key`, bound to the space, the
    /// key version and the member (`recipient_id`: base64url of their 16-byte account id), so it
    /// opens only as that space's key, and the unlocked account's `sig1` signature over the box
    /// (docs/crypto.md, "Signed key boxes"). Returns `{sealed, signature}`.
    #[wasm_bindgen(js_name = sealSpaceKeyTo)]
    pub fn seal_space_key_to(
        &self,
        space_id: &str,
        recipient_kx1: &str,
        recipient_id: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let recipient = b64::decode(recipient_kx1).map_err(fail)?;
        let recipient_id = b64_id(recipient_id)?;
        let sealed = self
            .session
            .seal_space_key_to(&space, &recipient, &recipient_id)
            .map_err(fail)?;
        json(&SignedBoxOut::from(sealed))
    }

    /// A collection key sealed to a member's `kx1` key, context `collection-key`, bound to the
    /// space, the collection, the key version and the member, and the unlocked account's signature
    /// over the box. Returns `{sealed, signature}`.
    #[wasm_bindgen(js_name = sealCollectionKeyTo)]
    pub fn seal_collection_key_to(
        &self,
        space_id: &str,
        collection_id: &str,
        recipient_kx1: &str,
        recipient_id: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let recipient = b64::decode(recipient_kx1).map_err(fail)?;
        let recipient_id = b64_id(recipient_id)?;
        let sealed = self
            .session
            .seal_collection_key_to(&space, &collection, &recipient, &recipient_id)
            .map_err(fail)?;
        json(&SignedBoxOut::from(sealed))
    }

    /// Whether `signature` is the sealer's `sig1` signature over a key box: the space key's box
    /// (`collection_id` empty) or a collection key's, sealed to `recipient_id` at `key_version`,
    /// under the key in the sealer's bundle (base64url); the sealer's account id and key version are
    /// the bundle's own. Anything malformed is simply `false`.
    #[wasm_bindgen(js_name = verifyKeyBox)]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_key_box(
        &self,
        sealer_bundle: &str,
        space_id: &str,
        collection_id: &str,
        key_version: u32,
        recipient_id: &str,
        sealed: &str,
        signature: &str,
    ) -> bool {
        let (Ok(bundle), Ok(space), Ok(recipient), Ok(sealed), Ok(signature)) = (
            b64::decode(sealer_bundle),
            ids::parse_uuid(space_id),
            b64_id(recipient_id),
            b64::decode(sealed),
            b64::decode(signature),
        ) else {
            return false;
        };
        let collection = if collection_id.is_empty() {
            None
        } else {
            match ids::parse_uuid(collection_id) {
                Ok(collection) => Some(collection),
                Err(_) => return false,
            }
        };
        spaces::verify_key_box(
            &bundle,
            &space,
            collection.as_ref(),
            key_version,
            &recipient,
            &sealed,
            &signature,
        )
    }

    /// A `sig1` signature (base64url, 3,373 bytes) of the unlocked account over a manifest
    /// (base64url of its exact bytes, docs/crypto.md "Signed manifest"), under context
    /// `"manifest"`. Only bytes that parse as a manifest of this account's own vault, or of a
    /// space, are signed.
    #[wasm_bindgen(js_name = manifestSign)]
    pub fn manifest_sign(&self, manifest: &str) -> Result<String, JsError> {
        let manifest = b64::decode(manifest).map_err(fail)?;
        let signature = self.session.sign_manifest(&manifest).map_err(fail)?;
        Ok(b64::encode(&signature))
    }

    /// Whether `signature` is the unlocked account's own `sig1` signature of `manifest`, which
    /// must be of the account's own vault. The key is the account's own, never one the server
    /// served. Anything malformed is simply `false`. A locked vault, or one opened without the
    /// private keys, has no key to check with and gives no verdict at all: it throws `"locked"`,
    /// so the page can tell "could not be verified" from "can not verify".
    #[wasm_bindgen(js_name = manifestVerifyOwn)]
    pub fn manifest_verify_own(&self, manifest: &str, signature: &str) -> Result<bool, JsError> {
        let (Ok(manifest), Ok(signature)) = (b64::decode(manifest), b64::decode(signature)) else {
            return Ok(false);
        };
        match self.session.verify_own_manifest(&manifest, &signature) {
            Ok(()) => Ok(true),
            Err(Error::Locked) => Err(fail(Error::Locked)),
            Err(Error::Invalid) => Ok(false),
        }
    }

    /// Whether `signature` is the `sig1` signature of the space manifest `manifest` under the key
    /// in `signer_bundle` (the page has checked that bundle against the space's members). A
    /// manifest of a person's vault is never accepted here. Anything malformed is `false`.
    #[wasm_bindgen(js_name = manifestVerify)]
    pub fn manifest_verify(&self, signer_bundle: &str, manifest: &str, signature: &str) -> bool {
        let (Ok(bundle), Ok(manifest), Ok(signature)) = (
            b64::decode(signer_bundle),
            b64::decode(manifest),
            b64::decode(signature),
        ) else {
            return false;
        };
        manifests::verify_space_manifest(&bundle, &manifest, &signature).is_ok()
    }

    /// The key version the unlocked account is at, which a signature of its own is checked at; a
    /// signature at an older version is checked against that version's bundle instead.
    #[wasm_bindgen(js_name = ownKeyVersion)]
    pub fn own_key_version(&self) -> Result<u32, JsError> {
        self.session.own_key_version().map_err(fail)
    }

    /// Signs a write of an item as the unlocked account (docs/crypto.md, "Signed item writes").
    /// `fields` is JSON: `{owner, id, kind, revision, deleted, keyVersion, ciphertext?, itemKey?}`
    /// with the base64url `ciphertext` and `itemKey` the write carries (absent on a tombstone).
    /// Answers JSON `{writer, writerKeyVersion, writeSignature}`: the three members the server
    /// takes with the item. Only a write for this account's own vault or a space is signed.
    #[wasm_bindgen(js_name = itemWriteSign)]
    pub fn item_write_sign(&self, fields: &str) -> Result<String, JsError> {
        let fields = item_writes::WriteFields::parse(fields).map_err(fail)?;
        let signed = self.session.sign_item_write(&fields).map_err(fail)?;
        json(&signed)
    }

    /// Whether `signature` (base64url) is the unlocked account's own signature of the write
    /// `fields` (as above, with `writer` and `writerKeyVersion` naming this account). The key is
    /// the account's own, never one the server served. Anything malformed is `false`; a vault
    /// opened without the private keys gives no verdict and throws `"locked"`.
    #[wasm_bindgen(js_name = itemWriteVerifyOwn)]
    pub fn item_write_verify_own(&self, fields: &str, signature: &str) -> Result<bool, JsError> {
        let (Ok(fields), Ok(signature)) = (
            item_writes::WriteFields::parse(fields),
            b64::decode(signature),
        ) else {
            return Ok(false);
        };
        match self.session.verify_own_item_write(&fields, &signature) {
            Ok(()) => Ok(true),
            Err(Error::Locked) => Err(fail(Error::Locked)),
            Err(Error::Invalid) => Ok(false),
        }
    }

    /// Whether `signature` is the signature of the write `fields` by the account whose bundle is
    /// `signer_bundle` (the page has checked that bundle against the space's members), at the
    /// bundle's key version. Anything malformed is `false`.
    #[wasm_bindgen(js_name = itemWriteVerify)]
    pub fn item_write_verify(&self, signer_bundle: &str, fields: &str, signature: &str) -> bool {
        let (Ok(bundle), Ok(fields), Ok(signature)) = (
            b64::decode(signer_bundle),
            item_writes::WriteFields::parse(fields),
            b64::decode(signature),
        ) else {
            return false;
        };
        item_writes::verify_item_write(&bundle, &fields, &signature).is_ok()
    }

    // ---- the space chain (src/chain.rs) -----------------------------------------------------

    /// Verifies the chain the server served for a space and keeps its state. `records` is the
    /// JSON array of wire-form records (`entry`, `signature`, `cosignature` on a `rekey`), and
    /// `anchor` the JSON `{seq, epoch, links}` the page kept for the space, when it did. Answers
    /// JSON: `{ok: false, reason, seq}` for a chain that is refused, or the view of the verified
    /// state (members, collections, groups, grants, key versions, the links to keep as the anchor
    /// and what first contact asks for). Keys open only after first contact.
    #[wasm_bindgen(js_name = verifySpaceChain)]
    pub fn verify_space_chain(
        &mut self,
        space_id: &str,
        records: &str,
        anchor: Option<String>,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let records: Vec<chain::WireIn> =
            serde_json::from_str(records).map_err(|_| fail(Error::Invalid))?;
        let anchor: Option<chain::AnchorIn> = match anchor {
            Some(text) => Some(serde_json::from_str(&text).map_err(|_| fail(Error::Invalid))?),
            None => None,
        };
        let verdict = self
            .session
            .verify_space_chain(&space, &records, anchor.as_ref())
            .map_err(fail)?;
        json(&verdict)
    }

    /// A new space as a chain: JSON `{ok: true, records, seals, names}`, the body of
    /// `POST /kem/v1/spaces/{id}/chain`. The `create` record is signed with this account's
    /// `sig1` key, the space key and the first collection's key are sealed to this account, and
    /// both names are under the space key. No key is kept: the space opens through its chain once
    /// the record is appended. `at` is the time in Unix seconds.
    #[wasm_bindgen(js_name = newChainedSpace)]
    pub fn new_chained_space(
        &self,
        space_id: &str,
        collection_id: &str,
        space_name: &str,
        collection_name: &str,
        at: u32,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let built = self
            .session
            .create_chained_space(
                &space,
                &collection,
                space_name,
                collection_name,
                u64::from(at),
            )
            .map_err(fail)?;
        json(&built)
    }

    /// The records of one change to a chained space, made from the verified state this unlock
    /// holds for it (first contact done) and signed with this account's `sig1` key. `change` is
    /// the JSON of one change (`{action: "invite" | "confirm" | ..., ...}`, see
    /// src/chain_build.rs). Answers JSON: `{ok: true, records, seals, names}`, the body of
    /// `POST /kem/v1/spaces/{id}/chain` (no records when there is nothing to do), or `{ok: false,
    /// reason, seq}` with the verifier's reason when the chain's rules refuse the change.
    #[wasm_bindgen(js_name = buildChainRecords)]
    pub fn build_chain_records(
        &self,
        space_id: &str,
        at: u32,
        change: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let change: chain_build::Change =
            serde_json::from_str(change).map_err(|_| fail(Error::Invalid))?;
        let built = self
            .session
            .build_chain_records(&space, u64::from(at), &change)
            .map_err(fail)?;
        json(&built)
    }

    /// Replaces the keys a removal or an ungrant marked: a `keys` record, and the items of the
    /// replaced collections sealed again under their new key versions. `replacement` is the JSON
    /// `{items: [{id, collection, kind, revision, keyVersion, ciphertext, itemKey}], names:
    /// [{target, sealed}]}`: the space's live items as the server serves them, and, when the space
    /// key is replaced, its sealed names. Answers as `buildChainRecords` does, with `held` (the ids
    /// of the items this account can't re-write) and `writes` beside the records, or no records
    /// when there is nothing this account can replace.
    #[wasm_bindgen(js_name = buildKeyReplacement)]
    pub fn build_key_replacement(
        &self,
        space_id: &str,
        at: u32,
        replacement: &str,
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let replacement: chain_build::Replacement =
            serde_json::from_str(replacement).map_err(|_| fail(Error::Invalid))?;
        let built = self
            .session
            .build_key_replacement(&space, u64::from(at), &replacement)
            .map_err(fail)?;
        json(&built)
    }

    /// Seals again the items still under an older key version than their collection's current
    /// one. `reseal` is the JSON `{items: [{id, collection, kind, revision, keyVersion,
    /// ciphertext, itemKey}]}`. Answers `{ok: true, records: [], seals: [], names: [], writes,
    /// held}`: the writes for the batch route, and the ids this unlock can't seal again.
    #[wasm_bindgen(js_name = buildReseal)]
    pub fn build_reseal(&self, space_id: &str, reseal: &str) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let reseal: chain_build::Reseal =
            serde_json::from_str(reseal).map_err(|_| fail(Error::Invalid))?;
        let built = self.session.build_reseal(&space, &reseal).map_err(fail)?;
        json(&built)
    }

    /// The view of the chain this unlock verified for a space, as `verifySpaceChain` answers it,
    /// or nothing when it hasn't verified one.
    #[wasm_bindgen(js_name = spaceChainView)]
    pub fn space_chain_view(&self, space_id: &str) -> Result<Option<String>, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        self.session.space_chain_view(&space).map_err(fail)
    }

    /// Says the person compared the fingerprint first contact asked for and it matched: the
    /// chain is trusted, and the space's keys may be opened.
    #[wasm_bindgen(js_name = acceptFirstContact)]
    pub fn accept_first_contact(&mut self, space_id: &str) -> Result<(), JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        self.session.accept_first_contact(&space).map_err(fail)
    }

    /// Opens a key of a chained space (`space` or `collection:<uuid>`) at the chain's current
    /// version: `servedVersion` and `sealed` are what the server served for this account, and
    /// `list` the JSON of the server's seal hash list for the record that committed the seal
    /// (`GET /chain/{seq}/seals`) when the chain says it is needed.
    #[wasm_bindgen(js_name = openChainKey)]
    pub fn open_chain_key(
        &mut self,
        space_id: &str,
        key: &str,
        served_version: u32,
        sealed: &str,
        list: Option<String>,
    ) -> Result<(), JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let key = KeyRef::parse(key).ok_or_else(|| fail(Error::Invalid))?;
        let sealed = b64::decode(sealed).map_err(fail)?;
        let entries = match list {
            Some(text) => {
                let items: Vec<chain::SealListIn> =
                    serde_json::from_str(&text).map_err(|_| fail(Error::Invalid))?;
                Some(chain::seal_list(&items, &key, served_version).map_err(fail)?)
            }
            None => None,
        };
        self.session
            .open_chain_key(&space, &key, served_version, &sealed, entries.as_deref())
            .map_err(fail)
    }

    /// Seals a text this browser keeps for the unlocked account (base64url out), bound to `label`.
    #[wasm_bindgen(js_name = sealLocal)]
    pub fn seal_local(&self, label: &str, text: &str) -> Result<String, JsError> {
        let sealed = self
            .session
            .seal_local(label, text.as_bytes())
            .map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// Opens what `sealLocal` sealed under the same label and account; anything else is
    /// `invalid`.
    #[wasm_bindgen(js_name = openLocal)]
    pub fn open_local(&self, label: &str, sealed: &str) -> Result<String, JsError> {
        let sealed = b64::decode(sealed).map_err(fail)?;
        let plain = self.session.open_local(label, &sealed).map_err(fail)?;
        String::from_utf8(plain).map_err(|_| fail(Error::Invalid))
    }

    // ---- rotating the root key (docs/crypto.md, "Rotating the root key"; rotation.rs) ----

    /// Starts a rotation of the open account: a new root key and key pair held in the worker, and
    /// what the server stores of them: `{keyVersion, publicBundle, bundleSignature,
    /// sealedPrivateKeys, sealedPreviousPrivateKeys, fingerprint}`. The account must have been
    /// unlocked with its sealed private keys. A rotation already started is replaced.
    #[wasm_bindgen(js_name = rotationStart)]
    pub fn rotation_start(&mut self) -> Result<String, JsError> {
        let started = self.session.rotation_start().map_err(fail)?;
        json(&RotationStartOut {
            key_version: started.key_version,
            public_bundle: b64::encode(&started.public_bundle),
            bundle_signature: b64::encode(&started.bundle_signature),
            sealed_private_keys: b64::encode(&started.sealed_private_keys),
            sealed_previous_private_keys: b64::encode(&started.sealed_previous_private_keys),
            fingerprint: started.fingerprint,
        })
    }

    /// Moves one item of the account's own vault to the new keys: `{ciphertext, itemKey, revision,
    /// keyVersion, writer, writerKeyVersion, writeSignature}`, at `revision + 1` under a fresh item
    /// key, signed by the new keys as a write of the account.
    #[wasm_bindgen(js_name = rotationResealItem)]
    #[allow(clippy::too_many_arguments)]
    pub fn rotation_reseal_item(
        &self,
        id: &str,
        owner: &str,
        kind: &str,
        revision: u64,
        ciphertext: &str,
        item_key: &str,
        key_version: Option<u32>,
    ) -> Result<String, JsError> {
        let id = ids::parse_uuid(id).map_err(fail)?;
        let owner = ids::parse_owner(owner).map_err(fail)?;
        let ciphertext = b64::decode(ciphertext).map_err(fail)?;
        let item_key = b64::decode(item_key).map_err(fail)?;
        let moved = self
            .session
            .rotation_reseal_item(&SealedItemRef {
                id: &id,
                owner: &owner,
                kind,
                revision,
                ciphertext: &ciphertext,
                item_key: &item_key,
                key_version,
            })
            .map_err(fail)?;
        json(&ResealedItemOut {
            ciphertext: b64::encode(&moved.moved.ciphertext),
            item_key: b64::encode(&moved.moved.item_key),
            revision: moved.moved.revision,
            key_version: moved.key_version,
            writer: moved.signature.writer,
            writer_key_version: moved.signature.writer_key_version,
            write_signature: moved.signature.write_signature,
        })
    }

    /// Moves one Send's sealed key and meta to the new keys: `{sealedKey, meta}`.
    #[wasm_bindgen(js_name = rotationResealSend)]
    pub fn rotation_reseal_send(
        &self,
        id: &str,
        kind: &str,
        sealed_key: &str,
        meta: &str,
    ) -> Result<String, JsError> {
        let id = sends::send_id(id).map_err(fail)?;
        let kind = sends::kind(kind).map_err(fail)?;
        let sealed_key = b64::decode(sealed_key).map_err(fail)?;
        let meta = b64::decode(meta).map_err(fail)?;
        let moved = self
            .session
            .rotation_reseal_send(&id, kind, &sealed_key, &meta)
            .map_err(fail)?;
        json(&ResealedSendOut {
            sealed_key: b64::encode(&moved.sealed_key),
            meta: b64::encode(&moved.meta),
        })
    }

    /// The new root key wrapped under a master key and OPAQUE export key (handles of a fresh
    /// sign-in): base64url of the 92-byte password wrap at the new key version. Consumes both
    /// handles on success.
    #[wasm_bindgen(js_name = rotationWrapPassword)]
    pub fn rotation_wrap_password(
        &mut self,
        master: u32,
        export_key: u32,
    ) -> Result<String, JsError> {
        let wrapped = self
            .session
            .rotation_wrap_password(master, export_key)
            .map_err(fail)?;
        Ok(b64::encode(&wrapped))
    }

    /// The new root key wrapped under a passkey's PRF output and credential id:
    /// `{wrappedKey, keyVersion}` at the new key version.
    #[wasm_bindgen(js_name = rotationPrfWrap)]
    pub fn rotation_prf_wrap(
        &self,
        prf_output: &str,
        credential_id: &str,
    ) -> Result<String, JsError> {
        let prf = b64::decode(prf_output).map_err(fail)?;
        let credential = b64::decode(credential_id).map_err(fail)?;
        let (wrapped, key_version) = self
            .session
            .rotation_prf_wrap(&prf, &credential)
            .map_err(fail)?;
        json(&PrfWrapOut {
            wrapped_key: b64::encode(&wrapped),
            key_version,
        })
    }

    /// A new Recovery Kit for the new root key: `{kitId, pieces, wrappedKey, keyVersion}`.
    #[wasm_bindgen(js_name = rotationKitMake)]
    pub fn rotation_kit_make(&self) -> Result<String, JsError> {
        let made = self.session.rotation_kit_make().map_err(fail)?;
        json(&KitOut {
            kit_id: made.kit_id,
            pieces: made.pieces,
            wrapped_key: b64::encode(&made.wrapped),
            key_version: made.key_version,
        })
    }

    /// The new root key (base64url, 64 bytes), for the worker to seal under this device's own key.
    /// It is never sent to the page.
    #[wasm_bindgen(js_name = rotationExportRoot)]
    pub fn rotation_export_root(&self) -> Result<String, JsError> {
        let root = self.session.rotation_export_root().map_err(fail)?;
        Ok(b64::encode(&*root))
    }

    /// Seals the new root key to a `kx1` public key under `emergency-access` (`aad`: the contact's
    /// account id, 16 bytes) or `account-recovery` (`aad`: space id, account id, `u64be(keySeq)`).
    #[wasm_bindgen(js_name = rotationSealRootKey)]
    pub fn rotation_seal_root_key(
        &self,
        recipient_kx1: &str,
        context: &str,
        aad: &str,
    ) -> Result<String, JsError> {
        let recipient = b64::decode(recipient_kx1).map_err(fail)?;
        let aad = b64::decode(aad).map_err(fail)?;
        let sealed = self
            .session
            .rotation_seal_root_key(&recipient, context, &aad)
            .map_err(fail)?;
        Ok(b64::encode(&sealed))
    }

    /// Makes the new keys the account's. Returns `{keyVersion, fingerprint}`.
    #[wasm_bindgen(js_name = rotationCommit)]
    pub fn rotation_commit(&mut self) -> Result<String, JsError> {
        let (key_version, fingerprint) = self.session.rotation_commit().map_err(fail)?;
        json(&RotationCommitOut {
            key_version,
            fingerprint,
        })
    }

    /// Moves a value this browser keeps for the account (`sealLocal`, base64url) to the new keys, for
    /// the same label: base64url.
    #[wasm_bindgen(js_name = rotationResealLocal)]
    pub fn rotation_reseal_local(&self, label: &str, sealed: &str) -> Result<String, JsError> {
        let sealed = b64::decode(sealed).map_err(fail)?;
        let moved = self
            .session
            .rotation_reseal_local(label, &sealed)
            .map_err(fail)?;
        Ok(b64::encode(&moved))
    }

    /// Forgets a rotation that was started and not committed.
    #[wasm_bindgen(js_name = rotationAbort)]
    pub fn rotation_abort(&mut self) {
        self.session.rotation_abort();
    }

    /// A `sig1` signature over a space-chain signing input, by the key before the last rotation
    /// (`previous`) or the new one: the two signatures of a `rekey` record.
    #[wasm_bindgen(js_name = rotationSign)]
    pub fn rotation_sign(
        &self,
        previous: bool,
        context: &str,
        message: &str,
    ) -> Result<String, JsError> {
        let message = b64::decode(message).map_err(fail)?;
        let signature = self
            .session
            .rotation_sign(previous, context, &message)
            .map_err(fail)?;
        Ok(b64::encode(&signature))
    }

    /// Wipes every secret: all handles and the unlocked account.
    pub fn lock(&mut self) {
        self.session.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_only_their_code() {
        // JsError can only be built on wasm32, so the mapping is checked through the codes.
        assert_eq!(Error::Invalid.code(), "invalid");
        assert_eq!(Error::Locked.code(), "locked");
    }

    #[test]
    fn views_use_the_wire_names() {
        let text = serde_json::to_string(&SealedSend {
            payload: "p".into(),
            meta: "m".into(),
        })
        .expect("json");
        assert_eq!(text, r#"{"payload":"p","meta":"m"}"#);
        let text = serde_json::to_string(&SealedOut {
            ciphertext: "c".into(),
            item_key: "k".into(),
            key_version: 1,
        })
        .expect("json");
        assert_eq!(text, r#"{"ciphertext":"c","itemKey":"k","keyVersion":1}"#);
        let text = serde_json::to_string(&Started {
            state: 3,
            request: "r".into(),
        })
        .expect("json");
        assert_eq!(text, r#"{"state":3,"request":"r"}"#);
        let text = serde_json::to_string(&NewSpaceOut {
            name: "n".into(),
            sealed_space_key: "s".into(),
            sealed_space_key_signature: "t".into(),
            collection: CollectionOut {
                name: "c".into(),
                sealed_key: "k".into(),
                sealed_key_signature: "u".into(),
            },
        })
        .expect("json");
        assert_eq!(
            text,
            r#"{"name":"n","sealedSpaceKey":"s","sealedSpaceKeySignature":"t","collection":{"name":"c","sealedKey":"k","sealedKeySignature":"u"}}"#
        );
        let text = serde_json::to_string(&LoginFinished {
            finalization: "f".into(),
            export_key: 4,
        })
        .expect("json");
        assert_eq!(text, r#"{"finalization":"f","exportKey":4}"#);
    }
}
