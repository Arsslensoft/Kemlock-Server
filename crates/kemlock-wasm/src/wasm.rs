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

use crate::{
    b64,
    error::Error,
    ids, kit, sends,
    session::{self, SealedItemRef, Session},
    sharing::{self, Facts},
    spaces::{NameKind, NewCollection},
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
}

impl From<NewCollection> for CollectionOut {
    fn from(made: NewCollection) -> CollectionOut {
        CollectionOut {
            name: b64::encode(&made.name),
            sealed_key: b64::encode(&made.sealed_key),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewSpaceOut {
    name: String,
    sealed_space_key: String,
    collection: CollectionOut,
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
    /// request id, 32 bytes), `emergency-access` (`aad`: the contact's account id, 16 bytes) or
    /// `account-recovery` (`aad`: space id, account id, `u64be(keySeq)`, 40 bytes; see
    /// `sealRootKeyForRecovery`); no other context is sealed. Returns the box, base64url.
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
    /// `sealed_private_keys` it opens the `kx1` and `sig1` private keys too. Consumes the handle
    /// on success.
    #[wasm_bindgen(js_name = unlockWithRoot)]
    pub fn unlock_with_root(
        &mut self,
        account_id: &str,
        root_handle: u32,
        key_version: u32,
        sealed_private_keys: Option<String>,
    ) -> Result<(), JsError> {
        let account = ids::parse_uuid(account_id).map_err(fail)?;
        let sealed = sealed_private_keys
            .as_deref()
            .map(b64::decode)
            .transpose()
            .map_err(fail)?;
        self.session
            .unlock_with_root(&account, root_handle, key_version, sealed.as_deref())
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

    /// Opens an item of a space's collection and returns its JSON. `key_version` is the
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
    ) -> Result<String, JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let id = ids::parse_uuid(id).map_err(fail)?;
        let ciphertext = b64::decode(ciphertext).map_err(fail)?;
        let item_key = b64::decode(item_key).map_err(fail)?;
        let owner = kemlock_crypto::owner::Owner::space(space);
        let plain = self
            .session
            .open_space_item(
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
            collection: made.collection.into(),
        })
    }

    /// Opens the space key sealed to this account and keeps it for the space at `key_version`.
    #[wasm_bindgen(js_name = openSpace)]
    pub fn open_space(
        &mut self,
        space_id: &str,
        key_version: u32,
        sealed: &str,
    ) -> Result<(), JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let sealed = b64::decode(sealed).map_err(fail)?;
        self.session
            .open_space(&space, key_version, &sealed)
            .map_err(fail)
    }

    /// Opens a collection key sealed to this account and keeps it.
    #[wasm_bindgen(js_name = openCollection)]
    pub fn open_collection(
        &mut self,
        space_id: &str,
        collection_id: &str,
        key_version: u32,
        sealed: &str,
    ) -> Result<(), JsError> {
        let space = ids::parse_uuid(space_id).map_err(fail)?;
        let collection = ids::parse_uuid(collection_id).map_err(fail)?;
        let sealed = b64::decode(sealed).map_err(fail)?;
        self.session
            .open_collection(&space, &collection, key_version, &sealed)
            .map_err(fail)
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

    /// The space key sealed to a member's `kx1` key (base64url), context `space-key`, bound
    /// to the space, the key version and the member (`recipient_id`: base64url of their 16-byte
    /// account id), so it opens only as that space's key.
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
        Ok(b64::encode(&sealed))
    }

    /// A collection key sealed to a member's `kx1` key, context `collection-key`, bound
    /// to the space, the collection, the key version and the member.
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
        Ok(b64::encode(&sealed))
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
            collection: CollectionOut {
                name: "c".into(),
                sealed_key: "k".into(),
            },
        })
        .expect("json");
        assert_eq!(
            text,
            r#"{"name":"n","sealedSpaceKey":"s","collection":{"name":"c","sealedKey":"k"}}"#
        );
        let text = serde_json::to_string(&LoginFinished {
            finalization: "f".into(),
            export_key: 4,
        })
        .expect("json");
        assert_eq!(text, r#"{"finalization":"f","exportKey":4}"#);
    }
}
