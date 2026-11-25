// Written from Bitwarden's clients (https://github.com/bitwarden/clients), at commit
// f9c68e008ba91dc19edf519305a82d3a994a7baa:
//   libs/tools/export/vault-export/vault-export-core/src/services/base-vault-export.service.ts
//   libs/tools/export/vault-export/vault-export-core/src/services/individual-vault-export.service.ts
//   libs/common/src/models/export/{cipher,login,card,identity,field,folder,ssh-key}.export.ts
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Writing Bitwarden's password-protected JSON export: the counterpart of [`bitwarden`]'s reader,
//! so a file made here opens in Bitwarden and Vaultwarden, and back in Kemlock.
//!
//! The file is what Bitwarden's `buildPasswordExport` writes, byte for byte in layout:
//!
//! ```text
//! {
//!   "encrypted": true,
//!   "passwordProtected": true,
//!   "salt": "<16 random bytes, standard base64>",
//!   "kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4,
//!   "encKeyValidation_DO_NOT_EDIT": "2.<iv>|<ct>|<mac>",   (a random GUID, encrypted)
//!   "data": "2.<iv>|<ct>|<mac>"                              (the plain export, encrypted)
//! }
//! ```
//!
//! two-space indented, as `JSON.stringify(doc, null, "  ")` prints it. The key is
//! [`derive_export_key`] (the KDF, then HKDF-Expand with `enc` and `mac`), and each value an
//! `EncString` of type 2 (AES-256-CBC, HMAC-SHA256 over IV and ciphertext). `kdfMemory` and
//! `kdfParallelism` are left out for PBKDF2, as Bitwarden leaves them out.
//!
//! The plain export inside is Bitwarden's individual-vault JSON (`encrypted: false`, `folders`,
//! `items`), its keys in the order Bitwarden's exporters print them. A Kemlock export is the same
//! file with one more top-level member, `kemlock`, that holds every item of every kind exactly as
//! Kemlock stores it; Bitwarden ignores it, Kemlock's own reader uses the Bitwarden part, and the
//! `kemlock` member is there for a reader that wants every field.
//!
//! The crate is pure Rust with no source of randomness: the caller hands over an [`Entropy`].
//!
//! [`bitwarden`]: crate::bitwarden

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::bwcrypto::{Kdf, derive_export_key, encrypt_enc_string};
use crate::error::{ImportError, Result};
use crate::passkey::{decode_base64_any, encode_base64, encode_base64url};
use crate::util::{is_blank, jarr, jbool, jint, jstr, scalar_text};

/// The KDF a new export records unless the caller asks for another: Argon2id, 3 passes, 64 MiB,
/// 4 lanes, which is what a Kemlock account's master key uses and what Bitwarden's Argon2id
/// default is.
pub const DEFAULT_KDF: Kdf = Kdf::Argon2id {
    iterations: 3,
    memory_mib: 64,
    parallelism: 4,
};

/// The random bytes an export needs, so the writer itself needs no random source.
#[derive(Clone, PartialEq, Eq)]
pub struct Entropy {
    /// The export's salt.
    pub salt: [u8; 16],
    /// The bytes of the GUID encrypted as `encKeyValidation_DO_NOT_EDIT`.
    pub validation_guid: [u8; 16],
    /// The IV of the validation string.
    pub validation_iv: [u8; 16],
    /// The IV of the data.
    pub data_iv: [u8; 16],
}

impl Entropy {
    /// Fills the four values from `fill`, which writes random bytes into its argument.
    pub fn from_fn(mut fill: impl FnMut(&mut [u8])) -> Entropy {
        let mut entropy = Entropy {
            salt: [0; 16],
            validation_guid: [0; 16],
            validation_iv: [0; 16],
            data_iv: [0; 16],
        };
        fill(&mut entropy.salt);
        fill(&mut entropy.validation_guid);
        fill(&mut entropy.validation_iv);
        fill(&mut entropy.data_iv);
        entropy
    }
}

impl std::fmt::Debug for Entropy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entropy(..)")
    }
}

/// Which file to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// Bitwarden's password-protected JSON.
    Bitwarden,
    /// The same file with a `kemlock` member holding every item as Kemlock stores it.
    Kemlock,
}

/// One item of a vault as Kemlock holds it: its id, its kind and its plaintext JSON object.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ExportItem {
    /// The item's id.
    pub id: String,
    /// The item's kind: `login`, `otp`, `note`, `card`, `identity`, `ssh-key` and the rest.
    pub kind: String,
    /// The item's JSON object.
    pub data: Value,
}

/// Reads the items an export is made from: a JSON array of `{ id, kind, data }`.
pub fn parse_items(json: &str) -> Result<Vec<ExportItem>> {
    serde_json::from_str(json)
        .map_err(|_| ImportError::malformed("the items to export are not a list"))
}

/// Writes the password-protected export of `items` with [`DEFAULT_KDF`].
pub fn write(
    kind: ExportKind,
    items: &[ExportItem],
    password: &str,
    entropy: &Entropy,
) -> Result<String> {
    write_with(kind, items, password, DEFAULT_KDF, entropy)
}

/// [`write`] with a chosen KDF, which must be within the bounds an import accepts.
pub fn write_with(
    kind: ExportKind,
    items: &[ExportItem],
    password: &str,
    kdf: Kdf,
    entropy: &Entropy,
) -> Result<String> {
    let clear = plain_json(kind, items)?;
    protect(&clear, password, kdf, entropy)
}

// ---------------------------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Protected {
    encrypted: bool,
    password_protected: bool,
    salt: String,
    kdf_type: u8,
    kdf_iterations: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: String,
    data: String,
}

/// Bitwarden's `Utils.newGuid()` text from 16 random bytes: a version 4 GUID.
fn guid_text(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Encrypts `clear_text` under `password` as Bitwarden's password-protected export.
pub fn protect(clear_text: &str, password: &str, kdf: Kdf, entropy: &Entropy) -> Result<String> {
    if is_blank(password) {
        return Err(ImportError::PasswordRequired);
    }
    // The same bounds an import holds an export to, so what is written can be read back.
    kdf_in_bounds(kdf)?;
    let salt = encode_base64(&entropy.salt);
    let key = derive_export_key(password, &salt, kdf)?;
    let validation = encrypt_enc_string(
        guid_text(entropy.validation_guid).as_bytes(),
        &key,
        &entropy.validation_iv,
    )?;
    let data = encrypt_enc_string(clear_text.as_bytes(), &key, &entropy.data_iv)?;
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) = match kdf {
        Kdf::Pbkdf2 { iterations } => (0, iterations, None, None),
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => (1, iterations, Some(memory_mib), Some(parallelism)),
    };
    to_text(&Protected {
        encrypted: true,
        password_protected: true,
        salt,
        kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        enc_key_validation: validation,
        data,
    })
}

fn kdf_in_bounds(kdf: Kdf) -> Result<()> {
    use crate::bwcrypto::{MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_MIB, MIN_PBKDF2_ITERATIONS};
    let limits = crate::limits::Limits::default();
    let ok = match kdf {
        Kdf::Pbkdf2 { iterations } => {
            (MIN_PBKDF2_ITERATIONS..=limits.max_pbkdf2_iterations).contains(&iterations)
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            (MIN_ARGON2_ITERATIONS..=limits.max_argon2_iterations).contains(&iterations)
                && (MIN_ARGON2_MEMORY_MIB..=limits.max_argon2_memory_kib / 1024)
                    .contains(&memory_mib)
                && (1..=limits.max_argon2_parallelism).contains(&parallelism)
        }
    };
    if ok {
        Ok(())
    } else {
        Err(ImportError::KdfOutOfBounds)
    }
}

/// `JSON.stringify(value, null, "  ")`.
fn to_text<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value)
        .map_err(|_| ImportError::malformed("the export can't be written"))
}

// ---------------------------------------------------------------------------------------------
// The plain export
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct Plain {
    encrypted: bool,
    folders: Vec<FolderOut>,
    items: Vec<ItemOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kemlock: Option<KemlockOut>,
}

#[derive(Serialize)]
struct KemlockOut {
    version: u32,
    items: Vec<KemlockItem>,
}

#[derive(Serialize)]
struct KemlockItem {
    id: String,
    kind: String,
    data: Value,
}

#[derive(Serialize)]
struct FolderOut {
    id: String,
    name: String,
}

/// One item in the order Bitwarden's `CipherExport` prints its keys.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemOut {
    password_history: Option<Vec<HistoryOut>>,
    revision_date: Option<String>,
    creation_date: Option<String>,
    deleted_date: Option<String>,
    id: String,
    organization_id: Option<String>,
    folder_id: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
    reprompt: u8,
    name: String,
    notes: Option<String>,
    favorite: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<FieldOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<LoginOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_note: Option<SecureNoteOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<CardOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_key: Option<SshKeyOut>,
    collection_ids: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryOut {
    last_used_date: Option<String>,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldOut {
    name: String,
    value: String,
    #[serde(rename = "type")]
    kind: u8,
    linked_id: Option<u32>,
}

#[derive(Serialize)]
struct LoginOut {
    uris: Vec<UriOut>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(rename = "fido2Credentials", skip_serializing_if = "Vec::is_empty")]
    fido2_credentials: Vec<PasskeyOut>,
}

#[derive(Serialize)]
struct UriOut {
    #[serde(rename = "match")]
    match_rule: Option<u8>,
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyOut {
    credential_id: String,
    key_type: &'static str,
    key_algorithm: &'static str,
    key_curve: &'static str,
    key_value: String,
    rp_id: String,
    rp_name: Option<String>,
    user_handle: String,
    user_name: String,
    user_display_name: Option<String>,
    counter: &'static str,
    discoverable: &'static str,
    creation_date: Option<String>,
}

#[derive(Serialize)]
struct SecureNoteOut {
    #[serde(rename = "type")]
    kind: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CardOut {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityOut {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SshKeyOut {
    private_key: String,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

/// The plain export of `items`, as Bitwarden's individual-vault JSON export prints it.
pub fn plain_json(kind: ExportKind, items: &[ExportItem]) -> Result<String> {
    let mut folders = Folders::default();
    let mut out: Vec<ItemOut> = Vec::with_capacity(items.len());

    // A code linked to a login in this export, one that has no one-time password of its own,
    // becomes that login's one-time-password field (the first such code only); every other code is
    // a login of its own, as Bitwarden has no item that is only a code.
    let logins_without_totp: BTreeSet<&str> = items
        .iter()
        .filter(|i| i.kind == "login" && text(&i.data, "totp").is_none())
        .map(|i| i.id.as_str())
        .collect();
    let mut linked: BTreeMap<String, String> = BTreeMap::new();
    let mut folded: BTreeSet<&str> = BTreeSet::new();
    for item in items {
        if item.kind == "otp"
            && let Some(login) = text(&item.data, "linkedLoginId")
            && logins_without_totp.contains(login.as_str())
            && !linked.contains_key(&login)
            && let Some(secret) = text(&item.data, "secret")
        {
            linked.insert(login, secret);
            folded.insert(item.id.as_str());
        }
    }

    for item in items {
        if folded.contains(item.id.as_str()) {
            continue;
        }
        out.push(item_out(item, &mut folders, linked.get(&item.id)));
    }

    let kemlock = (kind == ExportKind::Kemlock).then(|| KemlockOut {
        version: 1,
        items: items
            .iter()
            .map(|i| KemlockItem {
                id: i.id.clone(),
                kind: i.kind.clone(),
                data: i.data.clone(),
            })
            .collect(),
    });
    to_text(&Plain {
        encrypted: false,
        folders: folders.into_list(),
        items: out,
        kemlock,
    })
}

/// Folders as Bitwarden has them: one entry per path, each with a GUID. The GUID is derived from
/// the path, so the same export of the same vault names its folders the same.
#[derive(Default)]
struct Folders {
    by_path: BTreeMap<String, String>,
    order: Vec<String>,
}

impl Folders {
    fn id_of(&mut self, path: &str) -> String {
        if let Some(id) = self.by_path.get(path) {
            return id.clone();
        }
        let digest = Sha256::digest(format!("kemlock/v1/export-folder{path}").as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        let id = guid_text(bytes);
        self.by_path.insert(path.to_string(), id.clone());
        self.order.push(path.to_string());
        id
    }

    fn into_list(self) -> Vec<FolderOut> {
        self.order
            .into_iter()
            .filter_map(|path| {
                let id = self.by_path.get(&path)?.clone();
                Some(FolderOut { id, name: path })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// One item
// ---------------------------------------------------------------------------------------------

/// A non-blank text member of a JSON object.
fn text(data: &Value, key: &str) -> Option<String> {
    jstr(data, key)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

/// A text member that may be written as a number (a card's month, say).
fn scalar(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(scalar_text)
        .filter(|s| !s.trim().is_empty())
}

fn rule_number(value: &Value) -> Option<u8> {
    value
        .as_i64()
        .and_then(|n| u8::try_from(n).ok())
        .filter(|n| *n <= 5)
}

fn uris_of(data: &Value) -> Vec<UriOut> {
    let mut out = Vec::new();
    if let Some(list) = data.get("uris").and_then(Value::as_array) {
        for entry in list {
            match entry {
                Value::String(uri) if !is_blank(uri) => out.push(UriOut {
                    match_rule: None,
                    uri: uri.clone(),
                }),
                Value::Object(_) => {
                    if let Some(uri) = jstr(entry, "uri").filter(|u| !is_blank(u)) {
                        out.push(UriOut {
                            match_rule: entry.get("match").and_then(rule_number),
                            uri: uri.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
        return out;
    }
    for key in ["urls", "websites"] {
        let list: Vec<&str> = jarr(data, key).iter().filter_map(Value::as_str).collect();
        if !list.is_empty() {
            return list
                .into_iter()
                .filter(|u| !is_blank(u))
                .map(|uri| UriOut {
                    match_rule: None,
                    uri: uri.to_string(),
                })
                .collect();
        }
    }
    out
}

fn field_kind(name: &str) -> u8 {
    match name {
        "hidden" => 1,
        "boolean" => 2,
        "linked" => 3,
        _ => 0,
    }
}

fn fields_of(data: &Value) -> Vec<FieldOut> {
    jarr(data, "fields")
        .iter()
        .filter_map(|f| {
            let name = jstr(f, "name").unwrap_or("");
            let value = f.get("value").and_then(scalar_text).unwrap_or_default();
            if name.is_empty() && value.is_empty() {
                return None;
            }
            Some(FieldOut {
                name: name.to_string(),
                value,
                kind: field_kind(jstr(f, "kind").unwrap_or("text")),
                linked_id: None,
            })
        })
        .collect()
}

fn history_of(data: &Value) -> Option<Vec<HistoryOut>> {
    let list: Vec<HistoryOut> = jarr(data, "passwordHistory")
        .iter()
        .filter_map(|h| {
            Some(HistoryOut {
                last_used_date: text(h, "replacedAt"),
                password: text(h, "password")?,
            })
        })
        .collect();
    (!list.is_empty()).then_some(list)
}

/// A passkey as Bitwarden's `fido2Credentials` holds it. A 16-byte credential id is written as a
/// GUID and any other as `b64.` and base64url; the key is PKCS#8 in base64url. Only ES256 keys,
/// which are the only ones Kemlock keeps.
fn passkeys_of(data: &Value) -> Vec<PasskeyOut> {
    jarr(data, "passkeys")
        .iter()
        .filter_map(|p| {
            if jint(p, "algorithm").is_some_and(|a| a != -7) {
                return None;
            }
            let id = decode_base64_any(jstr(p, "credentialId")?)?;
            let key = decode_base64_any(jstr(p, "privateKey")?)?;
            let handle = decode_base64_any(jstr(p, "userHandle")?)?;
            let credential_id = match <[u8; 16]>::try_from(id.as_slice()) {
                Ok(bytes) => guid_of(bytes),
                Err(_) => format!("b64.{}", encode_base64url(&id)),
            };
            Some(PasskeyOut {
                credential_id,
                key_type: "public-key",
                key_algorithm: "ECDSA",
                key_curve: "P-256",
                key_value: encode_base64url(&key),
                rp_id: jstr(p, "rpId")?.to_string(),
                rp_name: text(p, "rpName"),
                user_handle: encode_base64url(&handle),
                user_name: jstr(p, "userName").unwrap_or("").to_string(),
                user_display_name: text(p, "userDisplayName"),
                counter: "0",
                discoverable: "true",
                creation_date: text(p, "createdAt"),
            })
        })
        .collect()
}

/// A GUID's text from its 16 bytes as they are, with no version bits changed: it is an id the
/// authenticator made, not one made here.
fn guid_of(bytes: [u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn card_of(data: &Value) -> CardOut {
    CardOut {
        cardholder_name: text(data, "cardholder"),
        brand: text(data, "brand"),
        number: text(data, "number"),
        exp_month: scalar(data, "expMonth"),
        exp_year: scalar(data, "expYear"),
        code: text(data, "code"),
    }
}

fn identity_of(data: &Value) -> IdentityOut {
    let address = data.get("address").filter(|a| a.is_object());
    let line = |n: usize| {
        address.and_then(|a| {
            jarr(a, "lines")
                .get(n)
                .and_then(Value::as_str)
                .filter(|l| !is_blank(l))
                .map(str::to_string)
        })
    };
    let part = |key: &str| address.and_then(|a| text(a, key));
    let document = |kinds: &[&str]| {
        jarr(data, "documents")
            .iter()
            .find(|d| jstr(d, "kind").is_some_and(|k| kinds.contains(&k)))
            .and_then(|d| text(d, "number"))
    };
    IdentityOut {
        title: text(data, "title"),
        first_name: text(data, "firstName"),
        middle_name: text(data, "middleName"),
        last_name: text(data, "lastName"),
        address1: line(0),
        address2: line(1),
        address3: line(2),
        city: part("city"),
        state: part("region"),
        postal_code: part("postalCode"),
        country: part("country"),
        company: text(data, "company"),
        email: text(data, "email"),
        phone: text(data, "phone"),
        ssn: document(&["tax-number"]),
        username: text(data, "username"),
        passport_number: document(&["passport"]),
        license_number: document(&["drivers-licence"]),
    }
}

/// A kind Bitwarden has no item for, written as a secure note that keeps what it held: the notes
/// or text, and every other plain value as a custom field. Not the files (`file`, `attachments`):
/// each holds the key of a file, and an export carries no file bytes; and not `links`, which name
/// items by an id that means nothing to Bitwarden.
fn note_of_other(data: &Value, fields: &mut Vec<FieldOut>) -> Option<String> {
    let notes = text(data, "notes").or_else(|| text(data, "text"));
    if let Value::Object(map) = data {
        for (key, value) in map {
            if matches!(
                key.as_str(),
                "name"
                    | "notes"
                    | "text"
                    | "folder"
                    | "favorite"
                    | "createdAt"
                    | "updatedAt"
                    | "fields"
                    | "file"
                    | "attachments"
                    | "links"
            ) {
                continue;
            }
            let shown = match value {
                Value::String(s) if !s.is_empty() => s.clone(),
                Value::Number(_) | Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
                    value.to_string()
                }
                _ => continue,
            };
            fields.push(FieldOut {
                name: key.clone(),
                value: shown,
                kind: 1,
                linked_id: None,
            });
        }
    }
    notes
}

/// The note a File item becomes: its own notes, then a line naming the file and saying that the
/// export holds no file bytes. The file's key and its place on the server are not written.
fn file_note(data: &Value, notes: Option<String>) -> String {
    let entry = data.get("file");
    let name = entry
        .and_then(|file| text(file, "name"))
        .or_else(|| text(data, "name"))
        .unwrap_or_else(|| "a file".to_string());
    let said = format!("The file {name} is not included: an export holds no file bytes.");
    match notes {
        Some(notes) => format!("{notes}

{said}"),
        None => said,
    }
}

fn item_out(item: &ExportItem, folders: &mut Folders, linked_totp: Option<&String>) -> ItemOut {
    let data = &item.data;
    let mut fields = fields_of(data);
    let mut notes = text(data, "notes");
    let mut base = ItemOut {
        password_history: None,
        revision_date: text(data, "updatedAt"),
        creation_date: text(data, "createdAt"),
        deleted_date: None,
        id: item.id.clone(),
        organization_id: None,
        folder_id: text(data, "folder").map(|path| folders.id_of(&path)),
        kind: 1,
        reprompt: 0,
        name: text(data, "name").unwrap_or_else(|| "--".to_string()),
        notes: None,
        favorite: jbool(data, "favorite").unwrap_or(false),
        fields: Vec::new(),
        login: None,
        secure_note: None,
        card: None,
        identity: None,
        ssh_key: None,
        collection_ids: None,
    };
    match item.kind.as_str() {
        "login" => {
            base.password_history = history_of(data);
            base.login = Some(LoginOut {
                uris: uris_of(data),
                username: text(data, "username"),
                password: text(data, "password"),
                totp: text(data, "totp").or_else(|| linked_totp.cloned()),
                fido2_credentials: passkeys_of(data),
            });
        }
        "otp" => {
            // A code of its own: a login that holds only the secret.
            base.login = Some(LoginOut {
                uris: Vec::new(),
                username: text(data, "label"),
                password: None,
                totp: text(data, "secret"),
                fido2_credentials: Vec::new(),
            });
        }
        "note" => {
            base.kind = 2;
            notes = text(data, "text").or(notes);
            base.secure_note = Some(SecureNoteOut { kind: 0 });
        }
        "card" => {
            base.kind = 3;
            base.card = Some(card_of(data));
            if let Some(value) = text(data, "pin") {
                fields.push(FieldOut {
                    name: "PIN".to_string(),
                    value,
                    kind: 1,
                    linked_id: None,
                });
            }
            let from = [
                scalar(data, "validFromMonth"),
                scalar(data, "validFromYear"),
            ];
            if let [Some(month), Some(year)] = from {
                fields.push(FieldOut {
                    name: "Valid from".to_string(),
                    value: format!("{month}/{year}"),
                    kind: 0,
                    linked_id: None,
                });
            }
        }
        "identity" => {
            base.kind = 4;
            base.identity = Some(identity_of(data));
            if let Some(birth) = text(data, "birthDate") {
                fields.push(FieldOut {
                    name: "Birth date".to_string(),
                    value: birth,
                    kind: 0,
                    linked_id: None,
                });
            }
        }
        "ssh-key" if text(data, "privateKey").is_some() => {
            base.kind = 5;
            base.ssh_key = Some(SshKeyOut {
                private_key: text(data, "privateKey").unwrap_or_default(),
                public_key: text(data, "publicKey"),
                key_fingerprint: text(data, "fingerprint"),
            });
        }
        "file" => {
            // A file's bytes are not in an export, so the item becomes a note that says so.
            base.kind = 2;
            base.secure_note = Some(SecureNoteOut { kind: 0 });
            notes = Some(file_note(data, note_of_other(data, &mut fields)));
        }
        _ => {
            base.kind = 2;
            base.secure_note = Some(SecureNoteOut { kind: 0 });
            notes = note_of_other(data, &mut fields);
        }
    }
    base.fields = fields;
    base.notes = notes;
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, Limits, bitwarden, model::Format};
    use serde_json::json;

    const PASSWORD: &str = "correct horse";

    fn entropy() -> Entropy {
        let mut next = 0u8;
        Entropy::from_fn(|buf| {
            for byte in buf {
                *byte = next;
                next = next.wrapping_add(1);
            }
        })
    }

    /// The smallest Argon2id an export may record, so the tests stay quick.
    const FAST: Kdf = Kdf::Argon2id {
        iterations: 2,
        memory_mib: 16,
        parallelism: 1,
    };
    const PBKDF2: Kdf = Kdf::Pbkdf2 { iterations: 5000 };

    fn item(id: &str, kind: &str, data: Value) -> ExportItem {
        ExportItem {
            id: id.to_string(),
            kind: kind.to_string(),
            data,
        }
    }

    fn vault() -> Vec<ExportItem> {
        vec![
            item(
                "11111111-1111-4111-8111-111111111111",
                "login",
                json!({
                    "name": "Example Mail",
                    "username": "ada",
                    "password": "pw-now",
                    "notes": "a note",
                    "folder": "Work/Projects",
                    "favorite": true,
                    "createdAt": "2023-01-02T03:04:05.000Z",
                    "updatedAt": "2024-01-02T03:04:05.678Z",
                    "uris": [{"uri": "https://mail.example.com"}, {"uri": "https://alt.example.com", "match": 3}],
                    "fields": [{"name": "pin", "value": "1234", "kind": "hidden"}],
                    "passwordHistory": [{"password": "old", "replacedAt": "2023-06-01T00:00:00.000Z"}],
                }),
            ),
            item(
                "22222222-2222-4222-8222-222222222222",
                "otp",
                json!({
                    "name": "Example Mail",
                    "secret": "JBSWY3DPEHPK3PXP",
                    "linkedLoginId": "11111111-1111-4111-8111-111111111111"
                }),
            ),
            item(
                "33333333-3333-4333-8333-333333333333",
                "otp",
                json!({"name": "Alone", "secret": "MFRGGZDFMZTWQ2LK", "label": "me"}),
            ),
            item(
                "44444444-4444-4444-8444-444444444444",
                "note",
                json!({"name": "Wifi", "text": "the password is on the fridge"}),
            ),
            item(
                "55555555-5555-4555-8555-555555555555",
                "card",
                json!({"name": "Visa", "cardholder": "Ada L", "number": "4111111111111111",
                       "expMonth": 3, "expYear": 2030, "code": "123", "pin": "9999"}),
            ),
            item(
                "66666666-6666-4666-8666-666666666666",
                "identity",
                json!({"name": "Me", "firstName": "Ada", "lastName": "Lovelace", "email": "ada@example.com",
                       "address": {"lines": ["1 Main St", "Flat 2"], "city": "London", "postalCode": "N1", "country": "GB"},
                       "documents": [{"kind": "passport", "number": "P123"}]}),
            ),
            item(
                "77777777-7777-4777-8777-777777777777",
                "ssh-key",
                json!({"name": "Laptop", "privateKey": "-----BEGIN-----", "publicKey": "ssh-ed25519 AAAA"}),
            ),
            item(
                "88888888-8888-4888-8888-888888888888",
                "backup-codes",
                json!({"name": "Codes", "codes": ["a", "b"], "notes": "kept offline"}),
            ),
        ]
    }

    fn read_back(text: &str) -> crate::ImportBatch {
        let limits = Limits::default();
        let ctx = Context::new(&limits).with_password(PASSWORD);
        bitwarden::parse(text.as_bytes(), &ctx).expect("the export reads back")
    }

    #[test]
    fn the_envelope_has_bitwardens_keys_in_bitwardens_order() {
        let text =
            write_with(ExportKind::Bitwarden, &vault(), PASSWORD, FAST, &entropy()).expect("write");
        let keys: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("  \""))
            .map(|l| l.trim_start().split('"').nth(1).expect("a key"))
            .collect();
        assert_eq!(
            keys,
            [
                "encrypted",
                "passwordProtected",
                "salt",
                "kdfType",
                "kdfIterations",
                "kdfMemory",
                "kdfParallelism",
                "encKeyValidation_DO_NOT_EDIT",
                "data"
            ]
        );
        assert!(text.starts_with("{\n  \"encrypted\": true,\n  \"passwordProtected\": true,\n"));
        // The salt is the standard base64 of the 16 bytes handed over, padding included.
        assert!(text.contains("\"salt\": \"AAECAwQFBgcICQoLDA0ODw==\","));
        assert!(text.contains("\"kdfType\": 1,\n  \"kdfIterations\": 2,\n  \"kdfMemory\": 16,\n  \"kdfParallelism\": 1,"));
        assert!(
            !text.ends_with('\n'),
            "JSON.stringify adds no trailing newline"
        );
    }

    #[test]
    fn pbkdf2_exports_leave_out_the_argon2_members() {
        let text = write_with(
            ExportKind::Bitwarden,
            &vault(),
            PASSWORD,
            PBKDF2,
            &entropy(),
        )
        .expect("write");
        assert!(text.contains(
            "\"kdfType\": 0,\n  \"kdfIterations\": 5000,\n  \"encKeyValidation_DO_NOT_EDIT\""
        ));
        assert!(!text.contains("kdfMemory"));
        assert!(!text.contains("kdfParallelism"));
        assert_eq!(read_back(&text).logins.len(), 2);
    }

    #[test]
    fn an_export_is_a_pure_function_of_its_inputs() {
        let a =
            write_with(ExportKind::Bitwarden, &vault(), PASSWORD, FAST, &entropy()).expect("write");
        let b =
            write_with(ExportKind::Bitwarden, &vault(), PASSWORD, FAST, &entropy()).expect("write");
        assert_eq!(a, b);
        let other = Entropy::from_fn(|buf| buf.fill(9));
        let c = write_with(ExportKind::Bitwarden, &vault(), PASSWORD, FAST, &other).expect("write");
        assert_ne!(a, c);
    }

    #[test]
    fn the_validation_string_is_an_encrypted_guid() {
        let text =
            write_with(ExportKind::Bitwarden, &[], PASSWORD, FAST, &entropy()).expect("write");
        let root: Value = serde_json::from_str(&text).expect("json");
        let salt = jstr(&root, "salt").expect("salt");
        let key = derive_export_key(PASSWORD, salt, FAST).expect("key");
        let validation = crate::bwcrypto::decrypt_enc_text(
            jstr(&root, "encKeyValidation_DO_NOT_EDIT").expect("validation"),
            &key,
        )
        .expect("opens");
        assert_eq!(validation, guid_text(entropy().validation_guid));
        assert_eq!(validation.len(), 36);
        assert_eq!(&validation[14..15], "4");
        assert!(matches!(&validation[19..20], "8" | "9" | "a" | "b"));
        let plain = crate::bwcrypto::decrypt_enc_text(jstr(&root, "data").expect("data"), &key)
            .expect("data");
        assert_eq!(
            plain,
            "{\n  \"encrypted\": false,\n  \"folders\": [],\n  \"items\": []\n}"
        );
    }

    #[test]
    fn a_wrong_password_does_not_open_it() {
        let text =
            write_with(ExportKind::Bitwarden, &vault(), PASSWORD, FAST, &entropy()).expect("write");
        let limits = Limits::default();
        let ctx = Context::new(&limits).with_password("wrong");
        assert_eq!(
            bitwarden::parse(text.as_bytes(), &ctx),
            Err(ImportError::BadPassword)
        );
    }

    #[test]
    fn it_reads_back_into_every_kind() {
        let text =
            write_with(ExportKind::Bitwarden, &vault(), PASSWORD, FAST, &entropy()).expect("write");
        let batch = read_back(&text);
        assert_eq!(batch.format, Format::BitwardenJson);

        // The mail login, with its linked code folded in, and the code on its own as a login.
        assert_eq!(batch.logins.len(), 2);
        let mail = &batch.logins[0];
        assert_eq!(mail.name, "Example Mail");
        assert_eq!(mail.username.as_deref(), Some("ada"));
        assert_eq!(mail.password.as_deref(), Some("pw-now"));
        assert_eq!(mail.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(mail.notes.as_deref(), Some("a note"));
        assert_eq!(mail.uris.len(), 2);
        assert_eq!(mail.uris[1].match_rule, Some(crate::model::UriMatch::Exact));
        assert_eq!(mail.fields[0].name, "pin");
        assert_eq!(mail.fields[0].kind, crate::model::FieldKind::Hidden);
        assert_eq!(mail.previous_passwords[0].password, "old");
        assert!(mail.meta.favorite);
        assert_eq!(mail.meta.created_ms, Some(1_672_628_645_000));
        assert_eq!(mail.meta.modified_ms, Some(1_704_164_645_678));
        assert_eq!(
            batch.folders[mail.meta.folder.expect("folder")].path,
            "Work/Projects"
        );
        let alone = &batch.logins[1];
        assert_eq!(alone.name, "Alone");
        assert_eq!(alone.totp.as_deref(), Some("MFRGGZDFMZTWQ2LK"));
        assert_eq!(alone.username.as_deref(), Some("me"));

        // Notes, including the kind Bitwarden has no item for.
        assert_eq!(batch.notes.len(), 2);
        assert_eq!(
            batch.notes[0].text.as_deref(),
            Some("the password is on the fridge")
        );
        assert_eq!(batch.notes[1].name, "Codes");
        assert_eq!(batch.notes[1].text.as_deref(), Some("kept offline"));
        assert!(batch.notes[1].fields.iter().any(|f| f.name == "codes"));

        let card = &batch.cards[0];
        assert_eq!(card.cardholder.as_deref(), Some("Ada L"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.exp_month, Some(3));
        assert_eq!(card.exp_year, Some(2030));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert!(card.fields.iter().any(|f| f.name == "PIN"));

        let me = &batch.identities[0];
        assert_eq!(me.given_name.as_deref(), Some("Ada"));
        assert_eq!(me.family_name.as_deref(), Some("Lovelace"));
        let address = me.address.as_ref().expect("address");
        assert_eq!(address.lines, ["1 Main St", "Flat 2"]);
        assert_eq!(address.city.as_deref(), Some("London"));
        assert_eq!(me.documents[0].number.as_deref(), Some("P123"));

        let key = &batch.ssh_keys[0];
        assert_eq!(key.private_key, "-----BEGIN-----");
        assert_eq!(key.public_key.as_deref(), Some("ssh-ed25519 AAAA"));
        assert!(batch.skipped.is_empty(), "{:?}", batch.skipped);
    }

    #[test]
    fn a_kemlock_export_keeps_every_item_beside_the_bitwarden_part() {
        let items = vault();
        let clear = plain_json(ExportKind::Kemlock, &items).expect("plain");
        let root: Value = serde_json::from_str(&clear).expect("json");
        assert_eq!(root["kemlock"]["version"], 1);
        assert_eq!(
            root["kemlock"]["items"].as_array().map(Vec::len),
            Some(items.len())
        );
        assert_eq!(root["kemlock"]["items"][7]["kind"], "backup-codes");
        assert_eq!(
            root["kemlock"]["items"][1]["data"]["linkedLoginId"],
            "11111111-1111-4111-8111-111111111111"
        );
        // The Bitwarden part is the one a Bitwarden export has.
        assert_eq!(root["encrypted"], false);
        assert!(root["items"].is_array() && root["folders"].is_array());
        let bitwarden_only = plain_json(ExportKind::Bitwarden, &items).expect("plain");
        assert!(!bitwarden_only.contains("\"kemlock\""));

        let text =
            write_with(ExportKind::Kemlock, &items, PASSWORD, FAST, &entropy()).expect("write");
        assert_eq!(read_back(&text).logins.len(), 2);
    }

    #[test]
    fn a_file_is_a_note_that_says_its_bytes_are_not_included_and_no_key_leaves() {
        let items = vec![
            item(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "file",
                json!({
                    "name": "Lease",
                    "notes": "Signed",
                    "file": {
                        "id": "abc",
                        "name": "Lease agreement.pdf",
                        "size": 12,
                        "key": "SECRETKEY",
                        "addedAt": 5,
                        "sha256": "ab".repeat(32),
                        "kemlockFile": "server-1",
                    },
                    "links": [{"id": "11111111-1111-4111-8111-111111111111"}],
                    "attachments": [{"name": "x", "key": "OTHERKEY"}],
                }),
            ),
            item(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "future-kind",
                json!({
                    "name": "From a newer app",
                    "text": "kept",
                    "colour": "blue",
                    "file": {"key": "SECRETKEY"},
                    "attachments": [{"key": "OTHERKEY"}],
                    "links": [{"id": "11111111-1111-4111-8111-111111111111"}],
                }),
            ),
        ];
        let clear = plain_json(ExportKind::Bitwarden, &items).expect("plain");
        let root: Value = serde_json::from_str(&clear).expect("json");

        let file = &root["items"][0];
        assert_eq!(file["type"], 2, "a note");
        let notes = file["notes"].as_str().expect("notes");
        assert!(notes.starts_with("Signed

"), "{notes}");
        assert!(notes.contains("Lease agreement.pdf is not included"), "{notes}");
        assert!(notes.contains("no file bytes"), "{notes}");
        // No key, no server id and no link leaves in a field or anywhere else.
        for secret in ["SECRETKEY", "OTHERKEY", "server-1", "11111111-1111-4111-8111-111111111111"] {
            assert!(!clear.contains(secret), "{secret} was exported");
        }

        // A kind Bitwarden doesn't know keeps its plain values as fields, but not these three.
        let names: Vec<&str> = root["items"][1]["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .filter_map(|field| field["name"].as_str())
            .collect();
        assert_eq!(names, ["colour"]);
        assert_eq!(root["items"][1]["notes"], "kept");
    }

    #[test]
    fn items_keep_bitwardens_key_order() {
        let clear = plain_json(ExportKind::Bitwarden, &vault()).expect("plain");
        let first = clear.find("\"passwordHistory\"").expect("first item");
        let order = [
            "\"passwordHistory\"",
            "\"revisionDate\"",
            "\"creationDate\"",
            "\"deletedDate\"",
            "\"id\"",
            "\"organizationId\"",
            "\"folderId\"",
            "\"type\"",
            "\"reprompt\"",
            "\"name\"",
            "\"notes\"",
            "\"favorite\"",
            "\"fields\"",
            "\"login\"",
            "\"collectionIds\"",
        ];
        let mut at = first;
        for key in order {
            let found = clear[at..]
                .find(key)
                .unwrap_or_else(|| panic!("{key} after {at}"));
            at += found + key.len();
        }
        // A folder is a GUID and a path, and the item points at it.
        assert!(clear.contains("\"name\": \"Work/Projects\""));
        let folder: Value = serde_json::from_str(&clear).expect("json");
        assert_eq!(folder["items"][0]["folderId"], folder["folders"][0]["id"]);
        assert_eq!(
            folder["items"][0]["folderId"].as_str().map(str::len),
            Some(36)
        );
    }

    #[test]
    fn a_passkey_is_written_as_bitwarden_keeps_it() {
        let key = encode_base64url(&[7u8; 40]);
        let items = vec![item(
            "99999999-9999-4999-8999-999999999999",
            "login",
            json!({"name": "Passkey site", "passkeys": [
                {"credentialId": encode_base64url(&[1u8; 16]), "rpId": "example.com", "userHandle": encode_base64url(b"u1"),
                 "userName": "ada", "privateKey": key, "algorithm": -7},
                {"credentialId": encode_base64url(&[1, 2, 3, 4]), "rpId": "example.com", "userHandle": encode_base64url(b"u2"),
                 "userName": "ada", "privateKey": key, "algorithm": -7},
                {"credentialId": encode_base64url(&[9u8; 16]), "rpId": "example.com", "userHandle": encode_base64url(b"u3"),
                 "userName": "ada", "privateKey": key, "algorithm": -257}
            ]}),
        )];
        let clear = plain_json(ExportKind::Bitwarden, &items).expect("plain");
        let root: Value = serde_json::from_str(&clear).expect("json");
        let passkeys = root["items"][0]["login"]["fido2Credentials"]
            .as_array()
            .expect("passkeys");
        assert_eq!(
            passkeys.len(),
            2,
            "RS256 is not an ES256 key and is left out"
        );
        assert_eq!(
            passkeys[0]["credentialId"],
            "01010101-0101-0101-0101-010101010101"
        );
        assert_eq!(passkeys[1]["credentialId"], "b64.AQIDBA");
        assert_eq!(passkeys[0]["keyType"], "public-key");
        assert_eq!(passkeys[0]["keyAlgorithm"], "ECDSA");
        assert_eq!(passkeys[0]["keyCurve"], "P-256");
        assert_eq!(passkeys[0]["counter"], "0");
    }

    #[test]
    fn an_empty_vault_is_a_valid_export() {
        let text =
            write_with(ExportKind::Bitwarden, &[], PASSWORD, FAST, &entropy()).expect("write");
        let limits = Limits::default();
        let ctx = Context::new(&limits).with_password(PASSWORD);
        // The reader opens it, reaches the empty list and says so.
        assert_eq!(
            bitwarden::parse(text.as_bytes(), &ctx),
            Err(ImportError::Empty)
        );
    }

    #[test]
    fn the_default_kdf_is_one_an_import_accepts() {
        assert_eq!(kdf_in_bounds(DEFAULT_KDF), Ok(()));
        assert_eq!(
            DEFAULT_KDF,
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4
            }
        );
    }

    #[test]
    fn a_second_code_for_the_same_login_is_not_lost() {
        let mut items = vault();
        items.push(item(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "otp",
            json!({"name": "Backup", "secret": "ZZZZZZZZ", "linkedLoginId": "11111111-1111-4111-8111-111111111111"}),
        ));
        let clear = plain_json(ExportKind::Bitwarden, &items).expect("plain");
        assert!(clear.contains("ZZZZZZZZ"));
        assert!(clear.contains("JBSWY3DPEHPK3PXP"));
        // A login that has a code of its own keeps it, and the linked code stays an item.
        let mut own = vault();
        own[0].data["totp"] = json!("OWNSECRET");
        let clear = plain_json(ExportKind::Bitwarden, &own).expect("plain");
        assert!(clear.contains("OWNSECRET") && clear.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn the_password_and_the_kdf_are_checked_before_any_work() {
        for blank in ["", "   "] {
            assert_eq!(
                write_with(ExportKind::Bitwarden, &[], blank, FAST, &entropy()),
                Err(ImportError::PasswordRequired)
            );
        }
        for kdf in [
            Kdf::Pbkdf2 { iterations: 4999 },
            Kdf::Pbkdf2 {
                iterations: 2_000_001,
            },
            Kdf::Argon2id {
                iterations: 1,
                memory_mib: 64,
                parallelism: 4,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 15,
                parallelism: 4,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 0,
            },
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 17,
            },
        ] {
            assert_eq!(
                write_with(ExportKind::Bitwarden, &[], PASSWORD, kdf, &entropy()),
                Err(ImportError::KdfOutOfBounds),
                "{kdf:?}"
            );
        }
    }

    #[test]
    fn the_items_to_export_must_be_a_list() {
        assert!(parse_items("{}").is_err());
        assert!(parse_items("[{\"id\": 1}]").is_err());
        let items =
            parse_items(r#"[{"id":"a","kind":"note","data":{"name":"n"}}]"#).expect("items");
        assert_eq!(items[0].kind, "note");
    }

    #[test]
    fn an_unnamed_item_is_written_as_bitwarden_names_it() {
        let items = vec![item("a", "note", json!({}))];
        let clear = plain_json(ExportKind::Bitwarden, &items).expect("plain");
        assert!(clear.contains("\"name\": \"--\""));
    }

    #[test]
    fn debug_never_shows_the_entropy() {
        assert_eq!(format!("{:?}", entropy()), "Entropy(..)");
    }
}
