// Ported from Bitwarden's clients (https://github.com/bitwarden/clients), at commit
// f9c68e008ba91dc19edf519305a82d3a994a7baa:
//   libs/importer/src/importers/bitwarden/bitwarden-json-importer.ts
//   libs/importer/src/importers/bitwarden/bitwarden-encrypted-json-importer.ts
//   libs/importer/src/importers/bitwarden/bitwarden-password-protected-importer.ts
//   libs/importer/src/importers/bitwarden/password-protected-kdf-config.ts
// Copyright (C) Bitwarden Inc. Licensed GPL-3.0-only; combined here into kemlock-import, which is
// AGPL-3.0-only, as the GPL-3.0 permits. See the crate's NOTICE.

//! Bitwarden JSON: plain, password-protected, and the account-restricted form that can't be opened
//! here. Individual and organisation exports both read; an organisation's collections become
//! shared vaults.
//!
//! A password-protected export records its KDF (PBKDF2-SHA256 or Argon2id). The cost is checked
//! against the bounds and [`Limits`](crate::limits::Limits) before any derivation, then HKDF-Expand
//! gives the encryption and MAC keys, `encKeyValidation_DO_NOT_EDIT` is opened first (a MAC failure
//! is a wrong password), and `data` holds the plain export as an `EncString`.
//!
//! Passkeys come with their private keys (`login.fido2Credentials`); only ES256 keys are kept, and
//! the others are listed as skipped.

use std::collections::HashMap;

use serde_json::Value;

use crate::builder::Builder;
use crate::bwcrypto::{decrypt_enc_text, derive_export_key, kdf_from_export};
use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::model::{
    Address, COSE_ES256, Card, CustomField, DocumentKind, FieldKind, Format, IdDocument, Identity,
    ImportBatch, Login, Meta, Note, Passkey, PreviousPassword, SharedKind, SkipReason, SshKey,
    UriMatch, UriRule,
};
use crate::passkey::{cose_algorithm_of_pkcs8, decode_base64_any, encode_base64, encode_base64url};
use crate::util::{
    card_brand, card_number, clean_notes, decode_text, is_blank, jarr, jbool, jint, jstr, nonblank,
    or_default, parse_iso_ms, parse_month, parse_year, scalar_text,
};

static NULL: Value = Value::Null;

/// Bitwarden keeps five earlier passwords.
const HISTORY_KEPT: usize = 5;

/// Reads a Bitwarden JSON export. A password-protected one needs `ctx.password`.
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    ctx.limits.check_input(bytes)?;
    let text = decode_text(bytes);
    let root: Value = serde_json::from_str(&text).map_err(|_| ImportError::Unsupported)?;
    if !root.is_object() {
        return Err(ImportError::Unsupported);
    }
    if jbool(&root, "passwordProtected") == Some(true) {
        return open_protected(&root, ctx);
    }
    if jbool(&root, "encrypted") == Some(true) {
        return Err(ImportError::AccountRestricted);
    }
    read_plain(&root, ctx)
}

fn open_protected(root: &Value, ctx: &Context<'_>) -> Result<ImportBatch> {
    let field = |name: &str| {
        jstr(root, name)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ImportError::malformed("the password-protected export is incomplete"))
    };
    let salt = field("salt")?;
    let validation = field("encKeyValidation_DO_NOT_EDIT")?;
    let data = field("data")?;
    // The KDF cost is bounded before asking for the password or doing any work.
    let kdf = kdf_from_export(root, ctx.limits)?;
    let password = ctx
        .password
        .filter(|p| !is_blank(p))
        .ok_or(ImportError::PasswordRequired)?;
    let key = derive_export_key(password, salt, kdf)?;
    decrypt_enc_text(validation, &key)?;
    let inner = decrypt_enc_text(data, &key)?;
    if inner.len() > ctx.limits.max_input_bytes {
        return Err(ImportError::TooLarge {
            limit: ctx.limits.max_input_bytes,
        });
    }
    let plain: Value = serde_json::from_str(&inner)
        .map_err(|_| ImportError::malformed("the decrypted export is not JSON"))?;
    if !plain.is_object() || jbool(&plain, "passwordProtected") == Some(true) {
        return Err(ImportError::malformed(
            "the decrypted export is not an export",
        ));
    }
    if jbool(&plain, "encrypted") == Some(true) {
        return Err(ImportError::AccountRestricted);
    }
    read_plain(&plain, ctx)
}

fn read_plain(root: &Value, ctx: &Context<'_>) -> Result<ImportBatch> {
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or(ImportError::Unsupported)?;
    let mut b = Builder::new(Format::BitwardenJson, ctx.limits);

    let mut folders: HashMap<String, Option<usize>> = HashMap::new();
    for folder in jarr(root, "folders") {
        if let (Some(id), Some(name)) = (jstr(folder, "id"), jstr(folder, "name")) {
            let index = b.folder(name);
            folders.insert(id.to_string(), index);
        }
    }
    let mut spaces: HashMap<String, usize> = HashMap::new();
    for collection in jarr(root, "collections") {
        if let (Some(id), Some(name)) = (jstr(collection, "id"), jstr(collection, "name"))
            && let Some(index) = b.space(id, name, SharedKind::Collection)
        {
            spaces.insert(id.to_string(), index);
        }
    }

    for (n, item) in items.iter().enumerate() {
        if b.full() {
            b.note_unread(items.len() - n);
            break;
        }
        read_item(&mut b, item, &folders, &spaces);
    }
    b.finish()
}

fn custom_fields(item: &Value) -> Vec<CustomField> {
    jarr(item, "fields")
        .iter()
        .filter_map(|f| {
            let name = jstr(f, "name").unwrap_or("");
            let value = f.get("value").and_then(scalar_text).unwrap_or_default();
            if name.is_empty() && value.is_empty() {
                return None;
            }
            let kind = match jint(f, "type") {
                Some(1) => FieldKind::Hidden,
                Some(2) => FieldKind::Boolean,
                Some(3) => FieldKind::Linked,
                _ => FieldKind::Text,
            };
            Some(CustomField {
                name: name.to_string(),
                value,
                kind,
            })
        })
        .collect()
}

fn read_item(
    b: &mut Builder<'_>,
    item: &Value,
    folders: &HashMap<String, Option<usize>>,
    spaces: &HashMap<String, usize>,
) {
    let title = jstr(item, "name");
    if item.get("deletedDate").is_some_and(|d| !d.is_null()) {
        b.skip(title, SkipReason::Trashed, None);
        return;
    }
    let meta = Meta {
        folder: jstr(item, "folderId").and_then(|id| folders.get(id).copied().flatten()),
        spaces: jarr(item, "collectionIds")
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|id| spaces.get(id).copied())
            .collect(),
        favorite: jbool(item, "favorite").unwrap_or(false),
        created_ms: jstr(item, "creationDate").and_then(parse_iso_ms),
        modified_ms: jstr(item, "revisionDate").and_then(parse_iso_ms),
        source_id: jstr(item, "id").map(str::to_string),
        tags: Vec::new(),
    };
    let name = or_default(title, "--");
    let notes = clean_notes(nonblank(jstr(item, "notes")));
    let fields = custom_fields(item);

    match jint(item, "type") {
        Some(1) => read_login(b, item, name, notes, fields, meta),
        Some(2) => {
            b.note(Note {
                name,
                text: notes,
                fields,
                meta,
            });
        }
        Some(3) => {
            let card = item.get("card").unwrap_or(&NULL);
            let number = jstr(card, "number").and_then(card_number);
            let brand =
                nonblank(jstr(card, "brand")).or_else(|| number.as_deref().and_then(card_brand));
            b.card(Card {
                name,
                cardholder: nonblank(jstr(card, "cardholderName")),
                brand,
                number,
                exp_month: card
                    .get("expMonth")
                    .and_then(scalar_text)
                    .and_then(|s| parse_month(&s)),
                exp_year: card
                    .get("expYear")
                    .and_then(scalar_text)
                    .and_then(|s| parse_year(&s)),
                code: nonblank(jstr(card, "code")),
                notes,
                fields,
                meta,
                ..Card::default()
            });
        }
        Some(4) => {
            let identity = read_identity(item.get("identity").unwrap_or(&NULL), name, notes);
            b.identity(Identity {
                fields,
                meta,
                ..identity
            });
        }
        Some(5) => {
            let key = item.get("sshKey").unwrap_or(&NULL);
            match nonblank(jstr(key, "privateKey")) {
                Some(private_key) => {
                    b.ssh_key(SshKey {
                        name,
                        private_key,
                        public_key: nonblank(jstr(key, "publicKey")),
                        fingerprint: nonblank(jstr(key, "keyFingerprint")),
                        notes,
                        fields,
                        meta,
                    });
                }
                None => b.skip(
                    title,
                    SkipReason::BadKey,
                    Some("the SSH key has no private key"),
                ),
            }
        }
        other => {
            let detail = match other {
                Some(n) => format!("item type {n}"),
                None => "no item type".to_string(),
            };
            b.skip(title, SkipReason::UnsupportedKind, Some(detail.as_str()));
        }
    }
}

fn read_login(
    b: &mut Builder<'_>,
    item: &Value,
    name: String,
    notes: Option<String>,
    fields: Vec<CustomField>,
    meta: Meta,
) {
    let login = item.get("login").unwrap_or(&NULL);
    let uris = jarr(login, "uris")
        .iter()
        .filter_map(|u| {
            let uri = jstr(u, "uri").filter(|s| !is_blank(s))?;
            Some(UriRule {
                uri: uri.to_string(),
                match_rule: jint(u, "match").and_then(UriMatch::from_number),
            })
        })
        .collect();

    let mut previous: Vec<PreviousPassword> = jarr(item, "passwordHistory")
        .iter()
        .filter_map(|h| {
            let password = nonblank(jstr(h, "password"))?;
            Some(PreviousPassword {
                password,
                until_ms: jstr(h, "lastUsedDate").and_then(parse_iso_ms).unwrap_or(0),
            })
        })
        .collect();
    // Newest first; entries with no date keep the file's order.
    previous.sort_by_key(|p| std::cmp::Reverse(p.until_ms));
    previous.truncate(HISTORY_KEPT);

    let title = jstr(item, "name");
    let mut passkeys = Vec::new();
    for credential in jarr(login, "fido2Credentials") {
        match passkey_from(credential) {
            PasskeyRead::Kept(passkey) => passkeys.push(passkey),
            PasskeyRead::Unsupported => b.skip(
                title,
                SkipReason::UnsupportedPasskey,
                Some("Kemlock keeps ES256 passkeys only"),
            ),
            PasskeyRead::Damaged => b.skip(
                title,
                SkipReason::BadKey,
                Some("a passkey is missing what signing in needs"),
            ),
        }
    }

    b.login(Login {
        name,
        uris,
        username: nonblank(jstr(login, "username")),
        password: nonblank(jstr(login, "password")),
        totp: nonblank(jstr(login, "totp")),
        notes,
        fields,
        previous_passwords: previous,
        passkeys,
        meta,
    });
}

fn read_identity(identity: &Value, name: String, notes: Option<String>) -> Identity {
    let text = |key: &str| nonblank(jstr(identity, key));
    let lines: Vec<String> = ["address1", "address2", "address3"]
        .iter()
        .filter_map(|&key| text(key))
        .collect();
    let (city, region, postal_code, country) = (
        text("city"),
        text("state"),
        text("postalCode"),
        text("country"),
    );
    let address = if lines.is_empty()
        && city.is_none()
        && region.is_none()
        && postal_code.is_none()
        && country.is_none()
    {
        None
    } else {
        Some(Address {
            lines,
            city,
            region,
            postal_code,
            country,
        })
    };
    let mut documents = Vec::new();
    for (key, kind) in [
        ("ssn", DocumentKind::TaxNumber),
        ("passportNumber", DocumentKind::Passport),
        ("licenseNumber", DocumentKind::DriversLicence),
    ] {
        if let Some(number) = text(key) {
            documents.push(IdDocument {
                kind,
                number: Some(number),
                ..IdDocument::default()
            });
        }
    }
    Identity {
        name,
        title: text("title"),
        given_name: text("firstName"),
        middle_name: text("middleName"),
        family_name: text("lastName"),
        company: text("company"),
        email: text("email"),
        phone: text("phone"),
        username: text("username"),
        address,
        documents,
        notes,
        ..Identity::default()
    }
}

/// What reading one `fido2Credentials` entry gave.
#[derive(Debug, PartialEq, Eq)]
enum PasskeyRead {
    Kept(Passkey),
    /// Not an ES256 key.
    Unsupported,
    /// Missing or damaged parts.
    Damaged,
}

/// A GUID as its 16 bytes.
fn guid_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut out = Vec::with_capacity(16);
    let mut high: Option<u8> = None;
    for (i, c) in text.chars().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != '-' {
                return None;
            }
            continue;
        }
        let digit = u8::try_from(c.to_digit(16)?).ok()?;
        match high.take() {
            Some(h) => out.push((h << 4) | digit),
            None => high = Some(digit),
        }
    }
    if out.len() == 16 { Some(out) } else { None }
}

/// A passkey Bitwarden keeps in a login's `fido2Credentials`. A 16-byte credential id is written
/// as a GUID and any other as `b64.` and base64url; the key is PKCS#8 in base64url.
fn passkey_from(credential: &Value) -> PasskeyRead {
    let is = |key: &str, want: &str| jstr(credential, key) == Some(want);
    if !is("keyType", "public-key") || !is("keyAlgorithm", "ECDSA") || !is("keyCurve", "P-256") {
        return PasskeyRead::Unsupported;
    }
    let raw_id = jstr(credential, "credentialId").unwrap_or("").trim();
    let id = if let Some(rest) = raw_id.strip_prefix("b64.") {
        decode_base64_any(rest)
    } else {
        guid_bytes(raw_id)
    };
    let key = jstr(credential, "keyValue").and_then(decode_base64_any);
    let user_handle = jstr(credential, "userHandle").and_then(decode_base64_any);
    let rp_id = jstr(credential, "rpId").unwrap_or("").trim().to_lowercase();
    let (Some(id), Some(key), Some(user_handle)) = (id, key, user_handle) else {
        return PasskeyRead::Damaged;
    };
    if id.is_empty() || key.is_empty() || user_handle.is_empty() || rp_id.is_empty() {
        return PasskeyRead::Damaged;
    }
    match cose_algorithm_of_pkcs8(&key) {
        Some(COSE_ES256) => {}
        Some(_) => return PasskeyRead::Unsupported,
        None => return PasskeyRead::Damaged,
    }
    PasskeyRead::Kept(Passkey {
        credential_id: encode_base64url(&id),
        rp_id,
        rp_name: nonblank(jstr(credential, "rpName")),
        user_handle: encode_base64url(&user_handle),
        user_name: jstr(credential, "userName").unwrap_or("").to_string(),
        user_display_name: nonblank(jstr(credential, "userDisplayName")),
        private_key: encode_base64(&key),
        algorithm: COSE_ES256,
        created_ms: jstr(credential, "creationDate").and_then(parse_iso_ms),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    const PLAIN: &str = include_str!("../tests/fixtures/bitwarden/export.json");
    const ORG: &str = include_str!("../tests/fixtures/bitwarden/org.json");
    const PBKDF2: &str = include_str!("../tests/fixtures/bitwarden/protected-pbkdf2.json");
    const ARGON2: &str = include_str!("../tests/fixtures/bitwarden/protected-argon2.json");
    const ACCOUNT: &str = include_str!("../tests/fixtures/bitwarden/account-restricted.json");
    const PASSWORD: &str = "correct horse";

    fn read(text: &str, password: Option<&str>) -> Result<ImportBatch> {
        let limits = Limits::default();
        let mut ctx = Context::new(&limits);
        if let Some(p) = password {
            ctx = ctx.with_password(p);
        }
        parse(text.as_bytes(), &ctx)
    }

    #[test]
    fn reads_every_kind_of_item() {
        let batch = read(PLAIN, None).expect("batch");
        assert_eq!(batch.format, Format::BitwardenJson);
        assert_eq!(batch.logins.len(), 1);
        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.cards.len(), 1);
        assert_eq!(batch.identities.len(), 1);
        assert_eq!(batch.ssh_keys.len(), 1);
        assert_eq!(batch.folders.len(), 3);
        assert_eq!(batch.folders[2].path, "Work/Projects");
        assert_eq!(batch.folders[2].parent, Some(1));
    }

    #[test]
    fn a_login_keeps_every_address_its_rules_history_and_fields() {
        let batch = read(PLAIN, None).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.name, "Example Mail");
        assert_eq!(login.username.as_deref(), Some("ada"));
        assert_eq!(login.password.as_deref(), Some("pw-now"));
        assert!(
            login
                .totp
                .as_deref()
                .expect("totp")
                .starts_with("otpauth://totp/Mail")
        );
        assert_eq!(login.notes.as_deref(), Some("a note"));
        assert_eq!(login.uris.len(), 2);
        assert_eq!(login.uris[0].match_rule, None);
        assert_eq!(login.uris[1].match_rule, Some(UriMatch::Exact));
        assert_eq!(login.fields.len(), 2);
        assert_eq!(login.fields[0].kind, FieldKind::Hidden);
        assert_eq!(login.fields[1].kind, FieldKind::Boolean);
        // Newest first.
        assert_eq!(login.previous_passwords[0].password, "old2");
        assert_eq!(login.previous_passwords[1].password, "old1");
        assert!(login.meta.favorite);
        assert_eq!(login.meta.folder, Some(0));
        assert_eq!(login.meta.created_ms, Some(1_641_092_645_000));
        assert_eq!(login.meta.modified_ms, Some(1_704_164_645_678));
        assert_eq!(login.meta.source_id.as_deref(), Some("i1"));
    }

    #[test]
    fn passkeys_keep_es256_and_list_the_rest() {
        let batch = read(PLAIN, None).expect("batch");
        let login = &batch.logins[0];
        assert_eq!(login.passkeys.len(), 2);
        let first = &login.passkeys[0];
        assert_eq!(first.rp_id, "example.com");
        assert_eq!(first.credential_id, "ASNFZ4mrze8BI0VniavN7w");
        assert_eq!(first.algorithm, COSE_ES256);
        assert_eq!(first.user_name, "ada@example.com");
        assert!(!first.private_key.is_empty());
        assert_eq!(login.passkeys[1].credential_id, "AQIDBA");
        let unsupported: Vec<_> = batch
            .skipped
            .iter()
            .filter(|s| s.reason == SkipReason::UnsupportedPasskey)
            .collect();
        assert_eq!(unsupported.len(), 1);
    }

    #[test]
    fn card_identity_note_and_key() {
        let batch = read(PLAIN, None).expect("batch");
        let card = &batch.cards[0];
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.brand.as_deref(), Some("Visa"));
        assert_eq!((card.exp_month, card.exp_year), (Some(5), Some(2029)));
        assert_eq!(card.code.as_deref(), Some("123"));
        assert_eq!(card.cardholder.as_deref(), Some("Ada Lovelace"));

        let id = &batch.identities[0];
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        let address = id.address.as_ref().expect("address");
        assert_eq!(address.lines, ["1 Analytical St"]);
        assert_eq!(address.region.as_deref(), Some("LDN"));
        let kinds: Vec<DocumentKind> = id.documents.iter().map(|d| d.kind).collect();
        assert_eq!(
            kinds,
            [
                DocumentKind::TaxNumber,
                DocumentKind::Passport,
                DocumentKind::DriversLicence
            ]
        );
        assert_eq!(id.documents[1].number.as_deref(), Some("P123"));

        assert_eq!(batch.notes[0].name, "Wi-Fi");
        assert_eq!(batch.notes[0].text.as_deref(), Some("router password: x"));
        assert_eq!(batch.notes[0].meta.folder, Some(2));

        let key = &batch.ssh_keys[0];
        assert!(key.private_key.contains("OPENSSH PRIVATE KEY"));
        assert_eq!(key.fingerprint.as_deref(), Some("SHA256:abc"));
    }

    #[test]
    fn the_trash_and_unknown_kinds_are_listed_as_skipped() {
        let batch = read(PLAIN, None).expect("batch");
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::Trashed && s.name.as_deref() == Some("Old"))
        );
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::UnsupportedKind
                    && s.detail.as_deref() == Some("item type 9"))
        );
    }

    #[test]
    fn an_organisation_export_makes_shared_vaults() {
        let batch = read(ORG, None).expect("batch");
        assert_eq!(batch.spaces.len(), 2);
        assert_eq!(batch.spaces[0].kind, SharedKind::Collection);
        assert_eq!(batch.spaces[0].name, "Shared logins");
        assert_eq!(batch.logins[0].meta.spaces, [0, 1]);
        assert!(batch.folders.is_empty());
        assert_eq!(batch.notes[0].meta.spaces, [1]);
    }

    #[test]
    fn opens_password_protected_exports_in_both_kdfs() {
        for file in [PBKDF2, ARGON2] {
            let batch = read(file, Some(PASSWORD)).expect("batch");
            assert_eq!(batch.logins.len(), 1);
            assert_eq!(batch.logins[0].name, "Example Mail");
            assert_eq!(batch.logins[0].passkeys.len(), 2);
        }
    }

    #[test]
    fn a_protected_export_asks_for_the_password_and_refuses_a_wrong_one() {
        assert_eq!(
            read(PBKDF2, None).err(),
            Some(ImportError::PasswordRequired)
        );
        assert_eq!(
            read(PBKDF2, Some("  ")).err(),
            Some(ImportError::PasswordRequired)
        );
        assert_eq!(
            read(PBKDF2, Some("wrong")).err(),
            Some(ImportError::BadPassword)
        );
        assert_eq!(
            read(ARGON2, Some("wrong")).err(),
            Some(ImportError::BadPassword)
        );
    }

    #[test]
    fn the_kdf_cost_is_bounded_before_anything_runs() {
        let mut value: Value = serde_json::from_str(PBKDF2).expect("json");
        value["kdfIterations"] = Value::from(50_000_000u64);
        assert_eq!(
            read(&value.to_string(), Some(PASSWORD)).err(),
            Some(ImportError::KdfOutOfBounds)
        );
        value["kdfIterations"] = Value::from(10);
        assert_eq!(
            read(&value.to_string(), None).err(),
            Some(ImportError::KdfOutOfBounds)
        );
        value["kdfType"] = Value::from(7);
        assert_eq!(
            read(&value.to_string(), Some(PASSWORD)).err(),
            Some(ImportError::KdfOutOfBounds)
        );
    }

    #[test]
    fn an_account_restricted_export_cannot_be_opened() {
        assert_eq!(
            read(ACCOUNT, Some(PASSWORD)).err(),
            Some(ImportError::AccountRestricted)
        );
    }

    #[test]
    fn a_damaged_protected_export_is_malformed() {
        let mut value: Value = serde_json::from_str(PBKDF2).expect("json");
        value["data"] = Value::from("2.not-base64|x|y");
        assert!(matches!(
            read(&value.to_string(), Some(PASSWORD)),
            Err(ImportError::Malformed(_))
        ));
        value.as_object_mut().expect("object").remove("salt");
        assert!(matches!(
            read(&value.to_string(), Some(PASSWORD)),
            Err(ImportError::Malformed(_))
        ));
    }

    #[test]
    fn refuses_other_text() {
        assert_eq!(read("", None).err(), Some(ImportError::Unsupported));
        assert_eq!(read("[1,2]", None).err(), Some(ImportError::Unsupported));
        assert_eq!(
            read("{\"a\":1}", None).err(),
            Some(ImportError::Unsupported)
        );
        assert_eq!(read("{\"items\":[]}", None).err(), Some(ImportError::Empty));
        assert_eq!(read("not json", None).err(), Some(ImportError::Unsupported));
    }

    #[test]
    fn passkeys_with_damaged_parts_are_skipped_with_a_reason() {
        let text = r#"{"items":[{"type":1,"name":"X","login":{"fido2Credentials":[
            {"keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256","credentialId":"nope","keyValue":"AQID","rpId":"a.b","userHandle":"AQID"},
            {"keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256"}]}}]}"#;
        let batch = read(text, None).expect("batch");
        assert!(batch.logins[0].passkeys.is_empty());
        assert_eq!(
            batch
                .skipped
                .iter()
                .filter(|s| s.reason == SkipReason::BadKey)
                .count(),
            2
        );
    }

    #[test]
    fn guids_are_read_as_bytes() {
        assert_eq!(
            guid_bytes("01234567-89ab-cdef-0123-456789abcdef"),
            Some(vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ])
        );
        assert_eq!(guid_bytes("0123456789abcdef0123456789abcdef"), None);
        assert_eq!(guid_bytes("0123456g-89ab-cdef-0123-456789abcdef"), None);
        assert_eq!(guid_bytes(""), None);
    }

    #[test]
    fn items_over_the_limit_are_counted() {
        let limits = Limits {
            max_entries: 2,
            ..Limits::default()
        };
        let batch = parse(PLAIN.as_bytes(), &Context::new(&limits)).expect("batch");
        assert_eq!(batch.entry_count(), 2);
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::OverLimit)
        );
    }
}
