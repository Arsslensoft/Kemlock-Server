//! KeePass, KeePassXC and compatible KDBX databases, versions 3.1 and 4.
//!
//! This is not a port: the container (header, key derivation, ciphers, block streams, compression
//! and the XML inside) is read by the [`keepass`] crate (MIT, `sseemayer/keepass-rs`), and this
//! module maps what it finds to the neutral batch.
//!
//! The file's own key-derivation settings are read first, here, and a cost over the limits is
//! refused with [`ImportError::KdfOutOfBounds`] before the `keepass` crate spends it: AES-KDF
//! rounds against [`Limits::max_aes_kdf_rounds`], Argon2 memory against
//! [`Limits::max_argon2_memory_kib`], and its passes and lanes against the larger of the
//! Bitwarden-sized limits and 256 and 64, since KeePass tunes Argon2 by time and sets far more
//! passes than Bitwarden does. The header walk is bounds-checked, and so is every length the
//! `keepass` crate would take on trust, so a damaged header is an error and not a panic.
//!
//! What the crate does not bound: it inflates the (compressed) payload without a limit. The
//! payload is decrypted first, so only a file made with the right key can reach it, and the input
//! limit bounds the compressed size.
//!
//! What maps to what: an entry is a login (title, user name, password, the `URL` field and any
//! other `URL…` or `KP2A_URL…` field as more websites, notes), with its `otp` field, or KeePassXC's
//! `TOTP Seed` and `TOTP Settings`, as its code; every other field is a custom field (hidden when
//! protected); tags are kept; history versions with other passwords give the previous passwords;
//! attachments are files; KeePassXC passkeys (`KPEX_PASSKEY_*` fields) are passkeys when they are
//! ES256. An entry with nothing to sign in with but notes is a note. Groups are folders, nested as
//! in the file, the top group being no folder; the recycle bin's entries are skipped.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use keepass::db::{DatabaseOpenError, Entry, EntryRef, GroupId, GroupRef};
use keepass::{Database, DatabaseKey};

use crate::builder::Builder;
use crate::context::Context;
use crate::error::{ImportError, Result};
use crate::limits::Limits;
use crate::model::{
    COSE_ES256, CustomField, FieldKind, Format, ImportBatch, ItemRef, Login, Meta, Note, Passkey,
    PreviousPassword, SkipReason,
};
use crate::passkey::{
    cose_algorithm_of_pkcs8, decode_base64_any, encode_base64, encode_base64url, pem_to_der,
};
use crate::util::{clean_name, clean_notes, is_noteworthy_login, kvp, make_uris, nonblank};

const SIGNATURE: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
/// The second signature of KDBX 2 and later; KeePass 1 (`65 FB 4B B5`) and the 2.0 pre-release
/// (`66 FB 4B B5`) have others.
const KDBX_ID: [u8; 4] = [0x67, 0xFB, 0x4B, 0xB5];

const AES_KDF_KDBX4: [u8; 16] = [
    0x7C, 0x02, 0xBB, 0x82, 0x79, 0xA7, 0x4A, 0xC0, 0x92, 0x7D, 0x11, 0x4A, 0x00, 0x64, 0x82, 0x38,
];
const AES_KDF_KDBX3: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];
const ARGON2D: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
const ARGON2ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

/// Groups nested deeper than this are not read.
const MAX_DEPTH: usize = 256;

/// The key derivation a file asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kdf {
    Aes {
        rounds: u64,
    },
    Argon2 {
        memory_kib: u64,
        iterations: u64,
        parallelism: u32,
    },
}

fn damaged() -> ImportError {
    ImportError::malformed("the KDBX header is damaged")
}

fn bytes_at(b: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    b.get(at..at.checked_add(len)?)
}

fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = bytes_at(b, at, 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = bytes_at(b, at, 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    let s = bytes_at(b, at, 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Walks the outer header of a KDBX 3.x file for its transform rounds.
fn kdbx3_kdf(bytes: &[u8]) -> Result<Kdf> {
    let mut rounds = None;
    let mut pos = 12usize;
    loop {
        let id = *bytes.get(pos).ok_or_else(damaged)?;
        let len = usize::from(le_u16(bytes, pos + 1).ok_or_else(damaged)?);
        let data = bytes_at(bytes, pos + 3, len).ok_or_else(damaged)?;
        pos += 3 + len;
        match id {
            0 => break,
            // The compression and inner stream ids are read as 32-bit numbers.
            3 | 10 => {
                if len != 4 {
                    return Err(damaged());
                }
            }
            6 => {
                rounds = Some(le_u64(data, 0).ok_or_else(damaged)?);
            }
            _ => {}
        }
    }
    rounds.map(|rounds| Kdf::Aes { rounds }).ok_or_else(damaged)
}

/// Walks the outer header of a KDBX 4 file for its KDF parameters.
fn kdbx4_kdf(bytes: &[u8]) -> Result<Kdf> {
    let mut kdf = None;
    let mut pos = 12usize;
    loop {
        let id = *bytes.get(pos).ok_or_else(damaged)?;
        let len =
            usize::try_from(le_u32(bytes, pos + 1).ok_or_else(damaged)?).map_err(|_| damaged())?;
        let data = bytes_at(bytes, pos + 5, len).ok_or_else(damaged)?;
        pos = pos
            .checked_add(5)
            .and_then(|p| p.checked_add(len))
            .ok_or_else(damaged)?;
        match id {
            0 => break,
            // The compression id is read as a 32-bit number.
            3 => {
                if len != 4 {
                    return Err(damaged());
                }
            }
            11 => kdf = Some(kdf_from_dictionary(data)?),
            _ => {}
        }
    }
    kdf.ok_or_else(damaged)
}

/// Reads the KDF out of a KDBX 4 variant dictionary, checking the width of every value on the way.
fn kdf_from_dictionary(buf: &[u8]) -> Result<Kdf> {
    if le_u16(buf, 0).ok_or_else(damaged)? != 0x0100 {
        return Err(damaged());
    }
    let mut pos = 2usize;
    let mut uuid: Option<&[u8]> = None;
    let mut rounds = None;
    let mut memory = None;
    let mut iterations = None;
    let mut parallelism = None;
    loop {
        let kind = *buf.get(pos).ok_or_else(damaged)?;
        pos += 1;
        if kind == 0 {
            break;
        }
        let key_len =
            usize::try_from(le_u32(buf, pos).ok_or_else(damaged)?).map_err(|_| damaged())?;
        pos += 4;
        let key = bytes_at(buf, pos, key_len).ok_or_else(damaged)?;
        pos += key_len;
        let value_len =
            usize::try_from(le_u32(buf, pos).ok_or_else(damaged)?).map_err(|_| damaged())?;
        pos += 4;
        let value = bytes_at(buf, pos, value_len).ok_or_else(damaged)?;
        pos += value_len;
        let width_ok = match kind {
            0x04 | 0x0C => value.len() == 4,
            0x05 | 0x0D => value.len() == 8,
            0x08 => value.len() == 1,
            0x18 | 0x42 => true,
            _ => false,
        };
        if !width_ok {
            return Err(damaged());
        }
        match (key, kind) {
            (b"$UUID", 0x42) => uuid = Some(value),
            (b"R", 0x05) => rounds = le_u64(value, 0),
            (b"M", 0x05) => memory = le_u64(value, 0),
            (b"I", 0x05) => iterations = le_u64(value, 0),
            (b"P", 0x04) => parallelism = le_u32(value, 0),
            _ => {}
        }
    }
    let uuid = uuid.ok_or_else(damaged)?;
    if uuid == AES_KDF_KDBX4.as_slice() || uuid == AES_KDF_KDBX3.as_slice() {
        Ok(Kdf::Aes {
            rounds: rounds.ok_or_else(damaged)?,
        })
    } else if uuid == ARGON2D.as_slice() || uuid == ARGON2ID.as_slice() {
        Ok(Kdf::Argon2 {
            memory_kib: memory.ok_or_else(damaged)? / 1024,
            iterations: iterations.ok_or_else(damaged)?,
            parallelism: parallelism.ok_or_else(damaged)?,
        })
    } else {
        Err(ImportError::UnsupportedEncryption(
            "a key derivation function KeePass doesn't define".to_string(),
        ))
    }
}

/// Checks that `bytes` is a KDBX 3.x or 4.x file and that the key derivation it asks for is within
/// `limits`, reading nothing but the outer header. [`ImportError::Unsupported`] for anything that
/// isn't KDBX 3 or 4 (KeePass 1 files, other text), [`ImportError::KdfOutOfBounds`] for a cost over
/// the limits, [`ImportError::Malformed`] for a header that doesn't hold together.
pub fn check_header(bytes: &[u8], limits: &Limits) -> Result<()> {
    if bytes.len() < 12 || bytes[..4] != SIGNATURE || bytes[4..8] != KDBX_ID {
        return Err(ImportError::Unsupported);
    }
    let kdf = match le_u16(bytes, 10).ok_or_else(damaged)? {
        3 => kdbx3_kdf(bytes)?,
        4 => kdbx4_kdf(bytes)?,
        _ => return Err(ImportError::Unsupported),
    };
    match kdf {
        Kdf::Aes { rounds } => {
            if rounds > limits.max_aes_kdf_rounds {
                return Err(ImportError::KdfOutOfBounds);
            }
        }
        Kdf::Argon2 {
            memory_kib,
            iterations,
            parallelism,
        } => {
            let most_iterations = u64::from(limits.max_argon2_iterations.max(256));
            let most_lanes = limits.max_argon2_parallelism.max(64);
            if iterations == 0
                || iterations > most_iterations
                || parallelism == 0
                || parallelism > most_lanes
                || memory_kib > u64::from(limits.max_argon2_memory_kib)
            {
                return Err(ImportError::KdfOutOfBounds);
            }
            // Memory and passes together are the work done: no more than 16 passes over the memory cap.
            if memory_kib.saturating_mul(iterations)
                > u64::from(limits.max_argon2_memory_kib).saturating_mul(16)
            {
                return Err(ImportError::KdfOutOfBounds);
            }
            // Argon2 itself needs 8 KiB for each lane.
            if memory_kib < 8 * u64::from(parallelism) {
                return Err(damaged());
            }
        }
    }
    Ok(())
}

/// The key from what the person gave: the password, the key file, or both.
fn database_key(ctx: &Context<'_>) -> Result<DatabaseKey> {
    let mut key = DatabaseKey::new();
    if let Some(password) = ctx.password {
        key = key.with_password(password);
    }
    if let Some(file) = ctx.key_file {
        let mut reader: &[u8] = file;
        key = key
            .with_keyfile(&mut reader)
            .map_err(|_| ImportError::malformed("the key file can't be read"))?;
    }
    Ok(key)
}

fn map_open_error(error: DatabaseOpenError) -> ImportError {
    match error {
        // A wrong password or key file shows as a bad key, a failed header MAC or a padding error.
        DatabaseOpenError::Key(_) | DatabaseOpenError::Cryptography(_) => ImportError::BadPassword,
        DatabaseOpenError::UnsupportedVersion | DatabaseOpenError::VersionParse(_) => {
            ImportError::Unsupported
        }
        _ => ImportError::malformed("the KDBX database is damaged"),
    }
}

/// Reads a KDBX database. `ctx.password` and `ctx.key_file` are its key; with neither,
/// [`ImportError::PasswordRequired`].
pub fn parse(bytes: &[u8], ctx: &Context<'_>) -> Result<ImportBatch> {
    ctx.limits.check_input(bytes)?;
    check_header(bytes, ctx.limits)?;
    if ctx.password.is_none() && ctx.key_file.is_none() {
        return Err(ImportError::PasswordRequired);
    }
    let key = database_key(ctx)?;
    // The reader is a third party's; whatever it does on a file made to break it, this isn't a
    // crash of the importer where unwinding is possible.
    let opened = catch_unwind(AssertUnwindSafe(|| Database::parse(bytes, key)));
    let db = match opened {
        Ok(Ok(db)) => db,
        Ok(Err(error)) => return Err(map_open_error(error)),
        Err(_) => {
            return Err(ImportError::malformed(
                "the KDBX reader could not read this file",
            ));
        }
    };
    let mut walk = Walk {
        b: Builder::new(Format::Kdbx, ctx.limits),
        trash: db.recycle_bin().map(|group| group.id()),
    };
    walk.group(&db.root(), &mut Vec::new(), 0, false);
    walk.b.finish()
}

/// Reads the groups and entries into the builder.
struct Walk<'a> {
    b: Builder<'a>,
    trash: Option<GroupId>,
}

/// What a passkey in the entry's fields came to.
enum Passkeys {
    None,
    Key(Box<Passkey>),
    Unsupported,
    Damaged,
}

impl Walk<'_> {
    fn group(&mut self, group: &GroupRef<'_>, path: &mut Vec<String>, depth: usize, trashed: bool) {
        if !trashed && !path.is_empty() {
            self.b.folder(&path.join("/"));
        }
        for entry in group.entries() {
            self.entry(&entry, path, trashed);
        }
        for child in group.groups() {
            if depth >= MAX_DEPTH {
                self.b.skip(
                    Some(child.name.as_str()),
                    SkipReason::Other,
                    Some("groups nested too deeply"),
                );
                continue;
            }
            let child_trashed = trashed || Some(child.id()) == self.trash;
            path.push(child.name.clone());
            self.group(&child, path, depth + 1, child_trashed);
            path.pop();
        }
    }

    fn entry(&mut self, entry: &EntryRef<'_>, path: &[String], trashed: bool) {
        let e: &Entry = entry;
        let title = e.get("Title").unwrap_or("");
        if trashed {
            self.b.skip(Some(title), SkipReason::Trashed, None);
            return;
        }
        let created_ms = e.times.creation.map(|t| t.and_utc().timestamp_millis());
        let meta = Meta {
            folder: self.b.folder(&path.join("/")),
            created_ms,
            modified_ms: modified_ms(e),
            tags: e
                .tags
                .iter()
                .map(|tag| tag.trim())
                .filter(|tag| !tag.is_empty())
                .map(str::to_string)
                .collect(),
            ..Meta::default()
        };

        let mut keys: Vec<&String> = e.fields.keys().collect();
        keys.sort();

        // Websites: `URL` first, then the other URL-like fields in name order.
        let mut urls: Vec<&str> = Vec::new();
        if let Some(url) = e.get("URL") {
            urls.push(url);
        }
        for key in &keys {
            if key.as_str() != "URL"
                && is_url_key(key)
                && let Some(url) = e.get(key)
            {
                urls.push(url);
            }
        }
        let mut uris = make_uris(urls.iter().copied());
        let mut seen: Vec<String> = Vec::new();
        uris.retain(|u| {
            if seen.contains(&u.uri) {
                false
            } else {
                seen.push(u.uri.clone());
                true
            }
        });

        // Custom fields: all the others.
        let mut fields: Vec<CustomField> = Vec::new();
        let mut spill: Option<String> = None;
        for key in &keys {
            if is_reserved(key) {
                continue;
            }
            if let Some(value) = e.fields.get(key.as_str()) {
                let kind = if value.is_protected() {
                    FieldKind::Hidden
                } else {
                    FieldKind::Text
                };
                kvp(&mut fields, &mut spill, key, value.get(), kind);
            }
        }

        let mut passkeys = Vec::new();
        match passkey_of(e, created_ms) {
            Passkeys::None => {}
            Passkeys::Key(key) => passkeys.push(*key),
            Passkeys::Unsupported => self.b.skip(
                Some(title),
                SkipReason::UnsupportedPasskey,
                Some("only ES256 passkeys are kept"),
            ),
            Passkeys::Damaged => self.b.skip(
                Some(title),
                SkipReason::BadKey,
                Some("a passkey with missing or damaged parts"),
            ),
        }

        let password = nonblank(e.get("Password"));
        let history: Vec<(Option<i64>, Option<String>)> = e
            .history
            .as_ref()
            .map(|h| {
                h.get_entries()
                    .iter()
                    .map(|version| {
                        (
                            modified_ms(version),
                            version.get("Password").map(str::to_string),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let previous_passwords = previous_passwords(&history, &(modified_ms(e), password.clone()));

        let login = Login {
            name: clean_name(Some(title)),
            uris,
            username: nonblank(e.get("UserName")),
            password,
            totp: totp_of(e, title),
            notes: join_notes(nonblank(e.get("Notes")), spill),
            fields,
            previous_passwords,
            passkeys,
            meta,
        };

        // Attachments, in name order.
        let mut attachments: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut too_big: Vec<String> = Vec::new();
        let limit = self.b.limits().max_entry_bytes;
        for (name, attachment) in entry.attachments_named() {
            let data = attachment.data.get();
            if data.len() > limit {
                too_big.push(name.to_string());
            } else {
                attachments.insert(name.to_string(), data.clone());
            }
        }
        too_big.sort();
        for name in &too_big {
            self.b.skip(Some(name), SkipReason::FileOverLimit, None);
        }

        let placed: Option<ItemRef> =
            if is_noteworthy_login(&login) && login.totp.is_none() && login.passkeys.is_empty() {
                self.b.note(Note {
                    name: login.name,
                    text: login.notes,
                    fields: login.fields,
                    meta: login.meta,
                })
            } else {
                self.b.login(login)
            };
        if let Some(owner) = placed {
            for (name, data) in attachments {
                self.b.file(&name, None, data, Some(owner));
            }
        }
    }
}

fn modified_ms(e: &Entry) -> Option<i64> {
    e.times
        .last_modification
        .map(|t| t.and_utc().timestamp_millis())
}

fn is_url_key(key: &str) -> bool {
    key.starts_with("URL") || key.starts_with("KP2A_URL")
}

/// Fields that become something other than a custom field.
fn is_reserved(key: &str) -> bool {
    matches!(
        key,
        "Title"
            | "UserName"
            | "Password"
            | "Notes"
            | "otp"
            | "TOTP Seed"
            | "TOTP Settings"
            | "TimeOtp-Secret-Base32"
            | "TimeOtp-Period"
            | "TimeOtp-Length"
            | "TimeOtp-Algorithm"
    ) || is_url_key(key)
        || key.starts_with("KPEX_PASSKEY_")
}

fn join_notes(note: Option<String>, spill: Option<String>) -> Option<String> {
    let joined = match (note, spill) {
        (Some(note), Some(spill)) => Some(format!("{note}\n{spill}")),
        (note, spill) => note.or(spill),
    };
    clean_notes(joined.map(|text| text.trim_end().to_string()))
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The entry's code: an `otpauth://` link as KeePassXC stores it in `otp`, or a seed with its
/// settings (KeePassXC's `TOTP Seed` and `TOTP Settings`, the TrayTOTP plug-in's `TimeOtp-*`),
/// written as a link. A Steam seed (`TOTP Settings` ending in `S`) is a `steam://` link.
fn totp_of(e: &Entry, title: &str) -> Option<String> {
    if let Some(link) = nonblank(e.get("otp")) {
        return Some(link.trim().to_string());
    }
    let label = percent_encode(title);
    if let Some(seed) = nonblank(e.get("TOTP Seed")) {
        let seed: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
        let settings = e.get("TOTP Settings").unwrap_or("");
        let mut parts = settings.split(';');
        let period = parts
            .next()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .filter(|p| *p > 0)
            .unwrap_or(30);
        let digits = parts.next().map(str::trim);
        if digits == Some("S") {
            return Some(format!("steam://{seed}"));
        }
        let digits = digits
            .and_then(|d| d.parse::<u32>().ok())
            .filter(|d| (4..=10).contains(d))
            .unwrap_or(6);
        return Some(format!(
            "otpauth://totp/{label}?secret={seed}&period={period}&digits={digits}"
        ));
    }
    if let Some(seed) = nonblank(e.get("TimeOtp-Secret-Base32")) {
        let seed: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
        let period = e
            .get("TimeOtp-Period")
            .and_then(|p| p.trim().parse::<u32>().ok())
            .filter(|p| *p > 0)
            .unwrap_or(30);
        let digits = e
            .get("TimeOtp-Length")
            .and_then(|d| d.trim().parse::<u32>().ok())
            .filter(|d| (4..=10).contains(d))
            .unwrap_or(6);
        let algorithm = match e.get("TimeOtp-Algorithm").map(str::trim) {
            Some("HMAC-SHA-256") => "&algorithm=SHA256",
            Some("HMAC-SHA-512") => "&algorithm=SHA512",
            _ => "",
        };
        return Some(format!(
            "otpauth://totp/{label}?secret={seed}&period={period}&digits={digits}{algorithm}"
        ));
    }
    None
}

/// A KeePassXC passkey: the `KPEX_PASSKEY_*` fields.
fn passkey_of(e: &Entry, created_ms: Option<i64>) -> Passkeys {
    if !e.fields.keys().any(|k| k.starts_with("KPEX_PASSKEY_")) {
        return Passkeys::None;
    }
    let part = |name: &str| nonblank(e.get(name));
    let (Some(credential), Some(pem), Some(rp), Some(handle)) = (
        part("KPEX_PASSKEY_CREDENTIAL_ID"),
        part("KPEX_PASSKEY_PRIVATE_KEY_PEM"),
        part("KPEX_PASSKEY_RELYING_PARTY"),
        part("KPEX_PASSKEY_USER_HANDLE"),
    ) else {
        return Passkeys::Damaged;
    };
    let (Some(credential), Some(handle), Some(der)) = (
        decode_base64_any(&credential),
        decode_base64_any(&handle),
        pem_to_der(&pem),
    ) else {
        return Passkeys::Damaged;
    };
    if credential.is_empty() || handle.is_empty() || rp.trim().is_empty() {
        return Passkeys::Damaged;
    }
    if cose_algorithm_of_pkcs8(&der) != Some(COSE_ES256) {
        return Passkeys::Unsupported;
    }
    Passkeys::Key(Box::new(Passkey {
        credential_id: encode_base64url(&credential),
        rp_id: rp.trim().to_lowercase(),
        rp_name: None,
        user_handle: encode_base64url(&handle),
        user_name: e.get("KPEX_PASSKEY_USERNAME").unwrap_or("").to_string(),
        user_display_name: None,
        private_key: encode_base64(&der),
        algorithm: COSE_ES256,
        created_ms,
    }))
}

/// The passwords the entry had before, newest first, at most five. `history` is the entry's older
/// versions (time, password) in any order and `current` its present one. A password counts when
/// the next version has another; it was replaced at the next version's time.
fn previous_passwords(
    history: &[(Option<i64>, Option<String>)],
    current: &(Option<i64>, Option<String>),
) -> Vec<PreviousPassword> {
    let mut versions: Vec<&(Option<i64>, Option<String>)> = history.iter().collect();
    versions.sort_by_key(|v| v.0);
    versions.push(current);
    let mut found: Vec<PreviousPassword> = Vec::new();
    for pair in versions.windows(2) {
        let (old, next) = (pair[0], pair[1]);
        if let Some(password) = old.1.as_deref()
            && !password.is_empty()
            && next.1.as_deref() != Some(password)
            && current.1.as_deref() != Some(password)
        {
            found.push(PreviousPassword {
                password: password.to_string(),
                until_ms: next.0.or(old.0).unwrap_or(0),
            });
        }
    }
    found.reverse();
    let mut seen: Vec<String> = Vec::new();
    found.retain(|p| {
        if seen.contains(&p.password) {
            false
        } else {
            seen.push(p.password.clone());
            true
        }
    });
    found.truncate(5);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::config::KdfConfig;
    use keepass::db::Value;

    const V3: &[u8] = include_bytes!("../tests/fixtures/kdbx/v3-aes.kdbx");
    const V4: &[u8] = include_bytes!("../tests/fixtures/kdbx/v4-argon2d.kdbx");
    const V4_CHACHA: &[u8] = include_bytes!("../tests/fixtures/kdbx/v4-aes-chacha20.kdbx");
    const KEY_FILE: &[u8] = include_bytes!("../tests/fixtures/kdbx/fixture.keyx");
    const PASSWORD: &str = "correct horse";

    fn open(bytes: &[u8], password: Option<&str>, key_file: Option<&[u8]>) -> Result<ImportBatch> {
        let limits = Limits::default();
        let mut ctx = Context::new(&limits);
        if let Some(password) = password {
            ctx = ctx.with_password(password);
        }
        if let Some(key_file) = key_file {
            ctx = ctx.with_key_file(key_file);
        }
        parse(bytes, &ctx)
    }

    // ---- Files made by the fixture generator (tests/fixtures/kdbx/make.mjs) -------------------

    /// What `make.mjs` puts in every fixture's database.
    fn check_fixture_content(batch: &ImportBatch) {
        let mail = batch
            .logins
            .iter()
            .find(|l| l.name == "Example Mail")
            .expect("Example Mail");
        assert_eq!(mail.username.as_deref(), Some("ada@example.com"));
        assert_eq!(mail.password.as_deref(), Some("hunter2-current"));
        assert_eq!(mail.uris[0].uri, "https://mail.example.com");
        assert_eq!(mail.notes.as_deref(), Some("Recovery codes in the drawer"));
        assert_eq!(
            mail.totp.as_deref(),
            Some("otpauth://totp/Mail:ada?secret=JBSWY3DPEHPK3PXP&issuer=Mail")
        );
        let fields: Vec<(&str, &str, FieldKind)> = mail
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str(), f.kind))
            .collect();
        assert_eq!(
            fields,
            [
                ("Account ID", "12345", FieldKind::Text),
                ("Security PIN", "9876", FieldKind::Hidden)
            ]
        );
        assert_eq!(mail.meta.tags, ["mail", "personal"]);
        assert_eq!(mail.meta.created_ms, Some(1_704_164_645_000));
        assert_eq!(mail.meta.modified_ms, Some(1_709_528_767_000));
        assert_eq!(mail.previous_passwords.len(), 1);
        assert_eq!(mail.previous_passwords[0].password, "old-pass");
        assert_eq!(mail.previous_passwords[0].until_ms, 1_709_528_767_000);

        let vpn = batch
            .logins
            .iter()
            .find(|l| l.name == "Office VPN")
            .expect("Office VPN");
        assert_eq!(vpn.uris[0].uri, "http://vpn.example.org");
        let folder = vpn.meta.folder.expect("folder");
        assert_eq!(batch.folders[folder].path, "Work/VPN");
        assert_eq!(
            batch.folders[batch.folders[folder].parent.expect("parent")].name,
            "Work"
        );

        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.notes[0].name, "Wifi note");
        assert_eq!(
            batch.notes[0].text.as_deref(),
            Some("SSID: home, password: abc")
        );

        assert!(batch.logins.iter().all(|l| l.name != "Deleted login"));
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::Trashed
                    && s.name.as_deref() == Some("Deleted login"))
        );
    }

    #[test]
    fn reads_a_kdbx_3_1_file() {
        let batch = open(V3, Some(PASSWORD), None).expect("batch");
        assert_eq!(batch.format, Format::Kdbx);
        check_fixture_content(&batch);
        assert!(batch.files.is_empty());
    }

    #[test]
    fn reads_a_kdbx_4_file_made_with_argon2d_a_password_and_a_key_file() {
        let batch = open(V4, Some(PASSWORD), Some(KEY_FILE)).expect("batch");
        check_fixture_content(&batch);
        assert_eq!(batch.files.len(), 1);
        assert_eq!(batch.files[0].name, "recovery.txt");
        assert_eq!(batch.files[0].data, b"code-1\ncode-2\n");
        assert_eq!(
            batch.files[0].owner,
            Some(ItemRef {
                kind: crate::model::ItemKind::Login,
                index: batch
                    .logins
                    .iter()
                    .position(|l| l.name == "Example Mail")
                    .expect("index")
            })
        );
    }

    #[test]
    fn reads_a_kdbx_4_file_with_chacha20_outside_and_in() {
        let batch = open(V4_CHACHA, Some(PASSWORD), None).expect("batch");
        check_fixture_content(&batch);
        let pk = batch
            .logins
            .iter()
            .find(|l| l.name == "Passkey site")
            .expect("Passkey site");
        assert_eq!(pk.passkeys.len(), 1);
        let key = &pk.passkeys[0];
        assert_eq!(key.credential_id, "AQIDBA");
        assert_eq!(key.user_handle, "BQYHCA");
        assert_eq!(key.rp_id, "passkey.example");
        assert_eq!(key.user_name, "ada");
        assert_eq!(key.algorithm, COSE_ES256);
        assert!(!key.private_key.is_empty());
        assert!(pk.fields.iter().all(|f| !f.name.starts_with("KPEX")));
    }

    #[test]
    fn the_fixtures_need_their_keys() {
        for (bytes, key_file) in [(V3, None), (V4, Some(KEY_FILE)), (V4_CHACHA, None)] {
            assert_eq!(
                open(bytes, None, None).err(),
                Some(ImportError::PasswordRequired)
            );
            assert_eq!(
                open(bytes, Some("wrong horse"), key_file).err(),
                Some(ImportError::BadPassword)
            );
        }
        // The right password without the key file, and the key file without the password.
        assert_eq!(
            open(V4, Some(PASSWORD), None).err(),
            Some(ImportError::BadPassword)
        );
        assert_eq!(
            open(V4, None, Some(KEY_FILE)).err(),
            Some(ImportError::BadPassword)
        );
        assert_eq!(
            open(V4, Some(PASSWORD), Some(b"another key file".as_slice())).err(),
            Some(ImportError::BadPassword)
        );
    }

    #[test]
    fn damaged_fixtures_fail_without_panicking() {
        for bytes in [V3, V4, V4_CHACHA] {
            for cut in [0, 5, 11, 12, 40, 200, bytes.len() / 2, bytes.len() - 1] {
                let _ = open(
                    &bytes[..cut.min(bytes.len())],
                    Some(PASSWORD),
                    Some(KEY_FILE),
                );
            }
        }
        // KDBX 4 authenticates every byte, in the header and in the payload.
        for (bytes, key_file) in [(V4, Some(KEY_FILE)), (V4_CHACHA, None)] {
            assert!(open(bytes, Some(PASSWORD), key_file).is_ok());
            for at in [20, 100, 150, bytes.len() / 2, bytes.len() - 5] {
                let mut flipped = bytes.to_vec();
                flipped[at] ^= 0x40;
                assert!(
                    open(&flipped, Some(PASSWORD), key_file).is_err(),
                    "byte {at}"
                );
            }
        }
        // KDBX 3.1 doesn't authenticate its header; a flip in the encrypted body still shows.
        let mut flipped = V3.to_vec();
        let last_block = flipped.len() - 20;
        flipped[last_block] ^= 0x40;
        let _ = open(&flipped, Some(PASSWORD), None);
    }

    // ---- Files written by the keepass crate ---------------------------------------------------

    fn add_login(db: &mut Database, title: &str, user: &str, password: &str) {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", title);
        e.set_unprotected("UserName", user);
        e.set_protected("Password", password);
    }

    fn save(db: &Database, key: DatabaseKey) -> Vec<u8> {
        let mut out = Vec::new();
        db.save(&mut out, key).expect("save");
        out
    }

    fn password_key(password: &str) -> DatabaseKey {
        DatabaseKey::new().with_password(password)
    }

    fn fake_p256_pem() -> String {
        // The start every PKCS#8 P-256 key has, then filler: only the algorithm is read.
        let mut der = vec![
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
            0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        ];
        der.extend_from_slice(&[7; 100]);
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            encode_base64(&der)
        )
    }

    fn fake_rsa_pem() -> String {
        let mut der = vec![
            0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
            0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
        ];
        der.extend_from_slice(&[7; 100]);
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            encode_base64(&der)
        )
    }

    fn sample_db() -> Database {
        let mut db = Database::new();
        db.config.kdf_config = KdfConfig::Aes { rounds: 100 };
        {
            let mut root = db.root_mut();
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "Example Mail");
                e.set_unprotected("UserName", "ada@example.com");
                e.set_protected("Password", "pw1");
                e.set_unprotected("URL", "https://mail.example.com");
                e.set_unprotected("URL_2", "https://mail2.example.com");
                e.set_unprotected("KP2A_URL_1", "https://mail.example.com");
                e.set_unprotected("Notes", "Recovery codes in the drawer");
                e.set_protected(
                    "otp",
                    "otpauth://totp/Mail:ada?secret=JBSWY3DPEHPK3PXP&issuer=Mail",
                );
                e.set_unprotected("Account ID", "12345");
                e.set_protected("Security PIN", "9876");
                e.tags.push("mail".into());
                e.tags.push("personal".into());
                e.add_attachment(
                    "recovery.txt",
                    Value::unprotected(b"code-1\ncode-2\n".to_vec()),
                );
                e.edit_tracking(|t| t.set_protected("Password", "pw2"));
                e.edit_tracking(|t| t.set_protected("Password", "pw3"));
            }
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "Wifi note");
                e.set_unprotected("Notes", "SSID: home");
            }
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "Passkey site");
                e.set_unprotected("UserName", "ada");
                e.set_unprotected("URL", "https://passkey.example");
                e.set_unprotected("KPEX_PASSKEY_CREDENTIAL_ID", encode_base64(&[1, 2, 3, 4]));
                e.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", fake_p256_pem());
                e.set_unprotected("KPEX_PASSKEY_RELYING_PARTY", "Passkey.Example");
                e.set_unprotected("KPEX_PASSKEY_USERNAME", "ada");
                e.set_unprotected("KPEX_PASSKEY_USER_HANDLE", encode_base64url(&[5, 6, 7, 8]));
            }
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "RSA passkey");
                e.set_unprotected("UserName", "bob");
                e.set_unprotected("KPEX_PASSKEY_CREDENTIAL_ID", encode_base64url(&[1]));
                e.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", fake_rsa_pem());
                e.set_unprotected("KPEX_PASSKEY_RELYING_PARTY", "rsa.example");
                e.set_unprotected("KPEX_PASSKEY_USER_HANDLE", encode_base64url(&[2]));
            }
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "Broken passkey");
                e.set_unprotected("UserName", "carol");
                e.set_unprotected("KPEX_PASSKEY_CREDENTIAL_ID", encode_base64url(&[1]));
            }
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "Legacy code");
                e.set_unprotected("UserName", "dan");
                e.set_unprotected("TOTP Seed", "JBSWY3DP EHPK3PXP");
                e.set_unprotected("TOTP Settings", "30;8");
            }
            {
                let mut e = root.add_entry();
                e.set_unprotected("Title", "Steam");
                e.set_unprotected("UserName", "gabe");
                e.set_unprotected("TOTP Seed", "STEAMSEED");
                e.set_unprotected("TOTP Settings", "30;S");
            }
            {
                let mut work = root.add_group();
                work.name = "Work".into();
                let mut vpn = work.add_group();
                vpn.name = "VPN".into();
                let mut e = vpn.add_entry();
                e.set_unprotected("Title", "Office VPN");
                e.set_unprotected("UserName", "bob");
                e.set_protected("Password", "vpn-secret");
                e.set_unprotected("URL", "vpn.example.org");
            }
            {
                let mut empty = root.add_group();
                empty.name = "Empty".into();
            }
        }
        let bin_id = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".into();
            bin.id()
        };
        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        {
            let mut bin = db.group_mut(bin_id).expect("bin");
            let mut e = bin.add_entry();
            e.set_unprotected("Title", "Deleted login");
            e.set_unprotected("UserName", "gone");
        }
        db
    }

    fn sample_file() -> Vec<u8> {
        save(&sample_db(), password_key("pw"))
    }

    #[test]
    fn maps_entries_groups_history_files_and_passkeys() {
        let batch = open(&sample_file(), Some("pw"), None).expect("batch");

        let titles: Vec<&str> = batch.logins.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Example Mail",
                "Passkey site",
                "RSA passkey",
                "Broken passkey",
                "Legacy code",
                "Steam",
                "Office VPN"
            ]
        );
        assert_eq!(batch.notes.len(), 1);
        assert_eq!(batch.notes[0].name, "Wifi note");
        assert_eq!(batch.notes[0].text.as_deref(), Some("SSID: home"));

        let mail = &batch.logins[0];
        assert_eq!(mail.username.as_deref(), Some("ada@example.com"));
        assert_eq!(mail.password.as_deref(), Some("pw3"));
        // `URL`, `URL_2` and `KP2A_URL_1` (a repeat of the first), as websites.
        let uris: Vec<&str> = mail.uris.iter().map(|u| u.uri.as_str()).collect();
        assert_eq!(
            uris,
            ["https://mail.example.com", "https://mail2.example.com"]
        );
        assert_eq!(mail.notes.as_deref(), Some("Recovery codes in the drawer"));
        assert!(
            mail.totp
                .as_deref()
                .expect("totp")
                .starts_with("otpauth://totp/Mail:ada")
        );
        let fields: Vec<(&str, FieldKind)> = mail
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.kind))
            .collect();
        assert_eq!(
            fields,
            [
                ("Account ID", FieldKind::Text),
                ("Security PIN", FieldKind::Hidden)
            ]
        );
        assert_eq!(mail.meta.tags, ["mail", "personal"]);
        let mut previous: Vec<&str> = mail
            .previous_passwords
            .iter()
            .map(|p| p.password.as_str())
            .collect();
        previous.sort_unstable();
        assert_eq!(previous, ["pw1", "pw2"]);

        assert_eq!(batch.files.len(), 1);
        assert_eq!(batch.files[0].name, "recovery.txt");
        assert_eq!(batch.files[0].data, b"code-1\ncode-2\n");
        assert_eq!(batch.files[0].owner.map(|o| o.index), Some(0));

        // Folders: the top group is none; empty groups are kept; the bin is left out.
        let paths: Vec<&str> = batch.folders.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["Work", "Work/VPN", "Empty"]);
        assert_eq!(batch.logins[6].meta.folder, Some(1));
        assert_eq!(batch.logins[6].uris[0].uri, "http://vpn.example.org");
        assert_eq!(batch.logins[0].meta.folder, None);

        // The passkey, the unsupported and the broken one.
        let key = &batch.logins[1].passkeys[0];
        assert_eq!(key.credential_id, "AQIDBA");
        assert_eq!(key.user_handle, "BQYHCA");
        assert_eq!(key.rp_id, "passkey.example");
        assert_eq!(key.algorithm, COSE_ES256);
        assert!(batch.logins[1].fields.is_empty());
        assert!(batch.logins[2].passkeys.is_empty());
        let reasons: Vec<(Option<&str>, SkipReason)> = batch
            .skipped
            .iter()
            .map(|s| (s.name.as_deref(), s.reason))
            .collect();
        assert_eq!(
            reasons,
            [
                (Some("RSA passkey"), SkipReason::UnsupportedPasskey),
                (Some("Broken passkey"), SkipReason::BadKey),
                (Some("Deleted login"), SkipReason::Trashed)
            ]
        );

        // Codes from the older fields.
        assert_eq!(
            batch.logins[4].totp.as_deref(),
            Some("otpauth://totp/Legacy%20code?secret=JBSWY3DPEHPK3PXP&period=30&digits=8")
        );
        assert_eq!(batch.logins[5].totp.as_deref(), Some("steam://STEAMSEED"));
        assert!(batch.logins[4].fields.is_empty());
    }

    #[test]
    fn a_key_file_alone_or_with_a_password_opens_a_database() {
        let mut db = Database::new();
        db.config.kdf_config = KdfConfig::Aes { rounds: 100 };
        add_login(&mut db, "Only entry", "u", "p");
        let key_file: &[u8] = b"0123456789abcdef0123456789abcdef";
        let mut reader = key_file;
        let both = DatabaseKey::new()
            .with_password("pw")
            .with_keyfile(&mut reader)
            .expect("key file");
        let bytes = save(&db, both);
        let batch = open(&bytes, Some("pw"), Some(key_file)).expect("batch");
        assert_eq!(batch.logins[0].name, "Only entry");
        assert_eq!(
            open(&bytes, Some("pw"), None).err(),
            Some(ImportError::BadPassword)
        );
        assert_eq!(
            open(
                &bytes,
                Some("pw"),
                Some(b"0123456789abcdef0123456789abcdeX".as_slice())
            )
            .err(),
            Some(ImportError::BadPassword)
        );
    }

    #[test]
    fn a_wrong_or_missing_password_is_told_apart() {
        let bytes = sample_file();
        assert_eq!(
            open(&bytes, None, None).err(),
            Some(ImportError::PasswordRequired)
        );
        assert_eq!(
            open(&bytes, Some("nope"), None).err(),
            Some(ImportError::BadPassword)
        );
    }

    #[test]
    fn entries_over_the_limit_are_counted() {
        let limits = Limits {
            max_entries: 3,
            ..Limits::default()
        };
        let batch =
            parse(&sample_file(), &Context::new(&limits).with_password("pw")).expect("batch");
        assert_eq!(batch.entry_count(), 3);
        assert!(
            batch
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::OverLimit)
        );
    }

    #[test]
    fn a_kdf_over_the_limits_is_refused_before_it_runs() {
        let mut db = Database::new();
        db.config.kdf_config = KdfConfig::Aes { rounds: 30_000 };
        add_login(&mut db, "x", "u", "p");
        let bytes = save(&db, password_key("pw"));
        let small = Limits::small();
        assert_eq!(
            parse(&bytes, &Context::new(&small).with_password("pw")).err(),
            Some(ImportError::KdfOutOfBounds)
        );
        assert!(open(&bytes, Some("pw"), None).is_ok());
    }

    // ---- The header check on made-up headers --------------------------------------------------

    fn start(major: u16, id: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE);
        out.extend_from_slice(&id);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&major.to_le_bytes());
        out
    }

    fn v3_header(rounds: u64) -> Vec<u8> {
        let mut out = start(3, KDBX_ID);
        out.extend_from_slice(&[2, 16, 0]);
        out.extend_from_slice(&[0x31; 16]);
        out.extend_from_slice(&[6, 8, 0]);
        out.extend_from_slice(&rounds.to_le_bytes());
        out.extend_from_slice(&[0, 4, 0, 13, 10, 13, 10]);
        out
    }

    fn entry(kind: u8, key: &str, value: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        out
    }

    fn dictionary(uuid: [u8; 16], entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0x00, 0x01];
        out.extend_from_slice(&entry(0x42, "$UUID", &uuid));
        for e in entries {
            out.extend_from_slice(e);
        }
        out.push(0);
        out
    }

    fn v4_header(dict: &[u8]) -> Vec<u8> {
        let mut out = start(4, KDBX_ID);
        out.push(11);
        out.extend_from_slice(&(dict.len() as u32).to_le_bytes());
        out.extend_from_slice(dict);
        out.extend_from_slice(&[0, 4, 0, 0, 0, 13, 10, 13, 10]);
        out
    }

    fn argon(memory: u64, iterations: u64, parallelism: u32) -> Vec<u8> {
        v4_header(&dictionary(
            ARGON2ID,
            &[
                entry(0x05, "M", &memory.to_le_bytes()),
                entry(0x05, "I", &iterations.to_le_bytes()),
                entry(0x04, "P", &parallelism.to_le_bytes()),
            ],
        ))
    }

    fn aes4(rounds: u64) -> Vec<u8> {
        v4_header(&dictionary(
            AES_KDF_KDBX4,
            &[entry(0x05, "R", &rounds.to_le_bytes())],
        ))
    }

    #[test]
    fn the_header_check_bounds_every_kdf() {
        let limits = Limits::default();
        assert_eq!(check_header(&v3_header(60_000), &limits), Ok(()));
        assert_eq!(check_header(&v3_header(100_000_000), &limits), Ok(()));
        assert_eq!(
            check_header(&v3_header(100_000_001), &limits),
            Err(ImportError::KdfOutOfBounds)
        );
        assert_eq!(check_header(&aes4(6_000_000), &limits), Ok(()));
        assert_eq!(
            check_header(&aes4(u64::MAX), &limits),
            Err(ImportError::KdfOutOfBounds)
        );
        // KeePass's own defaults: 64 MiB, 2 passes, 2 lanes; and a tuned one with many passes.
        assert_eq!(check_header(&argon(64 << 20, 2, 2), &limits), Ok(()));
        assert_eq!(check_header(&argon(64 << 20, 200, 4), &limits), Ok(()));
        for bad in [
            argon(2048 << 20, 2, 2),
            argon(64 << 20, 257, 2),
            argon(64 << 20, 0, 2),
            argon(64 << 20, 2, 0),
            argon(64 << 20, 2, 65),
            argon(u64::MAX, 2, 2),
        ] {
            assert_eq!(
                check_header(&bad, &limits),
                Err(ImportError::KdfOutOfBounds)
            );
        }
        // Below Argon2's own floor of 8 KiB a lane.
        assert!(matches!(
            check_header(&argon(1024, 2, 2), &limits),
            Err(ImportError::Malformed(_))
        ));
        let small = Limits::small();
        assert_eq!(check_header(&aes4(20_000), &small), Ok(()));
        assert_eq!(
            check_header(&aes4(20_001), &small),
            Err(ImportError::KdfOutOfBounds)
        );
        assert_eq!(
            check_header(&argon(2 << 20, 2, 2), &small),
            Err(ImportError::KdfOutOfBounds)
        );
    }

    #[test]
    fn parse_refuses_a_costly_header_before_asking_for_a_key() {
        let limits = Limits::default();
        assert_eq!(
            parse(&aes4(u64::MAX), &Context::new(&limits)).err(),
            Some(ImportError::KdfOutOfBounds)
        );
        assert_eq!(
            parse(
                &v3_header(u64::MAX),
                &Context::new(&limits).with_password("x")
            )
            .err(),
            Some(ImportError::KdfOutOfBounds)
        );
    }

    #[test]
    fn other_files_are_not_kdbx() {
        let limits = Limits::default();
        assert_eq!(
            check_header(b"hello", &limits),
            Err(ImportError::Unsupported)
        );
        assert_eq!(check_header(&[], &limits), Err(ImportError::Unsupported));
        // KeePass 1 and the 2.0 pre-release have other second signatures.
        for id in [[0x65, 0xFB, 0x4B, 0xB5], [0x66, 0xFB, 0x4B, 0xB5]] {
            let mut header = start(3, id);
            header.extend_from_slice(&[0, 0, 0]);
            assert_eq!(
                check_header(&header, &limits),
                Err(ImportError::Unsupported)
            );
        }
        // Major version 2 and 5.
        for major in [2u16, 5] {
            let mut header = start(major, KDBX_ID);
            header.extend_from_slice(&[0, 0, 0]);
            assert_eq!(
                check_header(&header, &limits),
                Err(ImportError::Unsupported)
            );
        }
        assert_eq!(
            parse(
                b"just some text that is long enough",
                &Context::new(&limits).with_password("x")
            )
            .err(),
            Some(ImportError::Unsupported)
        );
    }

    #[test]
    fn damaged_headers_are_errors_not_panics() {
        let limits = Limits::default();
        let good = v3_header(1000);
        for cut in 0..good.len() {
            let _ = check_header(&good[..cut], &limits);
        }
        let good4 = aes4(1000);
        for cut in 0..good4.len() {
            let _ = check_header(&good4[..cut], &limits);
        }
        // A compression field that isn't four bytes, a rounds field that isn't eight.
        let mut bad = start(3, KDBX_ID);
        bad.extend_from_slice(&[3, 2, 0, 1, 0, 0, 0, 0]);
        assert!(matches!(
            check_header(&bad, &limits),
            Err(ImportError::Malformed(_))
        ));
        let mut bad = start(3, KDBX_ID);
        bad.extend_from_slice(&[6, 3, 0, 1, 2, 3, 0, 0, 0]);
        assert!(matches!(
            check_header(&bad, &limits),
            Err(ImportError::Malformed(_))
        ));
        let mut bad = start(4, KDBX_ID);
        bad.extend_from_slice(&[3, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0]);
        assert!(matches!(
            check_header(&bad, &limits),
            Err(ImportError::Malformed(_))
        ));
        // A dictionary with a value of the wrong width, an unknown type, a huge key length, no
        // terminator, an unknown KDF, and a missing parameter.
        for dict in [
            dictionary(AES_KDF_KDBX4, &[entry(0x05, "R", &[1, 2, 3])]),
            dictionary(AES_KDF_KDBX4, &[entry(0x77, "R", &[1])]),
            dictionary(AES_KDF_KDBX4, &[]),
            {
                let mut d = vec![0x00, 0x01, 0x05];
                d.extend_from_slice(&u32::MAX.to_le_bytes());
                d
            },
            {
                let mut d = dictionary(AES_KDF_KDBX4, &[entry(0x05, "R", &1u64.to_le_bytes())]);
                d.pop();
                d
            },
        ] {
            assert!(
                matches!(
                    check_header(&v4_header(&dict), &limits),
                    Err(ImportError::Malformed(_))
                ),
                "{dict:?}"
            );
        }
        assert!(matches!(
            check_header(&v4_header(&dictionary([9; 16], &[])), &limits),
            Err(ImportError::UnsupportedEncryption(_))
        ));
        let mut wrong_version = dictionary(AES_KDF_KDBX4, &[entry(0x05, "R", &1u64.to_le_bytes())]);
        wrong_version[1] = 9;
        assert!(check_header(&v4_header(&wrong_version), &limits).is_err());
    }

    #[test]
    fn previous_passwords_follow_the_versions_by_time() {
        let history = [
            (Some(300), Some("c".to_string())),
            (Some(100), Some("a".to_string())),
            (Some(200), Some("b".to_string())),
            (Some(250), Some("b".to_string())),
            (Some(50), None),
            (Some(60), Some(String::new())),
        ];
        let found = previous_passwords(&history, &(Some(400), Some("d".to_string())));
        let got: Vec<(&str, i64)> = found
            .iter()
            .map(|p| (p.password.as_str(), p.until_ms))
            .collect();
        // a (until 200), b (until 300, the 250 version repeats it), c (until 400); newest first.
        assert_eq!(got, [("c", 400), ("b", 300), ("a", 200)]);

        // A password that comes back is not its own previous one.
        let found = previous_passwords(
            &[(Some(1), Some("x".to_string()))],
            &(Some(2), Some("x".to_string())),
        );
        assert!(found.is_empty());

        // At most five, each once.
        let many: Vec<(Option<i64>, Option<String>)> = (0..9)
            .map(|i| (Some(i), Some(format!("p{}", i % 7))))
            .collect();
        let found = previous_passwords(&many, &(Some(99), Some("now".to_string())));
        assert_eq!(found.len(), 5);
        let mut names: Vec<&str> = found.iter().map(|p| p.password.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 5);
    }

    #[test]
    fn totp_links_are_written_from_the_older_fields() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "Tray TOTP");
            e.set_unprotected("TimeOtp-Secret-Base32", "ABCD EFGH");
            e.set_unprotected("TimeOtp-Period", "60");
            e.set_unprotected("TimeOtp-Length", "8");
            e.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
        }
        let entry_ref = db.root().entries().next().map(|e| e.id()).expect("entry");
        let found = db.entry(entry_ref).expect("entry");
        let e: &Entry = &found;
        assert_eq!(
            totp_of(e, "Tray TOTP").as_deref(),
            Some("otpauth://totp/Tray%20TOTP?secret=ABCDEFGH&period=60&digits=8&algorithm=SHA256")
        );
        assert_eq!(percent_encode("a b/é"), "a%20b%2F%C3%A9");
    }
}
