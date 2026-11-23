//! From a Vaultwarden snapshot to what Kemlock Server stores.
//!
//! The mapping is pure: it reads a [`VaultwardenSnapshot`] and returns plain structs, and writes
//! nothing. The store side is the [`crate::sink::ImportSink`] trait.
//!
//! - Accounts arrive unchanged in Compatible mode: the same password hash, salt, wrapped user key,
//!   RSA key pair, KDF settings and security stamp, so master passwords keep working and nobody
//!   re-keys.
//! - Ciphers become `bw` items: Vaultwarden's own cipher JSON ([`crate::cipher_json`]), still
//!   encrypted as their owners' apps wrote it. A cipher owned by a user is stored as that user's
//!   sync shows it; an organization's cipher is stored viewer-independent and the Bitwarden API
//!   adds each member's view with [`crate::cipher_json::apply_viewer`].
//! - The per-user state of a cipher (folder, favorite, archive date) is kept beside the item.
//! - Attachments and send files are listed to be copied as they are, encrypted.
//! - `rsa_key.pem` is carried so signed-in Bitwarden apps keep their tokens; `config.json` becomes
//!   settings ([`crate::settings`]).
//! - Everything else (organizations with their members, collections, groups and policies;
//!   two-step setups; emergency access; sends; the event log; devices; invitations; SSO links)
//!   is carried row for row as stored, for the store to put in its own tables. Rows that only
//!   hold short-lived state are left out: two-step challenges (`twofactor` types 1000 and up),
//!   `twofactor_incomplete` and `auth_requests`.

use crate::cipher_json::{ViewerState, apply_viewer, base_json, kind_name};
use crate::error::MapError;
use crate::settings::{MappedSettings, map_settings};
use crate::snapshot::{DataFiles, RowKey, RowRef, Table, VaultwardenSnapshot};
use crate::vwtime::{format_date, parse_db_time, to_utc};
use kemlock_domain::{AccountMode, ItemFormat, ItemId, ItemKind, Owner, Role, SpaceId, UserId};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

/// Every column Vaultwarden keeps for a user that a Bitwarden client or the Bitwarden API reads.
/// Bytes and secrets stay out of the `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct BitwardenAccount {
    pub enabled: bool,
    pub verified_at: Option<OffsetDateTime>,
    pub last_verifying_at: Option<OffsetDateTime>,
    pub login_verify_count: i64,
    pub email_new: Option<String>,
    pub email_new_token: Option<String>,
    /// The server-side PBKDF2 hash of the client's master password hash.
    pub password_hash: Vec<u8>,
    /// The salt of `password_hash`.
    pub salt: Vec<u8>,
    /// The rounds of `password_hash` (600,000 on current Vaultwarden; older accounts keep theirs
    /// until OPAQUE replaces them).
    pub password_iterations: i64,
    pub password_hint: Option<String>,
    /// The user key, wrapped by the master key.
    pub akey: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_recover: Option<String>,
    pub security_stamp: String,
    pub stamp_exception: Option<String>,
    pub equivalent_domains: String,
    pub excluded_globals: String,
    /// 0 for PBKDF2-SHA256, 1 for Argon2id.
    pub client_kdf_type: i64,
    pub client_kdf_iter: i64,
    pub client_kdf_memory: Option<i64>,
    pub client_kdf_parallelism: Option<i64>,
    pub api_key: Option<String>,
    pub avatar_color: Option<String>,
    pub external_id: Option<String>,
    pub key_id: Option<String>,
}

impl fmt::Debug for BitwardenAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenAccount")
            .field("enabled", &self.enabled)
            .field("client_kdf_type", &self.client_kdf_type)
            .field("client_kdf_iter", &self.client_kdf_iter)
            .finish_non_exhaustive()
    }
}

/// An account, as Kemlock stores it after the move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedAccount {
    pub id: UserId,
    pub email: String,
    pub name: String,
    /// Always [`AccountMode::Compatible`]: sign-in takes Bitwarden's prelogin and password hash.
    pub mode: AccountMode,
    /// Always [`Role::User`]: Vaultwarden has no admin accounts, only its admin token.
    pub role: Role,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub bitwarden: BitwardenAccount,
}

/// A cipher as a `bw` item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedItem {
    /// The cipher's UUID.
    pub id: ItemId,
    /// The user, or the organization as a space (the space has the organization's UUID).
    pub owner: Owner,
    pub kind: ItemKind,
    /// Always [`ItemFormat::Bw`].
    pub format: ItemFormat,
    /// Bitwarden's cipher type number (1 login, 2 secure note, 3 card, 4 identity, 5 SSH key).
    pub atype: i64,
    /// The JSON Vaultwarden returns for the cipher; see [`crate::cipher_json`].
    pub json: Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl MappedItem {
    /// The bytes a `bw` item stores: the JSON, compact.
    pub fn payload(&self) -> Vec<u8> {
        serde_json::to_vec(&self.json).unwrap_or_default()
    }
}

/// What one user has set on one cipher: the folder it is in, whether it is a favorite and when
/// they archived it. Vaultwarden keeps these per user, even for an organization's cipher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedCipherState {
    pub user: UserId,
    pub item: ItemId,
    pub folder: Option<Uuid>,
    pub favorite: bool,
    pub archived_at: Option<OffsetDateTime>,
}

/// A folder. Its name is encrypted as its owner's app wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedFolder {
    pub id: Uuid,
    pub user: UserId,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    /// What Vaultwarden returns for the folder.
    pub json: Value,
}

/// An attachment's row. `url` is made per request, so the server builds the entry of the cipher's
/// `attachments` with [`crate::cipher_json::attachment_json`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedAttachment {
    pub id: String,
    pub item: ItemId,
    /// Encrypted.
    pub file_name: String,
    pub size: i64,
    /// The attachment's own key, wrapped by the cipher key.
    pub key: Option<String>,
    /// Where the file goes in file storage (`attachments/<cipher>/<attachment>`).
    pub storage_key: String,
    /// Whether the file was found; if not, the plan says so.
    pub file_found: bool,
}

/// What a file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileKind {
    Attachment,
    Send,
}

/// A file to copy, as it is (it is encrypted already).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileCopy {
    pub kind: FileKind,
    /// Where to read it, in the Vaultwarden data folder.
    pub from: PathBuf,
    /// Where it goes in file storage: `attachments/<cipher>/<attachment>` or
    /// `sends/<send>/<file>`.
    pub storage_key: String,
    pub size: u64,
}

/// The key pair that signs Vaultwarden's tokens. With it moved, the RS256 tokens the Bitwarden
/// apps hold still verify and nobody is signed out.
#[derive(Clone, PartialEq, Eq)]
pub struct MappedRsaKey {
    /// `rsa_key.pem`.
    pub private_pem: Vec<u8>,
    /// `rsa_key.pub.pem`, if Vaultwarden wrote one.
    pub public_pem: Option<Vec<u8>>,
}

impl fmt::Debug for MappedRsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MappedRsaKey(..)")
    }
}

/// Everything the move puts in Kemlock Server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MappedImport {
    pub accounts: Vec<MappedAccount>,
    pub folders: Vec<MappedFolder>,
    pub items: Vec<MappedItem>,
    pub cipher_states: Vec<MappedCipherState>,
    pub attachments: Vec<MappedAttachment>,
    /// Attachment and send files to copy.
    pub files: Vec<FileCopy>,
    /// Tables carried row for row; see the module docs.
    pub carried: Vec<Table>,
    pub settings: MappedSettings,
    pub rsa_key: Option<MappedRsaKey>,
    /// Things the person moving should read; the plan prints them.
    pub warnings: Vec<String>,
}

/// The tables carried as they are, in this order.
const CARRIED: &[&str] = &[
    "devices",
    "organizations",
    "users_organizations",
    "collections",
    "ciphers_collections",
    "users_collections",
    "groups",
    "collections_groups",
    "groups_users",
    "org_policies",
    "organization_api_key",
    "twofactor",
    "emergency_access",
    "sends",
    "event",
    "sso_users",
    "invitations",
];

/// `twofactor` rows of this type and above are login challenges, not setups.
const FIRST_TWOFACTOR_CHALLENGE: i64 = 1000;

fn need_text<'a>(row: &RowRef<'a>, column: &'static str) -> Result<&'a str, MapError> {
    row.text(column).ok_or_else(|| MapError::Missing {
        table: row.table(),
        key: row.key_text(),
        column,
    })
}

fn opt_text(row: &RowRef<'_>, column: &str) -> Option<String> {
    row.text(column).map(str::to_owned)
}

fn need_int(row: &RowRef<'_>, column: &'static str) -> Result<i64, MapError> {
    row.int(column).ok_or_else(|| MapError::Missing {
        table: row.table(),
        key: row.key_text(),
        column,
    })
}

fn need_bytes(row: &RowRef<'_>, column: &'static str) -> Result<Vec<u8>, MapError> {
    row.bytes(column)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| MapError::Missing {
            table: row.table(),
            key: row.key_text(),
            column,
        })
}

fn parse_uuid(row: &RowRef<'_>, column: &'static str, text: &str) -> Result<Uuid, MapError> {
    Uuid::parse_str(text.trim()).map_err(|_| MapError::BadId {
        table: row.table(),
        key: row.key_text(),
        column,
        value: text.to_owned(),
    })
}

fn need_uuid(row: &RowRef<'_>, column: &'static str) -> Result<Uuid, MapError> {
    let text = need_text(row, column)?;
    parse_uuid(row, column, text)
}

fn parse_time(
    row: &RowRef<'_>,
    column: &'static str,
    text: &str,
) -> Result<PrimitiveDateTime, MapError> {
    parse_db_time(text).ok_or_else(|| MapError::BadTime {
        table: row.table(),
        key: row.key_text(),
        column,
        value: text.to_owned(),
    })
}

fn need_time(row: &RowRef<'_>, column: &'static str) -> Result<PrimitiveDateTime, MapError> {
    let text = need_text(row, column)?;
    parse_time(row, column, text)
}

fn opt_time(row: &RowRef<'_>, column: &'static str) -> Result<Option<PrimitiveDateTime>, MapError> {
    match row.text(column) {
        Some(text) => parse_time(row, column, text).map(Some),
        None => Ok(None),
    }
}

fn map_account(row: &RowRef<'_>) -> Result<MappedAccount, MapError> {
    let id = UserId(need_uuid(row, "uuid")?);
    let created_at = to_utc(need_time(row, "created_at")?);
    let updated_at = to_utc(need_time(row, "updated_at")?);
    let bitwarden = BitwardenAccount {
        enabled: row.bool("enabled").unwrap_or(true),
        verified_at: opt_time(row, "verified_at")?.map(to_utc),
        last_verifying_at: opt_time(row, "last_verifying_at")?.map(to_utc),
        login_verify_count: row.int("login_verify_count").unwrap_or(0),
        email_new: opt_text(row, "email_new"),
        email_new_token: opt_text(row, "email_new_token"),
        password_hash: need_bytes(row, "password_hash")?,
        salt: need_bytes(row, "salt")?,
        password_iterations: need_int(row, "password_iterations")?,
        password_hint: opt_text(row, "password_hint"),
        akey: need_text(row, "akey")?.to_owned(),
        private_key: opt_text(row, "private_key"),
        public_key: opt_text(row, "public_key"),
        totp_secret: opt_text(row, "totp_secret"),
        totp_recover: opt_text(row, "totp_recover"),
        security_stamp: need_text(row, "security_stamp")?.to_owned(),
        stamp_exception: opt_text(row, "stamp_exception"),
        equivalent_domains: need_text(row, "equivalent_domains")?.to_owned(),
        excluded_globals: need_text(row, "excluded_globals")?.to_owned(),
        client_kdf_type: need_int(row, "client_kdf_type")?,
        client_kdf_iter: need_int(row, "client_kdf_iter")?,
        client_kdf_memory: row.int("client_kdf_memory"),
        client_kdf_parallelism: row.int("client_kdf_parallelism"),
        api_key: opt_text(row, "api_key"),
        avatar_color: opt_text(row, "avatar_color"),
        external_id: opt_text(row, "external_id"),
        key_id: opt_text(row, "key_id"),
    };
    Ok(MappedAccount {
        id,
        email: need_text(row, "email")?.to_owned(),
        name: need_text(row, "name")?.to_owned(),
        mode: AccountMode::Compatible,
        role: Role::User,
        created_at,
        updated_at,
        bitwarden,
    })
}

/// What each user has set on each cipher, from `folders_ciphers`, `favorites` and `archives`.
#[derive(Default)]
struct UserStates {
    by_pair: BTreeMap<(String, String), PairState>,
}

#[derive(Default, Clone)]
struct PairState {
    folder: Option<String>,
    favorite: bool,
    archived_at: Option<PrimitiveDateTime>,
}

impl UserStates {
    fn build(snapshot: &VaultwardenSnapshot) -> Result<UserStates, MapError> {
        let mut folder_owner: BTreeMap<&str, &str> = BTreeMap::new();
        for row in snapshot.folders.rows() {
            if let (Some(uuid), Some(user)) = (row.text("uuid"), row.text("user_uuid")) {
                folder_owner.insert(uuid, user);
            }
        }
        let mut states = UserStates::default();
        for row in snapshot.folders_ciphers.rows() {
            let (Some(cipher), Some(folder)) = (row.text("cipher_uuid"), row.text("folder_uuid"))
            else {
                continue;
            };
            // A folder belongs to one user, so it tells whose state this is.
            if let Some(user) = folder_owner.get(folder) {
                states
                    .by_pair
                    .entry(((*user).to_owned(), cipher.to_owned()))
                    .or_default()
                    .folder = Some(folder.to_owned());
            }
        }
        for row in snapshot.favorites.rows() {
            if let (Some(user), Some(cipher)) = (row.text("user_uuid"), row.text("cipher_uuid")) {
                states
                    .by_pair
                    .entry((user.to_owned(), cipher.to_owned()))
                    .or_default()
                    .favorite = true;
            }
        }
        for row in snapshot.archives.rows() {
            if let (Some(user), Some(cipher)) = (row.text("user_uuid"), row.text("cipher_uuid")) {
                states
                    .by_pair
                    .entry((user.to_owned(), cipher.to_owned()))
                    .or_default()
                    .archived_at = opt_time(&row, "archived_at")?;
            }
        }
        Ok(states)
    }

    fn viewer(&self, user: &str, cipher: &str) -> ViewerState {
        let state = self
            .by_pair
            .get(&(user.to_owned(), cipher.to_owned()))
            .cloned()
            .unwrap_or_default();
        ViewerState {
            folder_id: state.folder,
            favorite: state.favorite,
            archived_at: state.archived_at,
            read_only: false,
            hide_passwords: false,
        }
    }
}

fn collection_ids_by_cipher(snapshot: &VaultwardenSnapshot) -> BTreeMap<String, Vec<String>> {
    let mut by_cipher: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in snapshot.ciphers_collections.rows() {
        if let (Some(cipher), Some(collection)) =
            (row.text("cipher_uuid"), row.text("collection_uuid"))
        {
            by_cipher
                .entry(cipher.to_owned())
                .or_default()
                .push(collection.to_owned());
        }
    }
    for ids in by_cipher.values_mut() {
        ids.sort();
    }
    by_cipher
}

fn map_items(
    snapshot: &VaultwardenSnapshot,
    warnings: &mut Vec<String>,
) -> Result<Vec<MappedItem>, MapError> {
    let states = UserStates::build(snapshot)?;
    let collections = collection_ids_by_cipher(snapshot);
    let mut items = Vec::with_capacity(snapshot.ciphers.len());
    for row in snapshot.ciphers.rows() {
        let id_text = need_text(&row, "uuid")?;
        let id = ItemId(parse_uuid(&row, "uuid", id_text)?);
        let created = need_time(&row, "created_at")?;
        let updated = need_time(&row, "updated_at")?;
        let atype = need_int(&row, "atype")?;
        let owner = match (row.text("organization_uuid"), row.text("user_uuid")) {
            (Some(org), _) => Owner::Space(SpaceId(parse_uuid(&row, "organization_uuid", org)?)),
            (None, Some(user)) => Owner::User(UserId(parse_uuid(&row, "user_uuid", user)?)),
            (None, None) => {
                warnings.push(format!("cipher {id_text} has no owner and was left out"));
                continue;
            }
        };
        let parts = crate::cipher_json::CipherParts {
            id: id_text,
            created_at: created,
            updated_at: updated,
            deleted_at: opt_time(&row, "deleted_at")?,
            organization_uuid: row.text("organization_uuid"),
            key: row.text("key"),
            atype,
            name: need_text(&row, "name")?,
            notes: row.text("notes"),
            fields: row.text("fields"),
            data: need_text(&row, "data")?,
            password_history: row.text("password_history"),
            reprompt: row.int("reprompt"),
        };
        let empty = Vec::new();
        let collection_ids = collections.get(id_text).unwrap_or(&empty);
        let (Some(mut json), Some(kind)) = (base_json(&parts, collection_ids), kind_name(atype))
        else {
            // Vaultwarden fails the whole sync on a type it doesn't know, so no working server
            // has one; say so rather than guess.
            warnings.push(format!(
                "cipher {id_text} has the unknown type {atype} and was left out"
            ));
            continue;
        };
        if let (Owner::User(_), Some(user)) = (owner, row.text("user_uuid")) {
            apply_viewer(&mut json, &states.viewer(user, id_text));
        }
        let kind = ItemKind::try_from(kind.to_owned()).map_err(|_| MapError::Missing {
            table: "ciphers",
            key: id_text.to_owned(),
            column: "atype",
        })?;
        items.push(MappedItem {
            id,
            owner,
            kind,
            format: ItemFormat::Bw,
            atype,
            json,
            created_at: to_utc(created),
            updated_at: to_utc(updated),
        });
    }
    Ok(items)
}

fn map_cipher_states(snapshot: &VaultwardenSnapshot) -> Result<Vec<MappedCipherState>, MapError> {
    let states = UserStates::build(snapshot)?;
    let known: BTreeSet<&str> = snapshot
        .ciphers
        .rows()
        .filter_map(|r| r.text("uuid"))
        .collect();
    let mut out = Vec::new();
    for ((user, cipher), state) in &states.by_pair {
        if !known.contains(cipher.as_str()) {
            continue;
        }
        let user_id = UserId(Uuid::parse_str(user.trim()).map_err(|_| MapError::BadId {
            table: "favorites",
            key: user.clone(),
            column: "user_uuid",
            value: user.clone(),
        })?);
        let item = ItemId(Uuid::parse_str(cipher.trim()).map_err(|_| MapError::BadId {
            table: "favorites",
            key: cipher.clone(),
            column: "cipher_uuid",
            value: cipher.clone(),
        })?);
        let folder = match &state.folder {
            Some(f) => Some(Uuid::parse_str(f.trim()).map_err(|_| MapError::BadId {
                table: "folders_ciphers",
                key: cipher.clone(),
                column: "folder_uuid",
                value: f.clone(),
            })?),
            None => None,
        };
        out.push(MappedCipherState {
            user: user_id,
            item,
            folder,
            favorite: state.favorite,
            archived_at: state.archived_at.map(to_utc),
        });
    }
    Ok(out)
}

fn map_folders(snapshot: &VaultwardenSnapshot) -> Result<Vec<MappedFolder>, MapError> {
    let mut out = Vec::with_capacity(snapshot.folders.len());
    for row in snapshot.folders.rows() {
        let id = need_uuid(&row, "uuid")?;
        let updated = need_time(&row, "updated_at")?;
        let name = need_text(&row, "name")?.to_owned();
        out.push(MappedFolder {
            id,
            user: UserId(need_uuid(&row, "user_uuid")?),
            json: serde_json::json!({
                "id": id,
                "revisionDate": format_date(updated),
                "name": name,
                "object": "folder",
            }),
            name,
            created_at: to_utc(need_time(&row, "created_at")?),
            updated_at: to_utc(updated),
        });
    }
    Ok(out)
}

fn file_copy(
    kind: FileKind,
    dir: Option<&PathBuf>,
    listed: &BTreeMap<String, u64>,
    relative: &str,
    storage_key: String,
) -> Option<FileCopy> {
    let dir = dir?;
    let size = *listed.get(relative)?;
    Some(FileCopy {
        kind,
        from: dir.join(relative),
        storage_key,
        size,
    })
}

fn map_attachments(
    snapshot: &VaultwardenSnapshot,
    warnings: &mut Vec<String>,
) -> Result<(Vec<MappedAttachment>, Vec<FileCopy>), MapError> {
    let known: BTreeSet<&str> = snapshot
        .ciphers
        .rows()
        .filter_map(|r| r.text("uuid"))
        .collect();
    let files: &DataFiles = &snapshot.files;
    let mut attachments = Vec::new();
    let mut copies = Vec::new();
    for row in snapshot.attachments.rows() {
        let id = need_text(&row, "id")?.to_owned();
        let cipher = need_text(&row, "cipher_uuid")?;
        if !known.contains(cipher) {
            warnings.push(format!(
                "attachment {id} belongs to the missing cipher {cipher} and was left out"
            ));
            continue;
        }
        let item = ItemId(parse_uuid(&row, "cipher_uuid", cipher)?);
        let storage_key = format!("attachments/{cipher}/{id}");
        let copy = file_copy(
            FileKind::Attachment,
            files.attachments_dir.as_ref(),
            &files.attachment_files,
            &format!("{cipher}/{id}"),
            storage_key.clone(),
        );
        let file_found = copy.is_some();
        if let Some(copy) = copy {
            copies.push(copy);
        } else {
            warnings.push(format!(
                "attachment {id} of cipher {cipher} has no file under attachments/; its row is \
                 carried and the download will fail"
            ));
        }
        attachments.push(MappedAttachment {
            id,
            item,
            file_name: need_text(&row, "file_name")?.to_owned(),
            size: need_int(&row, "file_size")?,
            key: opt_text(&row, "akey"),
            storage_key,
            file_found,
        });
    }
    Ok((attachments, copies))
}

fn map_send_files(snapshot: &VaultwardenSnapshot, warnings: &mut Vec<String>) -> Vec<FileCopy> {
    let files = &snapshot.files;
    let mut copies = Vec::new();
    for row in snapshot.sends.rows() {
        // Type 1 is a file send; its data names the file.
        if row.int("atype") != Some(1) {
            continue;
        }
        let uuid = row.text("uuid").unwrap_or_default();
        let file_id = row
            .text("data")
            .and_then(|data| serde_json::from_str::<Value>(data).ok())
            .map(crate::cipher_json::lcase_keys)
            .and_then(|data| data.get("id").and_then(Value::as_str).map(str::to_owned));
        let Some(file_id) = file_id else {
            warnings.push(format!("file send {uuid} names no file"));
            continue;
        };
        let copy = file_copy(
            FileKind::Send,
            files.sends_dir.as_ref(),
            &files.send_files,
            &format!("{uuid}/{file_id}"),
            format!("sends/{uuid}/{file_id}"),
        );
        match copy {
            Some(copy) => copies.push(copy),
            None => warnings.push(format!(
                "file send {uuid} has no file under sends/; its row is carried and the \
                 download will fail"
            )),
        }
    }
    copies
}

fn carried_tables(snapshot: &VaultwardenSnapshot) -> Vec<Table> {
    let mut out = Vec::new();
    for name in CARRIED {
        let Some(table) = snapshot.table(name) else {
            continue;
        };
        if *name == "twofactor" {
            // Login challenges are not setups; they expire in minutes.
            let mut setups = Table::empty(table.spec());
            for row in table.rows() {
                if row.int("atype").unwrap_or(0) < FIRST_TWOFACTOR_CHALLENGE {
                    let key: RowKey = row.key();
                    if let Some(cells) = table.cells(&key) {
                        setups.insert(cells.to_vec());
                    }
                }
            }
            out.push(setups);
        } else {
            out.push(table.clone());
        }
    }
    out
}

/// Maps a snapshot to what Kemlock Server stores.
pub fn map_snapshot(snapshot: &VaultwardenSnapshot) -> Result<MappedImport, MapError> {
    let mut warnings = Vec::new();

    let mut accounts = Vec::with_capacity(snapshot.users.len());
    for row in snapshot.users.rows() {
        accounts.push(map_account(&row)?);
    }
    let items = map_items(snapshot, &mut warnings)?;
    let cipher_states = map_cipher_states(snapshot)?;
    let folders = map_folders(snapshot)?;
    let (attachments, mut files) = map_attachments(snapshot, &mut warnings)?;
    files.extend(map_send_files(snapshot, &mut warnings));

    let settings = map_settings(snapshot.files.config_json.as_deref())?;
    for secret in &settings.secrets {
        warnings.push(format!(
            "the setting {secret} is a secret and is not carried; enter it again in the admin console"
        ));
    }
    let rsa_key = snapshot.files.rsa_key_pem.as_ref().map(|pem| MappedRsaKey {
        private_pem: pem.clone(),
        public_pem: snapshot.files.rsa_pub_pem.clone(),
    });
    if snapshot.files.root.is_none() {
        warnings.push(
            "no data folder was given, so attachments, send files, rsa_key.pem and config.json \
             were not read (pass --files <folder> for a MySQL or PostgreSQL server)"
                .to_owned(),
        );
    } else if rsa_key.is_none() {
        warnings.push(
            "there is no rsa_key.pem: Bitwarden apps will have to sign in again because their \
             tokens can't be verified"
                .to_owned(),
        );
    }

    Ok(MappedImport {
        accounts,
        folders,
        items,
        cipher_states,
        attachments,
        files,
        carried: carried_tables(snapshot),
        settings,
        rsa_key,
        warnings,
    })
}

fn changed<T: Clone + PartialEq, K: Ord>(new: &[T], old: &[T], key: impl Fn(&T) -> K) -> Vec<T> {
    let before: BTreeMap<K, &T> = old.iter().map(|x| (key(x), x)).collect();
    new.iter()
        .filter(|x| before.get(&key(*x)).is_none_or(|old| *old != *x))
        .cloned()
        .collect()
}

impl MappedImport {
    /// What the second pass has to put on top of a copy made from `first`: the accounts, items,
    /// files and rows that are new or different. Rows that went away are the diff's
    /// [`crate::diff::SnapshotDiff::deletions`].
    pub fn delta_since(&self, first: &MappedImport) -> MappedImport {
        let carried = self
            .carried
            .iter()
            .map(
                |table| match first.carried.iter().find(|t| t.name() == table.name()) {
                    Some(old) => table.delta(old),
                    None => table.clone(),
                },
            )
            .collect();
        MappedImport {
            accounts: changed(&self.accounts, &first.accounts, |a| a.id),
            folders: changed(&self.folders, &first.folders, |f| f.id),
            items: changed(&self.items, &first.items, |i| i.id),
            cipher_states: changed(&self.cipher_states, &first.cipher_states, |s| {
                (s.user, s.item)
            }),
            attachments: changed(&self.attachments, &first.attachments, |a| {
                a.storage_key.clone()
            }),
            files: changed(&self.files, &first.files, |f| {
                (f.kind, f.storage_key.clone())
            }),
            carried,
            settings: if self.settings == first.settings {
                MappedSettings::default()
            } else {
                self.settings.clone()
            },
            rsa_key: if self.rsa_key == first.rsa_key {
                None
            } else {
                self.rsa_key.clone()
            },
            warnings: self.warnings.clone(),
        }
    }

    /// How many rows the carried tables hold.
    pub fn carried_rows(&self) -> usize {
        self.carried.iter().map(Table::len).sum()
    }

    /// Bytes of files to copy.
    pub fn file_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}
