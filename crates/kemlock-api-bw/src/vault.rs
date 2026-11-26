//! The vault: sync, folders and ciphers, over the shared items table.
//!
//! Every cipher is one `bw` item whose ciphertext is a [`StoredCipher`] document, every folder one
//! `bw-folder` item holding its encrypted name. A write is a new revision of the item (so the
//! change log and its sequence move) and moves the account's revision date; a permanent delete
//! leaves a tombstone.

use crate::account::{profile_json, user_decryption_json};
use crate::app::{App, Authed, BwStore};
use crate::cipher::{
    CipherData, FOLDER_KIND, OUT_OF_DATE, StoredCipher, cipher_json, shows_ssh_keys,
    update_from_data, validate_import,
};
use crate::dates::format_date;
use crate::env::random_uuid;
use crate::error::{BwError, BwResult};
use crate::imported;
use crate::tokens::FileDownloadClaims;
use axum::http::StatusCode;
use kemlock_app::bw_events::{Change, UserSync};
use kemlock_app::ports::{ChangePage, ItemStore, StoreError};
use kemlock_domain::{
    Item, ItemDraft, ItemFormat, ItemId, ItemKind, Owner, Revision, UserId, VersionVector,
};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::collections::HashSet;
use time::OffsetDateTime;
use uuid::Uuid;

/// Items per page when the whole vault is read.
const PAGE: u32 = 500;
/// The most items one batch write takes.
const BATCH: usize = 500;

/// A cipher item and the document in it.
pub(crate) struct Loaded {
    pub item: Item,
    pub cipher: StoredCipher,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FolderDoc {
    pub name: String,
}

fn is_folder(item: &Item) -> bool {
    item.kind.as_str() == FOLDER_KIND
}

fn mine(item: &Item, user: UserId) -> bool {
    item.owner == Owner::User(user) && item.format == ItemFormat::Bw && !item.is_tombstone()
}

fn corrupt(item: &Item) -> BwError {
    BwError::Server(format!("the item {} holds no valid document", item.id))
}

/// What a cipher item holds: the Bitwarden API's own document, or Vaultwarden's cipher JSON as the
/// move from Vaultwarden stored it (served as it is, until a change makes it the first).
enum Doc {
    Stored(Box<StoredCipher>),
    Imported(Value),
}

impl Doc {
    fn cipher_type(&self) -> i64 {
        match self {
            Doc::Stored(cipher) => i64::from(cipher.r#type),
            Doc::Imported(doc) => doc.get("type").and_then(Value::as_i64).unwrap_or(0),
        }
    }
}

fn parse_doc(item: &Item) -> BwResult<Doc> {
    let doc: Value = item
        .ciphertext
        .as_deref()
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .ok_or_else(|| corrupt(item))?;
    if imported::is_imported(&doc) {
        return Ok(Doc::Imported(doc));
    }
    serde_json::from_value(doc)
        .map(|cipher: StoredCipher| Doc::Stored(Box::new(cipher)))
        .map_err(|_| corrupt(item))
}

fn parse_cipher(item: &Item) -> BwResult<StoredCipher> {
    match parse_doc(item)? {
        Doc::Stored(cipher) => Ok(*cipher),
        Doc::Imported(doc) => imported::stored_from_details(&doc).ok_or_else(|| corrupt(item)),
    }
}

fn parse_folder(item: &Item) -> BwResult<FolderDoc> {
    item.ciphertext
        .as_deref()
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .ok_or_else(|| corrupt(item))
}

fn folder_json(item: &Item) -> BwResult<Value> {
    let doc = parse_folder(item)?;
    Ok(json!({
        "id": item.id.to_string(),
        "revisionDate": format_date(item.updated_at),
        "name": doc.name,
        "object": "folder",
    }))
}

fn list_json(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })
}

fn item_id(text: &str) -> Option<ItemId> {
    Uuid::parse_str(text).ok().map(ItemId)
}

impl<S: BwStore> App<S> {
    /// The user's live `bw` items, ciphers and folders, with the corrupt ones left out.
    async fn bw_items(&self, user: UserId) -> BwResult<Vec<Item>> {
        let owners = [Owner::User(user)];
        let mut since = VersionVector::new();
        let mut out = Vec::new();
        loop {
            let ChangePage { items, next, more } =
                ItemStore::changes_since(&self.store, &owners, &since, PAGE).await?;
            out.extend(items.into_iter().filter(|i| mine(i, user)));
            if !more {
                return Ok(out);
            }
            since = next;
        }
    }

    /// The download link of one attachment: valid for a minute, on this server's own host.
    pub(crate) fn download_url(&self, cipher: &str, attachment: &str) -> BwResult<String> {
        let now = self.now_secs();
        let claims = FileDownloadClaims {
            nbf: now,
            exp: now + 60,
            iss: self.settings.issuer("file_download"),
            sub: cipher.to_owned(),
            file_id: attachment.to_owned(),
        };
        let token = self
            .keys
            .encode(&claims)
            .map_err(|e| BwError::Server(e.to_string()))?;
        Ok(format!(
            "{}/attachments/{cipher}/{attachment}?token={token}",
            self.host()
        ))
    }

    /// `cipherDetails` for a stored cipher, with fresh download links.
    pub(crate) fn cipher_to_json(&self, cipher: &StoredCipher) -> BwResult<Value> {
        let urls = cipher
            .attachments
            .iter()
            .map(|a| self.download_url(&cipher.id, &a.id))
            .collect::<BwResult<Vec<String>>>()?;
        cipher_json(cipher, &urls)
    }

    /// What a cipher item's document says, as `cipherDetails`: an imported cipher is Vaultwarden's
    /// own JSON with fresh download links, any other goes through [`cipher_json`].
    fn doc_to_json(&self, doc: &Doc) -> BwResult<Value> {
        match doc {
            Doc::Stored(cipher) => self.cipher_to_json(cipher),
            Doc::Imported(details) => {
                let cipher = details
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                imported::imported_json(details, None, |attachment| {
                    self.download_url(cipher, attachment)
                })
            }
        }
    }

    /// `cipherDetails` for a cipher item.
    pub(crate) fn item_to_json(&self, item: &Item) -> BwResult<Value> {
        self.doc_to_json(&parse_doc(item)?)
    }

    /// A cipher of this user by id; anything else is "Cipher doesn't exist".
    pub(crate) async fn load_cipher(&self, user: UserId, id: &str) -> BwResult<Loaded> {
        let id = item_id(id).ok_or(BwError::NotFound)?;
        match ItemStore::get(&self.store, id).await? {
            Some(item) if mine(&item, user) && !is_folder(&item) => {
                let cipher = parse_cipher(&item)?;
                Ok(Loaded { item, cipher })
            }
            _ => Err(BwError::msg("Cipher doesn't exist")),
        }
    }

    async fn load_folder(&self, user: UserId, id: &str) -> BwResult<Item> {
        let invalid = || BwError::msg("Invalid folder");
        let id = item_id(id).ok_or_else(invalid)?;
        match ItemStore::get(&self.store, id).await? {
            Some(item) if mine(&item, user) && is_folder(&item) => Ok(item),
            _ => Err(invalid()),
        }
    }

    /// Whether `id` is one of the user's folders.
    async fn folder_exists(&self, user: UserId, id: &str) -> BwResult<bool> {
        let Some(id) = item_id(id) else {
            return Ok(false);
        };
        Ok(ItemStore::get(&self.store, id)
            .await?
            .is_some_and(|i| mine(&i, user) && is_folder(&i)))
    }

    pub(crate) async fn folder_valid(&self, user: UserId, folder: Option<&str>) -> BwResult<bool> {
        match folder {
            None => Ok(true),
            Some(id) => self.folder_exists(user, id).await,
        }
    }

    /// Writes a new revision of an item: `body` is its document, or `None` for a tombstone.
    async fn write_item(
        &self,
        user: UserId,
        id: ItemId,
        kind: &str,
        prev: Option<&Item>,
        body: Option<Vec<u8>>,
        now: OffsetDateTime,
    ) -> BwResult<Item> {
        let draft = self.draft(user, id, kind, prev, body, now)?;
        match ItemStore::put(&self.store, draft).await {
            Ok(item) => Ok(item),
            // Someone else wrote it between our read and our write: the client's copy is stale.
            Err(StoreError::Conflict { .. }) => Err(BwError::msg(OUT_OF_DATE)),
            Err(e) => Err(e.into()),
        }
    }

    fn draft(
        &self,
        user: UserId,
        id: ItemId,
        kind: &str,
        prev: Option<&Item>,
        body: Option<Vec<u8>>,
        now: OffsetDateTime,
    ) -> BwResult<ItemDraft> {
        let revision = match prev {
            None => Revision::FIRST,
            Some(p) => p
                .revision
                .next()
                .ok_or_else(|| BwError::Server("an item ran out of revisions".to_owned()))?,
        };
        Ok(ItemDraft {
            id,
            owner: Owner::User(user),
            kind: ItemKind::try_from(kind.to_owned())
                .map_err(|_| BwError::Server(format!("{kind:?} is not an item kind")))?,
            format: ItemFormat::Bw,
            expected: prev.map(|p| p.revision),
            revision,
            key_version: 0,
            deleted_at: body.is_none().then_some(now),
            ciphertext: body,
            item_key: None,
            updated_at: now,
            signature: None,
        })
    }

    /// Stores a cipher document as the next revision of its item.
    pub(crate) async fn save_cipher(
        &self,
        user: UserId,
        prev: Option<&Item>,
        cipher: &StoredCipher,
        now: OffsetDateTime,
    ) -> BwResult<Item> {
        let id = item_id(&cipher.id)
            .ok_or_else(|| BwError::Server("a cipher has no valid id".to_owned()))?;
        let body = serde_json::to_vec(cipher).map_err(|e| BwError::Server(e.to_string()))?;
        self.write_item(user, id, cipher.kind(), prev, Some(body), now)
            .await
    }

    /// Leaves a tombstone where the item was.
    async fn tombstone(&self, user: UserId, item: &Item, now: OffsetDateTime) -> BwResult<()> {
        self.write_item(user, item.id, item.kind.as_str(), Some(item), None, now)
            .await?;
        Ok(())
    }
}

/// The bytes the account's own ciphers' attachments take, for the attachment quota. A cipher that
/// can't be read counts for nothing.
pub(crate) async fn attachment_bytes<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<u64> {
    let mut total = 0u64;
    for item in app.bw_items(user).await? {
        if is_folder(&item) {
            continue;
        }
        if let Ok(cipher) = parse_cipher(&item) {
            for attachment in &cipher.attachments {
                total = total.saturating_add(u64::try_from(attachment.size).unwrap_or(0));
            }
        }
    }
    Ok(total)
}

/// `GET /api/sync`.
pub(crate) async fn sync<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    exclude_domains: bool,
    client_version: Option<&str>,
) -> BwResult<Value> {
    let user = authed.user.id;
    let items = app.bw_items(user).await?;
    let show_ssh_keys = shows_ssh_keys(client_version);

    let mut folders = Vec::new();
    let mut ciphers = Vec::new();
    for item in &items {
        if is_folder(item) {
            folders.push(folder_json(item)?);
            continue;
        }
        let doc = match parse_doc(item) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(error = ?e, "leaving a damaged cipher out of a sync");
                continue;
            }
        };
        if doc.cipher_type() == 5 && !show_ssh_keys {
            continue;
        }
        ciphers.push(app.doc_to_json(&doc)?);
    }

    let org_parts = crate::orgs::sync_parts(app, user, client_version).await?;
    ciphers.extend(org_parts.ciphers);
    let domains = crate::domains::sync_json(app, authed, exclude_domains).await?;
    let sends = crate::sends::sync_json(app, user).await?;
    let key_id = kemlock_app::bitwarden::BwUserKeyIdRepo::user_key_id(&app.store, user).await?;
    Ok(json!({
        "profile": profile_json(app, &authed.user, &authed.account).await?,
        "folders": folders,
        "collections": org_parts.collections,
        "policies": org_parts.policies,
        "policiesNew": org_parts.policies_new,
        "ciphers": ciphers,
        "domains": domains,
        "sends": sends,
        "userDecryption": user_decryption_json(&authed.user, &authed.account, key_id.as_deref()),
        "object": "sync",
    }))
}

/// `GET /api/ciphers`.
pub(crate) async fn list_ciphers<S: BwStore>(app: &App<S>, authed: &Authed) -> BwResult<Value> {
    let mut out = Vec::new();
    let user = authed.user.id;
    for item in app.bw_items(authed.user.id).await? {
        if is_folder(&item) {
            continue;
        }
        if let Ok(doc) = parse_doc(&item) {
            out.push(app.doc_to_json(&doc)?);
        }
    }
    let orgs = app.orgs_of(user).await?;
    out.extend(crate::orgs::ciphers::visible_ciphers(app, user, &orgs, Some("2024.12.0")).await?);
    Ok(list_json(out))
}

/// `GET /api/ciphers/{id}`.
pub(crate) async fn get_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
) -> BwResult<Value> {
    if let Some(l) = crate::orgs::ciphers::org_cipher(app, authed.user.id, id).await? {
        return crate::orgs::ciphers::get(app, authed, &l).await;
    }
    let loaded = app.load_cipher(authed.user.id, id).await?;
    app.item_to_json(&loaded.item)
}

fn unprocessable(message: &str) -> BwError {
    BwError::status(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// `POST /api/ciphers`, and `POST /api/ciphers/create` with its wrapped body.
pub(crate) async fn create_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    mut data: CipherData,
) -> BwResult<Value> {
    let user = authed.user.id;
    if data.encrypted_for != user.to_string() {
        return Err(unprocessable("Invalid user cipher"));
    }
    if data.organization_id.is_some() {
        return crate::orgs::ciphers::create_in_org(app, authed, data, &[]).await;
    }
    // New ciphers have nothing to be stale against; the mobile apps send `0001-01-01T00:00:00`.
    data.last_known_revision_date = None;

    let now = app.now();
    let folder_valid = app.folder_valid(user, data.folder_id.as_deref()).await?;
    let mut cipher = StoredCipher::new(random_uuid(app.env.as_ref()).to_string(), data.r#type, now);
    update_from_data(&mut cipher, data, now, false, folder_valid)?;
    app.save_cipher(user, None, &cipher, now).await?;
    app.touch(user).await?;
    app.cipher_changed(authed, Change::Created, &cipher.id, now);
    app.cipher_to_json(&cipher)
}

/// `PUT /api/ciphers/{id}` and `POST /api/ciphers/{id}`.
pub(crate) async fn update_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    data: CipherData,
) -> BwResult<Value> {
    let user = authed.user.id;
    if let Some(l) = crate::orgs::ciphers::org_cipher(app, user, id).await? {
        return crate::orgs::ciphers::update(app, authed, l, data).await;
    }
    let mut loaded = app.load_cipher(user, id).await?;
    if data.organization_id.is_some() {
        return Err(BwError::msg(
            "Organization mismatch. Please resync the client before updating the cipher",
        ));
    }
    let now = app.now();
    let folder_valid = app.folder_valid(user, data.folder_id.as_deref()).await?;
    update_from_data(&mut loaded.cipher, data, now, true, folder_valid)?;
    app.save_cipher(user, Some(&loaded.item), &loaded.cipher, now)
        .await?;
    app.touch(user).await?;
    app.cipher_changed(authed, Change::Updated, &loaded.cipher.id, now);
    app.cipher_to_json(&loaded.cipher)
}

/// A cipher changed without its revision date moving: folder, favourite, archive, attachments.
pub(crate) async fn save_quietly<S: BwStore>(
    app: &App<S>,
    user: UserId,
    loaded: &Loaded,
) -> BwResult<()> {
    app.save_cipher(user, Some(&loaded.item), &loaded.cipher, app.now())
        .await?;
    app.touch(user).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PartialData {
    #[serde(default, deserialize_with = "nonempty")]
    pub folder_id: Option<String>,
    pub favorite: bool,
}

fn nonempty<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.filter(|s| !s.is_empty()))
}

/// `PUT /api/ciphers/{id}/partial`: only the folder and the favourite flag.
pub(crate) async fn partial_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    data: PartialData,
) -> BwResult<Value> {
    let user = authed.user.id;
    if let Some(l) = crate::orgs::ciphers::org_cipher(app, user, id).await? {
        return crate::orgs::ciphers::partial(app, authed, &l, data.folder_id, data.favorite).await;
    }
    let mut loaded = app.load_cipher(user, id).await?;
    if !app.folder_valid(user, data.folder_id.as_deref()).await? {
        return Err(BwError::msg("Invalid folder"));
    }
    loaded.cipher.folder_id = data.folder_id;
    loaded.cipher.favorite = data.favorite;
    save_quietly(app, user, &loaded).await?;
    app.cipher_to_json(&loaded.cipher)
}

/// Trashes a cipher (`soft`) or deletes it for good.
pub(crate) async fn delete_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    soft: bool,
) -> BwResult<()> {
    delete_one(app, authed, id, soft, true).await
}

/// [`delete_cipher`]; `notify` is false inside a bulk delete, which tells clients once at the end.
async fn delete_one<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    soft: bool,
    notify: bool,
) -> BwResult<()> {
    let user = authed.user.id;
    if let Some(l) = crate::orgs::ciphers::org_cipher(app, user, id).await? {
        return crate::orgs::ciphers::delete(app, authed, l, soft, notify).await;
    }
    let mut loaded = app.load_cipher(user, id).await?;
    let now = app.now();
    if soft {
        let stamp = format_date(now);
        loaded.cipher.deleted_date = Some(stamp.clone());
        loaded.cipher.revision_date = stamp;
        app.save_cipher(user, Some(&loaded.item), &loaded.cipher, now)
            .await?;
    } else {
        app.tombstone(user, &loaded.item, now).await?;
        for attachment in &loaded.cipher.attachments {
            // A file that can't be removed is a leak of space, not of the vault: say so and go on.
            if let Err(e) = app
                .blobs
                .delete(&format!("{}/{}", loaded.cipher.id, attachment.id))
                .await
            {
                tracing::warn!(error = %e, "couldn't remove an attachment file");
            }
        }
    }
    app.touch(user).await?;
    if notify {
        let change = if soft {
            Change::Updated
        } else {
            Change::Deleted
        };
        app.cipher_changed(authed, change, &loaded.cipher.id, now);
    }
    Ok(())
}

/// `PUT /api/ciphers/{id}/restore`.
pub(crate) async fn restore_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
) -> BwResult<Value> {
    restore_one(app, authed, id, true).await
}

/// [`restore_cipher`]; `notify` is false inside a bulk restore, which tells clients once.
async fn restore_one<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    notify: bool,
) -> BwResult<Value> {
    let user = authed.user.id;
    if let Some(l) = crate::orgs::ciphers::org_cipher(app, user, id).await? {
        return crate::orgs::ciphers::restore(app, authed, l, notify).await;
    }
    let mut loaded = app.load_cipher(user, id).await?;
    let now = app.now();
    loaded.cipher.deleted_date = None;
    loaded.cipher.revision_date = format_date(now);
    app.save_cipher(user, Some(&loaded.item), &loaded.cipher, now)
        .await?;
    app.touch(user).await?;
    if notify {
        app.cipher_changed(authed, Change::Updated, &loaded.cipher.id, now);
    }
    app.cipher_to_json(&loaded.cipher)
}

#[derive(Debug, Deserialize)]
pub(crate) struct IdsData {
    pub ids: HashSet<String>,
}

/// `DELETE /api/ciphers`, `POST …/delete` (permanent) and `PUT …/delete` (trash).
pub(crate) async fn delete_ciphers<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    ids: &HashSet<String>,
    soft: bool,
) -> BwResult<()> {
    for id in ids {
        delete_one(app, authed, id, soft, false).await?;
    }
    // A bulk delete sends no message per cipher, as Vaultwarden's doesn't.
    app.user_synced(authed, UserSync::Ciphers);
    Ok(())
}

/// `PUT /api/ciphers/restore`.
pub(crate) async fn restore_ciphers<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    ids: &HashSet<String>,
) -> BwResult<Value> {
    let mut out = Vec::new();
    for id in ids {
        out.push(restore_one(app, authed, id, false).await?);
    }
    app.user_synced(authed, UserSync::Ciphers);
    Ok(list_json(out))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MoveData {
    #[serde(default, deserialize_with = "nonempty")]
    pub folder_id: Option<String>,
    pub ids: Vec<String>,
}

/// `POST /api/ciphers/move`: ciphers the user can't see are skipped, and the answer says so.
pub(crate) async fn move_ciphers<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    data: MoveData,
) -> BwResult<()> {
    let user = authed.user.id;
    if !app.folder_valid(user, data.folder_id.as_deref()).await? {
        return Err(BwError::msg("Invalid folder"));
    }
    let total = data.ids.len();
    let mut moved = 0;
    for id in &data.ids {
        if crate::orgs::ciphers::move_to_folder(app, user, id, data.folder_id.as_deref()).await? {
            moved += 1;
            continue;
        }
        let Ok(mut loaded) = app.load_cipher(user, id).await else {
            continue;
        };
        loaded.cipher.folder_id = data.folder_id.clone();
        save_quietly(app, user, &loaded).await?;
        moved += 1;
    }
    if moved > 0 {
        // One cipher moved is told as that cipher, several as a general sync, as Vaultwarden does.
        match data.ids.as_slice() {
            [only] if app.load_cipher(user, only).await.is_ok() => {
                app.cipher_changed(authed, Change::Updated, only, app.now());
            }
            _ => app.user_synced(authed, UserSync::Ciphers),
        }
    }
    if moved != total {
        return Err(BwError::msg(format!(
            "Not all ciphers are moved! {moved} of the selected {total} were moved."
        )));
    }
    Ok(())
}

/// `PUT /api/ciphers/{id}/archive` and `unarchive`.
pub(crate) async fn archive_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    archive: bool,
) -> BwResult<Value> {
    archive_one(app, authed, id, archive, true).await
}

/// [`archive_cipher`]; `notify` is false inside a bulk archive, which tells clients once.
async fn archive_one<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    archive: bool,
    notify: bool,
) -> BwResult<Value> {
    let user = authed.user.id;
    if let Some(l) = crate::orgs::ciphers::org_cipher(app, user, id).await? {
        return crate::orgs::ciphers::archive(app, authed, &l, archive, notify).await;
    }
    let mut loaded = app.load_cipher(user, id).await?;
    let now = app.now();
    loaded.cipher.archived_date = archive.then(|| format_date(now));
    save_quietly(app, user, &loaded).await?;
    if notify {
        app.cipher_changed(authed, Change::Updated, &loaded.cipher.id, now);
    }
    app.cipher_to_json(&loaded.cipher)
}

/// `PUT /api/ciphers/archive` and `unarchive`.
pub(crate) async fn archive_ciphers<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    ids: &HashSet<String>,
    archive: bool,
) -> BwResult<Value> {
    let mut out = Vec::new();
    for id in ids {
        out.push(archive_one(app, authed, id, archive, false).await?);
    }
    app.user_synced(authed, UserSync::Ciphers);
    Ok(list_json(out))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FolderData {
    pub name: String,
    #[serde(default, deserialize_with = "nonempty")]
    pub id: Option<String>,
}

/// `GET /api/folders`.
pub(crate) async fn list_folders<S: BwStore>(app: &App<S>, authed: &Authed) -> BwResult<Value> {
    let mut out = Vec::new();
    for item in app.bw_items(authed.user.id).await? {
        if is_folder(&item) {
            out.push(folder_json(&item)?);
        }
    }
    Ok(list_json(out))
}

/// `GET /api/folders/{id}`.
pub(crate) async fn get_folder<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
) -> BwResult<Value> {
    folder_json(&app.load_folder(authed.user.id, id).await?)
}

fn folder_body(name: &str) -> BwResult<Vec<u8>> {
    serde_json::to_vec(&json!({ "name": name })).map_err(|e| BwError::Server(e.to_string()))
}

/// `POST /api/folders`.
pub(crate) async fn create_folder<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    data: FolderData,
) -> BwResult<Value> {
    let user = authed.user.id;
    let now = app.now();
    let id = ItemId(random_uuid(app.env.as_ref()));
    let item = app
        .write_item(
            user,
            id,
            FOLDER_KIND,
            None,
            Some(folder_body(&data.name)?),
            now,
        )
        .await?;
    app.touch(user).await?;
    app.folder_changed(authed, Change::Created, id.0, now);
    folder_json(&item)
}

/// `PUT /api/folders/{id}` and `POST /api/folders/{id}`.
pub(crate) async fn update_folder<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    data: FolderData,
) -> BwResult<Value> {
    let user = authed.user.id;
    let prev = app.load_folder(user, id).await?;
    let now = app.now();
    let item = app
        .write_item(
            user,
            prev.id,
            FOLDER_KIND,
            Some(&prev),
            Some(folder_body(&data.name)?),
            now,
        )
        .await?;
    app.touch(user).await?;
    app.folder_changed(authed, Change::Updated, item.id.0, now);
    folder_json(&item)
}

/// `DELETE /api/folders/{id}`: the folder goes, and the ciphers in it stay, with no folder.
pub(crate) async fn delete_folder<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
) -> BwResult<()> {
    let user = authed.user.id;
    let folder = app.load_folder(user, id).await?;
    let now = app.now();
    app.tombstone(user, &folder, now).await?;
    let folder_id = folder.id.to_string();
    for item in app.bw_items(user).await? {
        if is_folder(&item) {
            continue;
        }
        let Ok(mut cipher) = parse_cipher(&item) else {
            continue;
        };
        if cipher.folder_id.as_deref() == Some(folder_id.as_str()) {
            cipher.folder_id = None;
            app.save_cipher(user, Some(&item), &cipher, now).await?;
        }
    }
    app.touch(user).await?;
    app.folder_changed(authed, Change::Deleted, folder.id.0, now);
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportData {
    pub ciphers: Vec<CipherData>,
    pub folders: Vec<FolderData>,
    pub folder_relationships: Vec<Relation>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Relation {
    /// The cipher's index in `ciphers`.
    pub key: usize,
    /// The folder's index in `folders`.
    pub value: usize,
}

/// `POST /api/ciphers/import`: nothing is imported unless every cipher is valid.
pub(crate) async fn import<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    data: ImportData,
) -> BwResult<()> {
    let user = authed.user.id;
    validate_import(&data.ciphers)?;

    let now = app.now();
    let mut drafts = Vec::new();

    // A folder the file names by an id the user already has is reused; the rest are made.
    let mut folders: Vec<String> = Vec::with_capacity(data.folders.len());
    for folder in &data.folders {
        let existing = match &folder.id {
            Some(id) if app.folder_exists(user, id).await? => Some(id.clone()),
            _ => None,
        };
        if let Some(id) = existing {
            folders.push(id);
            continue;
        }
        let id = ItemId(random_uuid(app.env.as_ref()));
        drafts.push(app.draft(
            user,
            id,
            FOLDER_KIND,
            None,
            Some(folder_body(&folder.name)?),
            now,
        )?);
        folders.push(id.to_string());
    }

    // A cipher is in at most one folder.
    let relations: std::collections::HashMap<usize, usize> = data
        .folder_relationships
        .iter()
        .map(|r| (r.key, r.value))
        .collect();
    for (index, mut request) in data.ciphers.into_iter().enumerate() {
        request.folder_id = relations.get(&index).and_then(|i| folders.get(*i)).cloned();
        // A personal import makes personal ciphers: an organization id is dropped, not refused.
        request.organization_id = None;
        let mut cipher = StoredCipher::new(
            random_uuid(app.env.as_ref()).to_string(),
            request.r#type,
            now,
        );
        update_from_data(&mut cipher, request, now, false, true)?;
        let id = item_id(&cipher.id)
            .ok_or_else(|| BwError::Server("a cipher has no valid id".to_owned()))?;
        let body = serde_json::to_vec(&cipher).map_err(|e| BwError::Server(e.to_string()))?;
        drafts.push(app.draft(user, id, cipher.kind(), None, Some(body), now)?);
    }

    for chunk in drafts.chunks(BATCH) {
        ItemStore::put_batch(&app.store, chunk.to_vec()).await?;
    }
    app.touch(user).await?;
    app.user_synced(authed, UserSync::Vault);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_have_vaultwardens_envelope() {
        let list = list_json(vec![json!(1)]);
        assert_eq!(list["object"], "list");
        assert_eq!(list["data"], json!([1]));
        assert!(list["continuationToken"].is_null());
    }

    #[test]
    fn empty_folder_ids_mean_no_folder() {
        let data: FolderData =
            serde_json::from_value(json!({"name": "2.n", "id": ""})).expect("parses");
        assert_eq!(data.id, None);
        let data: MoveData =
            serde_json::from_value(json!({"folderId": "", "ids": []})).expect("parses");
        assert_eq!(data.folder_id, None);
        let data: PartialData =
            serde_json::from_value(json!({"folderId": "f", "favorite": true})).expect("parses");
        assert_eq!(data.folder_id.as_deref(), Some("f"));
    }

    #[test]
    fn a_cipher_id_must_be_a_uuid() {
        assert!(item_id("3785303e-d4f8-4724-be0a-6c3599471ffe").is_some());
        assert!(item_id("not-a-uuid").is_none());
    }
}
