//! Ciphers of organizations.
//!
//! An organization cipher is a `bw` item owned by the space, holding the same cipher document as
//! a personal one (encrypted under the organization key the client holds, stored as given). What
//! differs is where its links live: the collections it is in are a document of the organization
//! (`cc`), read through [`links_of`] so ciphers whose only link is the space tables' first
//! collection (`item_collections`) still show it; and a member's folder, favourite and archive
//! are per account, kept as documents of the account (`orgpref`).
//!
//! A personal cipher can't change owner in the item store, so sharing one makes a new item with a
//! new id and leaves a tombstone where the personal one was.

use super::guard::Ctx;
use super::model::{KIND_LINKS, KIND_PREFS, MemberDoc, Org, PrefDoc, Restrict};
use crate::app::{App, Authed, BwStore};
use crate::cipher::{
    CipherData, FOLDER_KIND, OUT_OF_DATE, StoredCipher, shows_ssh_keys, update_from_data,
    validate_import,
};
use crate::dates::format_date;
use crate::env::random_uuid;
use crate::error::{BwError, BwResult};
use crate::events::{Acting, kind, log_event};
use axum::http::StatusCode;
use kemlock_app::bw_events::Change;
use kemlock_app::ports::{ChangePage, ItemStore, StoreError};
use kemlock_app::spaces::SpaceRepo;
use kemlock_domain::spaces::{Collection, CollectionId};
use kemlock_domain::{
    Item, ItemDraft, ItemFormat, ItemId, ItemKind, Owner, Revision, SpaceId, UserId, VersionVector,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use time::OffsetDateTime;
use uuid::Uuid;

const PAGE: u32 = 500;

/// An organization cipher with the organization it is in and what the caller may do with it.
pub(crate) struct OrgLoaded {
    pub item: Item,
    pub cipher: StoredCipher,
    pub org: Org,
    pub links: Vec<CollectionId>,
    /// `None` when the caller can't see the cipher.
    pub restrict: Option<Restrict>,
}

/// The cipher an item holds: the API's own document, or Vaultwarden's cipher JSON as the move
/// stored it, which is the first until an app changes it.
fn parse_cipher(item: &Item) -> Option<StoredCipher> {
    let doc: Value = serde_json::from_slice(item.ciphertext.as_deref()?).ok()?;
    if crate::imported::is_imported(&doc) {
        return crate::imported::stored_from_details(&doc);
    }
    serde_json::from_value(doc).ok()
}

fn item_id(text: &str) -> Option<ItemId> {
    Uuid::parse_str(text).ok().map(ItemId)
}

fn is_org_cipher(item: &Item) -> Option<SpaceId> {
    match item.owner {
        Owner::Space(space)
            if item.format == ItemFormat::Bw
                && !item.is_tombstone()
                && item.kind.as_str() != FOLDER_KIND =>
        {
            Some(space)
        }
        _ => None,
    }
}

fn collection_ids(links: &[CollectionId]) -> Vec<String> {
    links.iter().map(ToString::to_string).collect()
}

impl<S: BwStore> App<S> {
    /// The live cipher items of an organization.
    async fn org_items(&self, org: SpaceId) -> BwResult<Vec<Item>> {
        let owners = [Owner::Space(org)];
        let mut since = VersionVector::new();
        let mut out = Vec::new();
        loop {
            let ChangePage { items, next, more } =
                ItemStore::changes_since(&self.store, &owners, &since, PAGE).await?;
            out.extend(items.into_iter().filter(|i| is_org_cipher(i).is_some()));
            if !more {
                return Ok(out);
            }
            since = next;
        }
    }

    /// Every cipher's collections in an organization, by cipher id.
    pub(crate) async fn links_of(
        &self,
        org: SpaceId,
    ) -> BwResult<BTreeMap<String, Vec<CollectionId>>> {
        let mut out: BTreeMap<String, Vec<CollectionId>> = BTreeMap::new();
        for (key, ids) in self.docs::<Vec<String>>(org.0, KIND_LINKS).await? {
            let links = ids
                .iter()
                .filter_map(|id| Uuid::parse_str(id).ok().map(CollectionId))
                .collect();
            out.insert(key, links);
        }
        // Items written by something that only knows the space tables have their first collection
        // there.
        for info in SpaceRepo::space_items(&self.store, org).await? {
            if info.deleted {
                continue;
            }
            if let Some(collection) = info.collection {
                out.entry(info.id.to_string())
                    .or_insert_with(|| vec![collection]);
            }
        }
        Ok(out)
    }

    async fn links_for(&self, org: SpaceId, item: ItemId) -> BwResult<Vec<CollectionId>> {
        if let Some(ids) = self
            .doc::<Vec<String>>(org.0, KIND_LINKS, &item.to_string())
            .await?
        {
            return Ok(ids
                .iter()
                .filter_map(|id| Uuid::parse_str(id).ok().map(CollectionId))
                .collect());
        }
        Ok(SpaceRepo::item_collections(&self.store, &[item])
            .await?
            .into_iter()
            .map(|(_, c)| c)
            .collect())
    }

    async fn set_links(&self, org: SpaceId, cipher: &str, links: &[CollectionId]) -> BwResult<()> {
        self.put_doc(org.0, KIND_LINKS, cipher, &collection_ids(links))
            .await
    }

    async fn prefs_of(&self, user: UserId, cipher: &str) -> BwResult<PrefDoc> {
        Ok(self
            .doc::<PrefDoc>(user.0, KIND_PREFS, cipher)
            .await?
            .unwrap_or_default())
    }

    /// Writes a new revision of an organization cipher; the first collection is recorded in the
    /// space tables too.
    async fn write_org_cipher(
        &self,
        org: SpaceId,
        prev: Option<&Item>,
        cipher: &StoredCipher,
        first: Option<CollectionId>,
        now: OffsetDateTime,
    ) -> BwResult<Item> {
        let id = item_id(&cipher.id)
            .ok_or_else(|| BwError::Server("a cipher has no valid id".to_owned()))?;
        let body = serde_json::to_vec(cipher).map_err(|e| BwError::Server(e.to_string()))?;
        let draft = self.org_draft(org, id, cipher.kind(), prev, Some(body), now)?;
        let written = match first {
            Some(collection) => SpaceRepo::put_item(&self.store, draft, collection).await,
            None => ItemStore::put(&self.store, draft).await,
        };
        match written {
            Ok(item) => Ok(item),
            Err(StoreError::Conflict { .. }) => Err(BwError::msg(OUT_OF_DATE)),
            Err(e) => Err(e.into()),
        }
    }

    fn org_draft(
        &self,
        org: SpaceId,
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
            owner: Owner::Space(org),
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
        })
    }

    async fn tombstone_org_cipher(
        &self,
        org: SpaceId,
        item: &Item,
        now: OffsetDateTime,
    ) -> BwResult<()> {
        let draft = self.org_draft(org, item.id, item.kind.as_str(), Some(item), None, now)?;
        match ItemStore::put(&self.store, draft).await {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict { .. }) => Err(BwError::msg(OUT_OF_DATE)),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes the files of a cipher's attachments; a file that can't go is logged, not fatal.
    async fn drop_attachment_files(&self, cipher: &StoredCipher) {
        for attachment in &cipher.attachments {
            if let Err(e) = self
                .blobs
                .delete(&format!("{}/{}", cipher.id, attachment.id))
                .await
            {
                tracing::warn!(error = %e, "couldn't remove an attachment file");
            }
        }
    }
}

/// The organization cipher with this id as `user` sees it; `None` when the id isn't an
/// organization cipher at all, so the caller carries on with a personal one.
pub(crate) async fn org_cipher<S: BwStore>(
    app: &App<S>,
    user: UserId,
    id: &str,
) -> BwResult<Option<OrgLoaded>> {
    let Some(item_id) = item_id(id) else {
        return Ok(None);
    };
    let Some(item) = ItemStore::get(&app.store, item_id).await? else {
        return Ok(None);
    };
    let Some(space) = is_org_cipher(&item) else {
        return Ok(None);
    };
    let Some(org) = app.load_org(space).await? else {
        return Ok(None);
    };
    let Some(cipher) = parse_cipher(&item) else {
        return Err(BwError::Server(format!(
            "the item {} holds no valid document",
            item.id
        )));
    };
    let links = app.links_for(space, item.id).await?;
    let restrict = org.cipher_restrictions(user, &links);
    Ok(Some(OrgLoaded {
        item,
        cipher,
        org,
        links,
        restrict,
    }))
}

/// Whether `id` is a cipher the account owns itself, for the messages that tell the two apart.
async fn owns_personal<S: BwStore>(app: &App<S>, user: UserId, id: &str) -> BwResult<bool> {
    let Some(item_id) = item_id(id) else {
        return Ok(false);
    };
    Ok(ItemStore::get(&app.store, item_id)
        .await?
        .is_some_and(|i| i.owner == Owner::User(user) && !i.is_tombstone()))
}

/// `cipherDetails` of an organization cipher. With `view` it is the account's own view (its
/// folder, favourite, archive and rights); without, the organization's (what an admin lists).
fn org_cipher_json<S: BwStore>(
    app: &App<S>,
    user: UserId,
    org: &Org,
    cipher: &StoredCipher,
    links: &[CollectionId],
    view: Option<(&PrefDoc, Restrict)>,
) -> BwResult<Value> {
    let mut out = app.cipher_to_json(cipher)?;
    let visible: Vec<CollectionId> = links
        .iter()
        .copied()
        .filter(|c| org.can_access_collection(user, *c))
        .collect();
    if let Some(object) = out.as_object_mut() {
        object.insert("organizationId".to_owned(), json!(org.id.to_string()));
        object.insert("collectionIds".to_owned(), json!(collection_ids(&visible)));
        match view {
            Some((prefs, restrict)) => {
                object.insert("folderId".to_owned(), json!(prefs.folder_id));
                object.insert("favorite".to_owned(), json!(prefs.favorite));
                object.insert("archivedDate".to_owned(), json!(prefs.archived_date));
                object.insert("edit".to_owned(), json!(!restrict.read_only));
                object.insert("viewPassword".to_owned(), json!(!restrict.hide_passwords));
                object.insert(
                    "permissions".to_owned(),
                    json!({ "delete": !restrict.read_only, "restore": !restrict.read_only }),
                );
            }
            None => {
                for key in [
                    "folderId",
                    "favorite",
                    "archivedDate",
                    "edit",
                    "viewPassword",
                    "permissions",
                ] {
                    object.remove(key);
                }
            }
        }
    }
    Ok(out)
}

async fn user_view<S: BwStore>(app: &App<S>, user: UserId, l: &OrgLoaded) -> BwResult<Value> {
    let prefs = app.prefs_of(user, &l.cipher.id).await?;
    let restrict = l.restrict.unwrap_or(Restrict {
        read_only: true,
        hide_passwords: true,
        manage: false,
    });
    org_cipher_json(
        app,
        user,
        &l.org,
        &l.cipher,
        &l.links,
        Some((&prefs, restrict)),
    )
}

/// The ciphers an account sees in its organizations, for `/api/sync` and `/api/ciphers`.
pub(crate) async fn visible_ciphers<S: BwStore>(
    app: &App<S>,
    user: UserId,
    orgs: &[Org],
    client_version: Option<&str>,
) -> BwResult<Vec<Value>> {
    let show_ssh_keys = shows_ssh_keys(client_version);
    let prefs: BTreeMap<String, PrefDoc> = app
        .docs::<PrefDoc>(user.0, KIND_PREFS)
        .await?
        .into_iter()
        .collect();
    let mut out = Vec::new();
    for org in orgs {
        if !org.member(user).is_some_and(|m| m.confirmed()) {
            continue;
        }
        let links = app.links_of(org.id).await?;
        for item in app.org_items(org.id).await? {
            let Some(cipher) = parse_cipher(&item) else {
                tracing::warn!(item = %item.id, "leaving a damaged cipher out of a sync");
                continue;
            };
            if cipher.r#type == 5 && !show_ssh_keys {
                continue;
            }
            let own = links.get(&cipher.id).cloned().unwrap_or_default();
            let Some(restrict) = org.cipher_restrictions(user, &own) else {
                continue;
            };
            let blank = PrefDoc::default();
            let pref = prefs.get(&cipher.id).unwrap_or(&blank);
            out.push(org_cipher_json(
                app,
                user,
                org,
                &cipher,
                &own,
                Some((pref, restrict)),
            )?);
        }
    }
    Ok(out)
}

/// `GET /api/ciphers/{id}`.
pub(crate) async fn get<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    l: &OrgLoaded,
) -> BwResult<Value> {
    if l.restrict.is_none() {
        return Err(BwError::msg("Cipher is not owned by user"));
    }
    user_view(app, authed.user.id, l).await
}

/// Writes an organization cipher whose attachments changed: its own revision date stays, and
/// every member's clients sync.
pub(crate) async fn org_save_quietly<S: BwStore>(app: &App<S>, l: &OrgLoaded) -> BwResult<()> {
    app.write_org_cipher(
        l.org.id,
        Some(&l.item),
        &l.cipher,
        l.links.first().copied(),
        app.now(),
    )
    .await?;
    app.touch_members(&l.org).await
}

/// The organization cipher as the caller sees it.
pub(crate) async fn org_view<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    l: &OrgLoaded,
) -> BwResult<Value> {
    user_view(app, authed.user.id, l).await
}

fn org_id_text(l: &OrgLoaded) -> String {
    l.org.id.to_string()
}

/// Logs an event about an organization cipher, made by the caller.
async fn log_cipher<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    org: SpaceId,
    event_type: i32,
    cipher: &str,
) {
    log_event(app, event_type, cipher, org.0, &Acting::of(authed)).await;
}

/// `PUT /api/ciphers/{id}` on an organization cipher.
pub(crate) async fn update<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    l: OrgLoaded,
    data: CipherData,
) -> BwResult<Value> {
    update_with(app, authed, l, data, true, false).await
}

/// [`update`]; `log` is whether the change is logged (a bulk share does not), and `shared` is a
/// share, which names the collections in the message to clients.
async fn update_with<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    mut l: OrgLoaded,
    data: CipherData,
    log: bool,
    shared: bool,
) -> BwResult<Value> {
    let user = authed.user.id;
    if !l.restrict.is_some_and(|r| r.writable()) {
        return Err(BwError::msg("Cipher is not write accessible"));
    }
    if data.organization_id.as_deref() != Some(org_id_text(&l).as_str()) {
        return Err(BwError::msg(
            "Organization mismatch. Please resync the client before updating the cipher",
        ));
    }
    let now = app.now();
    let folder_valid = app.folder_valid(user, data.folder_id.as_deref()).await?;
    let prefs = app.prefs_of(user, &l.cipher.id).await?;
    l.cipher.folder_id = prefs.folder_id;
    l.cipher.favorite = prefs.favorite;
    l.cipher.archived_date = prefs.archived_date;
    update_from_data(&mut l.cipher, data, now, true, folder_valid)?;
    let own = PrefDoc {
        folder_id: l.cipher.folder_id.take(),
        favorite: std::mem::take(&mut l.cipher.favorite),
        archived_date: l.cipher.archived_date.take(),
    };
    app.write_org_cipher(
        l.org.id,
        Some(&l.item),
        &l.cipher,
        l.links.first().copied(),
        now,
    )
    .await?;
    app.put_doc(user.0, KIND_PREFS, &l.cipher.id, &own).await?;
    app.touch_members(&l.org).await?;
    if log {
        log_cipher(app, authed, l.org.id, kind::CIPHER_UPDATED, &l.cipher.id).await;
    }
    app.org_cipher_changed(
        authed,
        Change::Updated,
        &l.org,
        &l.cipher.id,
        &l.links,
        shared,
    );
    org_cipher_json(
        app,
        user,
        &l.org,
        &l.cipher,
        &l.links,
        Some((&own, l.restrict.unwrap_or(Restrict::FULL))),
    )
}

/// `PUT /api/ciphers/{id}/partial` on an organization cipher: the account's folder and favourite.
pub(crate) async fn partial<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    l: &OrgLoaded,
    folder: Option<String>,
    favorite: bool,
) -> BwResult<Value> {
    let user = authed.user.id;
    if l.restrict.is_none() {
        return Err(BwError::msg("Cipher does not exist"));
    }
    if !app.folder_valid(user, folder.as_deref()).await? {
        return Err(BwError::msg("Invalid folder"));
    }
    let mut prefs = app.prefs_of(user, &l.cipher.id).await?;
    prefs.folder_id = folder;
    prefs.favorite = favorite;
    app.put_doc(user.0, KIND_PREFS, &l.cipher.id, &prefs)
        .await?;
    app.touch(user).await?;
    user_view(app, user, l).await
}

/// Moves an organization cipher to one of the account's folders; false when the account can't
/// see the cipher.
pub(crate) async fn move_to_folder<S: BwStore>(
    app: &App<S>,
    user: UserId,
    id: &str,
    folder: Option<&str>,
) -> BwResult<bool> {
    let Some(l) = org_cipher(app, user, id).await? else {
        return Ok(false);
    };
    if l.restrict.is_none() {
        return Ok(false);
    }
    let mut prefs = app.prefs_of(user, &l.cipher.id).await?;
    prefs.folder_id = folder.map(str::to_owned);
    app.put_doc(user.0, KIND_PREFS, &l.cipher.id, &prefs)
        .await?;
    app.touch(user).await?;
    Ok(true)
}

/// Trashes an organization cipher, or deletes it for good.
pub(crate) async fn delete<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    mut l: OrgLoaded,
    soft: bool,
    notify: bool,
) -> BwResult<()> {
    if !l.restrict.is_some_and(|r| r.writable()) {
        return Err(BwError::msg("Cipher can't be deleted by user"));
    }
    let now = app.now();
    if soft {
        let stamp = format_date(now);
        l.cipher.deleted_date = Some(stamp.clone());
        l.cipher.revision_date = stamp;
        app.write_org_cipher(
            l.org.id,
            Some(&l.item),
            &l.cipher,
            l.links.first().copied(),
            now,
        )
        .await?;
    } else {
        app.tombstone_org_cipher(l.org.id, &l.item, now).await?;
        app.drop_attachment_files(&l.cipher).await;
        app.del_doc(l.org.id.0, KIND_LINKS, &l.cipher.id).await?;
    }
    app.touch_members(&l.org).await?;
    let event = if soft {
        kind::CIPHER_SOFT_DELETED
    } else {
        kind::CIPHER_DELETED
    };
    log_cipher(app, authed, l.org.id, event, &l.cipher.id).await;
    if notify {
        let change = if soft {
            Change::Updated
        } else {
            Change::Deleted
        };
        app.org_cipher_changed(authed, change, &l.org, &l.cipher.id, &l.links, false);
    }
    Ok(())
}

/// `PUT /api/ciphers/{id}/restore` on an organization cipher.
pub(crate) async fn restore<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    mut l: OrgLoaded,
    notify: bool,
) -> BwResult<Value> {
    if !l.restrict.is_some_and(|r| r.writable()) {
        return Err(BwError::msg("Cipher can't be restored by user"));
    }
    let now = app.now();
    l.cipher.deleted_date = None;
    l.cipher.revision_date = format_date(now);
    app.write_org_cipher(
        l.org.id,
        Some(&l.item),
        &l.cipher,
        l.links.first().copied(),
        now,
    )
    .await?;
    app.touch_members(&l.org).await?;
    log_cipher(app, authed, l.org.id, kind::CIPHER_RESTORED, &l.cipher.id).await;
    if notify {
        app.org_cipher_changed(
            authed,
            Change::Updated,
            &l.org,
            &l.cipher.id,
            &l.links,
            false,
        );
    }
    user_view(app, authed.user.id, &l).await
}

/// `PUT /api/ciphers/{id}/archive` and `unarchive` on an organization cipher: the account's own.
pub(crate) async fn archive<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    l: &OrgLoaded,
    archive: bool,
    notify: bool,
) -> BwResult<Value> {
    let user = authed.user.id;
    if l.restrict.is_none() {
        return Err(BwError::msg("Cipher doesn't exist"));
    }
    let mut prefs = app.prefs_of(user, &l.cipher.id).await?;
    prefs.archived_date = archive.then(|| format_date(app.now()));
    app.put_doc(user.0, KIND_PREFS, &l.cipher.id, &prefs)
        .await?;
    app.touch(user).await?;
    if notify {
        app.org_cipher_changed(
            authed,
            Change::Updated,
            &l.org,
            &l.cipher.id,
            &l.links,
            false,
        );
    }
    user_view(app, user, l).await
}

/// Parses an organization id the way Vaultwarden's lookups fail on a bad one: no such organization.
fn parse_space(text: &str) -> Option<SpaceId> {
    Uuid::parse_str(text).ok().map(SpaceId)
}

fn parse_collections(ids: &[String]) -> BwResult<Vec<CollectionId>> {
    ids.iter()
        .map(|id| {
            Uuid::parse_str(id)
                .map(CollectionId)
                .map_err(|_| BwError::msg("Invalid collection ID provided"))
        })
        .collect()
}

/// Checks the collections a cipher is being put in: they exist in the organization and the
/// account may write to them.
fn check_target_collections(org: &Org, user: UserId, collections: &[CollectionId]) -> BwResult<()> {
    for id in collections {
        if org.collection(*id).is_none() {
            return Err(BwError::msg("Invalid collection ID provided"));
        }
        if !org.collection_writable(user, *id) {
            return Err(BwError::msg("No rights to modify the collection"));
        }
    }
    Ok(())
}

fn member_or_refuse(org: &Org, user: UserId) -> BwResult<&MemberDoc> {
    org.member(user)
        .filter(|m| m.confirmed())
        .ok_or_else(|| BwError::msg("You don't have permission to add item to organization"))
}

/// `POST /api/ciphers/create` and `/api/ciphers/admin` for a cipher of an organization.
pub(crate) async fn create_in_org<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    data: CipherData,
    collection_ids: &[String],
) -> BwResult<Value> {
    let user = authed.user.id;
    let org_text = data.organization_id.clone().unwrap_or_default();
    let collections = parse_collections(collection_ids)?;
    let org = match parse_space(&org_text) {
        Some(space) => app.load_org(space).await?,
        None => None,
    };
    let Some(org) = org else {
        return Err(BwError::msg(if collections.is_empty() {
            "You don't have permission to add item to organization"
        } else {
            "Invalid collection ID provided"
        }));
    };
    check_target_collections(&org, user, &collections)?;
    let member = member_or_refuse(&org, user)?;
    if collections.is_empty() && !member.full_access() {
        return Err(BwError::msg(
            "You don't have permission to add cipher directly to organization",
        ));
    }

    let now = app.now();
    let folder_valid = app.folder_valid(user, data.folder_id.as_deref()).await?;
    let id = random_uuid(app.env.as_ref()).to_string();
    let mut cipher = StoredCipher::new(id.clone(), data.r#type, now);
    update_from_data(&mut cipher, data, now, false, folder_valid)?;
    let prefs = PrefDoc {
        folder_id: cipher.folder_id.take(),
        favorite: std::mem::take(&mut cipher.favorite),
        archived_date: cipher.archived_date.take(),
    };
    let first = collections.first().copied();
    app.write_org_cipher(org.id, None, &cipher, first, now)
        .await?;
    app.set_links(org.id, &id, &collections).await?;
    app.put_doc(user.0, KIND_PREFS, &id, &prefs).await?;
    app.touch_members(&org).await?;
    log_cipher(app, authed, org.id, kind::CIPHER_CREATED, &id).await;
    app.org_cipher_changed(authed, Change::Created, &org, &id, &collections, true);
    let restrict = org
        .cipher_restrictions(user, &collections)
        .unwrap_or(Restrict::FULL);
    org_cipher_json(
        app,
        user,
        &org,
        &cipher,
        &collections,
        Some((&prefs, restrict)),
    )
}

/// The share of one cipher: `PUT /api/ciphers/{id}/share` and each cipher of a bulk share.
pub(crate) async fn share_one<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    mut data: CipherData,
    collection_ids: &[String],
    log: bool,
) -> BwResult<Value> {
    let user = authed.user.id;
    let now = app.now();
    let target = data.organization_id.clone().unwrap_or_default();
    let collections = parse_collections(collection_ids)?;

    // An organization cipher stays where it is and gains the collections.
    if let Some(mut l) = org_cipher(app, user, id).await? {
        if !l.restrict.is_some_and(|r| r.writable()) {
            return Err(BwError::msg("Cipher is not write accessible"));
        }
        if target != org_id_text(&l) {
            return Err(BwError::msg(
                "Organization mismatch. Please resync the client before updating the cipher",
            ));
        }
        check_target_collections(&l.org, user, &collections)?;
        for c in &collections {
            if !l.links.contains(c) {
                l.links.push(*c);
            }
        }
        app.set_links(l.org.id, &l.cipher.id, &l.links).await?;
        return update_with(app, authed, l, data, log, true).await;
    }

    // A personal cipher moves in: a new item, a tombstone where it was.
    let Some(old_id) = item_id(id) else {
        return Err(BwError::msg("Cipher doesn't exist"));
    };
    let old = match ItemStore::get(&app.store, old_id).await? {
        Some(item) if item.owner == Owner::User(user) && !item.is_tombstone() => item,
        Some(_) => return Err(BwError::msg("Cipher is not write accessible")),
        None => return Err(BwError::msg("Cipher doesn't exist")),
    };
    let Some(old_cipher) = parse_cipher(&old) else {
        return Err(BwError::msg("Cipher doesn't exist"));
    };
    let org = match parse_space(&target) {
        Some(space) => app.load_org(space).await?,
        None => None,
    };
    let Some(org) = org else {
        return Err(BwError::msg(if collections.is_empty() {
            "You don't have permission to add item to organization"
        } else {
            "Invalid collection ID provided"
        }));
    };
    check_target_collections(&org, user, &collections)?;
    let member = member_or_refuse(&org, user)?;
    if collections.is_empty() && !member.full_access() {
        return Err(BwError::msg(
            "You don't have permission to add cipher directly to organization",
        ));
    }

    let folder_valid = app.folder_valid(user, data.folder_id.as_deref()).await?;
    data.last_known_revision_date = None;
    let new_id = random_uuid(app.env.as_ref()).to_string();
    let mut cipher = StoredCipher::new(new_id.clone(), data.r#type, now);
    cipher.creation_date = old_cipher.creation_date.clone();
    cipher.attachments = old_cipher.attachments.clone();
    update_from_data(&mut cipher, data, now, false, folder_valid)?;
    let prefs = PrefDoc {
        folder_id: cipher.folder_id.take(),
        favorite: std::mem::take(&mut cipher.favorite),
        archived_date: cipher.archived_date.take(),
    };

    // The files follow the cipher to its new id.
    for attachment in &old_cipher.attachments {
        let from = format!("{}/{}", old_cipher.id, attachment.id);
        let to = format!("{new_id}/{}", attachment.id);
        match app.blobs.get(&from).await {
            Ok(Some(bytes)) => {
                if app.blobs.put(&to, bytes).await.is_ok() {
                    let _ = app.blobs.delete(&from).await;
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "couldn't move an attachment file"),
        }
    }

    let first = collections.first().copied();
    app.write_org_cipher(org.id, None, &cipher, first, now)
        .await?;
    app.set_links(org.id, &new_id, &collections).await?;
    app.put_doc(user.0, KIND_PREFS, &new_id, &prefs).await?;
    let draft = app.org_draft_personal(user, &old, now)?;
    match ItemStore::put(&app.store, draft).await {
        Ok(_) | Err(StoreError::Conflict { .. }) => {}
        Err(e) => return Err(e.into()),
    }
    app.touch_members(&org).await?;
    if log {
        log_cipher(app, authed, org.id, kind::CIPHER_SHARED, &new_id).await;
    }
    app.touch(user).await?;
    app.org_cipher_changed(authed, Change::Created, &org, &new_id, &collections, true);
    let restrict = org
        .cipher_restrictions(user, &collections)
        .unwrap_or(Restrict::FULL);
    org_cipher_json(
        app,
        user,
        &org,
        &cipher,
        &collections,
        Some((&prefs, restrict)),
    )
}

impl<S: BwStore> App<S> {
    /// The tombstone of a personal item that moved to an organization.
    fn org_draft_personal(
        &self,
        user: UserId,
        item: &Item,
        now: OffsetDateTime,
    ) -> BwResult<ItemDraft> {
        let revision = item
            .revision
            .next()
            .ok_or_else(|| BwError::Server("an item ran out of revisions".to_owned()))?;
        Ok(ItemDraft {
            id: item.id,
            owner: Owner::User(user),
            kind: item.kind.clone(),
            format: ItemFormat::Bw,
            expected: Some(item.revision),
            revision,
            key_version: 0,
            deleted_at: Some(now),
            ciphertext: None,
            item_key: None,
            updated_at: now,
        })
    }
}

/// `cipherMini` of a cipher: what a bulk share answers.
fn cipher_mini(mut cipher: Value) -> Value {
    const FIELDS: &[&str] = &[
        "id",
        "organizationId",
        "type",
        "data",
        "partialData",
        "name",
        "notes",
        "login",
        "card",
        "identity",
        "secureNote",
        "sshKey",
        "bankAccount",
        "driversLicense",
        "passport",
        "fields",
        "passwordHistory",
        "attachments",
        "organizationUseTotp",
        "revisionDate",
        "creationDate",
        "deletedDate",
        "reprompt",
        "key",
    ];
    let Some(object) = cipher.as_object_mut() else {
        return json!({ "object": "cipherMini" });
    };
    object.retain(|field, _| FIELDS.contains(&field.as_str()));
    object.insert("object".to_owned(), json!("cipherMini"));
    cipher
}

/// `PUT /api/ciphers/share`: several ciphers into one set of collections.
pub(crate) async fn share_selected<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    ciphers: Vec<CipherData>,
    collection_ids: Vec<String>,
) -> BwResult<Value> {
    if ciphers.is_empty() {
        return Err(BwError::msg("You must select at least one cipher."));
    }
    if collection_ids.is_empty() {
        return Err(BwError::msg("You must select at least one collection."));
    }
    for cipher in &ciphers {
        if cipher.id.is_none() {
            return Err(BwError::msg("Request missing ids field"));
        }
        if cipher.organization_id.is_none() {
            return Err(BwError::msg("Cipher OrganizationId is required."));
        }
    }
    let mut responses = Vec::with_capacity(ciphers.len());
    for mut cipher in ciphers {
        let Some(id) = cipher.id.take() else {
            return Err(BwError::msg("Request missing ids field"));
        };
        let shared = share_one(app, authed, &id, cipher, &collection_ids, false).await?;
        responses.push(cipher_mini(shared));
    }
    Ok(super::json::list(responses))
}

/// `PUT /api/ciphers/{id}/collections`, `collections_v2` and `collections-admin`.
pub(crate) async fn update_collections<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    id: &str,
    posted: &[String],
) -> BwResult<Value> {
    let user = authed.user.id;
    let Some(mut l) = org_cipher(app, user, id).await? else {
        return Err(BwError::msg(if owns_personal(app, user, id).await? {
            "Cipher is not owned by an organization"
        } else {
            "Cipher doesn't exist"
        }));
    };
    if !l.restrict.is_some_and(|r| r.editable()) {
        return Err(BwError::msg("Collection cannot be changed"));
    }
    let posted = parse_collections(posted)?;
    let posted_set: HashSet<CollectionId> = posted.iter().copied().collect();
    // Only the collections the account can write to are its to change.
    let current: HashSet<CollectionId> = l
        .links
        .iter()
        .copied()
        .filter(|c| l.org.collection_writable(user, *c))
        .collect();
    let mut links = l.links.clone();
    for collection in posted_set.symmetric_difference(&current) {
        if l.org.collection(*collection).is_none() {
            return Err(BwError::msg("Invalid collection ID provided"));
        }
        if !l.org.collection_writable(user, *collection) {
            return Err(BwError::msg("No rights to modify the collection"));
        }
        if posted_set.contains(collection) {
            if !links.contains(collection) {
                links.push(*collection);
            }
        } else {
            links.retain(|c| c != collection);
        }
    }
    app.set_links(l.org.id, &l.cipher.id, &links).await?;
    l.links = links;
    app.touch_members(&l.org).await?;
    let event = kind::CIPHER_UPDATED_COLLECTIONS;
    log_cipher(app, authed, l.org.id, event, &l.cipher.id).await;
    app.org_cipher_changed(
        authed,
        Change::Updated,
        &l.org,
        &l.cipher.id,
        &l.links,
        true,
    );
    l.restrict = l.org.cipher_restrictions(user, &l.links).or(l.restrict);
    user_view(app, user, &l).await
}

/// `GET /api/ciphers/organization-details`: every cipher of an organization, for an admin.
pub(crate) async fn org_details<S: BwStore>(
    app: &App<S>,
    org: &Org,
    user: UserId,
) -> BwResult<Vec<Value>> {
    let links = app.links_of(org.id).await?;
    let mut out = Vec::new();
    for item in app.org_items(org.id).await? {
        let Some(cipher) = parse_cipher(&item) else {
            continue;
        };
        let own = links.get(&cipher.id).cloned().unwrap_or_default();
        out.push(org_cipher_json(app, user, org, &cipher, &own, None)?);
    }
    Ok(out)
}

/// `POST /api/ciphers/bulk-collections`: adds ciphers to collections, or takes them out.
pub(crate) async fn bulk_collections<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    org_id: &str,
    cipher_ids: &[String],
    collection_ids: &[String],
    remove: bool,
) -> BwResult<()> {
    let user = authed.user.id;
    let not_found = || BwError::status(StatusCode::NOT_FOUND, "Resource not found");
    let org = match parse_space(org_id) {
        Some(space) => app.load_org(space).await?,
        None => None,
    };
    let Some(org) = org.filter(|o| o.member(user).is_some_and(|m| m.confirmed())) else {
        return Err(BwError::msg(
            "You need to be a Member of the Organization to call this endpoint",
        ));
    };
    let mut targets = Vec::new();
    for id in collection_ids {
        let collection = Uuid::parse_str(id).ok().map(CollectionId);
        match collection {
            Some(c)
                if org.collection(c).is_some()
                    && org.can_access_collection(user, c)
                    && org.collection_writable(user, c) =>
            {
                targets.push(c);
            }
            _ => return Err(not_found()),
        }
    }
    for id in cipher_ids {
        let Some(mut l) = org_cipher(app, user, id).await? else {
            continue;
        };
        if l.org.id != org.id || !l.restrict.is_some_and(|r| r.writable()) {
            continue;
        }
        for c in &targets {
            if remove {
                l.links.retain(|x| x != c);
            } else if !l.links.contains(c) {
                l.links.push(*c);
            }
        }
        app.set_links(org.id, &l.cipher.id, &l.links).await?;
    }
    Ok(())
}

/// Takes a deleted collection out of every cipher's links.
pub(crate) async fn forget_collection<S: BwStore>(
    app: &App<S>,
    org: SpaceId,
    collection: CollectionId,
) -> BwResult<()> {
    for (cipher, ids) in app.docs::<Vec<String>>(org.0, KIND_LINKS).await? {
        let text = collection.to_string();
        if ids.contains(&text) {
            let kept: Vec<String> = ids.into_iter().filter(|c| *c != text).collect();
            app.put_doc(org.0, KIND_LINKS, &cipher, &kept).await?;
        }
    }
    Ok(())
}

/// Deletes every cipher of an organization for good.
/// The bytes an organization's ciphers' attachments take, for the attachment quota.
pub(crate) async fn attachment_bytes<S: BwStore>(app: &App<S>, org: SpaceId) -> BwResult<u64> {
    let mut total = 0u64;
    for item in app.org_items(org).await? {
        if let Some(cipher) = parse_cipher(&item) {
            for attachment in &cipher.attachments {
                total = total.saturating_add(u64::try_from(attachment.size).unwrap_or(0));
            }
        }
    }
    Ok(total)
}

pub(crate) async fn purge_org<S: BwStore>(app: &App<S>, org: SpaceId) -> BwResult<()> {
    let now = app.now();
    for item in app.org_items(org).await? {
        if let Some(cipher) = parse_cipher(&item) {
            app.drop_attachment_files(&cipher).await;
        }
        app.tombstone_org_cipher(org, &item, now).await?;
    }
    Ok(())
}

/// A collection of an organization import: an existing one by id, or a new one by name.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportCollection {
    pub name: String,
    pub id: Option<String>,
    pub external_id: Option<String>,
}

/// `POST /api/ciphers/import-organization`'s body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrgImportData {
    pub ciphers: Vec<CipherData>,
    pub collections: Vec<ImportCollection>,
    /// A cipher's index in `ciphers` and a collection's in `collections`.
    pub collection_relationships: Vec<crate::vault::Relation>,
}

/// `POST /api/ciphers/import-organization`: makes the collections the file names that don't exist,
/// the ciphers, and the links between them. Nothing is imported unless every cipher is valid, the
/// caller may use every collection, and every relationship names a cipher and a collection of the
/// file; Vaultwarden checks the last of these after writing, and so can leave half an import.
pub(crate) async fn import_organization<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    data: OrgImportData,
) -> BwResult<()> {
    if !ctx.doc.confirmed() {
        return Err(BwError::msg(
            "You need to be a Member of the Organization to call this endpoint",
        ));
    }
    validate_import(&data.ciphers)?;
    let org = &ctx.org;
    let user = ctx.me;

    // Every collection: one the caller may write, or a new one the caller may make.
    let mut ids = Vec::with_capacity(data.collections.len());
    let mut made: Vec<(Collection, Option<String>)> = Vec::new();
    let now = app.now();
    for collection in &data.collections {
        let existing = collection
            .id
            .as_deref()
            .and_then(|text| Uuid::parse_str(text).ok())
            .map(CollectionId)
            .filter(|id| org.collection(*id).is_some());
        if let Some(id) = existing {
            if !ctx.doc.full_access() && !org.collection_writable(user, id) {
                return Err(BwError::msg(
                    "The current user isn't allowed to manage this collection",
                ));
            }
            ids.push(id);
            continue;
        }
        // Only a member with access to everything makes collections.
        if !ctx.doc.full_access() {
            return Err(BwError::msg(
                "The current user isn't allowed to create new collections",
            ));
        }
        let id = CollectionId(random_uuid(app.env.as_ref()));
        made.push((
            Collection {
                id,
                space: org.id,
                parent: None,
                name: collection.name.clone().into_bytes(),
                key_version: 1,
                stale_since: None,
                created_at: now,
            },
            collection
                .external_id
                .clone()
                .filter(|e| !e.trim().is_empty()),
        ));
        ids.push(id);
    }

    // The collections each cipher goes into.
    let mut links: Vec<Vec<CollectionId>> = vec![Vec::new(); data.ciphers.len()];
    for relation in &data.collection_relationships {
        let (Some(cipher_links), Some(collection)) =
            (links.get_mut(relation.key), ids.get(relation.value))
        else {
            return Err(BwError::msg("Invalid collection relationship"));
        };
        if !cipher_links.contains(collection) {
            cipher_links.push(*collection);
        }
    }

    for (collection, external_id) in made {
        app.put_collection(org, collection, external_id).await?;
    }
    let org_text = org.id.to_string();
    for (index, mut request) in data.ciphers.into_iter().enumerate() {
        request.folder_id = None;
        request.organization_id = Some(org_text.clone());
        let id = random_uuid(app.env.as_ref()).to_string();
        let mut cipher = StoredCipher::new(id.clone(), request.r#type, now);
        // A cipher that doesn't take is left out and the rest go on, as Vaultwarden's import does.
        if let Err(e) = update_from_data(&mut cipher, request, now, false, true) {
            tracing::warn!(error = ?e, index, "left a cipher out of an organization import");
            continue;
        }
        let own = &links[index];
        app.write_org_cipher(org.id, None, &cipher, own.first().copied(), now)
            .await?;
        app.set_links(org.id, &id, own).await?;
    }
    app.touch_members(org).await
}
