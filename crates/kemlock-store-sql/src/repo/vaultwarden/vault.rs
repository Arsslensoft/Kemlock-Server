//! Folders, ciphers, the state of organization ciphers per user, and attachments.
//!
//! A cipher is an item of format `bw` whose bytes are the JSON Vaultwarden would return for it
//! (`kemlock_vaultwarden::cipher_json`), with the attachments listed in its `attachments`. A
//! folder is a `bw-folder` item holding `{"name": …}`, as the Bitwarden API writes them.

use super::accounts::now_ms;
use super::rows;
use super::scope::{SPACE, USER};
use super::{Ctx, Res, invalid};
use crate::error::StoreResult;
use crate::repo::items::write_in;
use crate::tables::items as item_rows;
use crate::tables::{bw_accounts, bw_attachments};
use kemlock_domain::{ItemDraft, ItemFormat, ItemId, ItemKind, Owner, Revision};
use kemlock_vaultwarden::mapping::{MappedAttachment, MappedCipherState, MappedFolder, MappedItem};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// The item kind of a folder, as the Bitwarden API names it.
const FOLDER_KIND: &str = "bw-folder";
/// How many ids one query names.
const CHUNK: usize = 500;

async fn find(ctx: &Ctx, id: Uuid) -> Res<Option<item_rows::Model>> {
    Ok(item_rows::Entity::find_by_id(id)
        .one(&ctx.txn)
        .await
        .store()?)
}

/// The next revision of an item, or a tombstone of it when `body` is `None`.
fn draft(
    ctx: &Ctx,
    id: ItemId,
    owner: Owner,
    kind: &ItemKind,
    existing: Option<&item_rows::Model>,
    body: Option<Vec<u8>>,
    updated_at: OffsetDateTime,
) -> Res<ItemDraft> {
    let (expected, revision) = match existing {
        Some(row) => {
            let current = Revision(
                u64::try_from(row.revision)
                    .map_err(|_| invalid("an item has a negative revision"))?,
            );
            let next = current
                .next()
                .ok_or_else(|| invalid("an item ran out of revisions"))?;
            (Some(current), next)
        }
        None => (None, Revision::FIRST),
    };
    Ok(ItemDraft {
        id,
        owner,
        kind: kind.clone(),
        format: ItemFormat::Bw,
        expected,
        revision,
        key_version: 0,
        deleted_at: body.is_none().then_some(ctx.opts.now),
        ciphertext: body,
        item_key: None,
        updated_at,
    })
}

/// Whether the stored item already is what a pass would write.
fn unchanged(
    existing: Option<&item_rows::Model>,
    owner: Owner,
    kind: &ItemKind,
    body: &[u8],
) -> bool {
    let (owner_type, owner_id) = item_rows::owner_parts(owner);
    existing.is_some_and(|row| {
        row.deleted_at.is_none()
            && row.format == "bw"
            && row.kind == kind.as_str()
            && row.owner_type == owner_type
            && row.owner_id == owner_id
            && row.ciphertext.as_deref() == Some(body)
    })
}

async fn write(ctx: &Ctx, drafts: Vec<ItemDraft>) -> Res<()> {
    if drafts.is_empty() {
        return Ok(());
    }
    write_in(&ctx.txn, ctx.origin, drafts).await?;
    Ok(())
}

pub(super) async fn put_folders(ctx: &mut Ctx, folders: &[MappedFolder]) -> Res<()> {
    let kind = ItemKind::try_from(FOLDER_KIND.to_owned())
        .map_err(|_| invalid("the folder kind is not a valid item kind"))?;
    let mut drafts = Vec::new();
    for folder in folders {
        let body = json!({ "name": folder.name }).to_string().into_bytes();
        let owner = Owner::User(folder.user);
        if !ctx.item_allowed(folder.id, owner).await? {
            ctx.refuse("folder", folder.id);
            continue;
        }
        let existing = find(ctx, folder.id).await?;
        if !unchanged(existing.as_ref(), owner, &kind, &body) {
            drafts.push(draft(
                ctx,
                ItemId(folder.id),
                owner,
                &kind,
                existing.as_ref(),
                Some(body),
                folder.updated_at,
            )?);
        }
        ctx.touched.insert(folder.user.0);
    }
    write(ctx, drafts).await
}

fn attachment_entry(row: &bw_attachments::Model) -> Value {
    json!({
        "id": row.id,
        "fileName": row.file_name,
        "size": row.size,
        "key": row.akey,
    })
}

/// The attachments of ciphers as the entries of their `attachments`, by cipher.
async fn attachment_lists(ctx: &Ctx, ids: &[Uuid]) -> Res<BTreeMap<Uuid, Vec<Value>>> {
    let mut out: BTreeMap<Uuid, Vec<Value>> = BTreeMap::new();
    for chunk in ids.chunks(CHUNK) {
        let rows = bw_attachments::Entity::find()
            .filter(bw_attachments::Column::ItemId.is_in(chunk.to_vec()))
            .order_by_asc(bw_attachments::Column::Id)
            .all(&ctx.txn)
            .await
            .store()?;
        for row in rows {
            out.entry(row.item_id)
                .or_default()
                .push(attachment_entry(&row));
        }
    }
    Ok(out)
}

pub(super) async fn put_items(ctx: &mut Ctx, items: &[MappedItem]) -> Res<()> {
    let mut drafts = Vec::new();
    for chunk in items.chunks(CHUNK) {
        let ids: Vec<Uuid> = chunk.iter().map(|item| item.id.0).collect();
        let attachments = attachment_lists(ctx, &ids).await?;
        for item in chunk {
            if !ctx.item_allowed(item.id.0, item.owner).await? {
                ctx.refuse("item", item.id.0);
                continue;
            }
            let mut doc = item.json.clone();
            if let Some(list) = attachments.get(&item.id.0) {
                doc["attachments"] = Value::Array(list.clone());
            }
            let body = doc.to_string().into_bytes();
            let existing = find(ctx, item.id.0).await?;
            if !unchanged(existing.as_ref(), item.owner, &item.kind, &body) {
                drafts.push(draft(
                    ctx,
                    item.id,
                    item.owner,
                    &item.kind,
                    existing.as_ref(),
                    Some(body),
                    item.updated_at,
                )?);
            }
            if let Owner::User(user) = item.owner {
                ctx.touched.insert(user.0);
            }
        }
    }
    write(ctx, drafts).await
}

/// Keeps what a user has set on an organization's cipher (folder, favorite, archive date): an
/// organization's cipher is stored for all its members, so each member's own state goes beside it,
/// in `vw_rows` as `cipher_states`, for the Bitwarden API to add when it serves the cipher.
/// A user's own cipher already carries its state in its JSON.
pub(super) async fn put_cipher_states(ctx: &mut Ctx, states: &[MappedCipherState]) -> Res<()> {
    for state in states {
        let Some(row) = find(ctx, state.item.0).await? else {
            continue;
        };
        if row.owner_type != i16::from(Owner::TYPE_SPACE) {
            continue;
        }
        // Only a user and a space the import owns.
        if !ctx.owns(USER, state.user.0).await? || !ctx.owns(SPACE, row.owner_id).await? {
            ctx.refuse("cipher-state", cipher_state_key(state.user.0, state.item.0));
            continue;
        }
        let key = cipher_state_key(state.user.0, state.item.0);
        let value = json!({
            "user": state.user.to_string(),
            "item": state.item.to_string(),
            "folder": state.folder.map(|f| f.to_string()),
            "favorite": state.favorite,
            "archived_at": state.archived_at.and_then(|t| t.format(&Rfc3339).ok()),
        });
        rows::put_row(ctx, CIPHER_STATES, &key, &value, false).await?;
        super::org_docs::sync_pref(ctx, state.user.0, state.item.0).await?;
    }
    Ok(())
}

/// The `vw_rows` table name of the per-user state of organization ciphers.
pub(super) const CIPHER_STATES: &str = "cipher_states";

pub(super) fn cipher_state_key(user: Uuid, item: Uuid) -> String {
    format!("{user}/{item}")
}

pub(super) async fn put_attachments(ctx: &mut Ctx, attachments: &[MappedAttachment]) -> Res<()> {
    let mut touched = BTreeSet::new();
    for attachment in attachments {
        // The cipher is the import's, and the attachment id isn't another cipher's.
        let taken = bw_attachments::Entity::find_by_id(attachment.id.clone())
            .one(&ctx.txn)
            .await
            .store()?
            .is_some_and(|row| row.item_id != attachment.item.0);
        if taken || !ctx.item_owner_owned(attachment.item.0).await? {
            ctx.refuse("attachment", &attachment.id);
            continue;
        }
        bw_attachments::Entity::delete_many()
            .filter(bw_attachments::Column::Id.eq(attachment.id.as_str()))
            .exec(&ctx.txn)
            .await
            .store()?;
        bw_attachments::Entity::insert(bw_attachments::ActiveModel {
            id: Set(attachment.id.clone()),
            item_id: Set(attachment.item.0),
            file_name: Set(attachment.file_name.clone()),
            size: Set(attachment.size),
            akey: Set(attachment.key.clone()),
            storage_key: Set(attachment.storage_key.clone()),
        })
        .exec(&ctx.txn)
        .await
        .store()?;
        touched.insert(attachment.item.0);
    }
    for item in touched {
        rewrite_attachments(ctx, item).await?;
    }
    Ok(())
}

/// Makes the `attachments` of a cipher's document the rows of `bw_attachments`. The cipher's own
/// revision date stays: Vaultwarden doesn't move it when an attachment changes.
pub(super) async fn rewrite_attachments(ctx: &Ctx, item: Uuid) -> Res<()> {
    let Some(row) = find(ctx, item).await? else {
        return Ok(());
    };
    if row.deleted_at.is_some() || row.format != "bw" {
        return Ok(());
    }
    let Some(mut doc) = row
        .ciphertext
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
    else {
        return Ok(());
    };
    let mut lists = attachment_lists(ctx, &[item]).await?;
    let wanted = lists.remove(&item).unwrap_or_default();
    let current = doc
        .get("attachments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if current == wanted {
        return Ok(());
    }
    // The imported form has `null` for no attachments; the Bitwarden API's own has `[]`.
    let imported = doc.get("object").is_some();
    doc["attachments"] = if wanted.is_empty() && imported {
        Value::Null
    } else {
        Value::Array(wanted)
    };
    let body = doc.to_string().into_bytes();
    let owner = item_rows::owner_from(row.owner_type, row.owner_id)?;
    let kind = ItemKind::try_from(row.kind.clone())
        .map_err(|_| invalid("a stored item has an invalid kind"))?;
    let next = draft(
        ctx,
        ItemId(item),
        owner,
        &kind,
        Some(&row),
        Some(body),
        row.updated_at,
    )?;
    write(ctx, vec![next]).await
}

/// Leaves a tombstone where an item was (a cipher or folder that went away in Vaultwarden).
pub(super) async fn tombstone(ctx: &mut Ctx, id: Uuid) -> Res<()> {
    let Some(row) = find(ctx, id).await? else {
        return Ok(());
    };
    if row.deleted_at.is_some() || row.format != "bw" {
        return Ok(());
    }
    let owner = item_rows::owner_from(row.owner_type, row.owner_id)?;
    let kind = ItemKind::try_from(row.kind.clone())
        .map_err(|_| invalid("a stored item has an invalid kind"))?;
    let gone = draft(
        ctx,
        ItemId(id),
        owner,
        &kind,
        Some(&row),
        None,
        ctx.opts.now,
    )?;
    if let Owner::User(user) = owner {
        ctx.touched.insert(user.0);
    }
    write(ctx, vec![gone]).await
}

/// The owner of a stored item, if the item exists.
pub(super) async fn owner_of(ctx: &Ctx, id: Uuid) -> Res<Option<Owner>> {
    match find(ctx, id).await? {
        Some(row) => Ok(Some(item_rows::owner_from(row.owner_type, row.owner_id)?)),
        None => Ok(None),
    }
}

/// Moves the revision date of every account whose vault changed in this pass, so apps sync.
pub(super) async fn bump_revisions(ctx: &Ctx) -> Res<()> {
    let now = now_ms(ctx);
    for user in &ctx.touched {
        let Some(row) = bw_accounts::Entity::find_by_id(*user)
            .one(&ctx.txn)
            .await
            .store()?
        else {
            continue;
        };
        let next = now.max(row.revision_ms.saturating_add(1));
        bw_accounts::Entity::update_many()
            .col_expr(bw_accounts::Column::RevisionMs, Expr::value(next))
            .filter(bw_accounts::Column::UserId.eq(*user))
            .exec(&ctx.txn)
            .await
            .store()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_keys_name_the_user_then_the_cipher() {
        let user = Uuid::from_u128(1);
        let item = Uuid::from_u128(2);
        assert_eq!(
            cipher_state_key(user, item),
            format!("{user}/{item}"),
            "the key starts with the user, so a user's states share a prefix"
        );
    }

    #[test]
    fn attachment_entries_have_the_stored_cipher_shape() {
        let row = bw_attachments::Model {
            id: "att1".to_owned(),
            item_id: Uuid::nil(),
            file_name: "2.name".to_owned(),
            size: 12,
            akey: None,
            storage_key: "attachments/c/att1".to_owned(),
        };
        assert_eq!(
            attachment_entry(&row),
            json!({"id": "att1", "fileName": "2.name", "size": 12, "key": null})
        );
    }
}
