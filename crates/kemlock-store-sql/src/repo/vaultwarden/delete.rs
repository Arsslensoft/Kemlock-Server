//! What a second pass learned from the diff: rows that Vaultwarden no longer has, by table and
//! primary key.
//!
//! A cipher or folder that is gone becomes a tombstone (so devices that sync learn of it), and
//! the rows that hung off it go with it. A row that is already gone is not an error.

use super::accounts::rebuild_two_factor;
use super::org_docs;
use super::orgs::{member_of, reconcile_item_collection};
use super::rows::{self, row_uuid};
use super::scope;
use super::vault::{CIPHER_STATES, cipher_state_key, rewrite_attachments, tombstone};
use super::{Ctx, Res, files};
use crate::error::StoreResult;
use crate::tables::space_recovery;
use crate::tables::space_tables::{
    collection_grants, collection_keys, collections, group_members, groups, item_collections,
    members, spaces,
};
use crate::tables::{
    bw_account_extras, bw_accounts, bw_attachments, devices, emergency_access, events,
    refresh_tokens, two_factor, users,
};
use kemlock_vaultwarden::snapshot::RowKey;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

/// The `vw_rows` table that says which user a membership is.
const MEMBERSHIPS: &str = "users_organizations";

pub(super) async fn delete_rows(ctx: &mut Ctx, table: &'static str, keys: &[RowKey]) -> Res<()> {
    let mut reconcile: BTreeSet<Uuid> = BTreeSet::new();
    let mut rebuild: BTreeSet<Uuid> = BTreeSet::new();
    for key in keys {
        let first = row_uuid(key.first().map(String::as_str));
        let second = row_uuid(key.get(1).map(String::as_str));
        let stored_key = rows::key_text(key);
        // Only what the import owns goes: a second pass can't delete another owner's rows.
        if !scope::delete_allowed(ctx, table, first).await? {
            ctx.refuse(table, &stored_key);
            continue;
        }
        match table {
            "users" => {
                if let Some(user) = first {
                    delete_user(ctx, user).await?;
                    org_docs::forget_scope(ctx, user).await?;
                }
            }
            "devices" => {
                if let Some(device) = first {
                    delete_device(ctx, device).await?;
                }
            }
            "ciphers" | "folders" => {
                if let Some(id) = first {
                    if table == "ciphers" {
                        delete_cipher_parts(ctx, id).await?;
                    }
                    tombstone(ctx, id).await?;
                }
            }
            "folders_ciphers" => {
                // [cipher, folder]: whoever had the cipher in that folder has it in none now.
                if let (Some(cipher), Some(folder)) = (first, second) {
                    clear_folder(ctx, cipher, folder).await?;
                }
            }
            "favorites" => {
                // [user, cipher]
                if let (Some(user), Some(cipher)) = (first, second) {
                    clear_state(ctx, user, cipher, "favorite").await?;
                }
            }
            "archives" => {
                if let (Some(user), Some(cipher)) = (first, second) {
                    clear_state(ctx, user, cipher, "archived_at").await?;
                }
            }
            "attachments" => {
                if let Some(id) = key.first() {
                    delete_attachment(ctx, id).await?;
                }
            }
            "organizations" => {
                if let Some(space) = first {
                    delete_space(ctx, space).await?;
                    org_docs::forget_scope(ctx, space).await?;
                }
            }
            "users_organizations" => {
                if let Some(row) = rows::get_row(ctx, MEMBERSHIPS, &stored_key).await?
                    && let (Some(user), Some(space)) = (
                        row_uuid(rows::text(&row, "user_uuid")),
                        row_uuid(rows::text(&row, "org_uuid")),
                    )
                {
                    delete_membership(ctx, space, user).await?;
                    org_docs::forget_member(ctx, space, user).await?;
                }
            }
            "collections" => {
                if let Some(collection) = first {
                    delete_collection(ctx, collection).await?;
                    org_docs::forget_collection(ctx, collection).await?;
                }
            }
            "ciphers_collections" => {
                if let Some(cipher) = first {
                    reconcile.insert(cipher);
                }
            }
            "users_collections" => {
                // [user, collection]
                if let (Some(user), Some(collection)) = (first, second) {
                    delete_grant(ctx, collection, collection_grants::GRANTEE_MEMBER, user).await?;
                }
            }
            "collections_groups" => {
                // [collection, group]
                if let (Some(collection), Some(group)) = (first, second) {
                    delete_grant(ctx, collection, collection_grants::GRANTEE_GROUP, group).await?;
                }
            }
            "groups" => {
                if let Some(group) = first {
                    delete_group(ctx, group).await?;
                    org_docs::forget_group(ctx, group).await?;
                }
            }
            "groups_users" => {
                // [group, membership]
                if let (Some(group), Some(membership)) = (first, key.get(1))
                    && let Some(user) = member_of(ctx, membership).await?
                {
                    group_members::Entity::delete_many()
                        .filter(group_members::Column::GroupId.eq(group))
                        .filter(group_members::Column::UserId.eq(user))
                        .exec(&ctx.txn)
                        .await
                        .store()?;
                }
            }
            "twofactor" => {
                if let Some(row) = rows::get_row(ctx, "twofactor", &stored_key).await?
                    && let Some(user) = row_uuid(rows::text(&row, "user_uuid"))
                {
                    rebuild.insert(user);
                }
            }
            "emergency_access" => {
                if let Some(id) = first {
                    emergency_access::Entity::delete_many()
                        .filter(emergency_access::Column::Id.eq(id))
                        .exec(&ctx.txn)
                        .await
                        .store()?;
                }
            }
            "event" => {
                if let Some(id) = first {
                    // Only an event the import wrote, never one of the server's own.
                    events::Entity::delete_many()
                        .filter(events::Column::Id.eq(id))
                        .filter(events::Column::Action.starts_with("vw-event-"))
                        .exec(&ctx.txn)
                        .await
                        .store()?;
                }
            }
            "org_policies" => {
                if let Some(row) = rows::get_row(ctx, table, &stored_key).await? {
                    org_docs::forget_policy(ctx, &row).await?;
                }
            }
            "organization_api_key" => {
                if let Some(row) = rows::get_row(ctx, table, &stored_key).await? {
                    org_docs::forget_api_key(ctx, &row).await?;
                }
            }
            // Sends, SSO links and invitations only live in `vw_rows`.
            _ => {}
        }
        rows::delete_row(ctx, table, &stored_key).await?;
    }
    for cipher in reconcile {
        reconcile_item_collection(ctx, cipher).await?;
        org_docs::sync_links(ctx, cipher).await?;
    }
    rebuild_two_factor(ctx, &rebuild).await
}

async fn delete_user(ctx: &Ctx, user: Uuid) -> Res<()> {
    let txn = &ctx.txn;
    // Explicit, though the foreign keys cascade: not every backend is made to enforce them.
    refresh_tokens::Entity::delete_many()
        .filter(refresh_tokens::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    devices::Entity::delete_many()
        .filter(devices::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    two_factor::Entity::delete_many()
        .filter(two_factor::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    bw_account_extras::Entity::delete_many()
        .filter(bw_account_extras::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    bw_accounts::Entity::delete_many()
        .filter(bw_accounts::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    emergency_access::Entity::delete_many()
        .filter(emergency_access::Column::GrantorId.eq(user))
        .exec(txn)
        .await
        .store()?;
    users::Entity::delete_many()
        .filter(users::Column::Id.eq(user))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

async fn delete_device(ctx: &Ctx, device: Uuid) -> Res<()> {
    refresh_tokens::Entity::delete_many()
        .filter(refresh_tokens::Column::DeviceId.eq(device))
        .exec(&ctx.txn)
        .await
        .store()?;
    devices::Entity::delete_many()
        .filter(devices::Column::Id.eq(device))
        .exec(&ctx.txn)
        .await
        .store()?;
    Ok(())
}

/// What hangs off a cipher: its attachment rows and files, its collection and the states users
/// keep for it. The item itself becomes a tombstone.
async fn delete_cipher_parts(ctx: &Ctx, cipher: Uuid) -> Res<()> {
    org_docs::forget_cipher(ctx, cipher).await?;
    let attachments = bw_attachments::Entity::find()
        .filter(bw_attachments::Column::ItemId.eq(cipher))
        .all(&ctx.txn)
        .await
        .store()?;
    for attachment in &attachments {
        files::remove_file(ctx, &attachment.storage_key).await?;
    }
    bw_attachments::Entity::delete_many()
        .filter(bw_attachments::Column::ItemId.eq(cipher))
        .exec(&ctx.txn)
        .await
        .store()?;
    item_collections::Entity::delete_many()
        .filter(item_collections::Column::ItemId.eq(cipher))
        .exec(&ctx.txn)
        .await
        .store()?;
    for (key, _) in rows::rows_with_suffix(ctx, CIPHER_STATES, &format!("/{cipher}")).await? {
        rows::delete_row(ctx, CIPHER_STATES, &key).await?;
    }
    Ok(())
}

async fn delete_attachment(ctx: &Ctx, id: &str) -> Res<()> {
    let Some(row) = bw_attachments::Entity::find_by_id(id.to_owned())
        .one(&ctx.txn)
        .await
        .store()?
    else {
        return Ok(());
    };
    files::remove_file(ctx, &row.storage_key).await?;
    bw_attachments::Entity::delete_many()
        .filter(bw_attachments::Column::Id.eq(id))
        .exec(&ctx.txn)
        .await
        .store()?;
    rewrite_attachments(ctx, row.item_id).await
}

/// Takes `field` off the state a user keeps for an organization cipher, and the state with it when
/// nothing else is set.
async fn clear_state(ctx: &Ctx, user: Uuid, cipher: Uuid, field: &str) -> Res<()> {
    let key = cipher_state_key(user, cipher);
    let Some(mut state) = rows::get_row(ctx, CIPHER_STATES, &key).await? else {
        return Ok(());
    };
    state[field] = if field == "favorite" {
        Value::Bool(false)
    } else {
        Value::Null
    };
    let empty = !state["favorite"].as_bool().unwrap_or(false)
        && state["folder"].is_null()
        && state["archived_at"].is_null();
    if empty {
        rows::delete_row(ctx, CIPHER_STATES, &key).await?;
    } else {
        rows::put_row(ctx, CIPHER_STATES, &key, &state, false).await?;
    }
    org_docs::sync_pref(ctx, user, cipher).await
}

/// Takes the folder off the state of every user who had `cipher` in `folder`.
async fn clear_folder(ctx: &Ctx, cipher: Uuid, folder: Uuid) -> Res<()> {
    let folder = folder.to_string();
    for (key, state) in rows::rows_with_suffix(ctx, CIPHER_STATES, &format!("/{cipher}")).await? {
        if rows::text(&state, "folder") != Some(folder.as_str()) {
            continue;
        }
        if let Some(user) = key.split('/').next().and_then(|u| row_uuid(Some(u))) {
            clear_state(ctx, user, cipher, "folder").await?;
        }
    }
    Ok(())
}

async fn collection_ids(ctx: &Ctx, space: Uuid) -> Res<Vec<Uuid>> {
    Ok(collections::Entity::find()
        .filter(collections::Column::SpaceId.eq(space))
        .all(&ctx.txn)
        .await
        .store()?
        .into_iter()
        .map(|c| c.id)
        .collect())
}

async fn group_ids(ctx: &Ctx, space: Uuid) -> Res<Vec<Uuid>> {
    Ok(groups::Entity::find()
        .filter(groups::Column::SpaceId.eq(space))
        .all(&ctx.txn)
        .await
        .store()?
        .into_iter()
        .map(|g| g.id)
        .collect())
}

async fn delete_grant(ctx: &Ctx, collection: Uuid, grantee_type: i16, grantee: Uuid) -> Res<()> {
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::CollectionId.eq(collection))
        .filter(collection_grants::Column::GranteeType.eq(grantee_type))
        .filter(collection_grants::Column::GranteeId.eq(grantee))
        .exec(&ctx.txn)
        .await
        .store()?;
    Ok(())
}

async fn delete_collection(ctx: &Ctx, collection: Uuid) -> Res<()> {
    let txn = &ctx.txn;
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::CollectionId.eq(collection))
        .exec(txn)
        .await
        .store()?;
    collection_keys::Entity::delete_many()
        .filter(collection_keys::Column::CollectionId.eq(collection))
        .exec(txn)
        .await
        .store()?;
    item_collections::Entity::delete_many()
        .filter(item_collections::Column::CollectionId.eq(collection))
        .exec(txn)
        .await
        .store()?;
    collections::Entity::delete_many()
        .filter(collections::Column::Id.eq(collection))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

async fn delete_group(ctx: &Ctx, group: Uuid) -> Res<()> {
    let txn = &ctx.txn;
    group_members::Entity::delete_many()
        .filter(group_members::Column::GroupId.eq(group))
        .exec(txn)
        .await
        .store()?;
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::GranteeType.eq(collection_grants::GRANTEE_GROUP))
        .filter(collection_grants::Column::GranteeId.eq(group))
        .exec(txn)
        .await
        .store()?;
    groups::Entity::delete_many()
        .filter(groups::Column::Id.eq(group))
        .exec(txn)
        .await
        .store()?;
    Ok(())
}

/// Takes a user out of a space: the member, their grants, their collection keys and their place
/// in its groups.
async fn delete_membership(ctx: &Ctx, space: Uuid, user: Uuid) -> Res<()> {
    let txn = &ctx.txn;
    space_recovery::Entity::delete_many()
        .filter(space_recovery::Column::SpaceId.eq(space))
        .filter(space_recovery::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    members::Entity::delete_many()
        .filter(members::Column::SpaceId.eq(space))
        .filter(members::Column::UserId.eq(user))
        .exec(txn)
        .await
        .store()?;
    let in_collections = collection_ids(ctx, space).await?;
    if !in_collections.is_empty() {
        collection_grants::Entity::delete_many()
            .filter(collection_grants::Column::CollectionId.is_in(in_collections.clone()))
            .filter(collection_grants::Column::GranteeType.eq(collection_grants::GRANTEE_MEMBER))
            .filter(collection_grants::Column::GranteeId.eq(user))
            .exec(txn)
            .await
            .store()?;
        collection_keys::Entity::delete_many()
            .filter(collection_keys::Column::CollectionId.is_in(in_collections))
            .filter(collection_keys::Column::UserId.eq(user))
            .exec(txn)
            .await
            .store()?;
    }
    let in_groups = group_ids(ctx, space).await?;
    if !in_groups.is_empty() {
        group_members::Entity::delete_many()
            .filter(group_members::Column::GroupId.is_in(in_groups))
            .filter(group_members::Column::UserId.eq(user))
            .exec(txn)
            .await
            .store()?;
    }
    Ok(())
}

/// Removes a space with everything it owns but its items, which are Vaultwarden's ciphers and
/// have rows of their own in the diff.
async fn delete_space(ctx: &Ctx, space: Uuid) -> Res<()> {
    for collection in collection_ids(ctx, space).await? {
        delete_collection(ctx, collection).await?;
    }
    for group in group_ids(ctx, space).await? {
        delete_group(ctx, group).await?;
    }
    space_recovery::Entity::delete_many()
        .filter(space_recovery::Column::SpaceId.eq(space))
        .exec(&ctx.txn)
        .await
        .store()?;
    members::Entity::delete_many()
        .filter(members::Column::SpaceId.eq(space))
        .exec(&ctx.txn)
        .await
        .store()?;
    spaces::Entity::delete_many()
        .filter(spaces::Column::Id.eq(space))
        .exec(&ctx.txn)
        .await
        .store()?;
    Ok(())
}
