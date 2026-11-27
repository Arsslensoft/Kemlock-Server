//! Which ids a pass may write.
//!
//! The importer writes by Vaultwarden's own ids, so a snapshot that names an id this server
//! already uses for something else would rewrite it: an account's email, name and password hash,
//! its devices and two-step setups, a space's name and members. A pass therefore only writes
//! what the import made:
//!
//! - a user or space id is the import's when no row of that id exists yet (the pass creates it and
//!   records it in `vw_import_ids`), or when `vw_import_ids` says an earlier pass created it, so
//!   running a move again over its own earlier copy works as it always did;
//! - everything that hangs off a user or space (devices, two-step setups, memberships, items,
//!   collections, groups, Sends, events, files) is written only for users and spaces that are the
//!   import's, and never over an id that belongs to another owner;
//! - an account or space the server's own API changed since the import last wrote it (a later
//!   `updated_at`, another revision date, a changed member) is left alone as well, so a rerun
//!   can't roll it back to Vaultwarden's state; an item the API revised after the source's date
//!   likewise;
//! - an id that fails the test is skipped, remembered in `Ctx::refused` and reported by
//!   `ImportSink::refused`, and the rest of the pass carries on.
//!
//! An operator who really means to overwrite what is there (a server that already holds the same
//! users from an earlier move that left no record) sets `ImportOptions::adopt_existing`; only the
//! command line does, never the admin console.

use super::rows::{self, row_uuid};
use super::{Ctx, Res};
use crate::convert::utc;
use crate::error::StoreResult;
use crate::tables::items as item_rows;
use crate::tables::space_tables::{collections, groups, members, spaces};
use crate::tables::{
    bw_accounts, bw_attachments, devices, emergency_access, sends, users, vw_import_ids,
};
use kemlock_domain::Owner;
use kemlock_vaultwarden::snapshot::{RowRef, Table};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use uuid::Uuid;

/// The `vw_import_ids.kind` of an account, and the refused kind that names one.
pub(super) const USER: &str = "user";
/// The `vw_import_ids.kind` of a space, and the refused kind that names one.
pub(super) const SPACE: &str = "space";

impl Ctx {
    fn owned_set(&mut self, kind: &str) -> &mut BTreeSet<Uuid> {
        if kind == SPACE {
            &mut self.spaces
        } else {
            &mut self.users
        }
    }

    /// Remembers an id the pass left alone.
    pub(super) fn refuse(&mut self, kind: &'static str, id: impl ToString) {
        self.refused.entry(kind).or_default().insert(id.to_string());
    }

    fn was_refused(&self, kind: &str, id: Uuid) -> bool {
        self.refused
            .get(kind)
            .is_some_and(|ids| ids.contains(&id.to_string()))
    }

    async fn exists(&self, kind: &str, id: Uuid) -> Res<bool> {
        let txn = &self.txn;
        Ok(if kind == SPACE {
            spaces::Entity::find_by_id(id)
                .one(txn)
                .await
                .store()?
                .is_some()
        } else {
            users::Entity::find_by_id(id)
                .one(txn)
                .await
                .store()?
                .is_some()
        })
    }

    async fn mark_row(&self, kind: &str, id: Uuid) -> Res<Option<vw_import_ids::Model>> {
        Ok(vw_import_ids::Entity::find_by_id((kind.to_owned(), id))
            .one(&self.txn)
            .await
            .store()?)
    }

    async fn marked(&self, kind: &str, id: Uuid) -> Res<bool> {
        Ok(self.mark_row(kind, id).await?.is_some())
    }

    async fn mark(&self, kind: &str, id: Uuid) -> Res<()> {
        vw_import_ids::Entity::insert(vw_import_ids::ActiveModel {
            kind: Set(kind.to_owned()),
            id: Set(id),
            imported_at: Set(utc(self.opts.now)),
            written_at: Set(utc(self.opts.now)),
            revision_ms: Set(None),
        })
        .exec(&self.txn)
        .await
        .store()?;
        Ok(())
    }

    /// Whether the server's own API changed the user or space since the import last wrote it.
    async fn changed_since(&self, kind: &str, id: Uuid, mark: &vw_import_ids::Model) -> Res<bool> {
        let written = utc(mark.written_at);
        if kind == SPACE {
            let space = spaces::Entity::find_by_id(id)
                .one(&self.txn)
                .await
                .store()?;
            if space.is_some_and(|s| utc(s.updated_at) > written) {
                return Ok(true);
            }
            // A member invited, accepted, revoked or confirmed by the API since.
            let moved = members::Entity::find()
                .filter(members::Column::SpaceId.eq(id))
                .filter(
                    Condition::any()
                        .add(members::Column::InvitedAt.gt(written))
                        .add(members::Column::AcceptedAt.gt(written))
                        .add(members::Column::RevokedAt.gt(written))
                        .add(members::Column::ConfirmedAt.gt(written)),
                )
                .one(&self.txn)
                .await
                .store()?;
            return Ok(moved.is_some());
        }
        let user = users::Entity::find_by_id(id).one(&self.txn).await.store()?;
        if user.is_some_and(|u| utc(u.updated_at) > written) {
            return Ok(true);
        }
        if let Some(stored) = mark.revision_ms {
            let record = bw_accounts::Entity::find_by_id(id)
                .one(&self.txn)
                .await
                .store()?;
            return Ok(record.is_some_and(|r| r.revision_ms != stored));
        }
        Ok(false)
    }

    /// Whether `id` is a `kind` the import owns: one this pass took, one an earlier pass made, or
    /// (when the operator asked to adopt what is there) one that exists. An id that doesn't exist
    /// is not owned until [`Ctx::claim`] creates it.
    pub(super) async fn owns(&mut self, kind: &'static str, id: Uuid) -> Res<bool> {
        if self.owned_set(kind).contains(&id) {
            return Ok(true);
        }
        let changed = changed_kind(kind);
        if self.was_refused(changed, id) {
            return Ok(false);
        }
        if !self.exists(kind, id).await? {
            return Ok(false);
        }
        match self.mark_row(kind, id).await? {
            None if !self.opts.adopt_existing => return Ok(false),
            None => self.mark(kind, id).await?,
            Some(mark) => {
                // Changed here since the import wrote it: not rolled back, unless the operator
                // says so.
                if !self.opts.adopt_existing && self.changed_since(kind, id, &mark).await? {
                    self.refuse(changed, id);
                    return Ok(false);
                }
            }
        }
        self.owned_set(kind).insert(id);
        Ok(true)
    }

    /// Whether the import owns `id`, or nothing of that id exists on this server at all.
    pub(super) async fn owns_or_absent(&mut self, kind: &'static str, id: Uuid) -> Res<bool> {
        if self.owns(kind, id).await? {
            return Ok(true);
        }
        Ok(!self.exists(kind, id).await?)
    }

    /// Writes the record that the import created `id`, unless there is one. Only the code that
    /// really inserts the user or space calls this: an id the pass merely names (a cipher of an
    /// organization whose row never comes) must not become the import's, or a space made later
    /// under that id would count as owned.
    pub(super) async fn remember(&self, kind: &str, id: Uuid) -> Res<()> {
        if !self.marked(kind, id).await? {
            self.mark(kind, id).await?;
        }
        Ok(())
    }

    /// Takes `id` for this pass if the import may have it: it owns it already, or nothing of
    /// that id exists yet, as a user or as a space (the two share `bw_docs` scopes and are never
    /// the same thing). The id is only held in memory until the row is created and
    /// [`Ctx::remember`] records it. An id that exists and isn't the import's is refused.
    pub(super) async fn claim(&mut self, kind: &'static str, id: Uuid) -> Res<bool> {
        if self.was_refused(kind, id) {
            return Ok(false);
        }
        if self.owns(kind, id).await? {
            return Ok(true);
        }
        if self.was_refused(changed_kind(kind), id) {
            return Ok(false);
        }
        let other = if kind == SPACE { USER } else { SPACE };
        if self.exists(kind, id).await? || self.exists(other, id).await? {
            self.refuse(kind, id);
            return Ok(false);
        }
        self.owned_set(kind).insert(id);
        Ok(true)
    }

    /// Whether the import may write the item `id` for `owner`: the owner is the import's (a space
    /// that doesn't exist yet is taken, as its row comes later in the pass), and an item of that id
    /// that already exists is the same owner's and not newer than `incoming`, the source's date.
    pub(super) async fn item_allowed(
        &mut self,
        id: Uuid,
        owner: Owner,
        incoming: OffsetDateTime,
    ) -> Res<bool> {
        let owner_ok = match owner {
            Owner::User(user) => self.owns(USER, user.0).await?,
            Owner::Space(space) => self.claim(SPACE, space.0).await?,
        };
        if !owner_ok {
            return Ok(false);
        }
        let (owner_type, owner_id) = item_rows::owner_parts(owner);
        let existing = item_rows::Entity::find_by_id(id)
            .one(&self.txn)
            .await
            .store()?;
        // An item the API revised after the source's own date is newer than what the source has.
        Ok(existing.is_none_or(|row| {
            row.owner_type == owner_type
                && row.owner_id == owner_id
                && (self.opts.adopt_existing || utc(row.updated_at) <= utc(incoming))
        }))
    }

    /// Whether the stored item `item` belongs to a user or space the import owns.
    pub(super) async fn item_owner_owned(&mut self, item: Uuid) -> Res<bool> {
        let Some(row) = item_rows::Entity::find_by_id(item)
            .one(&self.txn)
            .await
            .store()?
        else {
            return Ok(false);
        };
        match item_rows::owner_from(row.owner_type, row.owner_id)? {
            Owner::User(user) => self.owns(USER, user.0).await,
            Owner::Space(space) => self.owns(SPACE, space.0).await,
        }
    }

    /// Whether a file bound for storage under `storage_key` belongs to what the pass wrote: an
    /// attachment of an item the import owns, or the file of a Send row it kept.
    pub(super) async fn file_allowed(&mut self, storage_key: &str) -> Res<bool> {
        let mut parts = storage_key.split('/');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("sends"), Some(send), Some(_), None) => {
                Ok(rows::get_row(self, "sends", send).await?.is_some())
            }
            (Some("attachments"), Some(_), Some(attachment), None) => {
                let Some(row) = bw_attachments::Entity::find_by_id(attachment.to_owned())
                    .one(&self.txn)
                    .await
                    .store()?
                else {
                    return Ok(false);
                };
                if row.storage_key != storage_key {
                    return Ok(false);
                }
                self.item_owner_owned(row.item_id).await
            }
            _ => Ok(false),
        }
    }
}

/// The refused kind of a user or space the API changed since the import wrote it.
fn changed_kind(kind: &str) -> &'static str {
    if kind == SPACE {
        "space-changed"
    } else {
        "user-changed"
    }
}

/// At the end of a pass: records that the import has just written every user and space it owns in
/// it, and the revision date each account's Bitwarden record has now (after the pass moved it), so
/// that a change made later shows.
pub(super) async fn refresh_marks(ctx: &Ctx) -> Res<()> {
    let now = utc(ctx.opts.now);
    for user in &ctx.users {
        let revision = bw_accounts::Entity::find_by_id(*user)
            .one(&ctx.txn)
            .await
            .store()?
            .map(|record| record.revision_ms);
        vw_import_ids::Entity::update_many()
            .col_expr(vw_import_ids::Column::WrittenAt, Expr::value(now))
            .col_expr(vw_import_ids::Column::RevisionMs, Expr::value(revision))
            .filter(vw_import_ids::Column::Kind.eq(USER))
            .filter(vw_import_ids::Column::Id.eq(*user))
            .exec(&ctx.txn)
            .await
            .store()?;
    }
    for space in &ctx.spaces {
        vw_import_ids::Entity::update_many()
            .col_expr(vw_import_ids::Column::WrittenAt, Expr::value(now))
            .filter(vw_import_ids::Column::Kind.eq(SPACE))
            .filter(vw_import_ids::Column::Id.eq(*space))
            .exec(&ctx.txn)
            .await
            .store()?;
    }
    Ok(())
}

async fn user_ok(ctx: &mut Ctx, id: Option<Uuid>) -> Res<bool> {
    match id {
        Some(id) => ctx.owns(USER, id).await,
        None => Ok(false),
    }
}

async fn space_ok(ctx: &mut Ctx, id: Option<Uuid>) -> Res<bool> {
    match id {
        Some(id) => ctx.owns(SPACE, id).await,
        None => Ok(false),
    }
}

async fn collection_space(ctx: &Ctx, id: Option<Uuid>) -> Res<Option<Uuid>> {
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(collections::Entity::find_by_id(id)
        .one(&ctx.txn)
        .await
        .store()?
        .map(|c| c.space_id))
}

async fn group_space(ctx: &Ctx, id: Option<Uuid>) -> Res<Option<Uuid>> {
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(groups::Entity::find_by_id(id)
        .one(&ctx.txn)
        .await
        .store()?
        .map(|g| g.space_id))
}

/// The rows of a carried table the import may write; the others are remembered as refused.
pub(super) async fn admit(ctx: &mut Ctx, table: &Table) -> Res<Table> {
    let mut kept = Table::empty(table.spec());
    for row in table.rows() {
        if admit_row(ctx, table.name(), &row).await? {
            if let Some(cells) = table.cells(&row.key()) {
                kept.insert(cells.to_vec());
            }
        } else {
            ctx.refuse(table.name(), row.key_text());
        }
    }
    Ok(kept)
}

async fn admit_row(ctx: &mut Ctx, table: &str, row: &RowRef<'_>) -> Res<bool> {
    let id = |column: &str| row_uuid(row.text(column));
    match table {
        "devices" | "twofactor" | "sso_users" => user_ok(ctx, id("user_uuid")).await,
        "organizations" => match id("uuid") {
            Some(space) => ctx.claim(SPACE, space).await,
            None => Ok(false),
        },
        "users_organizations" => {
            Ok(space_ok(ctx, id("org_uuid")).await? && user_ok(ctx, id("user_uuid")).await?)
        }
        "org_policies" | "organization_api_key" => space_ok(ctx, id("org_uuid")).await,
        "collections" => {
            let space = id("org_uuid");
            if !space_ok(ctx, space).await? {
                return Ok(false);
            }
            // A collection of that id that is in another space isn't the import's to move.
            Ok(collection_space(ctx, id("uuid"))
                .await?
                .is_none_or(|existing| Some(existing) == space))
        }
        "groups" => {
            let space = id("organizations_uuid");
            if !space_ok(ctx, space).await? {
                return Ok(false);
            }
            Ok(group_space(ctx, id("uuid"))
                .await?
                .is_none_or(|existing| Some(existing) == space))
        }
        "ciphers_collections" => {
            let Some(cipher) = id("cipher_uuid") else {
                return Ok(false);
            };
            let Some(item) = item_rows::Entity::find_by_id(cipher)
                .one(&ctx.txn)
                .await
                .store()?
            else {
                return Ok(false);
            };
            if item.owner_type != i16::from(Owner::TYPE_SPACE)
                || !ctx.owns(SPACE, item.owner_id).await?
            {
                return Ok(false);
            }
            // Its collection, when it is stored, is in the same space.
            Ok(collection_space(ctx, id("collection_uuid"))
                .await?
                .is_none_or(|space| space == item.owner_id))
        }
        "users_collections" => {
            if !user_ok(ctx, id("user_uuid")).await? {
                return Ok(false);
            }
            let space = collection_space(ctx, id("collection_uuid")).await?;
            space_ok(ctx, space).await
        }
        "collections_groups" => {
            let collection = collection_space(ctx, id("collections_uuid")).await?;
            let group = group_space(ctx, id("groups_uuid")).await?;
            Ok(space_ok(ctx, collection).await? && space_ok(ctx, group).await?)
        }
        "groups_users" => {
            let group = group_space(ctx, id("groups_uuid")).await?;
            if !space_ok(ctx, group).await? {
                return Ok(false);
            }
            let Some(membership) = row.text("users_organizations_uuid") else {
                return Ok(false);
            };
            let user = super::orgs::member_of(ctx, membership).await?;
            user_ok(ctx, user).await
        }
        "emergency_access" => {
            let (Some(grant), Some(grantor)) = (id("uuid"), id("grantor_uuid")) else {
                return Ok(false);
            };
            if !ctx.owns(USER, grantor).await? {
                return Ok(false);
            }
            let existing = emergency_access::Entity::find_by_id(grant)
                .one(&ctx.txn)
                .await
                .store()?;
            Ok(existing.is_none_or(|e| e.grantor_id == grantor))
        }
        "sends" => {
            let Some(send) = id("uuid") else {
                return Ok(false);
            };
            let owned = match (id("user_uuid"), id("organization_uuid")) {
                (Some(user), _) => ctx.owns(USER, user).await?,
                (None, Some(space)) => ctx.owns(SPACE, space).await?,
                (None, None) => false,
            };
            // Not an id of a Send this server keeps itself, nor of another owner's kept row.
            if !owned
                || sends::Entity::find_by_id(send)
                    .one(&ctx.txn)
                    .await
                    .store()?
                    .is_some()
            {
                return Ok(false);
            }
            Ok(match rows::get_row(ctx, "sends", &row.key_text()).await? {
                Some(kept) => {
                    rows::text(&kept, "user_uuid") == row.text("user_uuid")
                        && rows::text(&kept, "organization_uuid") == row.text("organization_uuid")
                }
                None => true,
            })
        }
        "event" => {
            // History names accounts and spaces Vaultwarden has since deleted, which is kept. It
            // is refused only when it names one this server has that isn't the import's.
            for column in ["act_user_uuid", "user_uuid"] {
                if let Some(user) = id(column)
                    && !ctx.owns_or_absent(USER, user).await?
                {
                    return Ok(false);
                }
            }
            match id("org_uuid") {
                Some(space) => ctx.owns_or_absent(SPACE, space).await,
                None => Ok(true),
            }
        }
        // Invitations hold an address and nothing else, and are only kept.
        "invitations" => Ok(true),
        _ => Ok(false),
    }
}

/// Whether the import may delete the Vaultwarden row `table`/`key` that a second pass learned
/// is gone: only what it owns. Rows that only hang off another (a grant, a link between a cipher
/// and a collection) are held to the owner of what they hang off.
pub(super) async fn delete_allowed(ctx: &mut Ctx, table: &str, key: &[String]) -> Res<bool> {
    let first = row_uuid(key.first().map(String::as_str));
    let second = row_uuid(key.get(1).map(String::as_str));
    match table {
        "users" => match first {
            Some(user) => ctx.owns(USER, user).await,
            None => Ok(true),
        },
        "organizations" => match first {
            Some(space) => ctx.owns(SPACE, space).await,
            None => Ok(true),
        },
        "devices" => {
            let Some(id) = first else {
                return Ok(true);
            };
            let Some(device) = devices::Entity::find_by_id(id)
                .one(&ctx.txn)
                .await
                .store()?
            else {
                return Ok(true);
            };
            ctx.owns(USER, device.user_id).await
        }
        // Attachment ids are not UUIDs.
        "attachments" => {
            let Some(id) = key.first() else {
                return Ok(true);
            };
            let Some(row) = bw_attachments::Entity::find_by_id(id.clone())
                .one(&ctx.txn)
                .await
                .store()?
            else {
                return Ok(true);
            };
            ctx.item_owner_owned(row.item_id).await
        }
        // [cipher, collection]: the cipher's owner.
        "ciphers" | "folders" | "ciphers_collections" => {
            let Some(id) = first else {
                return Ok(true);
            };
            let item = item_rows::Entity::find_by_id(id)
                .one(&ctx.txn)
                .await
                .store()?;
            match item {
                Some(_) => ctx.item_owner_owned(id).await,
                None => Ok(true),
            }
        }
        "collections" => collection_owned(ctx, first).await,
        "groups" => group_owned(ctx, first).await,
        // [user, collection], [collection, group] and [group, membership]: the space they are in.
        "users_collections" => collection_owned(ctx, second).await,
        "collections_groups" => {
            Ok(collection_owned(ctx, first).await? && group_owned(ctx, second).await?)
        }
        "groups_users" => group_owned(ctx, first).await,
        // The stored row names the user, and for a membership the organization too: dropping it
        // takes a two-step setup from an account, or a person out of a space, so the import may
        // only do it for what it owns. A row that isn't stored has nothing to drop.
        "twofactor" | "users_organizations" => {
            let Some(row) = rows::get_row(ctx, table, &rows::key_text(key)).await? else {
                return Ok(true);
            };
            let user = user_ok(ctx, row_uuid(rows::text(&row, "user_uuid"))).await?;
            if table == "twofactor" {
                return Ok(user);
            }
            Ok(user && space_ok(ctx, row_uuid(rows::text(&row, "org_uuid"))).await?)
        }
        "emergency_access" => {
            let Some(id) = first else {
                return Ok(true);
            };
            let grant = emergency_access::Entity::find_by_id(id)
                .one(&ctx.txn)
                .await
                .store()?;
            match grant {
                Some(grant) => ctx.owns(USER, grant.grantor_id).await,
                None => Ok(true),
            }
        }
        _ => Ok(true),
    }
}

/// Whether the collection `id` is in a space the import owns; one that isn't stored is nobody's.
async fn collection_owned(ctx: &mut Ctx, id: Option<Uuid>) -> Res<bool> {
    match collection_space(ctx, id).await? {
        Some(space) => ctx.owns(SPACE, space).await,
        None => Ok(true),
    }
}

/// Whether the group `id` is in a space the import owns; one that isn't stored is nobody's.
async fn group_owned(ctx: &mut Ctx, id: Option<Uuid>) -> Res<bool> {
    match group_space(ctx, id).await? {
        Some(space) => ctx.owns(SPACE, space).await,
        None => Ok(true),
    }
}
