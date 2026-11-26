//! Organizations as spaces (members, collections, groups, grants), emergency access, events and
//! settings.
//!
//! An organization's keys are Vaultwarden's, kept as stored: a member's `akey` (the organization
//! key wrapped for them) becomes the member's sealed space key without being opened, and names
//! stay as the plain text Vaultwarden keeps them in. They are opaque to the Kemlock side until
//! someone sets the space up there.

use super::rows::{self, row_time, row_uuid};
use super::scope::SPACE;
use super::vault::owner_of;
use super::{Ctx, Res};
use crate::convert::utc;
use crate::error::StoreResult;
use crate::tables::space_tables::{
    collection_grants, collections, group_members, groups, item_collections, members, spaces,
};
use crate::tables::{emergency_access, events, settings, users};
use kemlock_domain::{Email, Owner};
use kemlock_vaultwarden::settings::MappedSettings;
use kemlock_vaultwarden::snapshot::Table;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

/// The `vw_rows` table of a Vaultwarden table whose rows say which user a membership is.
const MEMBERSHIPS: &str = "users_organizations";

pub(super) async fn put_organizations(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let Some(id) = row_uuid(row.text("uuid")) else {
            continue;
        };
        let name = row.text("name").unwrap_or_default().as_bytes().to_vec();
        let existing = spaces::Entity::find_by_id(id).one(txn).await.store()?;
        match existing {
            Some(space) if space.name == name => {}
            Some(_) => {
                spaces::Entity::update_many()
                    .set(spaces::ActiveModel {
                        id: NotSet,
                        name: Set(name),
                        key_version: NotSet,
                        keys_pending_since: NotSet,
                        created_at: NotSet,
                        updated_at: Set(utc(ctx.opts.now)),
                    })
                    .filter(spaces::Column::Id.eq(id))
                    .exec(txn)
                    .await
                    .store()?;
            }
            None => {
                spaces::Entity::insert(spaces::ActiveModel {
                    id: Set(id),
                    name: Set(name),
                    key_version: Set(0),
                    keys_pending_since: Set(None),
                    created_at: Set(utc(ctx.opts.now)),
                    updated_at: Set(utc(ctx.opts.now)),
                })
                .exec(txn)
                .await
                .store()?;
                // Now that the space exists, it is the import's from here on.
                ctx.remember(SPACE, id).await?;
            }
        }
    }
    Ok(())
}

/// Vaultwarden's member types: owner (0), admin (1), user (2) and manager (3). A manager has no
/// permissions of its own here, only what its collections grant.
fn role_of(atype: i64) -> &'static str {
    match atype {
        0 => "owner",
        1 => "admin",
        3 => "custom",
        _ => "member",
    }
}

/// Vaultwarden's member statuses: revoked (-1), invited (0), accepted (1) and confirmed (2).
fn state_of(status: i64) -> &'static str {
    match status {
        s if s < 0 => "revoked",
        0 => "invited",
        1 => "accepted",
        _ => "confirmed",
    }
}

pub(super) async fn put_members(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let (Some(user), Some(space)) = (
            row_uuid(row.text("user_uuid")),
            row_uuid(row.text("org_uuid")),
        ) else {
            continue;
        };
        let status = row.int("status").unwrap_or(0);
        let inviter = match row.text("invited_by_email") {
            Some(email) => users::Entity::find()
                .filter(users::Column::Email.eq(email.trim().to_lowercase()))
                .one(txn)
                .await
                .store()?
                .map(|u| u.id),
            None => None,
        };
        let existing = members::Entity::find_by_id((space, user))
            .one(txn)
            .await
            .store()?;
        let invited_at = existing.map_or(utc(ctx.opts.now), |m| m.invited_at);
        let sealed = row
            .text("akey")
            .filter(|key| !key.is_empty())
            .map(|key| key.as_bytes().to_vec());
        let key_version = sealed.as_ref().map(|_| 0_i64);

        members::Entity::delete_many()
            .filter(members::Column::SpaceId.eq(space))
            .filter(members::Column::UserId.eq(user))
            .exec(txn)
            .await
            .store()?;
        members::Entity::insert(members::ActiveModel {
            space_id: Set(space),
            user_id: Set(user),
            role: Set(role_of(row.int("atype").unwrap_or(2)).to_owned()),
            custom_permissions: Set(0),
            state: Set(state_of(status).to_owned()),
            invited_by: Set(inviter.unwrap_or(user)),
            invited_at: Set(invited_at),
            accepted_at: Set((status >= 1).then_some(invited_at)),
            sealed_space_key: Set(sealed),
            key_version: Set(key_version),
            revoked_at: Set((status < 0).then_some(utc(ctx.opts.now))),
            confirmed_by: Set(None),
            confirmed_at: Set(None),
            confirmed_fingerprint: Set(None),
            confirmed_key_version: Set(None),
            confirmation_statement: Set(None),
            confirmation_signature: Set(None),
        })
        .exec(txn)
        .await
        .store()?;
    }
    Ok(())
}

pub(super) async fn put_collections(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let (Some(id), Some(space)) = (row_uuid(row.text("uuid")), row_uuid(row.text("org_uuid")))
        else {
            continue;
        };
        let existing = collections::Entity::find_by_id(id).one(txn).await.store()?;
        let created = existing
            .as_ref()
            .map_or(utc(ctx.opts.now), |c| c.created_at);
        let key_version = existing.as_ref().map_or(0, |c| c.key_version);
        collections::Entity::delete_many()
            .filter(collections::Column::Id.eq(id))
            .exec(txn)
            .await
            .store()?;
        collections::Entity::insert(collections::ActiveModel {
            id: Set(id),
            space_id: Set(space),
            parent_id: Set(None),
            name: Set(row.text("name").unwrap_or_default().as_bytes().to_vec()),
            key_version: Set(key_version),
            stale_since: Set(None),
            created_at: Set(created),
        })
        .exec(txn)
        .await
        .store()?;
    }
    Ok(())
}

pub(super) async fn put_groups(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let (Some(id), Some(space)) = (
            row_uuid(row.text("uuid")),
            row_uuid(row.text("organizations_uuid")),
        ) else {
            continue;
        };
        let created = row_time(row.text("creation_date")).unwrap_or(ctx.opts.now);
        groups::Entity::delete_many()
            .filter(groups::Column::Id.eq(id))
            .exec(txn)
            .await
            .store()?;
        groups::Entity::insert(groups::ActiveModel {
            id: Set(id),
            space_id: Set(space),
            name: Set(row.text("name").unwrap_or_default().as_bytes().to_vec()),
            created_at: Set(utc(created)),
        })
        .exec(txn)
        .await
        .store()?;
    }
    Ok(())
}

/// The user a membership row of `users_organizations` is for, from the rows kept in `vw_rows`.
pub(super) async fn member_of(ctx: &Ctx, membership: &str) -> Res<Option<Uuid>> {
    let row = rows::get_row(ctx, MEMBERSHIPS, membership).await?;
    Ok(row.and_then(|r| row_uuid(rows::text(&r, "user_uuid"))))
}

pub(super) async fn put_group_members(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let (Some(group), Some(membership)) = (
            row_uuid(row.text("groups_uuid")),
            row.text("users_organizations_uuid"),
        ) else {
            continue;
        };
        let Some(user) = member_of(ctx, membership).await? else {
            continue;
        };
        group_members::Entity::delete_many()
            .filter(group_members::Column::GroupId.eq(group))
            .filter(group_members::Column::UserId.eq(user))
            .exec(txn)
            .await
            .store()?;
        group_members::Entity::insert(group_members::ActiveModel {
            group_id: Set(group),
            user_id: Set(user),
        })
        .exec(txn)
        .await
        .store()?;
    }
    Ok(())
}

/// What a collection grant's flags mean here: `manage`, or view or edit, each with or without
/// hidden passwords.
fn permission_of(read_only: bool, hide_passwords: bool, manage: bool) -> &'static str {
    if manage {
        "manage"
    } else if read_only {
        if hide_passwords {
            "view-hide-passwords"
        } else {
            "view"
        }
    } else if hide_passwords {
        "edit-hide-passwords"
    } else {
        "edit"
    }
}

async fn put_grant(
    ctx: &Ctx,
    collection: Uuid,
    grantee_type: i16,
    grantee: Uuid,
    permission: &str,
) -> Res<()> {
    collection_grants::Entity::delete_many()
        .filter(collection_grants::Column::CollectionId.eq(collection))
        .filter(collection_grants::Column::GranteeType.eq(grantee_type))
        .filter(collection_grants::Column::GranteeId.eq(grantee))
        .exec(&ctx.txn)
        .await
        .store()?;
    collection_grants::Entity::insert(collection_grants::ActiveModel {
        collection_id: Set(collection),
        grantee_type: Set(grantee_type),
        grantee_id: Set(grantee),
        permission: Set(permission.to_owned()),
    })
    .exec(&ctx.txn)
    .await
    .store()?;
    Ok(())
}

pub(super) async fn put_member_grants(ctx: &Ctx, table: &Table) -> Res<()> {
    for row in table.rows() {
        let (Some(user), Some(collection)) = (
            row_uuid(row.text("user_uuid")),
            row_uuid(row.text("collection_uuid")),
        ) else {
            continue;
        };
        let permission = permission_of(
            row.bool("read_only").unwrap_or(false),
            row.bool("hide_passwords").unwrap_or(false),
            row.bool("manage").unwrap_or(false),
        );
        put_grant(
            ctx,
            collection,
            collection_grants::GRANTEE_MEMBER,
            user,
            permission,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn put_group_grants(ctx: &Ctx, table: &Table) -> Res<()> {
    for row in table.rows() {
        let (Some(collection), Some(group)) = (
            row_uuid(row.text("collections_uuid")),
            row_uuid(row.text("groups_uuid")),
        ) else {
            continue;
        };
        let permission = permission_of(
            row.bool("read_only").unwrap_or(false),
            row.bool("hide_passwords").unwrap_or(false),
            row.bool("manage").unwrap_or(false),
        );
        put_grant(
            ctx,
            collection,
            collection_grants::GRANTEE_GROUP,
            group,
            permission,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn put_item_collections(ctx: &Ctx, table: &Table) -> Res<()> {
    let ciphers: BTreeSet<Uuid> = table
        .rows()
        .filter_map(|row| row_uuid(row.text("cipher_uuid")))
        .collect();
    for cipher in ciphers {
        reconcile_item_collection(ctx, cipher).await?;
    }
    Ok(())
}

/// Makes the collection of a space's item the first of the collections Vaultwarden has it in. A
/// space item is in one collection here; the others stay in `vw_rows` (`ciphers_collections`).
pub(super) async fn reconcile_item_collection(ctx: &Ctx, cipher: Uuid) -> Res<()> {
    let found = rows::rows_with_prefix(ctx, "ciphers_collections", &format!("{cipher}/")).await?;
    let mut collections: Vec<Uuid> = found
        .iter()
        .filter_map(|(_, row)| row_uuid(rows::text(row, "collection_uuid")))
        .collect();
    collections.sort();
    item_collections::Entity::delete_many()
        .filter(item_collections::Column::ItemId.eq(cipher))
        .exec(&ctx.txn)
        .await
        .store()?;
    let Some(collection) = collections.first().copied() else {
        return Ok(());
    };
    let Some(Owner::Space(space)) = owner_of(ctx, cipher).await? else {
        return Ok(());
    };
    item_collections::Entity::insert(item_collections::ActiveModel {
        item_id: Set(cipher),
        space_id: Set(space.0),
        collection_id: Set(collection),
    })
    .exec(&ctx.txn)
    .await
    .store()?;
    Ok(())
}

pub(super) async fn put_emergency_access(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    for row in table.rows() {
        let (Some(id), Some(grantor)) = (
            row_uuid(row.text("uuid")),
            row_uuid(row.text("grantor_uuid")),
        ) else {
            continue;
        };
        if users::Entity::find_by_id(grantor)
            .one(txn)
            .await
            .store()?
            .is_none()
        {
            continue;
        }
        let grantee = match row_uuid(row.text("grantee_uuid")) {
            Some(user) => users::Entity::find_by_id(user).one(txn).await.store()?,
            None => None,
        };
        let email = row
            .text("email")
            .map(str::to_owned)
            .or_else(|| grantee.as_ref().map(|u| u.email.clone()));
        let Some(email) = email.and_then(|e| Email::parse(&e).ok()) else {
            continue;
        };
        let kind = if row.int("atype") == Some(1) {
            "takeover"
        } else {
            "view"
        };
        let state = match row.int("status") {
            Some(1) => "accepted",
            Some(2) => "confirmed",
            Some(3) => "recovery-initiated",
            Some(4) => "approved",
            _ => "invited",
        };
        let created = row_time(row.text("created_at")).unwrap_or(ctx.opts.now);
        let updated = row_time(row.text("updated_at")).unwrap_or(created);

        // One grant per grantor and contact.
        emergency_access::Entity::delete_many()
            .filter(emergency_access::Column::Id.eq(id))
            .exec(txn)
            .await
            .store()?;
        emergency_access::Entity::delete_many()
            .filter(emergency_access::Column::GrantorId.eq(grantor))
            .filter(emergency_access::Column::GranteeEmail.eq(email.as_str()))
            .exec(txn)
            .await
            .store()?;
        emergency_access::Entity::insert(emergency_access::ActiveModel {
            id: Set(id),
            grantor_id: Set(grantor),
            grantee_email: Set(email.as_str().to_owned()),
            grantee_id: Set(grantee.map(|u| u.id)),
            kind: Set(kind.to_owned()),
            wait_days: Set(row.int("wait_time_days").unwrap_or(0).max(0)),
            state: Set(state.to_owned()),
            sealed_key: Set(row
                .text("key_encrypted")
                .filter(|key| !key.is_empty())
                .map(|key| key.as_bytes().to_vec())),
            recovery_initiated_at: Set(row_time(row.text("recovery_initiated_at")).map(utc)),
            created_at: Set(utc(created)),
            updated_at: Set(utc(updated)),
        })
        .exec(txn)
        .await
        .store()?;
    }
    Ok(())
}

/// The columns of a Vaultwarden event that name what it was about, most specific first.
const EVENT_TARGETS: [&str; 6] = [
    "cipher_uuid",
    "collection_uuid",
    "group_uuid",
    "org_user_uuid",
    "policy_uuid",
    "org_uuid",
];

/// Events are kept under the id Vaultwarden gave them, as `vw-event-<type>`, unless they are older
/// than the retention window.
pub(super) async fn put_events(ctx: &Ctx, table: &Table) -> Res<()> {
    let txn = &ctx.txn;
    let cutoff = ctx
        .opts
        .events_retention_days
        .map(|days| ctx.opts.now - time::Duration::days(days));
    for row in table.rows() {
        let Some(id) = row_uuid(row.text("uuid")) else {
            continue;
        };
        let at = row_time(row.text("event_date")).unwrap_or(ctx.opts.now);
        if cutoff.is_some_and(|cutoff| at < cutoff) {
            continue;
        }
        // An event never changes, so one that is stored stays.
        if events::Entity::find_by_id(id)
            .one(txn)
            .await
            .store()?
            .is_some()
        {
            continue;
        }
        let actor = row_uuid(row.text("act_user_uuid")).or_else(|| row_uuid(row.text("user_uuid")));
        let target = EVENT_TARGETS
            .iter()
            .find_map(|column| row.text(column))
            .map(str::to_owned);
        events::Entity::insert(events::ActiveModel {
            // Vaultwarden kept only a truncated address, which this import doesn't carry.
            ip: Set(None),
            ip_full: Set(None),
            id: Set(id),
            actor: Set(actor),
            device: Set(None),
            action: Set(format!("vw-event-{}", row.int("event_type").unwrap_or(0))),
            target: Set(target),
            at: Set(utc(at)),
        })
        .exec(txn)
        .await
        .store()?;
    }
    Ok(())
}

/// `config.json` settings, under their Vaultwarden names: a string as it is, anything else as
/// JSON text. Only the names of the admin settings registry are kept, and never a secret (those
/// are sealed elsewhere): a `config.json` can't make this write any other row of `settings`,
/// which also holds the move's own status and the server's markers.
pub(super) async fn put_settings(ctx: &mut Ctx, mapped: &MappedSettings) -> Res<()> {
    for (name, value) in &mapped.values {
        if !is_registered(name) {
            ctx.refuse("setting", name);
            continue;
        }
        let text = match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        settings::Entity::delete_by_id(name.clone())
            .exec(&ctx.txn)
            .await
            .store()?;
        settings::Entity::insert(settings::ActiveModel {
            key: Set(name.clone()),
            value: Set(text),
        })
        .exec(&ctx.txn)
        .await
        .store()?;
    }
    Ok(())
}

/// Whether `name` is a setting the admin console has (and not a secret one).
fn is_registered(name: &str) -> bool {
    kemlock_app::admin::settings::definition(name)
        .is_some_and(|d| d.kind != kemlock_app::admin::settings::Kind::Secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_registered_settings_are_kept() {
        assert!(is_registered("signups_allowed"));
        assert!(is_registered("smtp_host"));
        assert!(!is_registered("smtp_password"), "a secret is sealed elsewhere");
        assert!(!is_registered("domain"));
        assert!(!is_registered("migration.status"));
        assert!(!is_registered("setting.signups_allowed"));
        assert!(!is_registered(""));
    }

    #[test]
    fn member_types_and_statuses_map_to_roles_and_states() {
        assert_eq!(role_of(0), "owner");
        assert_eq!(role_of(1), "admin");
        assert_eq!(role_of(2), "member");
        assert_eq!(role_of(3), "custom");
        assert_eq!(role_of(99), "member");
        assert_eq!(state_of(-1), "revoked");
        assert_eq!(state_of(0), "invited");
        assert_eq!(state_of(1), "accepted");
        assert_eq!(state_of(2), "confirmed");
    }

    #[test]
    fn grant_flags_map_to_permissions() {
        assert_eq!(permission_of(false, false, false), "edit");
        assert_eq!(permission_of(false, true, false), "edit-hide-passwords");
        assert_eq!(permission_of(true, false, false), "view");
        assert_eq!(permission_of(true, true, false), "view-hide-passwords");
        assert_eq!(permission_of(true, true, true), "manage");
    }
}
