//! The documents the Bitwarden API reads an organization from, made from the Vaultwarden rows the
//! import keeps in `vw_rows`.
//!
//! The space tables hold what Kemlock's own rules need (members with a role and a state, grants,
//! the first collection of an item). The Bitwarden API serves an organization from `bw_docs` on
//! top of them (see `kemlock-api-bw`'s `orgs::model`): the organization's key pair, each member's
//! wrapped key and access flags, external ids, policies, the API key, every collection an item is
//! in, and each member's own folder, favourite and archive of an organization cipher. Without
//! them an imported space is not an organization to a Bitwarden app. The shapes are the API's, so
//! a change to one there is a change here.
//!
//! [`sync`] writes them all from the rows at the end of a pass; the other functions follow the
//! rows a second pass deletes. A pass only writes the documents of rows Vaultwarden still has, and
//! never over one the API has changed since: it keeps the text it wrote of each (`imported_docs` in
//! `vw_rows`) and writes a document again only when it is still that text.

use super::rows::{self, row_uuid};
use super::{Ctx, Res};
use crate::error::StoreResult;
use crate::repo::policies::upsert_require_sso_in;
use crate::tables::bw_docs;
use kemlock_domain::SpaceId;
use kemlock_vaultwarden::vwtime::{format_date, parse_db_time};
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

const KIND_ORG: &str = "org";
const KIND_MEMBER: &str = "member";
const KIND_COLLECTION: &str = "collection";
const KIND_GROUP: &str = "group";
const KIND_POLICY: &str = "policy";
/// Bitwarden's number of the Require single sign-on policy, which `space_policy_settings` keeps.
const REQUIRE_SSO: i64 = 4;
const KIND_API_KEY: &str = "apikey";
/// Scope: the organization; key: a cipher id; body: the ids of its collections.
const KIND_LINKS: &str = "cc";
/// Scope: an account; key: a cipher id; body: that account's folder, favourite and archive.
const KIND_PREFS: &str = "orgpref";

/// What the API prints for a date Vaultwarden had none of.
const NO_DATE: &str = "1970-01-01T00:00:00.000000Z";

fn flag(row: &Value, column: &str) -> bool {
    row.get(column)
        .and_then(Value::as_i64)
        .is_some_and(|n| n != 0)
}

fn number(row: &Value, column: &str, default: i64) -> i64 {
    row.get(column).and_then(Value::as_i64).unwrap_or(default)
}

fn text<'a>(row: &'a Value, column: &str) -> Option<&'a str> {
    rows::text(row, column).filter(|t| !t.is_empty())
}

/// A date column as the API prints dates.
fn date(row: &Value, column: &str) -> String {
    rows::text(row, column)
        .and_then(parse_db_time)
        .map_or_else(|| NO_DATE.to_owned(), format_date)
}

/// The `vw_rows` table that remembers the text of each document the import wrote, to tell a
/// document the API has changed since from one nobody has touched.
const RECORDS: &str = "imported_docs";

fn record_key(scope: Uuid, kind: &str, key: &str) -> String {
    format!("{scope}/{kind}/{key}")
}

async fn current(ctx: &Ctx, scope: Uuid, kind: &str, key: &str) -> Res<Option<String>> {
    Ok(
        bw_docs::Entity::find_by_id((scope, kind.to_owned(), key.to_owned()))
            .one(&ctx.txn)
            .await
            .store()?
            .map(|row| row.body),
    )
}

/// Writes a document of the import, unless the API has changed it since a pass wrote it: a
/// document is written when there is none and no pass wrote one (a pass that wrote one and finds
/// it gone has been told by the API that it is), or when it is as the last pass left it. One the
/// API made itself has no record and stays.
async fn put_doc(ctx: &Ctx, scope: Uuid, kind: &str, key: &str, body: &Value) -> Res<()> {
    let text = body.to_string();
    let record = record_key(scope, kind, key);
    let now = current(ctx, scope, kind, key).await?;
    let written = rows::get_row(ctx, RECORDS, &record)
        .await?
        .and_then(|row| rows::text(&row, "body").map(str::to_owned));
    let free = match (&now, &written) {
        (None, None) => true,
        (Some(now), Some(written)) => now == written,
        _ => false,
    };
    if !free {
        return Ok(());
    }
    drop_doc(ctx, scope, kind, key).await?;
    bw_docs::Entity::insert(bw_docs::ActiveModel {
        scope: Set(scope),
        kind: Set(kind.to_owned()),
        doc_key: Set(key.to_owned()),
        body: Set(text.clone()),
    })
    .exec(&ctx.txn)
    .await
    .store()?;
    rows::put_row(ctx, RECORDS, &record, &json!({ "body": text }), false).await
}

/// Sets Require SSO in `space_policy_settings` to what the organization's policy document of that
/// type says now (the one a pass wrote, or the API's own if it changed it since).
async fn sync_require_sso(ctx: &Ctx, org: Uuid) -> Res<()> {
    let enabled = current(ctx, org, KIND_POLICY, &REQUIRE_SSO.to_string())
        .await?
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|doc| doc.get("enabled").and_then(Value::as_bool))
        .unwrap_or(false);
    upsert_require_sso_in(&ctx.txn, SpaceId(org), enabled).await
}

async fn drop_doc(ctx: &Ctx, scope: Uuid, kind: &str, key: &str) -> Res<()> {
    bw_docs::Entity::delete_many()
        .filter(bw_docs::Column::Scope.eq(scope))
        .filter(bw_docs::Column::Kind.eq(kind))
        .filter(bw_docs::Column::DocKey.eq(key))
        .exec(&ctx.txn)
        .await
        .store()?;
    Ok(())
}

/// Removes a document Vaultwarden no longer has a row for, and the note of having written it.
async fn delete_doc(ctx: &Ctx, scope: Uuid, kind: &str, key: &str) -> Res<()> {
    drop_doc(ctx, scope, kind, key).await?;
    rows::delete_row(ctx, RECORDS, &record_key(scope, kind, key)).await
}

/// Removes the documents of a kind and key in every scope.
async fn delete_named(ctx: &Ctx, kind: &str, key: &str) -> Res<()> {
    bw_docs::Entity::delete_many()
        .filter(bw_docs::Column::Kind.eq(kind))
        .filter(bw_docs::Column::DocKey.eq(key))
        .exec(&ctx.txn)
        .await
        .store()?;
    for (record, _) in rows::rows_with_suffix(ctx, RECORDS, &format!("/{kind}/{key}")).await? {
        rows::delete_row(ctx, RECORDS, &record).await?;
    }
    Ok(())
}

/// Writes the documents of every organization, member, collection, group, policy and API key the
/// rows hold, and the collections of every item that is in some.
pub(super) async fn sync(ctx: &Ctx) -> Res<()> {
    for (_, row) in rows::all_rows(ctx, "organizations").await? {
        let Some(org) = row_uuid(rows::text(&row, "uuid")) else {
            continue;
        };
        let body = json!({
            "billingEmail": rows::text(&row, "billing_email").unwrap_or_default(),
            "privateKey": text(&row, "private_key"),
            "publicKey": text(&row, "public_key"),
        });
        put_doc(ctx, org, KIND_ORG, "", &body).await?;
    }
    for (_, row) in rows::all_rows(ctx, "users_organizations").await? {
        let (Some(org), Some(user)) = (
            row_uuid(rows::text(&row, "org_uuid")),
            row_uuid(rows::text(&row, "user_uuid")),
        ) else {
            continue;
        };
        let body = json!({
            "akey": rows::text(&row, "akey").unwrap_or_default(),
            "accessAll": flag(&row, "access_all"),
            "atype": number(&row, "atype", 2),
            "status": number(&row, "status", 0),
            "resetPasswordKey": text(&row, "reset_password_key"),
            "externalId": text(&row, "external_id"),
            "invitedByEmail": text(&row, "invited_by_email"),
        });
        put_doc(ctx, org, KIND_MEMBER, &user.to_string(), &body).await?;
    }
    for (_, row) in rows::all_rows(ctx, "collections").await? {
        let (Some(org), Some(id)) = (
            row_uuid(rows::text(&row, "org_uuid")),
            row_uuid(rows::text(&row, "uuid")),
        ) else {
            continue;
        };
        let body = json!({ "externalId": text(&row, "external_id") });
        put_doc(ctx, org, KIND_COLLECTION, &id.to_string(), &body).await?;
    }
    for (_, row) in rows::all_rows(ctx, "groups").await? {
        let (Some(org), Some(id)) = (
            row_uuid(rows::text(&row, "organizations_uuid")),
            row_uuid(rows::text(&row, "uuid")),
        ) else {
            continue;
        };
        let body = json!({
            "accessAll": flag(&row, "access_all"),
            "externalId": text(&row, "external_id"),
        });
        put_doc(ctx, org, KIND_GROUP, &id.to_string(), &body).await?;
    }
    for (_, row) in rows::all_rows(ctx, "org_policies").await? {
        let Some(org) = row_uuid(rows::text(&row, "org_uuid")) else {
            continue;
        };
        let body = json!({
            "id": rows::text(&row, "uuid").unwrap_or_default(),
            "enabled": flag(&row, "enabled"),
            "data": text(&row, "data").unwrap_or("null"),
            "revisionDate": date(&row, "revision_date"),
        });
        put_doc(
            ctx,
            org,
            KIND_POLICY,
            &number(&row, "atype", 0).to_string(),
            &body,
        )
        .await?;
        if number(&row, "atype", 0) == REQUIRE_SSO {
            sync_require_sso(ctx, org).await?;
        }
    }
    for (_, row) in rows::all_rows(ctx, "organization_api_key").await? {
        let Some(org) = row_uuid(rows::text(&row, "org_uuid")) else {
            continue;
        };
        let body = json!({
            "id": rows::text(&row, "uuid").unwrap_or_default(),
            "apiKey": rows::text(&row, "api_key").unwrap_or_default(),
            "atype": number(&row, "atype", 0),
            "revisionDate": date(&row, "revision_date"),
        });
        put_doc(ctx, org, KIND_API_KEY, "", &body).await?;
    }
    let linked: BTreeSet<Uuid> = rows::all_rows(ctx, "ciphers_collections")
        .await?
        .iter()
        .filter_map(|(_, row)| row_uuid(rows::text(row, "cipher_uuid")))
        .collect();
    for cipher in linked {
        sync_links(ctx, cipher).await?;
    }
    Ok(())
}

/// Makes the collections a cipher is in, all of them, what its `cc` document says: the space
/// tables keep one, but a Bitwarden app shows and edits every one.
pub(super) async fn sync_links(ctx: &Ctx, cipher: Uuid) -> Res<()> {
    let found = rows::rows_with_prefix(ctx, "ciphers_collections", &format!("{cipher}/")).await?;
    let mut collections: Vec<Uuid> = found
        .iter()
        .filter_map(|(_, row)| row_uuid(rows::text(row, "collection_uuid")))
        .collect();
    collections.sort();
    let mut org = None;
    for collection in &collections {
        let row = rows::get_row(ctx, "collections", &collection.to_string()).await?;
        org = row.and_then(|r| row_uuid(rows::text(&r, "org_uuid")));
        if org.is_some() {
            break;
        }
    }
    let key = cipher.to_string();
    match org {
        Some(org) if !collections.is_empty() => {
            let ids: Vec<String> = collections.iter().map(ToString::to_string).collect();
            put_doc(ctx, org, KIND_LINKS, &key, &json!(ids)).await
        }
        _ => delete_named(ctx, KIND_LINKS, &key).await,
    }
}

/// Makes what a user keeps for an organization cipher (the `cipher_states` row) the user's
/// `orgpref` document, or removes the document when there is no state.
pub(super) async fn sync_pref(ctx: &Ctx, user: Uuid, cipher: Uuid) -> Res<()> {
    let key = cipher.to_string();
    let state = rows::get_row(
        ctx,
        super::vault::CIPHER_STATES,
        &super::vault::cipher_state_key(user, cipher),
    )
    .await?;
    let Some(state) = state else {
        return delete_doc(ctx, user, KIND_PREFS, &key).await;
    };
    let archived = rows::text(&state, "archived_at")
        .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
        .map(|t| {
            let utc = t.to_offset(time::UtcOffset::UTC);
            format_date(time::PrimitiveDateTime::new(utc.date(), utc.time()))
        });
    let body = json!({
        "folderId": text(&state, "folder"),
        "favorite": flag_or_bool(&state, "favorite"),
        "archivedDate": archived,
    });
    put_doc(ctx, user, KIND_PREFS, &key, &body).await
}

/// A flag that the import wrote as a JSON boolean.
fn flag_or_bool(row: &Value, column: &str) -> bool {
    row.get(column)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| flag(row, column))
}

/// Removes what the documents hold of a cipher that is gone: its collections, and every
/// account's state of it.
pub(super) async fn forget_cipher(ctx: &Ctx, cipher: Uuid) -> Res<()> {
    let key = cipher.to_string();
    delete_named(ctx, KIND_LINKS, &key).await?;
    delete_named(ctx, KIND_PREFS, &key).await
}

/// Removes every document of a scope: an organization's, or an account's.
pub(super) async fn forget_scope(ctx: &Ctx, scope: Uuid) -> Res<()> {
    bw_docs::Entity::delete_many()
        .filter(bw_docs::Column::Scope.eq(scope))
        .exec(&ctx.txn)
        .await
        .store()?;
    for (record, _) in rows::rows_with_prefix(ctx, RECORDS, &format!("{scope}/")).await? {
        rows::delete_row(ctx, RECORDS, &record).await?;
    }
    Ok(())
}

pub(super) async fn forget_member(ctx: &Ctx, org: Uuid, user: Uuid) -> Res<()> {
    delete_doc(ctx, org, KIND_MEMBER, &user.to_string()).await
}

pub(super) async fn forget_collection(ctx: &Ctx, collection: Uuid) -> Res<()> {
    delete_named(ctx, KIND_COLLECTION, &collection.to_string()).await
}

pub(super) async fn forget_group(ctx: &Ctx, group: Uuid) -> Res<()> {
    delete_named(ctx, KIND_GROUP, &group.to_string()).await
}

/// Removes the policy a deleted `org_policies` row (`row`, as it was kept) set.
pub(super) async fn forget_policy(ctx: &Ctx, row: &Value) -> Res<()> {
    if let Some(org) = row_uuid(rows::text(row, "org_uuid")) {
        delete_doc(ctx, org, KIND_POLICY, &number(row, "atype", 0).to_string()).await?;
        // A policy that is gone is off, in the table the Kemlock API reads as well.
        if number(row, "atype", 0) == REQUIRE_SSO {
            upsert_require_sso_in(&ctx.txn, SpaceId(org), false).await?;
        }
    }
    Ok(())
}

/// Removes the API key a deleted `organization_api_key` row (`row`, as it was kept) held.
pub(super) async fn forget_api_key(ctx: &Ctx, row: &Value) -> Res<()> {
    if let Some(org) = row_uuid(rows::text(row, "org_uuid")) {
        delete_doc(ctx, org, KIND_API_KEY, "").await?;
    }
    Ok(())
}
