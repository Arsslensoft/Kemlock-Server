//! `vw_rows`: Vaultwarden rows kept as they were, as JSON objects keyed by column name.
//!
//! The tables that hold secrets are kept sealed under `server.key`; a few tables are not kept
//! here at all because they land in a table of their own that is the only copy needed.

use super::{Ctx, Res};
use crate::error::StoreResult;
use crate::tables::vw_rows;
use kemlock_app::b64url;
use kemlock_vaultwarden::snapshot::Table;
use kemlock_vaultwarden::vwtime::{parse_db_time, to_utc};
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// The `SecretSeal` purpose of a sealed row.
pub(super) const PURPOSE_ROW: &str = "vw-row";
const SEALED_PREFIX: &str = "sealed:";

/// Tables whose rows hold secrets: two-step setups and organization API keys.
const SEALED_TABLES: &[&str] = &["twofactor", "organization_api_key"];
/// Tables whose rows are not copied here: devices and events have their own tables, and a device
/// row holds tokens.
const NOT_KEPT: &[&str] = &["devices", "event"];

/// A row key as it is the `row_key` of `vw_rows`: the key columns joined with `/`.
pub(super) fn key_text(key: &[String]) -> String {
    key.join("/")
}

/// Keeps every row of a carried table (see the module docs for what is skipped or sealed).
pub(super) async fn put_table(ctx: &Ctx, table: &Table) -> Res<()> {
    let name = table.name();
    if NOT_KEPT.contains(&name) {
        return Ok(());
    }
    let sealed = SEALED_TABLES.contains(&name);
    for row in table.rows() {
        put_row(ctx, name, &key_text(&row.key()), &row.to_json(), sealed).await?;
    }
    Ok(())
}

/// Stores one row, replacing the row of the same table and key.
pub(super) async fn put_row(
    ctx: &Ctx,
    table: &str,
    key: &str,
    value: &Value,
    sealed: bool,
) -> Res<()> {
    let text = value.to_string();
    let data = if sealed {
        let bytes = ctx.seal.seal(PURPOSE_ROW, text.as_bytes());
        format!("{SEALED_PREFIX}{}", b64url::encode(&bytes))
    } else {
        text
    };
    delete_row(ctx, table, key).await?;
    vw_rows::Entity::insert(vw_rows::ActiveModel {
        table_name: Set(table.to_owned()),
        row_key: Set(key.to_owned()),
        data: Set(data),
    })
    .exec(&ctx.txn)
    .await
    .store()?;
    Ok(())
}

/// Reads a stored value back: JSON text, or sealed JSON. `None` for anything that isn't either.
fn open(ctx: &Ctx, data: &str) -> Option<Value> {
    match data.strip_prefix(SEALED_PREFIX) {
        Some(sealed) => {
            let bytes = b64url::decode(sealed)?;
            let opened = ctx.seal.open(PURPOSE_ROW, &bytes).ok()?;
            serde_json::from_slice(&opened).ok()
        }
        None => serde_json::from_str(data).ok(),
    }
}

/// One stored row.
pub(super) async fn get_row(ctx: &Ctx, table: &str, key: &str) -> Res<Option<Value>> {
    let row = vw_rows::Entity::find_by_id((table.to_owned(), key.to_owned()))
        .one(&ctx.txn)
        .await
        .store()?;
    Ok(row.and_then(|r| open(ctx, &r.data)))
}

/// Every stored row of a table with its key, in key order.
pub(super) async fn all_rows(ctx: &Ctx, table: &str) -> Res<Vec<(String, Value)>> {
    let rows = vw_rows::Entity::find()
        .filter(vw_rows::Column::TableName.eq(table))
        .order_by_asc(vw_rows::Column::RowKey)
        .all(&ctx.txn)
        .await
        .store()?;
    Ok(rows
        .into_iter()
        .filter_map(|r| open(ctx, &r.data).map(|v| (r.row_key, v)))
        .collect())
}

/// The stored rows of a table whose key starts with `prefix` (a first key column and a `/`).
pub(super) async fn rows_with_prefix(
    ctx: &Ctx,
    table: &str,
    prefix: &str,
) -> Res<Vec<(String, Value)>> {
    let rows = vw_rows::Entity::find()
        .filter(vw_rows::Column::TableName.eq(table))
        .filter(vw_rows::Column::RowKey.like(format!("{prefix}%")))
        .order_by_asc(vw_rows::Column::RowKey)
        .all(&ctx.txn)
        .await
        .store()?;
    Ok(rows
        .into_iter()
        .filter_map(|r| open(ctx, &r.data).map(|v| (r.row_key, v)))
        .collect())
}

/// The stored rows of a table whose key ends with `suffix` (a `/` and a last key column).
pub(super) async fn rows_with_suffix(
    ctx: &Ctx,
    table: &str,
    suffix: &str,
) -> Res<Vec<(String, Value)>> {
    let rows = vw_rows::Entity::find()
        .filter(vw_rows::Column::TableName.eq(table))
        .filter(vw_rows::Column::RowKey.like(format!("%{suffix}")))
        .order_by_asc(vw_rows::Column::RowKey)
        .all(&ctx.txn)
        .await
        .store()?;
    Ok(rows
        .into_iter()
        .filter_map(|r| open(ctx, &r.data).map(|v| (r.row_key, v)))
        .collect())
}

/// Removes one stored row; a row that isn't there is fine.
pub(super) async fn delete_row(ctx: &Ctx, table: &str, key: &str) -> Res<()> {
    vw_rows::Entity::delete_many()
        .filter(vw_rows::Column::TableName.eq(table))
        .filter(vw_rows::Column::RowKey.eq(key))
        .exec(&ctx.txn)
        .await
        .store()?;
    Ok(())
}

/// A UUID in a text column; `None` when there is none or it isn't one.
pub(super) fn row_uuid(text: Option<&str>) -> Option<Uuid> {
    text.and_then(|t| Uuid::parse_str(t.trim()).ok())
}

/// A date-time as Vaultwarden's database prints it, as the UTC instant it stands for.
pub(super) fn row_time(text: Option<&str>) -> Option<OffsetDateTime> {
    text.and_then(parse_db_time).map(to_utc)
}

/// A text column of a stored row.
pub(super) fn text<'a>(row: &'a Value, column: &str) -> Option<&'a str> {
    row.get(column).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_join_with_slashes() {
        assert_eq!(key_text(&["a".to_owned()]), "a");
        assert_eq!(key_text(&["a".to_owned(), "b".to_owned()]), "a/b");
    }

    #[test]
    fn text_reads_strings_only() {
        let row = serde_json::json!({"a": "x", "b": 1, "c": null});
        assert_eq!(text(&row, "a"), Some("x"));
        assert_eq!(text(&row, "b"), None);
        assert_eq!(text(&row, "c"), None);
        assert_eq!(text(&row, "d"), None);
    }
}
