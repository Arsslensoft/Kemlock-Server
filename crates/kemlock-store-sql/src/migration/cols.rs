//! Column types the schema helpers do not pick well for every backend.
//!
//! SeaORM's `timestamp_with_time_zone` is a plain `timestamp` on MySQL, which has no fractional
//! seconds and stops in 2038, and its `blob` is MySQL's 64 KiB `BLOB`. Where a column needs more,
//! MySQL gets the type that fits; every other backend gets the portable one.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

/// A time with microseconds, in UTC (`timestamp with time zone` on PostgreSQL, RFC 3339 text on
/// SQLite, `datetime(6)` on MySQL).
pub(crate) fn time_col(backend: DbBackend, name: &'static str, nullable: bool) -> ColumnDef {
    let mut col = ColumnDef::new(name);
    if backend == DbBackend::MySql {
        col.custom(Alias::new("datetime(6)"));
    } else {
        col.timestamp_with_time_zone();
    }
    if nullable {
        col.null();
    } else {
        col.not_null();
    }
    col.take()
}

/// A binary value of up to a few megabytes (an item's ciphertext): `bytea` on PostgreSQL,
/// `blob` on SQLite, `longblob` on MySQL.
pub(crate) fn big_blob(backend: DbBackend, name: &'static str, nullable: bool) -> ColumnDef {
    let mut col = ColumnDef::new(name);
    if backend == DbBackend::MySql {
        col.custom(Alias::new("longblob"));
    } else {
        col.blob();
    }
    if nullable {
        col.null();
    } else {
        col.not_null();
    }
    col.take()
}

/// Text that is compared exactly: `utf8mb4_bin` on MySQL, whose usual collation treats `é` and `e`
/// (and `A` and `a`) as the same letter and would call two different names a duplicate. SQLite and
/// PostgreSQL compare text byte for byte already, so they get a plain `varchar`. Never null.
pub(crate) fn exact_text_col(
    backend: DbBackend,
    name: &'static str,
    len: u32,
    unique: bool,
) -> ColumnDef {
    let mut col = ColumnDef::new(name);
    if backend == DbBackend::MySql {
        col.custom(Alias::new(format!(
            "varchar({len}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
        )));
    } else {
        col.string_len(len);
    }
    col.not_null();
    if unique {
        col.unique_key();
    }
    col.take()
}
