//! `vw_import_ids`: the user and space ids the move from Vaultwarden created.
//!
//! The importer writes by Vaultwarden's own ids, so without a record of which ids it made it could
//! rewrite an account or a space that was never Vaultwarden's. A pass takes an id only when no row
//! of that id exists yet, or when this table says an earlier pass created it; anything else is
//! refused and reported. The rows carry no foreign key: an account or space that is later erased
//! leaves its mark behind, which only means that id is the import's if it ever came back.
//!
//! `written_at` is when the import last wrote the id, and for an account `revision_ms` is the
//! revision date its Bitwarden record had when it did. A user or space the server's own API changed
//! after that (a later `updated_at`, another revision) is left alone by a later pass, so a rerun
//! can't roll it back to Vaultwarden's state.
//!
//! Servers that moved before this table existed are backfilled: every account with a
//! `bw_account_extras` row (only the import writes one) and every organization the import kept in
//! `vw_rows` is recorded as the import's, as of this migration.

use super::cols::time_col;
use crate::convert::utc;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema as c;
use sea_orm_migration::sea_orm::{ConnectionTrait, Value};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

fn custom(error: impl std::fmt::Debug) -> DbErr {
    DbErr::Custom(format!("{error:?}"))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        manager
            .create_table(
                Table::create()
                    .table("vw_import_ids")
                    .if_not_exists()
                    // `user` or `space`.
                    .col(c::string_len("kind", 16))
                    .col(c::uuid("id"))
                    .col(time_col(backend, "imported_at", false))
                    .col(time_col(backend, "written_at", false))
                    .col(c::big_integer_null("revision_ms"))
                    .primary_key(Index::create().col("kind").col("id"))
                    .to_owned(),
            )
            .await?;
        backfill(manager).await
    }
}

/// Records the accounts and organizations an earlier move made. Rows are read and written one at a
/// time with the query builder, so ids and times go the way the rest of the store writes them on
/// every backend.
pub(crate) async fn backfill(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let now = utc(OffsetDateTime::now_utc());

    let mut ids: Vec<(&str, Uuid)> = Vec::new();
    if manager.has_table("bw_account_extras").await? {
        let rows = db
            .query_all(
                &Query::select()
                    .column(Alias::new("user_id"))
                    .from(Alias::new("bw_account_extras"))
                    .to_owned(),
            )
            .await?;
        for row in rows {
            let user: Uuid = row.try_get("", "user_id").map_err(custom)?;
            ids.push(("user", user));
        }
    }
    if manager.has_table("vw_rows").await? {
        let rows = db
            .query_all(
                &Query::select()
                    .column(Alias::new("row_key"))
                    .from(Alias::new("vw_rows"))
                    .and_where(Expr::col(Alias::new("table_name")).eq("organizations"))
                    .to_owned(),
            )
            .await?;
        for row in rows {
            let key: String = row.try_get("", "row_key").map_err(custom)?;
            if let Ok(space) = Uuid::parse_str(key.trim()) {
                ids.push(("space", space));
            }
        }
    }

    let mut seen = BTreeSet::new();
    for (kind, id) in ids {
        if !seen.insert((kind, id)) {
            continue;
        }
        let mut insert = Query::insert();
        insert
            .into_table(Alias::new("vw_import_ids"))
            .columns(["kind", "id", "imported_at", "written_at"].map(Alias::new))
            .values([
                Expr::val(kind),
                Expr::val(Value::Uuid(Some(id))),
                Expr::val(Value::TimeDateTimeWithTimeZone(Some(now))),
                Expr::val(Value::TimeDateTimeWithTimeZone(Some(now))),
            ])
            .map_err(custom)?;
        manager.exec_stmt(insert.to_owned()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqlStore;
    use crate::tables::{bw_account_extras, vw_import_ids, vw_rows};
    use kemlock_app::ports::UserRepo;
    use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
    use sea_orm::ActiveValue::Set;
    use sea_orm::EntityTrait;
    use time::macros::datetime;

    #[tokio::test]
    async fn a_server_that_moved_before_the_table_existed_is_backfilled() {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store");
        let at = datetime!(2026-01-02 03:04:05 UTC);
        let moved = User {
            id: UserId::random(),
            email: Email::parse("moved@example.org").expect("valid"),
            name: None,
            mode: AccountMode::Compatible,
            role: Role::User,
            kdf: KdfParams::new_account([1; 16]),
            opaque_record: None,
            wrapped_root_key: Vec::new(),
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            key_version: 0,
            security_stamp: Uuid::new_v4(),
            created_at: at,
            updated_at: at,
        };
        UserRepo::insert(&store, &moved).await.expect("a user");
        // What an earlier move left: the account's extras and the organization's kept row.
        bw_account_extras::Entity::insert(bw_account_extras::ActiveModel {
            user_id: Set(moved.id.0),
            enabled: Set(true),
            verified_at: Set(None),
            last_verifying_at: Set(None),
            login_verify_count: Set(0),
            email_new: Set(None),
            email_new_token: Set(None),
            stamp_exception: Set(None),
            equivalent_domains: Set("[]".to_owned()),
            excluded_globals: Set("[]".to_owned()),
            external_id: Set(None),
            key_id: Set(None),
            sealed_totp_secret: Set(None),
            sealed_totp_recover: Set(None),
            vw_security_stamp: Set("stamp".to_owned()),
        })
        .exec(store.writer())
        .await
        .expect("the extras");
        let org = Uuid::new_v4();
        vw_rows::Entity::insert(vw_rows::ActiveModel {
            table_name: Set("organizations".to_owned()),
            row_key: Set(org.to_string()),
            data: Set("{}".to_owned()),
        })
        .exec(store.writer())
        .await
        .expect("the row");
        // A table of another Vaultwarden table that happens to hold a UUID key is not a space.
        vw_rows::Entity::insert(vw_rows::ActiveModel {
            table_name: Set("collections".to_owned()),
            row_key: Set(Uuid::new_v4().to_string()),
            data: Set("{}".to_owned()),
        })
        .exec(store.writer())
        .await
        .expect("the row");

        backfill(&SchemaManager::new(store.writer()))
            .await
            .expect("backfills");
        let mut found: Vec<(String, Uuid)> = vw_import_ids::Entity::find()
            .all(store.writer())
            .await
            .expect("rows")
            .into_iter()
            .map(|row| (row.kind, row.id))
            .collect();
        found.sort();
        let mut expected = vec![("space".to_owned(), org), ("user".to_owned(), moved.id.0)];
        expected.sort();
        assert_eq!(found, expected);
    }
}
