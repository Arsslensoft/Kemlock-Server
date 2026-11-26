//! Gives the managers moved from Vaultwarden before the Bitwarden API read "every collection"
//! from the space row the permission that says so.
//!
//! A Vaultwarden manager with `access_all` is a space member with role `custom` and a member
//! document `{"accessAll":true,...}` (kind `member` in `bw_docs`). The Bitwarden API now keeps
//! `accessAll` of a custom member only while the row has the create-collections permission (bit
//! 4), and an earlier move wrote none, so such a manager would lose every collection at its next
//! load. The bit is set on each such row; a row that has it, or isn't custom, is left alone, so the
//! migration can run again.
//!
//! Rows are found and changed one at a time with the query builder, so ids are written the way
//! the rest of the store writes them on every backend.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub(crate) struct Migration;

/// `CustomPermissions::CREATE_COLLECTIONS`.
const CREATE_COLLECTIONS: i64 = 1 << 2;

fn custom(error: impl std::fmt::Debug) -> DbErr {
    DbErr::Custom(format!("{error:?}"))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_table("bw_docs").await? || !manager.has_table("members").await? {
            return Ok(());
        }
        let db = manager.get_connection();
        let docs = db
            .query_all(
                &Query::select()
                    .columns([Alias::new("scope"), Alias::new("doc_key")])
                    .from(Alias::new("bw_docs"))
                    .and_where(Expr::col(Alias::new("kind")).eq("member"))
                    .and_where(Expr::col(Alias::new("body")).like("%\"accessAll\":true%"))
                    .to_owned(),
            )
            .await?;
        for doc in docs {
            let space: Uuid = doc.try_get("", "scope").map_err(custom)?;
            let key: String = doc.try_get("", "doc_key").map_err(custom)?;
            let Ok(user) = Uuid::parse_str(&key) else {
                continue;
            };
            let rows = db
                .query_all(
                    &Query::select()
                        .column(Alias::new("custom_permissions"))
                        .from(Alias::new("members"))
                        .and_where(Expr::col(Alias::new("space_id")).eq(space))
                        .and_where(Expr::col(Alias::new("user_id")).eq(user))
                        .and_where(Expr::col(Alias::new("role")).eq("custom"))
                        .to_owned(),
                )
                .await?;
            for row in rows {
                let held: i64 = row.try_get("", "custom_permissions").map_err(custom)?;
                if held & CREATE_COLLECTIONS != 0 {
                    continue;
                }
                manager
                    .exec_stmt(
                        Query::update()
                            .table(Alias::new("members"))
                            .value(Alias::new("custom_permissions"), held | CREATE_COLLECTIONS)
                            .and_where(Expr::col(Alias::new("space_id")).eq(space))
                            .and_where(Expr::col(Alias::new("user_id")).eq(user))
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::utc;
    use crate::store::SqlStore;
    use crate::tables::bw_docs;
    use crate::tables::space_tables::members;
    use sea_orm::ActiveValue::Set;
    use sea_orm::EntityTrait;
    use time::macros::datetime;

    async fn seed(store: &SqlStore, space: Uuid, role: &str, doc: &str) -> Uuid {
        let user = Uuid::new_v4();
        let at = utc(datetime!(2026-11-26 10:00:00 UTC));
        members::Entity::insert(members::ActiveModel {
            space_id: Set(space),
            user_id: Set(user),
            role: Set(role.to_owned()),
            custom_permissions: Set(0),
            state: Set("confirmed".to_owned()),
            invited_by: Set(user),
            invited_at: Set(at),
            accepted_at: Set(Some(at)),
            sealed_space_key: Set(None),
            sealed_by: Set(None),
            sealed_by_key_version: Set(None),
            sealed_signature: Set(None),
            key_version: Set(None),
            revoked_at: Set(None),
            confirmed_by: Set(None),
            confirmed_at: Set(None),
            confirmed_fingerprint: Set(None),
            confirmed_key_version: Set(None),
            confirmation_statement: Set(None),
            confirmation_signature: Set(None),
        })
        .exec(store.writer())
        .await
        .expect("a member row");
        bw_docs::Entity::insert(bw_docs::ActiveModel {
            scope: Set(space),
            kind: Set("member".to_owned()),
            doc_key: Set(user.to_string()),
            body: Set(doc.to_owned()),
        })
        .exec(store.writer())
        .await
        .expect("a member document");
        user
    }

    async fn permissions(store: &SqlStore, space: Uuid, user: Uuid) -> i64 {
        members::Entity::find_by_id((space, user))
            .one(store.writer())
            .await
            .expect("reads")
            .expect("the row")
            .custom_permissions
    }

    #[tokio::test]
    async fn only_a_custom_member_whose_document_has_every_collection_gets_the_permission() {
        let store = SqlStore::connect("sqlite::memory:").await.expect("a store");
        let space = Uuid::new_v4();
        let all = seed(&store, space, "custom", r#"{"accessAll":true,"atype":3}"#).await;
        let some = seed(&store, space, "custom", r#"{"accessAll":false,"atype":3}"#).await;
        let admin = seed(&store, space, "admin", r#"{"accessAll":true,"atype":1}"#).await;

        let manager = SchemaManager::new(store.writer());
        Migration.up(&manager).await.expect("the migration");
        assert_eq!(permissions(&store, space, all).await, CREATE_COLLECTIONS);
        assert_eq!(permissions(&store, space, some).await, 0);
        assert_eq!(permissions(&store, space, admin).await, 0);
        // Running it again changes nothing.
        Migration.up(&manager).await.expect("the migration again");
        assert_eq!(permissions(&store, space, all).await, CREATE_COLLECTIONS);
    }
}
