//! `BwOrgStore` on `bw_docs`.

use crate::error::{StoreResult, map_db};
use crate::store::SqlStore;
use crate::tables::bw_docs;
use kemlock_app::bitwarden::BwOrgStore;
use kemlock_app::ports::StoreError;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use uuid::Uuid;

impl BwOrgStore for SqlStore {
    async fn doc_get(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        Ok(
            bw_docs::Entity::find_by_id((scope, kind.to_owned(), key.to_owned()))
                .one(self.reader())
                .await
                .store()?
                .map(|row| row.body),
        )
    }

    async fn doc_put(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
        body: &str,
    ) -> Result<(), StoreError> {
        let row = bw_docs::ActiveModel {
            scope: Set(scope),
            kind: Set(kind.to_owned()),
            doc_key: Set(key.to_owned()),
            body: Set(body.to_owned()),
        };
        let conflict = OnConflict::columns([
            bw_docs::Column::Scope,
            bw_docs::Column::Kind,
            bw_docs::Column::DocKey,
        ])
        .update_column(bw_docs::Column::Body)
        .to_owned();
        match bw_docs::Entity::insert(row)
            .on_conflict(conflict)
            .exec(self.writer())
            .await
        {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn doc_delete(&self, scope: Uuid, kind: &str, key: &str) -> Result<bool, StoreError> {
        let result = bw_docs::Entity::delete_many()
            .filter(bw_docs::Column::Scope.eq(scope))
            .filter(bw_docs::Column::Kind.eq(kind))
            .filter(bw_docs::Column::DocKey.eq(key))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected > 0)
    }

    async fn doc_list(&self, scope: Uuid, kind: &str) -> Result<Vec<(String, String)>, StoreError> {
        Ok(bw_docs::Entity::find()
            .filter(bw_docs::Column::Scope.eq(scope))
            .filter(bw_docs::Column::Kind.eq(kind))
            .order_by_asc(bw_docs::Column::DocKey)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| (row.doc_key, row.body))
            .collect())
    }

    async fn doc_find(&self, kind: &str, key: &str) -> Result<Vec<(Uuid, String)>, StoreError> {
        Ok(bw_docs::Entity::find()
            .filter(bw_docs::Column::Kind.eq(kind))
            .filter(bw_docs::Column::DocKey.eq(key))
            .order_by_asc(bw_docs::Column::Scope)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(|row| (row.scope, row.body))
            .collect())
    }

    async fn doc_delete_scope(&self, scope: Uuid) -> Result<u64, StoreError> {
        let result = bw_docs::Entity::delete_many()
            .filter(bw_docs::Column::Scope.eq(scope))
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> SqlStore {
        SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store")
    }

    #[tokio::test]
    async fn a_document_is_put_replaced_listed_and_deleted() {
        let store = store().await;
        let scope = Uuid::new_v4();
        assert_eq!(store.doc_get(scope, "k", "a").await, Ok(None));

        store.doc_put(scope, "k", "a", "one").await.expect("put");
        store.doc_put(scope, "k", "b", "two").await.expect("put");
        store
            .doc_put(scope, "k", "a", "uno")
            .await
            .expect("replace");
        assert_eq!(
            store.doc_get(scope, "k", "a").await,
            Ok(Some("uno".to_owned()))
        );
        assert_eq!(
            store.doc_list(scope, "k").await,
            Ok(vec![
                ("a".to_owned(), "uno".to_owned()),
                ("b".to_owned(), "two".to_owned())
            ])
        );
        assert_eq!(store.doc_delete(scope, "k", "a").await, Ok(true));
        assert_eq!(store.doc_delete(scope, "k", "a").await, Ok(false));
        assert_eq!(store.doc_list(scope, "k").await.map(|l| l.len()), Ok(1));
    }

    #[tokio::test]
    async fn documents_are_found_across_scopes_and_removed_by_scope() {
        let store = store().await;
        let (one, two) = (Uuid::new_v4(), Uuid::new_v4());
        store
            .doc_put(one, "pending", "x@y.z", "1")
            .await
            .expect("put");
        store
            .doc_put(two, "pending", "x@y.z", "2")
            .await
            .expect("put");
        store
            .doc_put(two, "other", "x@y.z", "3")
            .await
            .expect("put");

        let found = store.doc_find("pending", "x@y.z").await.expect("find");
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|(s, b)| *s == one && b == "1"));

        assert_eq!(store.doc_delete_scope(two).await, Ok(2));
        assert_eq!(
            store.doc_find("pending", "x@y.z").await.map(|f| f.len()),
            Ok(1)
        );
    }
}
