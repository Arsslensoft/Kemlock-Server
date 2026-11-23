//! `AttachmentRepo` on `attachments`.

use crate::convert::utc;
use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::attachments::{self, PENDING, READY};
use crate::tables::items;
use kemlock_app::files::AttachmentRepo;
use kemlock_app::ports::StoreError;
use kemlock_app::quota::{QuotaRefusal, check};
use kemlock_domain::{Attachment, AttachmentId, Owner};
use sea_orm::sea_query::{Expr, Query, SelectStatement};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};
use time::OffsetDateTime;

/// `SELECT 1 FROM items WHERE items.id = attachments.item_id`, for an `EXISTS` over the item of
/// the attachment row at hand.
fn item_row() -> SelectStatement {
    // Only here: with `ExprTrait` in scope, `Column::eq` would be ambiguous.
    use sea_orm::sea_query::ExprTrait;
    Query::select()
        .expr(Expr::val(1))
        .from(items::Entity)
        .and_where(
            Expr::col((items::Entity, items::Column::Id))
                .equals((attachments::Entity, attachments::Column::ItemId)),
        )
        .take()
}

/// What the owner's attachments announced, pending ones included, on `db`. Adds the sizes up here,
/// not in SQL: `SUM` comes back as a different type on each backend.
async fn bytes_of<C: ConnectionTrait>(db: &C, owner: Owner) -> Result<u64, StoreError> {
    let (kind, id) = match owner {
        Owner::User(user) => (Owner::TYPE_USER, user.0),
        Owner::Space(space) => (Owner::TYPE_SPACE, space.0),
    };
    let sizes = attachments::Entity::find()
        .select_only()
        .column(attachments::Column::Size)
        .filter(attachments::Column::OwnerType.eq(i16::from(kind)))
        .filter(attachments::Column::OwnerId.eq(id))
        .into_tuple::<i64>()
        .all(db)
        .await
        .store()?;
    Ok(sizes.into_iter().fold(0u64, |total, size| {
        total.saturating_add(u64::try_from(size).unwrap_or(0))
    }))
}

impl AttachmentRepo for SqlStore {
    async fn add(&self, attachment: &Attachment) -> Result<(), StoreError> {
        attachments::Entity::insert(attachments::active(attachment)?)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    /// The sum and the insert in one transaction, under the store's quota gate.
    async fn add_within_quota(
        &self,
        attachment: &Attachment,
        limit: Option<u64>,
    ) -> Result<Result<(), QuotaRefusal>, StoreError> {
        let _gate = self.quota_gate().await;
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            if limit.is_some() {
                let used = bytes_of(&txn, attachment.owner).await?;
                if let Err(refusal) = check(limit, used, attachment.size) {
                    return Ok(Err(refusal));
                }
            }
            attachments::Entity::insert(attachments::active(attachment)?)
                .exec(&txn)
                .await
                .store()?;
            Ok::<_, StoreError>(Ok(()))
        }
        .await;
        match outcome {
            Ok(done) => {
                txn.commit().await.store()?;
                Ok(done)
            }
            Err(err) => {
                if let Err(rollback) = txn.rollback().await {
                    tracing::warn!(%rollback, "rollback after adding an attachment failed");
                }
                Err(err)
            }
        }
    }

    async fn by_id(&self, id: AttachmentId) -> Result<Option<Attachment>, StoreError> {
        attachments::Entity::find_by_id(id.0)
            .one(self.reader())
            .await
            .store()?
            .map(attachments::Model::into_domain)
            .transpose()
    }

    async fn attachment_bytes(&self, owner: Owner) -> Result<u64, StoreError> {
        bytes_of(self.writer(), owner).await
    }

    /// One conditional update: of two uploads of one file finishing together, exactly one sees
    /// a row change.
    async fn mark_ready(&self, id: AttachmentId) -> Result<bool, StoreError> {
        let updated = attachments::Entity::update_many()
            .col_expr(attachments::Column::Status, Expr::val(READY))
            .filter(attachments::Column::Id.eq(id.0))
            .filter(attachments::Column::Status.eq(PENDING))
            .exec(self.writer())
            .await
            .store()?;
        Ok(updated.rows_affected > 0)
    }

    async fn remove(&self, id: AttachmentId) -> Result<(), StoreError> {
        attachments::Entity::delete_by_id(id.0)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    /// Old rows that are still pending (an upload nobody finished) or whose item has no row: it
    /// never came, or the tombstone purge deleted it.
    async fn orphans(
        &self,
        before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<Attachment>, StoreError> {
        let orphaned = Condition::any()
            .add(attachments::Column::Status.eq(PENDING))
            .add(Expr::not_exists(item_row()));
        attachments::Entity::find()
            .filter(attachments::Column::CreatedAt.lt(utc(before)))
            .filter(orphaned)
            .order_by_asc(attachments::Column::CreatedAt)
            .order_by_asc(attachments::Column::Id)
            .limit(u64::from(limit))
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(attachments::Model::into_domain)
            .collect()
    }
}
