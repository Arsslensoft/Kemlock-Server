//! `BwAccountRepo` on `bw_accounts`.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::bw_accounts;
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use sea_orm::ActiveValue::NotSet;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// How many times `touch` retries after losing a race for the revision date.
const TOUCH_TRIES: usize = 8;

impl BwAccountRepo for SqlStore {
    async fn get(&self, user: UserId) -> Result<Option<BwAccount>, StoreError> {
        bw_accounts::Entity::find_by_id(user.0)
            .one(self.reader())
            .await
            .store()?
            .map(bw_accounts::Model::into_domain)
            .transpose()
    }

    async fn insert(&self, account: &BwAccount) -> Result<(), StoreError> {
        bw_accounts::Entity::insert(bw_accounts::active(account))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn update(&self, account: &BwAccount) -> Result<(), StoreError> {
        let row = bw_accounts::ActiveModel {
            user_id: NotSet,
            revision_ms: NotSet,
            ..bw_accounts::active(account)
        };
        let result = bw_accounts::Entity::update_many()
            .set(row)
            .filter(bw_accounts::Column::UserId.eq(account.user.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Reads the revision date, then moves it with a compare-and-set, so two racing changes each
    /// take a different value.
    async fn touch(&self, user: UserId, now_ms: i64) -> Result<i64, StoreError> {
        let writer = self.writer();
        for _ in 0..TOUCH_TRIES {
            let row = bw_accounts::Entity::find_by_id(user.0)
                .one(writer)
                .await
                .store()?
                .ok_or(StoreError::NotFound)?;
            let next = now_ms.max(row.revision_ms.saturating_add(1));
            let result = bw_accounts::Entity::update_many()
                .col_expr(bw_accounts::Column::RevisionMs, Expr::value(next))
                .filter(bw_accounts::Column::UserId.eq(user.0))
                .filter(bw_accounts::Column::RevisionMs.eq(row.revision_ms))
                .exec(writer)
                .await
                .store()?;
            if result.rows_affected == 1 {
                return Ok(next);
            }
        }
        Err(StoreError::Backend(
            "the account's revision date kept changing under a touch".to_owned(),
        ))
    }
}
