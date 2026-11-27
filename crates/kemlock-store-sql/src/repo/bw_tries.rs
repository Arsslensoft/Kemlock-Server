//! `BwTryRepo` on `bw_tries`.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::bw_tries;
use kemlock_app::bitwarden::BwTryRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// How many times a count retries when another try moved the row between its read and its write.
/// Each retry means someone else counted, so the loop ends in a few turns.
const COUNT_TRIES: usize = 16;

impl BwTryRepo for SqlStore {
    async fn count_try(
        &self,
        user: UserId,
        kind: &str,
        now: i64,
        window_secs: i64,
    ) -> Result<u32, StoreError> {
        let writer = self.writer();
        for _ in 0..COUNT_TRIES {
            let Some(row) = bw_tries::Entity::find_by_id((user.0, kind.to_owned()))
                .one(writer)
                .await
                .store()?
            else {
                let inserted = bw_tries::Entity::insert(bw_tries::ActiveModel {
                    user_id: Set(user.0),
                    kind: Set(kind.to_owned()),
                    tries: Set(1),
                    window_start: Set(now),
                })
                .exec(writer)
                .await;
                match inserted {
                    Ok(_) => return Ok(1),
                    // Another try made the row first: count on top of it.
                    Err(err) if is_unique_violation(&err) => continue,
                    Err(err) => return Err(map_db(err)),
                }
            };
            // A window that has run out, or one that starts in the future (a clock that moved
            // back), begins again with this try.
            let over = now < row.window_start || now - row.window_start >= window_secs;
            let (tries, start) = if over {
                (1, now)
            } else {
                (row.tries.saturating_add(1), row.window_start)
            };
            let moved = bw_tries::Entity::update_many()
                .col_expr(bw_tries::Column::Tries, Expr::value(tries))
                .col_expr(bw_tries::Column::WindowStart, Expr::value(start))
                .filter(bw_tries::Column::UserId.eq(user.0))
                .filter(bw_tries::Column::Kind.eq(kind))
                .filter(bw_tries::Column::Tries.eq(row.tries))
                .filter(bw_tries::Column::WindowStart.eq(row.window_start))
                .exec(writer)
                .await
                .store()?;
            if moved.rows_affected == 1 {
                return Ok(u32::try_from(tries).unwrap_or(u32::MAX));
            }
        }
        Err(StoreError::Backend(
            "an account's tries kept changing under a count".to_owned(),
        ))
    }

    async fn forget_tries(&self, user: UserId, kind: &str) -> Result<(), StoreError> {
        bw_tries::Entity::delete_many()
            .filter(bw_tries::Column::UserId.eq(user.0))
            .filter(bw_tries::Column::Kind.eq(kind))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
