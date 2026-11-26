//! `SecondStepGuard` on `second_step_attempts`.
//!
//! A reservation reads the account's row, works out the next state with
//! [`Attempts::reserve`], and writes it back only if the row still holds what was read (a
//! compare-and-swap, as the two-step version's counter does), so two attempts never both read the
//! same count: one of them re-reads and sees the other's. The loop gives up after
//! [`RESERVE_RETRIES`] lost races and refuses the attempt with a one-second wait: a burst that
//! contended that long is the thing the limit is for.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::second_step_attempts;
use kemlock_app::ports::StoreError;
use kemlock_app::second_step_guard::{Attempts, Reservation, SecondStepGuard};
use kemlock_domain::UserId;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// How many times a reservation retries after another attempt changed the row under it.
const RESERVE_RETRIES: u32 = 32;

fn attempts_of(row: &second_step_attempts::Model) -> Attempts {
    Attempts {
        window_start: row.window_start,
        count: row.count,
        level: row.level,
        blocked_until: row.blocked_until,
    }
}

impl SecondStepGuard for SqlStore {
    async fn reserve_second_step(
        &self,
        user: UserId,
        now: i64,
        limit: u32,
        window_secs: i64,
    ) -> Result<Reservation, StoreError> {
        for _ in 0..RESERVE_RETRIES {
            // The writer, not the reader: a replica's lagging copy would hand out attempts that
            // were already used.
            let row = second_step_attempts::Entity::find_by_id(user.0)
                .one(self.writer())
                .await
                .store()?;
            let before = row.as_ref().map(attempts_of).unwrap_or_default();
            let (after, reservation) = before.reserve(now, limit, window_secs);
            if after == before {
                // A wait changes nothing.
                return Ok(reservation);
            }
            match row {
                None => {
                    let inserted =
                        second_step_attempts::Entity::insert(second_step_attempts::ActiveModel {
                            user_id: Set(user.0),
                            window_start: Set(after.window_start),
                            count: Set(after.count),
                            level: Set(after.level),
                            blocked_until: Set(after.blocked_until),
                        })
                        .exec(self.writer())
                        .await;
                    match inserted {
                        Ok(_) => return Ok(reservation),
                        // Another attempt made the row first: read it and add to it.
                        Err(err) if is_unique_violation(&err) => continue,
                        Err(err) => return Err(map_db(err)),
                    }
                }
                Some(row) => {
                    let moved = second_step_attempts::Entity::update_many()
                        .col_expr(
                            second_step_attempts::Column::WindowStart,
                            Expr::value(after.window_start),
                        )
                        .col_expr(
                            second_step_attempts::Column::Count,
                            Expr::value(after.count),
                        )
                        .col_expr(
                            second_step_attempts::Column::Level,
                            Expr::value(after.level),
                        )
                        .col_expr(
                            second_step_attempts::Column::BlockedUntil,
                            Expr::value(after.blocked_until),
                        )
                        .filter(second_step_attempts::Column::UserId.eq(user.0))
                        .filter(second_step_attempts::Column::WindowStart.eq(row.window_start))
                        .filter(second_step_attempts::Column::Count.eq(row.count))
                        .filter(second_step_attempts::Column::Level.eq(row.level))
                        .filter(second_step_attempts::Column::BlockedUntil.eq(row.blocked_until))
                        .exec(self.writer())
                        .await
                        .store()?;
                    if moved.rows_affected == 1 {
                        return Ok(reservation);
                    }
                }
            }
        }
        Ok(Reservation::Wait(1))
    }

    async fn clear_second_step(&self, user: UserId) -> Result<(), StoreError> {
        second_step_attempts::Entity::delete_many()
            .filter(second_step_attempts::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
