//! `SecondStepGuard` on `second_step_attempts` (the sign-in second step) and `step_up_attempts`
//! (the proofs of a sensitive change and the admin console's step-up).
//!
//! A reservation reads the account's row, works out the next state with
//! [`Attempts::reserve`], and writes it back only if the row still holds what was read (a
//! compare-and-swap, as the two-step version's counter does), so two attempts never both read the
//! same count: one of them re-reads and sees the other's. The loop gives up after
//! [`RESERVE_RETRIES`] lost races and refuses the attempt with a one-second wait: a burst that
//! contended that long is the thing the limit is for.
//!
//! The two tables have the same shape and the same rule, so one macro writes the reservation for
//! both: someone holding a session who guesses at proofs spends the proofs' row, never the row of
//! the owner's sign-in.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::{second_step_attempts, step_up_attempts};
use kemlock_app::ports::StoreError;
use kemlock_app::second_step_guard::{Attempts, Reservation, SecondStepGuard};
use kemlock_domain::UserId;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// How many times a reservation retries after another attempt changed the row under it.
const RESERVE_RETRIES: u32 = 32;

/// `reserve_in!(store, table, user, now, limit, window)`: the reservation on `table`, one of the
/// two attempt tables, which share their columns.
macro_rules! reserve_in {
    ($store:expr, $table:ident, $user:expr, $now:expr, $limit:expr, $window_secs:expr) => {{
        let (store, user, now, limit, window_secs) = ($store, $user, $now, $limit, $window_secs);
        let mut answer = Reservation::Wait(1);
        for _ in 0..RESERVE_RETRIES {
            // The writer, not the reader: a replica's lagging copy would hand out attempts that
            // were already used.
            let row = $table::Entity::find_by_id(user.0)
                .one(store.writer())
                .await
                .store()?;
            let before = row
                .as_ref()
                .map(|row| Attempts {
                    window_start: row.window_start,
                    count: row.count,
                    level: row.level,
                    blocked_until: row.blocked_until,
                })
                .unwrap_or_default();
            let (after, reservation) = before.reserve(now, limit, window_secs);
            if after == before {
                // A wait changes nothing.
                answer = reservation;
                break;
            }
            match row {
                None => {
                    let inserted = $table::Entity::insert($table::ActiveModel {
                        user_id: Set(user.0),
                        window_start: Set(after.window_start),
                        count: Set(after.count),
                        level: Set(after.level),
                        blocked_until: Set(after.blocked_until),
                    })
                    .exec(store.writer())
                    .await;
                    match inserted {
                        Ok(_) => {
                            answer = reservation;
                            break;
                        }
                        // Another attempt made the row first: read it and add to it.
                        Err(err) if is_unique_violation(&err) => continue,
                        Err(err) => return Err(map_db(err)),
                    }
                }
                Some(row) => {
                    let moved = $table::Entity::update_many()
                        .col_expr($table::Column::WindowStart, Expr::value(after.window_start))
                        .col_expr($table::Column::Count, Expr::value(after.count))
                        .col_expr($table::Column::Level, Expr::value(after.level))
                        .col_expr($table::Column::BlockedUntil, Expr::value(after.blocked_until))
                        .filter($table::Column::UserId.eq(user.0))
                        .filter($table::Column::WindowStart.eq(row.window_start))
                        .filter($table::Column::Count.eq(row.count))
                        .filter($table::Column::Level.eq(row.level))
                        .filter($table::Column::BlockedUntil.eq(row.blocked_until))
                        .exec(store.writer())
                        .await
                        .store()?;
                    if moved.rows_affected == 1 {
                        answer = reservation;
                        break;
                    }
                }
            }
        }
        answer
    }};
}

impl SecondStepGuard for SqlStore {
    async fn reserve_second_step(
        &self,
        user: UserId,
        now: i64,
        limit: u32,
        window_secs: i64,
    ) -> Result<Reservation, StoreError> {
        Ok(reserve_in!(
            self,
            second_step_attempts,
            user,
            now,
            limit,
            window_secs
        ))
    }

    async fn clear_second_step(&self, user: UserId) -> Result<(), StoreError> {
        second_step_attempts::Entity::delete_many()
            .filter(second_step_attempts::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn reserve_step_up(
        &self,
        user: UserId,
        now: i64,
        limit: u32,
        window_secs: i64,
    ) -> Result<Reservation, StoreError> {
        Ok(reserve_in!(
            self,
            step_up_attempts,
            user,
            now,
            limit,
            window_secs
        ))
    }

    async fn clear_step_up(&self, user: UserId) -> Result<(), StoreError> {
        step_up_attempts::Entity::delete_many()
            .filter(step_up_attempts::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
