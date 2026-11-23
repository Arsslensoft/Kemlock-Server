//! `TwoFactorRepo` on `two_factor`.
//!
//! The account's two-step version (`two_step_versions`) moves here whenever a method is turned on
//! or off: a method that is new or whose `enabled` flag changed, or one that was removed. Changing
//! a method's stored state (an emailed code, a spent TOTP step) leaves it alone, or every sign-in
//! by email code would end the remembered devices.

use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::{two_factor, two_step_versions};
use kemlock_app::ports::{StoreError, TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::UserId;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder};

/// How many times a bump retries when another change moved the counter between its read and its
/// write. Each retry means someone else bumped it, which is all the caller needs.
const BUMP_RETRIES: u32 = 8;

impl SqlStore {
    /// Moves the account's two-step version up by one.
    async fn bump_version(&self, user: UserId) -> Result<(), StoreError> {
        for _ in 0..BUMP_RETRIES {
            let Some(row) = two_step_versions::Entity::find_by_id(user.0)
                .one(self.writer())
                .await
                .store()?
            else {
                let inserted = two_step_versions::Entity::insert(two_step_versions::ActiveModel {
                    user_id: Set(user.0),
                    version: Set(1),
                })
                .exec(self.writer())
                .await;
                match inserted {
                    Ok(_) => return Ok(()),
                    // Another change made the row first: read it and add to it.
                    Err(err) if is_unique_violation(&err) => continue,
                    Err(err) => return Err(map_db(err)),
                }
            };
            let moved = two_step_versions::Entity::update_many()
                .col_expr(
                    two_step_versions::Column::Version,
                    Expr::value(row.version.saturating_add(1)),
                )
                .filter(two_step_versions::Column::UserId.eq(user.0))
                .filter(two_step_versions::Column::Version.eq(row.version))
                .exec(self.writer())
                .await
                .store()?;
            if moved.rows_affected == 1 {
                return Ok(());
            }
        }
        Err(StoreError::Backend(
            "an account's two-step version kept changing under a read".to_owned(),
        ))
    }
}

impl TwoFactorRepo for SqlStore {
    async fn list(&self, user: UserId) -> Result<Vec<TwoFactor>, StoreError> {
        two_factor::Entity::find()
            .filter(two_factor::Column::UserId.eq(user.0))
            .order_by_asc(two_factor::Column::Method)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(two_factor::Model::into_domain)
            .collect()
    }

    async fn put(&self, enrolment: &TwoFactor) -> Result<(), StoreError> {
        let turned = two_factor::Entity::find_by_id((
            enrolment.user.0,
            two_factor::method_str(enrolment.method).to_owned(),
        ))
        .one(self.writer())
        .await
        .store()?
        .is_none_or(|before| before.enabled != enrolment.enabled);
        let conflict =
            OnConflict::columns([two_factor::Column::UserId, two_factor::Column::Method])
                .update_columns([
                    two_factor::Column::SealedSecret,
                    two_factor::Column::Enabled,
                    two_factor::Column::CreatedAt,
                ])
                .to_owned();
        let inserted = two_factor::Entity::insert(two_factor::active(enrolment))
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match inserted {
            Ok(_) => {}
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => {}
            Err(err) if is_unique_violation(&err) => return Err(StoreError::Duplicate),
            Err(err) => return Err(map_db(err)),
        }
        if turned {
            self.bump_version(enrolment.user).await?;
        }
        Ok(())
    }

    async fn accept_totp_step(&self, user: UserId, step: u64) -> Result<bool, StoreError> {
        let step =
            i64::try_from(step).map_err(|_| StoreError::Backend("a TOTP step too large".into()))?;
        // One statement, so of two sign-ins presenting the same code exactly one changes the row.
        let result = two_factor::Entity::update_many()
            .col_expr(two_factor::Column::LastUsedStep, Expr::value(step))
            .filter(two_factor::Column::UserId.eq(user.0))
            .filter(two_factor::Column::Method.eq(two_factor::method_str(TwoFactorMethod::Totp)))
            .filter(
                Condition::any()
                    .add(two_factor::Column::LastUsedStep.is_null())
                    .add(two_factor::Column::LastUsedStep.lt(step)),
            )
            .exec(self.writer())
            .await
            .store()?;
        Ok(result.rows_affected == 1)
    }

    async fn remove(&self, user: UserId, method: TwoFactorMethod) -> Result<(), StoreError> {
        let removed = two_factor::Entity::delete_many()
            .filter(two_factor::Column::UserId.eq(user.0))
            .filter(two_factor::Column::Method.eq(two_factor::method_str(method)))
            .exec(self.writer())
            .await
            .store()?;
        if removed.rows_affected > 0 {
            self.bump_version(user).await?;
        }
        Ok(())
    }

    async fn two_step_version(&self, user: UserId) -> Result<i64, StoreError> {
        // The writer, not the reader: a remembered device is checked right after a change.
        Ok(two_step_versions::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .map_or(0, |row| row.version))
    }
}
