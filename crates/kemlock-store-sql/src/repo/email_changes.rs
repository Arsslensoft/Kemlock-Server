//! `ProfileRepo` on `sso_identities`, `email_changes`, and the two writes that replace an account's
//! sign-in records.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::sso::identities;
use crate::tables::{email_changes, emergency_access, users};
use kemlock_app::ports::StoreError;
use kemlock_app::profile::ProfileRepo;
use kemlock_domain::{Email, EmailChange, User, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter,
    TransactionTrait,
};

/// Commits only when the write happened (`Ok(true)`); anything else, a write that did not apply
/// included, rolls everything back, and the outcome is handed on.
async fn finish(
    txn: DatabaseTransaction,
    outcome: Result<bool, StoreError>,
    what: &str,
) -> Result<bool, StoreError> {
    match outcome {
        Ok(true) => {
            txn.commit().await.store()?;
            Ok(true)
        }
        other => {
            if let Err(rollback) = txn.rollback().await {
                tracing::warn!(%rollback, "rollback after {what} failed");
            }
            other
        }
    }
}

/// Writes the sign-in records of `after` (and its address, when `address`) over the account's row
/// while the row still is as `before` read it: the same `updated_at` and security stamp. Only these
/// columns are written, so nothing else on the row is put back to what `before` held. `false` when
/// no row matched, and `Duplicate` when the address is taken.
async fn update_account<C: ConnectionTrait>(
    db: &C,
    before: &User,
    after: &User,
    address: bool,
) -> Result<bool, StoreError> {
    let mut row = users::ActiveModel {
        opaque_record: Set(after.opaque_record.clone()),
        kdf_memory_kib: Set(i64::from(after.kdf.memory_kib)),
        kdf_iterations: Set(i64::from(after.kdf.iterations)),
        kdf_parallelism: Set(i64::from(after.kdf.parallelism)),
        kdf_salt: Set(after.kdf.salt.clone()),
        wrapped_root_key: Set(after.wrapped_root_key.clone()),
        security_stamp: Set(after.security_stamp),
        updated_at: Set(utc(after.updated_at)),
        ..Default::default()
    };
    if address {
        row.email = Set(after.email.as_str().to_owned());
    }
    let written = users::Entity::update_many()
        .set(row)
        .filter(users::Column::Id.eq(before.id.0))
        .filter(users::Column::UpdatedAt.eq(utc(before.updated_at)))
        .filter(users::Column::SecurityStamp.eq(before.security_stamp))
        .exec(db)
        .await;
    match written {
        Ok(result) => Ok(result.rows_affected == 1),
        Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
        Err(err) => Err(map_db(err)),
    }
}

/// Points the emergency-access grants of `user` at `new`: the grants the account is the contact
/// of, and the invitations still waiting at `old`. A grantor who has a grant to `new` already
/// (the unique index allows one grant per grantor and address) keeps the other as it was, still
/// tied to the account by its id.
async fn move_emergency<C: ConnectionTrait>(
    db: &C,
    user: UserId,
    old: &Email,
    new: &Email,
) -> Result<(), StoreError> {
    let rows = emergency_access::Entity::find()
        .filter(
            Condition::any()
                .add(emergency_access::Column::GranteeId.eq(user.0))
                .add(
                    Condition::all()
                        .add(emergency_access::Column::GranteeEmail.eq(old.as_str()))
                        .add(emergency_access::Column::GranteeId.is_null()),
                ),
        )
        .all(db)
        .await
        .store()?;
    for row in rows {
        if row.grantee_email == new.as_str() {
            continue;
        }
        let clash = emergency_access::Entity::find()
            .filter(emergency_access::Column::GrantorId.eq(row.grantor_id))
            .filter(emergency_access::Column::GranteeEmail.eq(new.as_str()))
            .one(db)
            .await
            .store()?
            .is_some();
        if clash {
            continue;
        }
        emergency_access::Entity::update_many()
            .col_expr(
                emergency_access::Column::GranteeEmail,
                Expr::value(new.as_str().to_owned()),
            )
            .filter(emergency_access::Column::Id.eq(row.id))
            .exec(db)
            .await
            .store()?;
    }
    Ok(())
}

impl ProfileRepo for SqlStore {
    async fn has_sso_identity(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(identities::Entity::find()
            .filter(identities::Column::UserId.eq(user.0))
            .one(self.reader())
            .await
            .store()?
            .is_some())
    }

    /// An upsert on the account: a new ask replaces the one before, whose link stops working.
    async fn put_email_change(&self, change: &EmailChange) -> Result<(), StoreError> {
        let conflict = OnConflict::column(email_changes::Column::UserId)
            .update_columns([
                email_changes::Column::Email,
                email_changes::Column::TokenHash,
                email_changes::Column::OpaqueRecord,
                email_changes::Column::KdfMemoryKib,
                email_changes::Column::KdfIterations,
                email_changes::Column::KdfParallelism,
                email_changes::Column::KdfSalt,
                email_changes::Column::WrappedRootKey,
                email_changes::Column::RequestedAt,
                email_changes::Column::ExpiresAt,
            ])
            .to_owned();
        let written = email_changes::Entity::insert(email_changes::active(change))
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match written {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn email_change_of(&self, user: UserId) -> Result<Option<EmailChange>, StoreError> {
        email_changes::Entity::find_by_id(user.0)
            .one(self.writer())
            .await
            .store()?
            .map(email_changes::Model::into_domain)
            .transpose()
    }

    /// Reads the change by its token's hash from the writer, so a link opened right after it was
    /// mailed finds it. The row stays: `apply_email_change` deletes it with the change it makes.
    async fn email_change_by_token(
        &self,
        token_hash: [u8; 32],
    ) -> Result<Option<EmailChange>, StoreError> {
        email_changes::Entity::find()
            .filter(email_changes::Column::TokenHash.eq(token_hash.to_vec()))
            .one(self.writer())
            .await
            .store()?
            .map(email_changes::Model::into_domain)
            .transpose()
    }

    async fn remove_email_change(&self, user: UserId) -> Result<(), StoreError> {
        email_changes::Entity::delete_many()
            .filter(email_changes::Column::UserId.eq(user.0))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    /// One transaction: the conditional update of the account's row, and the removal of its
    /// pending change.
    async fn replace_credentials(&self, before: &User, after: &User) -> Result<bool, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            if !update_account(&txn, before, after, false).await? {
                return Ok(false);
            }
            email_changes::Entity::delete_many()
                .filter(email_changes::Column::UserId.eq(before.id.0))
                .exec(&txn)
                .await
                .store()?;
            Ok::<bool, StoreError>(true)
        }
        .await;
        finish(txn, outcome, "replacing an account's credentials").await
    }

    /// One transaction: the conditional update of the account's row, the deletion of this very
    /// change (found by its user and its token's hash, so of two openings of the link at once one
    /// applies it), and the move of the emergency-access grants. When the change was already
    /// gone, the update is rolled back with it.
    async fn apply_email_change(
        &self,
        change: &EmailChange,
        before: &User,
        after: &User,
    ) -> Result<bool, StoreError> {
        let txn = self.writer().begin().await.store()?;
        let outcome = async {
            if !update_account(&txn, before, after, true).await? {
                return Ok(false);
            }
            let spent = email_changes::Entity::delete_many()
                .filter(email_changes::Column::UserId.eq(change.user.0))
                .filter(email_changes::Column::TokenHash.eq(change.token_hash.to_vec()))
                .exec(&txn)
                .await
                .store()?
                .rows_affected;
            if spent != 1 {
                return Ok(false);
            }
            move_emergency(&txn, change.user, &before.email, &after.email).await?;
            Ok::<bool, StoreError>(true)
        }
        .await;
        finish(txn, outcome, "applying a change of address").await
    }
}
