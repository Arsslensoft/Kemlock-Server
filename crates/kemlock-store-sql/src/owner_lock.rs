//! A row lock that makes a count-then-write check hold when several replicas share one database.
//!
//! The attachment quota and the push-token cap sum or count an owner's rows and then insert one.
//! The store's in-process gate serializes that inside one server; a second replica on PostgreSQL or
//! MySQL has its own gate, so two replicas could each count before either inserts. Locking the
//! owner's own row (`SELECT ... FOR UPDATE`) inside the transaction makes the second wait for the
//! first to commit.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::space_tables::spaces;
use crate::tables::users;
use kemlock_app::ports::StoreError;
use kemlock_domain::{Owner, UserId};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, QueryFilter,
    QuerySelect, TransactionTrait,
};

/// Locks the row of `owner` (an account or a space) until the transaction `db` ends. On SQLite,
/// which has one writer connection and no row locks, it does nothing. An owner with no row locks
/// nothing, which is fine: the insert that follows then fails its foreign key.
pub(crate) async fn lock_owner<C: ConnectionTrait>(db: &C, owner: Owner) -> Result<(), StoreError> {
    if db.get_database_backend() == DbBackend::Sqlite {
        return Ok(());
    }
    match owner {
        Owner::User(user) => {
            users::Entity::find_by_id(user.0)
                .lock_exclusive()
                .one(db)
                .await
                .store()?;
        }
        Owner::Space(space) => {
            spaces::Entity::find_by_id(space.0)
                .lock_exclusive()
                .one(db)
                .await
                .store()?;
        }
    }
    Ok(())
}

/// Locks the account's row (`SELECT … FOR UPDATE`; SQLite has one writer and no row locks) and
/// returns its `key_version` as that locking read saw it, or `None` when there is no such account.
/// Reading the version from the locking read itself matters on MySQL's REPEATABLE READ: a later
/// plain read in the same transaction would see the snapshot from before the lock was granted.
async fn lock_account<C: ConnectionTrait>(db: &C, user: UserId) -> Result<Option<i64>, StoreError> {
    let query = users::Entity::find_by_id(user.0);
    let query = if db.get_database_backend() == DbBackend::Sqlite {
        query
    } else {
        query.lock_exclusive()
    };
    Ok(query.one(db).await.store()?.map(|row| row.key_version))
}

/// Refuses a wrap whose key version is not the account's. `current` is the account's version as
/// the row lock's own read saw it, so a rotation's install is either committed (and shows here) or
/// waits for the writer. The account's own version `0` (no keys yet) and an account that isn't
/// there accept any, as the foreign key of the insert that follows decides the latter.
fn check_key_version(current: Option<i64>, key_version: u32) -> Result<(), StoreError> {
    match current {
        Some(current) if current != 0 && current != i64::from(key_version) => {
            Err(StoreError::StaleKeyVersion {
                current: u32::try_from(current).unwrap_or(u32::MAX),
            })
        }
        _ => Ok(()),
    }
}

/// Begins a transaction on the writer with the account's row locked until it ends. Every write of
/// a wrap of the account's root key (a passkey's PRF wrap, a device copy, the kit, an emergency
/// box, a recovery box, a Send, a device approval) takes it, and so does the install of a root-key
/// rotation, which reads what the account holds and then replaces it: a wrap written meanwhile
/// would otherwise be missed by the install and left sealed under the old root key.
pub(crate) async fn begin_locked(
    store: &SqlStore,
    user: UserId,
) -> Result<DatabaseTransaction, StoreError> {
    begin_locked_at(store, user, None).await
}

/// [`begin_locked`], and then, when the write is of a wrap made for `key_version`, the check of
/// that version against the one the lock's own read returned. `None` is a write that carries no
/// version (an old client's).
pub(crate) async fn begin_locked_at(
    store: &SqlStore,
    user: UserId,
    key_version: Option<u32>,
) -> Result<DatabaseTransaction, StoreError> {
    let txn = store.writer().begin().await.store()?;
    // A failure or a refusal drops the transaction, which rolls it back.
    let current = lock_account(&txn, user).await?;
    if let Some(key_version) = key_version {
        check_key_version(current, key_version)?;
    }
    Ok(txn)
}

/// A held account lock, for tests of the races it orders: the account's row is locked and its key
/// version set, as a rotation's install does, until [`AccountHold::commit`]. Not for production.
#[doc(hidden)]
pub struct AccountHold(DatabaseTransaction);

impl AccountHold {
    /// Takes the account's lock and sets its key version, uncommitted.
    pub async fn take(store: &SqlStore, user: UserId, key_version: u32) -> Result<Self, StoreError> {
        let txn = begin_locked(store, user).await?;
        users::Entity::update_many()
            .col_expr(
                users::Column::KeyVersion,
                sea_orm::sea_query::Expr::value(i64::from(key_version)),
            )
            .filter(users::Column::Id.eq(user.0))
            .exec(&txn)
            .await
            .store()?;
        Ok(AccountHold(txn))
    }

    /// Commits the key version and releases the lock.
    pub async fn commit(self) -> Result<(), StoreError> {
        self.0.commit().await.store()
    }
}
