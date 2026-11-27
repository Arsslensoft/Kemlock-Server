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
    ConnectionTrait, DatabaseTransaction, DbBackend, EntityTrait, QuerySelect, TransactionTrait,
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

/// Begins a transaction on the writer with the account's row locked until it ends. Every write of
/// a wrap of the account's root key (a passkey's PRF wrap, a device copy, the kit, an emergency
/// box, a recovery box, a Send, a device approval) takes it, and so does the install of a root-key
/// rotation, which reads what the account holds and then replaces it: a wrap written meanwhile
/// would otherwise be missed by the install and left sealed under the old root key.
pub(crate) async fn begin_locked(
    store: &SqlStore,
    user: UserId,
) -> Result<DatabaseTransaction, StoreError> {
    let txn = store.writer().begin().await.store()?;
    // A failure drops the transaction, which rolls it back.
    lock_owner(&txn, Owner::User(user)).await?;
    Ok(txn)
}

/// Refuses a wrap whose key version is not the account's: under the account's lock, the account's
/// `key_version` is read again, and a rotation's install is either committed (so it shows here) or
/// waits for the writer. The account's own version `0` (no keys yet) and an account that isn't
/// there accept any, as the foreign key of the insert that follows decides the latter.
pub(crate) async fn check_key_version<C: ConnectionTrait>(
    db: &C,
    user: UserId,
    key_version: u32,
) -> Result<(), StoreError> {
    let current: Option<i64> = users::Entity::find_by_id(user.0)
        .select_only()
        .column(users::Column::KeyVersion)
        .into_tuple()
        .one(db)
        .await
        .store()?;
    match current {
        Some(current) if current != 0 && current != i64::from(key_version) => {
            Err(StoreError::StaleKeyVersion {
                current: u32::try_from(current).unwrap_or(u32::MAX),
            })
        }
        _ => Ok(()),
    }
}

/// [`begin_locked`], and then, when the write is of a wrap made for `key_version`, the check of
/// [`check_key_version`]. `None` is a write that carries no version (an old client's Send).
pub(crate) async fn begin_locked_at(
    store: &SqlStore,
    user: UserId,
    key_version: Option<u32>,
) -> Result<DatabaseTransaction, StoreError> {
    let txn = begin_locked(store, user).await?;
    if let Some(key_version) = key_version {
        // A refusal drops the transaction, which rolls it back.
        check_key_version(&txn, user, key_version).await?;
    }
    Ok(txn)
}
