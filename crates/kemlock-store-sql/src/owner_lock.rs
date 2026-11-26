//! A row lock that makes a count-then-write check hold when several replicas share one database.
//!
//! The attachment quota and the push-token cap sum or count an owner's rows and then insert one.
//! The store's in-process gate serializes that inside one server; a second replica on PostgreSQL or
//! MySQL has its own gate, so two replicas could each count before either inserts. Locking the
//! owner's own row (`SELECT ... FOR UPDATE`) inside the transaction makes the second wait for the
//! first to commit.

use crate::error::StoreResult;
use crate::tables::space_tables::spaces;
use crate::tables::users;
use kemlock_app::ports::StoreError;
use kemlock_domain::Owner;
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, QuerySelect};

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
