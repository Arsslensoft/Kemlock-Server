//! Named leases in `job_leases`: whoever holds an unexpired row for a name has the right to do
//! that job, so it runs on one replica at a time (migrations now; background jobs later).
//!
//! Taking a lease is two atomic statements that behave the same on every backend: an insert,
//! which the primary key refuses when someone holds the name, then, when it is refused, an update
//! that succeeds only on an expired row. Expiry is a safety net for a holder that crashed; a
//! holder that lives releases the lease itself.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation};
use crate::tables::job_leases;
use kemlock_app::ports::StoreError;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use time::{Duration, OffsetDateTime};

/// Tries once to take the lease `name` for `ttl`. `Ok(false)` means someone else holds it.
pub(crate) async fn try_acquire<C: ConnectionTrait>(
    db: &C,
    name: &str,
    holder: &str,
    ttl: Duration,
) -> Result<bool, StoreError> {
    let now = utc(OffsetDateTime::now_utc());
    let expires_at = now + ttl;

    let fresh = job_leases::ActiveModel {
        name: Set(name.to_owned()),
        holder: Set(holder.to_owned()),
        expires_at: Set(expires_at),
    };
    match job_leases::Entity::insert(fresh).exec(db).await {
        Ok(_) => return Ok(true),
        Err(err) if is_unique_violation(&err) => {}
        Err(err) => return Err(crate::error::map_db(err)),
    }

    // Someone holds the name: take it over only if their lease has run out.
    let takeover = job_leases::ActiveModel {
        name: NotSet,
        holder: Set(holder.to_owned()),
        expires_at: Set(expires_at),
    };
    let result = job_leases::Entity::update_many()
        .set(takeover)
        .filter(job_leases::Column::Name.eq(name))
        .filter(job_leases::Column::ExpiresAt.lt(now))
        .exec(db)
        .await
        .store()?;
    Ok(result.rows_affected == 1)
}

/// Gives the lease back, if `holder` still has it.
pub(crate) async fn release<C: ConnectionTrait>(
    db: &C,
    name: &str,
    holder: &str,
) -> Result<(), StoreError> {
    job_leases::Entity::delete_many()
        .filter(job_leases::Column::Name.eq(name))
        .filter(job_leases::Column::Holder.eq(holder))
        .exec(db)
        .await
        .store()?;
    Ok(())
}
