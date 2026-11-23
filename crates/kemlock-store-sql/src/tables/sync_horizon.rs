//! `sync_horizon`: per owner and origin, the highest sequence number whose tombstone has been
//! purged. Per owner, so purging one account's old deletions never makes another account's
//! devices start a full sync.

use crate::convert::from_i64;
use kemlock_app::ports::StoreError;
use kemlock_domain::{ServerId, VersionVector};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sync_horizon")]
pub struct Model {
    /// `Owner::TYPE_USER` or `Owner::TYPE_SPACE`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_type: i16,
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub origin: Uuid,
    pub purged_through: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The horizon rows as one version vector: per origin, the highest sequence number purged among
/// them. Pass the rows of the owners the horizon is for.
pub(crate) fn to_vector(rows: Vec<Model>) -> Result<VersionVector, StoreError> {
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        entries.push((
            ServerId(row.origin),
            from_i64(row.purged_through, "purged_through")?,
        ));
    }
    Ok(entries.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(owner: Uuid, origin: ServerId, purged_through: i64) -> Model {
        Model {
            owner_type: 1,
            owner_id: owner,
            origin: origin.0,
            purged_through,
        }
    }

    #[test]
    fn rows_make_a_vector_and_zero_rows_vanish() {
        let a = ServerId::random();
        let b = ServerId::random();
        let owner = Uuid::new_v4();
        let v = to_vector(vec![row(owner, a, 9), row(owner, b, 0)]).expect("valid rows");
        assert_eq!(v.get(a), 9);
        assert_eq!(v.get(b), 0);
        assert!(to_vector(vec![row(owner, a, -1)]).is_err());
    }

    #[test]
    fn several_owners_rows_keep_the_highest_per_origin() {
        let a = ServerId::random();
        let v = to_vector(vec![
            row(Uuid::new_v4(), a, 4),
            row(Uuid::new_v4(), a, 11),
            row(Uuid::new_v4(), a, 7),
        ])
        .expect("valid rows");
        assert_eq!(v.get(a), 11);
    }
}
