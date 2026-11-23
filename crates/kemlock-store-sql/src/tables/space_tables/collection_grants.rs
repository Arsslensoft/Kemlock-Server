//! `collection_grants`: a member's or group's permission on one collection.

use crate::convert::corrupt;
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use kemlock_domain::spaces::{
    CollectionGrant, CollectionId, CollectionPermission, Grantee, GroupId,
};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

/// `grantee_type` of a member.
pub(crate) const GRANTEE_MEMBER: i16 = 1;
/// `grantee_type` of a group.
pub(crate) const GRANTEE_GROUP: i16 = 2;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "collection_grants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub collection_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub grantee_type: i16,
    #[sea_orm(primary_key, auto_increment = false)]
    pub grantee_id: Uuid,
    /// `view`, `view-hide-passwords`, `edit`, `edit-hide-passwords` or `manage`.
    pub permission: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The two columns that name a grantee.
pub(crate) fn grantee_parts(grantee: Grantee) -> (i16, Uuid) {
    match grantee {
        Grantee::Member(user) => (GRANTEE_MEMBER, user.0),
        Grantee::Group(group) => (GRANTEE_GROUP, group.0),
    }
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<CollectionGrant, StoreError> {
        let grantee = match self.grantee_type {
            GRANTEE_MEMBER => Grantee::Member(UserId(self.grantee_id)),
            GRANTEE_GROUP => Grantee::Group(GroupId(self.grantee_id)),
            _ => return Err(corrupt("grantee type")),
        };
        Ok(CollectionGrant {
            collection: CollectionId(self.collection_id),
            grantee,
            permission: CollectionPermission::parse(&self.permission)
                .ok_or_else(|| corrupt("collection permission"))?,
        })
    }
}

pub(crate) fn active(grant: &CollectionGrant) -> ActiveModel {
    let (grantee_type, grantee_id) = grantee_parts(grant.grantee);
    ActiveModel {
        collection_id: Set(grant.collection.0),
        grantee_type: Set(grantee_type),
        grantee_id: Set(grantee_id),
        permission: Set(grant.permission.as_str().to_owned()),
    }
}
