//! `groups`: a named set of a space's members (the members are in `group_members`).

use crate::convert::utc;
use kemlock_domain::spaces::{Group, GroupId};
use kemlock_domain::{SpaceId, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "groups")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub space_id: Uuid,
    /// The name, encrypted under the space key.
    pub name: Vec<u8>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    /// The group with the member ids read from `group_members`.
    pub(crate) fn into_domain(self, members: BTreeSet<UserId>) -> Group {
        Group {
            id: GroupId(self.id),
            space: SpaceId(self.space_id),
            name: self.name,
            members,
            created_at: self.created_at,
        }
    }
}

pub(crate) fn active(group: &Group) -> ActiveModel {
    ActiveModel {
        id: Set(group.id.0),
        space_id: Set(group.space.0),
        name: Set(group.name.clone()),
        created_at: Set(utc(group.created_at)),
    }
}
