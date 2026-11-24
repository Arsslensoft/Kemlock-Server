//! `recovery_kits`: an account's Recovery Kit record (docs/crypto.md, "The Recovery Kit").

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::{RecoveryKit, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "recovery_kits")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// 8 base32 characters.
    pub kit_id: String,
    /// The root key wrapped under the kit key.
    pub wrapped_key: Vec<u8>,
    pub key_version: i64,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<RecoveryKit, StoreError> {
        Ok(RecoveryKit {
            kit_id: self.kit_id,
            wrapped_key: self.wrapped_key,
            key_version: u32::try_from(self.key_version)
                .map_err(|_| corrupt("recovery kit key version"))?,
            created_at: self.created_at,
        })
    }
}

pub(crate) fn active(user: UserId, kit: &RecoveryKit) -> ActiveModel {
    ActiveModel {
        user_id: Set(user.0),
        kit_id: Set(kit.kit_id.clone()),
        wrapped_key: Set(kit.wrapped_key.clone()),
        key_version: Set(i64::from(kit.key_version)),
        created_at: Set(utc(kit.created_at)),
    }
}
