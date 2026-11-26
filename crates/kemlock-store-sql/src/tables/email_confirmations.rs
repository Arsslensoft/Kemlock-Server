//! `email_confirmations`: the accounts held back until the link mailed to their address is
//! opened, as `kemlock_app::ports::EmailConfirmation`.

use kemlock_app::ports::EmailConfirmation;
use kemlock_domain::UserId;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "email_confirmations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// The SHA-256 of the link's token, 32 bytes; unique.
    pub token_hash: Vec<u8>,
    pub requested_at: TimeDateTimeWithTimeZone,
    pub expires_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> EmailConfirmation {
        EmailConfirmation {
            user: UserId(self.user_id),
            requested_at: self.requested_at,
            expires_at: self.expires_at,
        }
    }
}
