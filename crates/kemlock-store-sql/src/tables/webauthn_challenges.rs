//! `webauthn_challenges`: the state of a WebAuthn ceremony between its two calls, one row per
//! account and kind.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "webauthn_challenges")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// `ChallengeKind::as_str`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    /// The relying party's state, as JSON.
    pub state: Vec<u8>,
    pub expires_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
