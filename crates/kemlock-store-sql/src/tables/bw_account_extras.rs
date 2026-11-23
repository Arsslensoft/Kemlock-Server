//! `bw_account_extras`: the columns of a Vaultwarden user that `bw_accounts` has no field for.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bw_account_extras")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    pub enabled: bool,
    pub verified_at: Option<TimeDateTimeWithTimeZone>,
    pub last_verifying_at: Option<TimeDateTimeWithTimeZone>,
    pub login_verify_count: i64,
    pub email_new: Option<String>,
    pub email_new_token: Option<String>,
    pub stamp_exception: Option<String>,
    pub equivalent_domains: String,
    pub excluded_globals: String,
    pub external_id: Option<String>,
    pub key_id: Option<String>,
    /// The legacy `users.totp_secret`, sealed under `server.key` (purpose `vw-account`).
    pub sealed_totp_secret: Option<Vec<u8>>,
    /// The legacy `users.totp_recover`, sealed likewise.
    pub sealed_totp_recover: Option<Vec<u8>>,
    /// The security stamp as Vaultwarden kept it; `users.security_stamp` is its UUID form.
    pub vw_security_stamp: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
