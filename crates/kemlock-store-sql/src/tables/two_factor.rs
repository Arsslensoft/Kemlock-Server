//! `two_factor`: the two-step enrolments of an account, one row per method.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::{StoreError, TwoFactor, TwoFactorMethod};
use kemlock_domain::UserId;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "two_factor")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: Uuid,
    /// `TwoFactorMethod::as_str`: `totp`, `webauthn`, `email`, `yubikey` or `duo`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub method: String,
    pub sealed_secret: Vec<u8>,
    pub enabled: bool,
    /// The newest TOTP time step accepted at sign-in; none before the first. Only
    /// `accept_totp_step` writes it.
    pub last_used_step: Option<i64>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub(crate) fn method_str(method: TwoFactorMethod) -> &'static str {
    method.as_str()
}

fn method_from(s: &str) -> Result<TwoFactorMethod, StoreError> {
    TwoFactorMethod::parse(s).ok_or_else(|| corrupt("two-step method"))
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<TwoFactor, StoreError> {
        Ok(TwoFactor {
            user: UserId(self.user_id),
            method: method_from(&self.method)?,
            sealed_secret: self.sealed_secret,
            enabled: self.enabled,
            created_at: self.created_at,
        })
    }
}

/// Every column an enrolment carries. `last_used_step` is left out: an insert gets the column's
/// null, and an upsert keeps the step already recorded.
pub(crate) fn active(two_factor: &TwoFactor) -> ActiveModel {
    ActiveModel {
        user_id: Set(two_factor.user.0),
        method: Set(method_str(two_factor.method).to_owned()),
        sealed_secret: Set(two_factor.sealed_secret.clone()),
        enabled: Set(two_factor.enabled),
        last_used_step: NotSet,
        created_at: Set(utc(two_factor.created_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn methods_round_trip() {
        for method in [
            TwoFactorMethod::Totp,
            TwoFactorMethod::WebAuthn,
            TwoFactorMethod::Email,
            TwoFactorMethod::YubiKey,
            TwoFactorMethod::Duo,
        ] {
            assert_eq!(method_from(method_str(method)), Ok(method));
        }
        assert!(method_from("sms").is_err());
    }

    #[test]
    fn a_row_becomes_an_enrolment() {
        let user = UserId::random();
        let model = Model {
            user_id: user.0,
            method: "totp".to_owned(),
            sealed_secret: vec![1, 2, 3],
            enabled: true,
            last_used_step: Some(7),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
        };
        let two_factor = model.into_domain().expect("valid row");
        assert_eq!(two_factor.user, user);
        assert_eq!(two_factor.method, TwoFactorMethod::Totp);
        assert_eq!(active(&two_factor).enabled, Set(true));
    }
}
