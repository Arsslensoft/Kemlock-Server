//! `space_policy_settings`: a space's typed policy settings, as `kemlock_domain::policies::SpacePolicies`.

use crate::convert::{corrupt, from_i64_u32, utc};
use kemlock_app::policies::StoredPolicies;
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use kemlock_domain::policies::{MasterPasswordPolicy, SpacePolicies, TimeoutAction};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_policy_settings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space_id: Uuid,
    pub require_sso: bool,
    pub two_step: bool,
    pub single_space: bool,
    pub disable_export: bool,
    pub disable_send: bool,
    pub always_show_email: bool,
    pub no_pin_unlock: bool,
    pub central_ownership: bool,
    pub no_card_items: bool,
    /// Whether there are master password rules; the `mp_*` columns are their values.
    pub mp_on: bool,
    pub mp_min_length: Option<i64>,
    pub mp_min_complexity: Option<i16>,
    pub mp_require_upper: bool,
    pub mp_require_lower: bool,
    pub mp_require_numbers: bool,
    pub mp_require_special: bool,
    pub mp_enforce_on_login: bool,
    pub timeout_minutes: Option<i64>,
    /// `lock` or `logOut`.
    pub timeout_action: Option<String>,
    pub updated_at: TimeDateTimeWithTimeZone,
    pub updated_by: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn policies(&self) -> Result<SpacePolicies, StoreError> {
        let master_password = if self.mp_on {
            Some(MasterPasswordPolicy {
                min_length: self
                    .mp_min_length
                    .map(|n| from_i64_u32(n, "minimum password length"))
                    .transpose()?,
                min_complexity: self
                    .mp_min_complexity
                    .map(|n| u8::try_from(n).map_err(|_| corrupt("minimum complexity")))
                    .transpose()?,
                require_upper: self.mp_require_upper,
                require_lower: self.mp_require_lower,
                require_numbers: self.mp_require_numbers,
                require_special: self.mp_require_special,
                enforce_on_login: self.mp_enforce_on_login,
            })
        } else {
            None
        };
        let session_timeout_action = self
            .timeout_action
            .as_deref()
            .map(|text| TimeoutAction::parse(text).ok_or_else(|| corrupt("timeout action")))
            .transpose()?;
        Ok(SpacePolicies {
            require_sso: self.require_sso,
            two_step: self.two_step,
            master_password,
            single_space: self.single_space,
            disable_export: self.disable_export,
            disable_send: self.disable_send,
            always_show_email: self.always_show_email,
            session_timeout_minutes: self
                .timeout_minutes
                .map(|n| from_i64_u32(n, "session timeout"))
                .transpose()?,
            session_timeout_action,
            no_pin_unlock: self.no_pin_unlock,
            central_ownership: self.central_ownership,
            no_card_items: self.no_card_items,
        })
    }

    pub(crate) fn into_domain(self) -> Result<StoredPolicies, StoreError> {
        Ok(StoredPolicies {
            policies: self.policies()?,
            updated_at: Some(self.updated_at),
            updated_by: self.updated_by.map(UserId),
        })
    }
}

/// Every column set, the id included.
pub(crate) fn active(
    space: Uuid,
    policies: &SpacePolicies,
    by: UserId,
    at: time::OffsetDateTime,
) -> ActiveModel {
    active_by(space, policies, Some(by.0), at)
}

/// [`active`] for a write nobody in particular made (`updated_by` null).
pub(crate) fn active_by(
    space: Uuid,
    policies: &SpacePolicies,
    by: Option<Uuid>,
    at: time::OffsetDateTime,
) -> ActiveModel {
    let mp = policies.master_password.unwrap_or_default();
    ActiveModel {
        space_id: Set(space),
        require_sso: Set(policies.require_sso),
        two_step: Set(policies.two_step),
        single_space: Set(policies.single_space),
        disable_export: Set(policies.disable_export),
        disable_send: Set(policies.disable_send),
        always_show_email: Set(policies.always_show_email),
        no_pin_unlock: Set(policies.no_pin_unlock),
        central_ownership: Set(policies.central_ownership),
        no_card_items: Set(policies.no_card_items),
        mp_on: Set(policies.master_password.is_some()),
        mp_min_length: Set(mp.min_length.map(i64::from)),
        mp_min_complexity: Set(mp.min_complexity.map(i16::from)),
        mp_require_upper: Set(mp.require_upper),
        mp_require_lower: Set(mp.require_lower),
        mp_require_numbers: Set(mp.require_numbers),
        mp_require_special: Set(mp.require_special),
        mp_enforce_on_login: Set(mp.enforce_on_login),
        timeout_minutes: Set(policies.session_timeout_minutes.map(i64::from)),
        timeout_action: Set(policies
            .session_timeout_action
            .map(|a| a.as_str().to_owned())),
        updated_at: Set(utc(at)),
        updated_by: Set(by),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ActiveValue;
    use time::macros::datetime;

    fn busy() -> SpacePolicies {
        SpacePolicies {
            require_sso: true,
            two_step: true,
            master_password: Some(MasterPasswordPolicy {
                min_length: Some(14),
                min_complexity: Some(3),
                require_upper: true,
                require_lower: false,
                require_numbers: true,
                require_special: false,
                enforce_on_login: true,
            }),
            single_space: true,
            disable_export: true,
            disable_send: true,
            always_show_email: true,
            session_timeout_minutes: Some(30),
            session_timeout_action: Some(TimeoutAction::LogOut),
            no_pin_unlock: true,
            central_ownership: true,
            no_card_items: true,
        }
    }

    /// The value inside a `Set`.
    fn set<T: Into<sea_orm::Value>>(value: ActiveValue<T>) -> T {
        match value {
            ActiveValue::Set(v) | ActiveValue::Unchanged(v) => v,
            ActiveValue::NotSet => panic!("a column was not set"),
        }
    }

    /// The model the all-`Set` `ActiveModel` of `active` stands for.
    fn model_of(policies: &SpacePolicies) -> Model {
        let at = datetime!(2026-06-01 12:00 UTC);
        let a = active(Uuid::new_v4(), policies, UserId::random(), at);
        Model {
            space_id: set(a.space_id),
            require_sso: set(a.require_sso),
            two_step: set(a.two_step),
            single_space: set(a.single_space),
            disable_export: set(a.disable_export),
            disable_send: set(a.disable_send),
            always_show_email: set(a.always_show_email),
            no_pin_unlock: set(a.no_pin_unlock),
            central_ownership: set(a.central_ownership),
            no_card_items: set(a.no_card_items),
            mp_on: set(a.mp_on),
            mp_min_length: set(a.mp_min_length),
            mp_min_complexity: set(a.mp_min_complexity),
            mp_require_upper: set(a.mp_require_upper),
            mp_require_lower: set(a.mp_require_lower),
            mp_require_numbers: set(a.mp_require_numbers),
            mp_require_special: set(a.mp_require_special),
            mp_enforce_on_login: set(a.mp_enforce_on_login),
            timeout_minutes: set(a.timeout_minutes),
            timeout_action: set(a.timeout_action),
            updated_at: set(a.updated_at),
            updated_by: set(a.updated_by),
        }
    }

    #[test]
    fn typed_settings_survive_the_trip_through_a_row() {
        for policies in [SpacePolicies::default(), busy()] {
            assert_eq!(model_of(&policies).policies(), Ok(policies));
        }
    }

    #[test]
    fn master_password_rules_with_nothing_in_them_are_still_on() {
        let policies = SpacePolicies {
            master_password: Some(MasterPasswordPolicy::default()),
            ..SpacePolicies::default()
        };
        let row = model_of(&policies);
        assert!(row.mp_on);
        assert_eq!(row.policies(), Ok(policies));
        let off = model_of(&SpacePolicies::default()).policies();
        assert_eq!(off.map(|p| p.master_password), Ok(None));
    }

    #[test]
    fn the_stored_form_carries_when_and_by_whom() {
        let row = model_of(&busy());
        let by = row.updated_by.map(UserId);
        let stored = row.into_domain().expect("a valid row");
        assert_eq!(stored.policies, busy());
        assert_eq!(stored.updated_at, Some(datetime!(2026-06-01 12:00 UTC)));
        assert_eq!(stored.updated_by, by);
    }

    #[test]
    fn corrupt_values_are_refused() {
        let mut row = model_of(&busy());
        row.timeout_action = Some("sleep".to_owned());
        assert!(row.policies().is_err());
        let mut row = model_of(&busy());
        row.mp_min_length = Some(-1);
        assert!(row.policies().is_err());
        let mut row = model_of(&busy());
        row.mp_min_complexity = Some(-1);
        assert!(row.policies().is_err());
    }
}
