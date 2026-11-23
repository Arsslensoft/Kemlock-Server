//! `sso_settings`: the provider connection, one row.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_app::sso::SsoSettings;
use kemlock_app::sso::rules::{rules_from_json, rules_to_json};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

/// The only row's id; the primary key keeps a second row from ever existing.
pub(crate) const ROW_ID: i32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sso_settings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub enabled: bool,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    /// The client secret sealed under `server.key`.
    pub sealed_client_secret: Option<Vec<u8>>,
    /// Space-separated scopes beyond `openid`.
    pub scopes: String,
    pub allow_unknown_email_verification: bool,
    pub link_by_email: bool,
    pub create_accounts: bool,
    pub require_verified_domain: bool,
    /// The group rules as a JSON list.
    pub group_rules: String,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<SsoSettings, StoreError> {
        let group_rules = rules_from_json(&self.group_rules).map_err(|_| corrupt("group rules"))?;
        Ok(SsoSettings {
            enabled: self.enabled,
            display_name: self.display_name,
            issuer: self.issuer,
            client_id: self.client_id,
            sealed_client_secret: self.sealed_client_secret,
            scopes: self.scopes.split_whitespace().map(str::to_owned).collect(),
            allow_unknown_email_verification: self.allow_unknown_email_verification,
            link_by_email: self.link_by_email,
            create_accounts: self.create_accounts,
            require_verified_domain: self.require_verified_domain,
            group_rules,
            updated_at: self.updated_at,
        })
    }
}

/// Every column set, the id included.
pub(crate) fn active(settings: &SsoSettings) -> ActiveModel {
    ActiveModel {
        id: Set(ROW_ID),
        enabled: Set(settings.enabled),
        display_name: Set(settings.display_name.clone()),
        issuer: Set(settings.issuer.clone()),
        client_id: Set(settings.client_id.clone()),
        sealed_client_secret: Set(settings.sealed_client_secret.clone()),
        scopes: Set(settings.scopes.join(" ")),
        allow_unknown_email_verification: Set(settings.allow_unknown_email_verification),
        link_by_email: Set(settings.link_by_email),
        create_accounts: Set(settings.create_accounts),
        require_verified_domain: Set(settings.require_verified_domain),
        group_rules: Set(rules_to_json(&settings.group_rules)),
        updated_at: Set(utc(settings.updated_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::sso::{GroupRule, SpaceRole};
    use kemlock_domain::SpaceId;
    use time::macros::datetime;

    fn settings() -> SsoSettings {
        let mut s = SsoSettings::new(
            "https://idp.example.org/realms/kemlock",
            "kemlock",
            datetime!(2026-01-02 03:04:05 UTC),
        );
        s.sealed_client_secret = Some(vec![1, 2, 3]);
        s.scopes = vec!["email".into(), "profile".into(), "groups".into()];
        s.group_rules = vec![GroupRule {
            group: "eng".into(),
            space: SpaceId::random(),
            role: SpaceRole::Admin,
            collections: vec![Uuid::from_u128(4)],
        }];
        s
    }

    fn model_of(s: &SsoSettings) -> Model {
        Model {
            id: ROW_ID,
            enabled: s.enabled,
            display_name: s.display_name.clone(),
            issuer: s.issuer.clone(),
            client_id: s.client_id.clone(),
            sealed_client_secret: s.sealed_client_secret.clone(),
            scopes: s.scopes.join(" "),
            allow_unknown_email_verification: s.allow_unknown_email_verification,
            link_by_email: s.link_by_email,
            create_accounts: s.create_accounts,
            require_verified_domain: s.require_verified_domain,
            group_rules: rules_to_json(&s.group_rules),
            updated_at: s.updated_at,
        }
    }

    #[test]
    fn settings_survive_the_trip_through_a_row() {
        let s = settings();
        assert_eq!(model_of(&s).into_domain(), Ok(s.clone()));
        assert_eq!(active(&s).scopes, Set("email profile groups".to_owned()));
    }

    #[test]
    fn corrupt_group_rules_are_refused() {
        let mut model = model_of(&settings());
        model.group_rules = "{not json".to_owned();
        assert!(model.into_domain().is_err());
    }

    #[test]
    fn no_scopes_is_an_empty_list() {
        let mut s = settings();
        s.scopes.clear();
        assert_eq!(
            model_of(&s).into_domain().expect("valid").scopes,
            Vec::<String>::new()
        );
    }
}
