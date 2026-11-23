//! A space's policies as Bitwarden's policies, and back: for the Bitwarden API, whose apps enforce
//! them from their own sync (`/sync`'s `policies`, `/organizations/{id}/policies`).
//!
//! Bitwarden keeps one record per policy type, each with an `enabled` flag and a `data` blob; a
//! Kemlock space keeps typed settings. [`bitwarden_policies`] makes the records of what is on,
//! [`bitwarden_policy`] the record of one type (on or off), and [`apply_bitwarden`] takes a
//! record a Bitwarden client saved and sets the matching typed setting.
//!
//! The type numbers are Bitwarden's (see [`PolicyType`]). The data shapes follow Bitwarden's server
//! (`PolicyType.cs` and the `*PolicyData` models) and Vaultwarden's use of them:
//!
//! | type | `data` |
//! |---|---|
//! | 1 Master password | `minComplexity`, `minLength`, `requireUpper`, `requireLower`, `requireNumbers`, `requireSpecial`, `enforceOnLogin` |
//! | 7 Send options | `{"disableHideEmail": bool}` |
//! | 9 Maximum vault timeout | `{"type": "custom", "minutes": n, "action": "lock"\|"logOut"\|null}` |
//! | 15 Restricted item types | `[3]`, the card cipher type |
//! | the rest | `null` |

use kemlock_domain::SpaceId;
use kemlock_domain::policies::{
    EffectivePolicies, MasterPasswordPolicy, PolicyInvalid, PolicyType, SpacePolicies,
    TimeoutAction,
};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// Bitwarden's number of the card item type, which "Restricted item types" lists.
const CARD_CIPHER_TYPE: i64 = 3;

/// One policy as Bitwarden has it.
#[derive(Clone, Debug, PartialEq)]
pub struct BwPolicy {
    pub kind: PolicyType,
    pub enabled: bool,
    pub data: Value,
}

impl BwPolicy {
    /// The number Bitwarden calls the type.
    pub fn type_number(&self) -> i32 {
        self.kind.number()
    }

    /// The record as Bitwarden's API sends it: `id`, `organizationId`, `type`, `data`, `enabled`,
    /// `revisionDate` and `object`. `revision` is when the policies were last set; a space nobody
    /// set policies for has none, and the epoch stands in.
    pub fn to_json(&self, space: SpaceId, revision: Option<OffsetDateTime>) -> Value {
        let revision = revision
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
            .format(&Rfc3339)
            .unwrap_or_default();
        json!({
            "id": policy_id(space, self.kind),
            "organizationId": space.to_string(),
            "type": self.kind.number(),
            "data": self.data,
            "enabled": self.enabled,
            "revisionDate": revision,
            "object": "policy",
        })
    }
}

/// A policy's id: stable, so a client that keeps one sees the same id on every sync. Derived from
/// the space and the type, as policies have no ids of their own here.
pub fn policy_id(space: SpaceId, kind: PolicyType) -> Uuid {
    let n = space.0.as_u128() ^ (u128::from(kind.number().unsigned_abs()) + 1);
    Uuid::from_u128(n)
}

fn master_password_data(mp: &MasterPasswordPolicy) -> Value {
    json!({
        "minComplexity": mp.min_complexity,
        "minLength": mp.min_length,
        "requireUpper": mp.require_upper,
        "requireLower": mp.require_lower,
        "requireNumbers": mp.require_numbers,
        "requireSpecial": mp.require_special,
        "enforceOnLogin": mp.enforce_on_login,
    })
}

/// The record of one policy type, on or off.
pub fn bitwarden_policy(policies: &SpacePolicies, kind: PolicyType) -> BwPolicy {
    let enabled = policies.is_enabled(kind);
    let data = match kind {
        PolicyType::MasterPassword => policies
            .master_password
            .as_ref()
            .map_or(Value::Null, master_password_data),
        PolicyType::SendOptions => json!({"disableHideEmail": policies.always_show_email}),
        PolicyType::MaximumVaultTimeout => match policies.session_timeout_minutes {
            Some(minutes) => json!({
                "type": "custom",
                "minutes": minutes,
                "action": policies.session_timeout_action.map(TimeoutAction::as_str),
            }),
            None => Value::Null,
        },
        PolicyType::RestrictedItemTypes if policies.no_card_items => json!([CARD_CIPHER_TYPE]),
        _ => Value::Null,
    };
    BwPolicy {
        kind,
        enabled,
        data,
    }
}

/// The records of every policy that is on, in type order.
pub fn bitwarden_policies(policies: &SpacePolicies) -> Vec<BwPolicy> {
    policies
        .enabled_types()
        .into_iter()
        .map(|kind| bitwarden_policy(policies, kind))
        .collect()
}

/// A number in a record's `data`, under its camelCase name or Bitwarden's PascalCase one.
fn number(data: &Value, key: &str) -> Option<i64> {
    pascal_or_camel(data, key).and_then(Value::as_i64)
}

fn flag(data: &Value, key: &str) -> bool {
    pascal_or_camel(data, key)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn pascal_or_camel<'a>(data: &'a Value, key: &str) -> Option<&'a Value> {
    let object = data.as_object()?;
    object.get(key).or_else(|| {
        let mut pascal = key.to_owned();
        pascal[..1].make_ascii_uppercase();
        object.get(&pascal)
    })
}

fn small(n: i64, what: &'static str) -> Result<u32, PolicyInvalid> {
    u32::try_from(n).map_err(|_| PolicyInvalid(what))
}

/// Applies a record a Bitwarden client saved (`PUT /organizations/{id}/policies/{type}`) to the
/// typed settings. A type Kemlock doesn't serve is refused. A record that turns a policy off clears
/// its setting. The result is checked with [`SpacePolicies::validate`].
pub fn apply_bitwarden(
    policies: &mut SpacePolicies,
    type_number: i32,
    enabled: bool,
    data: &Value,
) -> Result<(), PolicyInvalid> {
    let kind = PolicyType::from_number(type_number).ok_or(PolicyInvalid(
        "this server doesn't support that policy type",
    ))?;
    match kind {
        PolicyType::TwoFactorAuthentication => policies.two_step = enabled,
        PolicyType::SingleOrg => policies.single_space = enabled,
        PolicyType::RequireSso => policies.require_sso = enabled,
        PolicyType::PersonalOwnership => policies.central_ownership = enabled,
        PolicyType::DisableSend => policies.disable_send = enabled,
        PolicyType::DisablePersonalVaultExport => policies.disable_export = enabled,
        PolicyType::RemoveUnlockWithPin => policies.no_pin_unlock = enabled,
        PolicyType::RestrictedItemTypes => policies.no_card_items = enabled,
        PolicyType::SendOptions => {
            policies.always_show_email = enabled && flag(data, "disableHideEmail");
        }
        PolicyType::MasterPassword => {
            policies.master_password = if enabled {
                Some(master_password_from(data)?)
            } else {
                None
            };
        }
        PolicyType::MaximumVaultTimeout => {
            if enabled {
                let minutes = number(data, "minutes").ok_or(PolicyInvalid(
                    "the session timeout needs its length in minutes",
                ))?;
                policies.session_timeout_minutes = Some(small(
                    minutes,
                    "the session timeout must be 1 minute to a year",
                )?);
                policies.session_timeout_action = pascal_or_camel(data, "action")
                    .and_then(Value::as_str)
                    .and_then(TimeoutAction::parse);
            } else {
                policies.session_timeout_minutes = None;
                policies.session_timeout_action = None;
            }
        }
    }
    policies.validate()
}

fn master_password_from(data: &Value) -> Result<MasterPasswordPolicy, PolicyInvalid> {
    let min_length = number(data, "minLength")
        .map(|n| small(n, "the minimum password length must be 1 to 128 characters"))
        .transpose()?;
    let min_complexity = number(data, "minComplexity")
        .map(|n| {
            u8::try_from(n).map_err(|_| PolicyInvalid("the minimum complexity must be 0 to 4"))
        })
        .transpose()?;
    Ok(MasterPasswordPolicy {
        min_length,
        min_complexity,
        require_upper: flag(data, "requireUpper"),
        require_lower: flag(data, "requireLower"),
        require_numbers: flag(data, "requireNumbers"),
        require_special: flag(data, "requireSpecial"),
        enforce_on_login: flag(data, "enforceOnLogin"),
    })
}

/// The `masterPasswordPolicy` object of a Bitwarden sign-in answer, from what binds the person:
/// the camelCase keys Bitwarden's apps read, plus `Object`. Without a master password policy it is
/// only `Object`, as Vaultwarden answers. `identity` capitalises the keys, as the identity answer
/// does (some clients read only those).
pub fn master_password_policy_json(effective: &EffectivePolicies, identity: bool) -> Value {
    let mut object = match effective.master_password.as_ref().map(master_password_data) {
        Some(Value::Object(object)) => object,
        _ => Map::new(),
    };
    object.insert("Object".to_owned(), json!("masterPasswordPolicy"));
    if identity {
        object = object
            .into_iter()
            .map(|(mut key, value)| {
                key[..1].make_ascii_uppercase();
                (key, value)
            })
            .collect();
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on() -> SpacePolicies {
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

    #[test]
    fn a_space_with_everything_on_makes_one_record_per_type_in_number_order() {
        let records = bitwarden_policies(&all_on());
        let numbers: Vec<i32> = records.iter().map(BwPolicy::type_number).collect();
        assert_eq!(numbers, vec![0, 1, 3, 4, 5, 6, 7, 9, 10, 14, 15]);
        assert!(records.iter().all(|r| r.enabled));
    }

    #[test]
    fn a_space_with_nothing_on_makes_no_records_but_any_type_can_be_asked_for() {
        let none = SpacePolicies::default();
        assert!(bitwarden_policies(&none).is_empty());
        let asked = bitwarden_policy(&none, PolicyType::MasterPassword);
        assert!(!asked.enabled);
        assert_eq!(asked.data, Value::Null);
        let send = bitwarden_policy(&none, PolicyType::SendOptions);
        assert!(!send.enabled);
        assert_eq!(send.data, json!({"disableHideEmail": false}));
    }

    #[test]
    fn the_data_blobs_have_bitwardens_shapes() {
        let p = all_on();
        assert_eq!(
            bitwarden_policy(&p, PolicyType::MasterPassword).data,
            json!({
                "minComplexity": 3,
                "minLength": 14,
                "requireUpper": true,
                "requireLower": false,
                "requireNumbers": true,
                "requireSpecial": false,
                "enforceOnLogin": true,
            })
        );
        assert_eq!(
            bitwarden_policy(&p, PolicyType::SendOptions).data,
            json!({"disableHideEmail": true})
        );
        assert_eq!(
            bitwarden_policy(&p, PolicyType::MaximumVaultTimeout).data,
            json!({"type": "custom", "minutes": 30, "action": "logOut"})
        );
        assert_eq!(
            bitwarden_policy(&p, PolicyType::RestrictedItemTypes).data,
            json!([3])
        );
        assert_eq!(
            bitwarden_policy(&p, PolicyType::TwoFactorAuthentication).data,
            Value::Null
        );
    }

    #[test]
    fn a_record_serialises_as_bitwardens_policy_object() {
        let space = SpaceId::random();
        let at = time::macros::datetime!(2026-06-01 12:00 UTC);
        let record = bitwarden_policy(&all_on(), PolicyType::SingleOrg);
        let json = record.to_json(space, Some(at));
        assert_eq!(json["type"], 3);
        assert_eq!(json["enabled"], true);
        assert_eq!(json["object"], "policy");
        assert_eq!(json["organizationId"], space.to_string());
        assert_eq!(json["revisionDate"], "2026-06-01T12:00:00Z");
        assert_eq!(json["data"], Value::Null);
        assert_eq!(
            json["id"],
            policy_id(space, PolicyType::SingleOrg).to_string()
        );
        // An unset space dates from the epoch.
        let unset = record.to_json(space, None);
        assert_eq!(unset["revisionDate"], "1970-01-01T00:00:00Z");
    }

    #[test]
    fn policy_ids_are_stable_and_differ_by_space_and_type() {
        let a = SpaceId::random();
        let b = SpaceId::random();
        assert_eq!(
            policy_id(a, PolicyType::RequireSso),
            policy_id(a, PolicyType::RequireSso)
        );
        assert_ne!(
            policy_id(a, PolicyType::RequireSso),
            policy_id(a, PolicyType::SingleOrg)
        );
        assert_ne!(
            policy_id(a, PolicyType::RequireSso),
            policy_id(b, PolicyType::RequireSso)
        );
    }

    #[test]
    fn what_a_space_serves_a_client_can_save_back() {
        let original = all_on();
        let mut rebuilt = SpacePolicies::default();
        for record in bitwarden_policies(&original) {
            apply_bitwarden(
                &mut rebuilt,
                record.type_number(),
                record.enabled,
                &record.data,
            )
            .expect("a served record applies");
        }
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn saving_a_record_turned_off_clears_its_setting() {
        let mut p = all_on();
        for kind in PolicyType::ALL {
            apply_bitwarden(&mut p, kind.number(), false, &Value::Null).expect("turns off");
        }
        assert_eq!(p, SpacePolicies::default());
    }

    #[test]
    fn a_bitwarden_client_may_write_pascal_case_and_skip_fields() {
        let mut p = SpacePolicies::default();
        apply_bitwarden(
            &mut p,
            1,
            true,
            &json!({"MinLength": 14, "RequireUpper": true}),
        )
        .expect("applies");
        assert_eq!(
            p.master_password,
            Some(MasterPasswordPolicy {
                min_length: Some(14),
                require_upper: true,
                ..MasterPasswordPolicy::default()
            })
        );
        apply_bitwarden(&mut p, 7, true, &json!({"DisableHideEmail": true})).expect("applies");
        assert!(p.always_show_email);
        // Send options on without the flag does nothing.
        apply_bitwarden(&mut p, 7, true, &json!({"disableHideEmail": false})).expect("applies");
        assert!(!p.always_show_email);
    }

    #[test]
    fn unsupported_types_and_bad_values_are_refused() {
        let mut p = SpacePolicies::default();
        assert!(apply_bitwarden(&mut p, 2, true, &Value::Null).is_err());
        assert!(apply_bitwarden(&mut p, 99, true, &Value::Null).is_err());
        assert!(apply_bitwarden(&mut p, 1, true, &json!({"minLength": 500})).is_err());
        assert!(apply_bitwarden(&mut p, 1, true, &json!({"minLength": -3})).is_err());
        assert!(apply_bitwarden(&mut p, 9, true, &json!({"type": "custom"})).is_err());
        assert!(apply_bitwarden(&mut p, 9, true, &json!({"minutes": 0})).is_err());
    }

    #[test]
    fn the_master_password_policy_object_is_only_object_without_a_policy() {
        let none = EffectivePolicies::default();
        assert_eq!(
            master_password_policy_json(&none, false),
            json!({"Object": "masterPasswordPolicy"})
        );
        assert_eq!(
            master_password_policy_json(&none, true),
            json!({"Object": "masterPasswordPolicy"})
        );
    }

    #[test]
    fn the_master_password_policy_object_carries_the_strictest_rules() {
        let effective = EffectivePolicies {
            master_password: Some(MasterPasswordPolicy::fourteen_characters()),
            ..EffectivePolicies::default()
        };
        let plain = master_password_policy_json(&effective, false);
        assert_eq!(plain["minLength"], 14);
        assert_eq!(plain["minComplexity"], Value::Null);
        assert_eq!(plain["requireUpper"], false);
        assert_eq!(plain["Object"], "masterPasswordPolicy");
        let identity = master_password_policy_json(&effective, true);
        assert_eq!(identity["MinLength"], 14);
        assert_eq!(identity["EnforceOnLogin"], false);
        assert_eq!(identity["Object"], "masterPasswordPolicy");
        assert!(identity.get("minLength").is_none());
    }
}
