//! The JSON of organizations, members, collections, groups and policies, in the shapes of
//! Vaultwarden 1.37.5's `to_json` functions.

use super::model::{ACCEPTED, MANAGER, MemberDoc, Org, PendingDoc, PolicyDoc, level};
use crate::dates::format_date;
use crate::settings::BwSettings;
use kemlock_domain::UserId;
use kemlock_domain::spaces::{Collection, CollectionId, Grantee, Group};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Vaultwarden's `i16::MAX` storage quota: shown, never checked.
const MAX_STORAGE_GB: i32 = 32_767;

/// What an account contributes to the member lists.
#[derive(Clone, Debug, Default)]
pub(crate) struct UserInfo {
    pub email: String,
    pub name: Option<String>,
    pub avatar_color: Option<String>,
    pub two_factor: bool,
    pub has_password: bool,
}

pub(crate) fn list(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })
}

/// `Organization::to_json`.
pub(crate) fn org_json(org: &Org, settings: &BwSettings) -> Value {
    json!({
        "id": org.id.to_string(),
        "name": org.name,
        "seats": null,
        "maxCollections": null,
        "maxStorageGb": MAX_STORAGE_GB,
        "use2fa": true,
        "useCustomPermissions": true,
        "useDirectory": false,
        "useEvents": settings.org_events_enabled,
        "useGroups": settings.org_groups_enabled,
        "useTotp": true,
        "usePolicies": true,
        "useScim": false,
        "useSso": false,
        "useKeyConnector": false,
        "usePasswordManager": true,
        "useSecretsManager": false,
        "selfHost": true,
        "useApi": true,
        "useDisableSMAdsForUsers": true,
        "useInviteLinks": false,
        "useMyItems": false,
        "useOrganizationDomains": false,
        "usePam": false,
        "usePhishingBlocker": false,
        "hasPublicAndPrivateKeys": org.doc.private_key.is_some() && org.doc.public_key.is_some(),
        "useResetPassword": true,
        "allowAdminAccessToAllCollectionItems": true,
        "limitCollectionCreation": true,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,

        "businessName": org.name,
        "businessAddress1": null,
        "businessAddress2": null,
        "businessAddress3": null,
        "businessCountry": null,
        "businessTaxNumber": null,

        "maxAutoscaleSeats": null,
        "maxAutoscaleSmSeats": null,
        "maxAutoscaleSmServiceAccounts": null,

        "secretsManagerPlan": null,
        "smSeats": null,
        "smServiceAccounts": null,

        "billingEmail": org.doc.billing_email,
        "planType": 6,
        "usersGetPremium": true,
        "object": "organization",
    })
}

fn custom_permissions(on: bool) -> Value {
    json!({
        "accessEventLogs": false,
        "accessImportExport": false,
        "accessReports": false,
        // The three collection permissions together make a custom member's access to everything.
        "createNewCollections": on,
        "editAnyCollection": on,
        "deleteAnyCollection": on,
        "manageGroups": false,
        "managePolicies": false,
        "manageSso": false,
        "manageUsers": false,
        "manageResetPassword": false,
        "manageScim": false
    })
}

/// `Membership::to_json`: the organization as it shows in an account's profile.
pub(crate) fn profile_org_json(
    org: &Org,
    user: UserId,
    doc: &MemberDoc,
    settings: &BwSettings,
) -> Value {
    let wire_type = doc.wire_type();
    let permissions = custom_permissions(wire_type == 4 && doc.access_all);
    json!({
        "id": org.id.to_string(),
        "identifier": null,
        "name": org.name,
        "seats": 20,
        "maxCollections": null,
        "usersGetPremium": true,
        "use2fa": true,
        "useDirectory": false,
        "useEvents": settings.org_events_enabled,
        "useGroups": settings.org_groups_enabled,
        "useTotp": true,
        "useScim": false,
        "usePolicies": true,
        "useApi": true,
        "selfHost": true,
        "hasPublicAndPrivateKeys": org.doc.private_key.is_some() && org.doc.public_key.is_some(),
        "resetPasswordEnrolled": doc.reset_password_key.is_some(),
        "useResetPassword": true,
        "ssoBound": false,
        "useSso": false,
        "useKeyConnector": false,
        "useSecretsManager": false,
        "usePasswordManager": true,
        "useCustomPermissions": true,
        "useActivateAutofillPolicy": false,
        "useAdminSponsoredFamilies": false,
        "useRiskInsights": false,
        "useDisableSMAdsForUsers": true,
        "useInviteLinks": false,
        "useMyItems": false,
        "useOrganizationDomains": false,
        "usePam": false,
        "usePhishingBlocker": false,

        "organizationUserId": user.to_string(),
        "providerId": null,
        "providerName": null,
        "providerType": null,
        "familySponsorshipFriendlyName": null,
        "familySponsorshipAvailable": false,
        "productTierType": 3,
        "keyConnectorEnabled": false,
        "keyConnectorUrl": null,
        "familySponsorshipLastSyncDate": null,
        "familySponsorshipValidUntil": null,
        "familySponsorshipToDelete": null,
        "accessSecretsManager": false,
        // Collection creation is limited to managers with access to everything.
        "limitCollectionCreation": level(doc.atype) < level(MANAGER) || !doc.access_all,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,
        "allowAdminAccessToAllCollectionItems": true,
        "userIsClaimedByOrganization": false,

        "permissions": permissions,

        "maxStorageGb": MAX_STORAGE_GB,

        "userId": user.to_string(),
        "key": (!doc.akey.is_empty()).then_some(&doc.akey),
        "status": doc.status,
        "type": wire_type,
        "enabled": true,

        "object": "profileOrganization",
    })
}

/// `Collection::to_json`.
pub(crate) fn collection_json(org: &Org, collection: &Collection) -> Value {
    json!({
        "externalId": org.external_id_of_collection(collection.id),
        "id": collection.id.to_string(),
        "organizationId": org.id.to_string(),
        "name": Org::collection_name(collection),
        "type": 0,
        "defaultUserCollectionEmail": null,
        "object": "collection",
    })
}

/// `Collection::to_json_details`: the collection with what `user` may do with it.
pub(crate) fn collection_details_json(org: &Org, collection: &Collection, user: UserId) -> Value {
    let flags = org.collection_flags(user, collection.id);
    let mut object = collection_json(org, collection);
    object["object"] = json!("collectionDetails");
    object["readOnly"] = json!(flags.read_only);
    object["hidePasswords"] = json!(flags.hide_passwords);
    object["manage"] = json!(flags.manage);
    object
}

/// The members with a direct grant on a collection, as `CollectionMembership::to_json_details_for_member`.
pub(crate) fn collection_members_json(org: &Org, collection: CollectionId) -> Vec<Value> {
    org.state
        .grants
        .iter()
        .filter(|g| g.collection == collection)
        .filter_map(|g| match g.grantee {
            Grantee::Member(user) => Some((user, g.permission)),
            Grantee::Group(_) => None,
        })
        .map(|(user, permission)| {
            let flags = super::model::Restrict::from_permission(permission);
            let atype = org.member(user).map_or(super::model::USER, |m| m.atype);
            json!({
                "id": user.to_string(),
                "readOnly": flags.read_only,
                "hidePasswords": flags.hide_passwords,
                "manage": level(atype) >= level(super::model::ADMIN)
                    || flags.manage
                    || (atype == MANAGER && !flags.read_only && !flags.hide_passwords),
            })
        })
        .collect()
}

/// The groups with a grant on a collection, as `CollectionGroup::to_json_details_for_group`.
pub(crate) fn collection_groups_json(org: &Org, collection: CollectionId) -> Vec<Value> {
    org.state
        .grants
        .iter()
        .filter(|g| g.collection == collection)
        .filter_map(|g| match g.grantee {
            Grantee::Group(group) => Some((group, g.permission)),
            Grantee::Member(_) => None,
        })
        .map(|(group, permission)| {
            let flags = super::model::Restrict::from_permission(permission);
            json!({
                "id": group.to_string(),
                "readOnly": flags.read_only,
                "hidePasswords": flags.hide_passwords,
                "manage": flags.manage,
            })
        })
        .collect()
}

/// `Group::to_json`.
pub(crate) fn group_json(org: &Org, group: &Group) -> Value {
    json!({
        "id": group.id.to_string(),
        "organizationId": org.id.to_string(),
        "name": Org::group_name(group),
        "externalId": org.group_doc(group.id).external_id,
        "object": "group",
    })
}

/// `Group::to_json_details`: the group with the collections it was given.
pub(crate) fn group_details_json(org: &Org, group: &Group) -> Value {
    let collections: Vec<Value> = org
        .state
        .grants
        .iter()
        .filter(|g| g.grantee == Grantee::Group(group.id))
        .map(|g| {
            let flags = super::model::Restrict::from_permission(g.permission);
            json!({
                "id": g.collection.to_string(),
                "readOnly": flags.read_only,
                "hidePasswords": flags.hide_passwords,
                "manage": flags.manage,
            })
        })
        .collect();
    json!({
        "id": group.id.to_string(),
        "organizationId": org.id.to_string(),
        "name": Org::group_name(group),
        "externalId": org.group_doc(group.id).external_id,
        "collections": collections,
        "object": "groupDetails",
    })
}

/// `OrgPolicy::to_json`.
pub(crate) fn policy_json(org_id: &str, ptype: i32, policy: &PolicyDoc) -> Value {
    let data: Value = serde_json::from_str(&policy.data).unwrap_or(Value::Null);
    let mut out = json!({
        "id": policy.id,
        "organizationId": org_id,
        "type": ptype,
        "data": data,
        "enabled": policy.enabled,
        "revisionDate": policy.revision_date,
        "object": "policy",
    });
    // Upstream adds this to the Reset Password policy; the same is returned here.
    if ptype == 8 {
        out["canToggleState"] = json!(true);
    }
    out
}

/// A policy nobody set: off, with no data.
pub(crate) fn blank_policy(org_id: &str, ptype: i32, now: OffsetDateTime, id: String) -> Value {
    policy_json(
        org_id,
        ptype,
        &PolicyDoc {
            id,
            enabled: false,
            data: "null".to_owned(),
            revision_date: format_date(now),
        },
    )
}

/// `Membership::to_json_details_for_admin`: how an admin sees a member.
pub(crate) fn member_admin_json(
    org: &Org,
    user: UserId,
    doc: &MemberDoc,
    info: &UserInfo,
    include_collections: bool,
    include_groups: bool,
) -> Value {
    let groups: Vec<String> = if include_groups {
        org.groups_of(user)
            .iter()
            .map(|g| g.id.to_string())
            .collect()
    } else {
        Vec::new()
    };
    let full_access_group = org.group_full_access(user);
    let collections: Vec<Value> = if include_collections && !(full_access_group || doc.access_all) {
        org.state
            .collections
            .iter()
            .filter_map(|c| {
                org.user_grant(user, c.id).map(|r| {
                    json!({
                        "id": c.id.to_string(),
                        "readOnly": r.read_only,
                        "hidePasswords": r.hide_passwords,
                        "manage": r.manage
                            || (doc.atype == MANAGER && !r.read_only && !r.hide_passwords),
                    })
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    let wire_type = doc.wire_type();
    let permissions = if wire_type == 4 && doc.access_all {
        custom_permissions(true)
    } else {
        Value::Null
    };
    let name = if doc.unrevoked_status() >= ACCEPTED {
        info.name.clone()
    } else {
        None
    };
    json!({
        "id": user.to_string(),
        "userId": user.to_string(),
        "name": name,
        "email": info.email,
        "externalId": doc.external_id,
        "avatarColor": info.avatar_color,
        "groups": groups,
        "collections": collections,

        "status": doc.wire_status(),
        "type": wire_type,
        "twoFactorEnabled": info.two_factor,
        "resetPasswordEnrolled": doc.reset_password_key.is_some(),
        "hasMasterPassword": info.has_password,

        "permissions": permissions,

        "ssoBound": false,
        "claimedByOrganization": false,
        "usesKeyConnector": false,
        "accessSecretsManager": false,

        "object": "organizationUserUserDetails",
    })
}

/// A pending invitation, as an admin sees it in the member list.
pub(crate) fn pending_admin_json(
    pending: &PendingDoc,
    include_collections: bool,
    include_groups: bool,
) -> Value {
    let wire_type = if pending.atype == MANAGER {
        4
    } else {
        pending.atype
    };
    let collections: Vec<Value> = if include_collections && !pending.access_all {
        pending
            .collections
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "readOnly": c.read_only,
                    "hidePasswords": c.hide_passwords,
                    "manage": c.manage,
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    let groups: Vec<String> = if include_groups {
        pending.groups.clone()
    } else {
        Vec::new()
    };
    let permissions = if wire_type == 4 && pending.access_all {
        custom_permissions(true)
    } else {
        Value::Null
    };
    json!({
        "id": pending.id,
        "userId": pending.id,
        "name": null,
        "email": pending.email,
        "externalId": pending.external_id,
        "avatarColor": null,
        "groups": groups,
        "collections": collections,

        "status": 0,
        "type": wire_type,
        "twoFactorEnabled": false,
        "resetPasswordEnrolled": false,
        "hasMasterPassword": false,

        "permissions": permissions,

        "ssoBound": false,
        "claimedByOrganization": false,
        "usesKeyConnector": false,
        "accessSecretsManager": false,

        "object": "organizationUserUserDetails",
    })
}

/// `Membership::to_json_mini_details`.
pub(crate) fn member_mini_json(user: UserId, doc: &MemberDoc, info: &UserInfo) -> Value {
    json!({
        "id": user.to_string(),
        "userId": user.to_string(),
        "type": doc.wire_type(),
        "status": doc.wire_status(),
        "name": info.name,
        "email": info.email,
        "object": "organizationUserUserMiniDetails",
    })
}

/// `Membership::to_json_user_access_restrictions`: a member with their flags on one collection.
pub(crate) fn member_access_json(
    user: UserId,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
) -> Value {
    json!({
        "id": user.to_string(),
        "readOnly": read_only,
        "hidePasswords": hide_passwords,
        "manage": manage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::model::{ADMIN, CONFIRMED, OWNER, OrgDoc, USER};
    use kemlock_domain::SpaceId;
    use kemlock_domain::spaces::{Space, SpaceState};
    use std::collections::BTreeMap;
    use time::macros::datetime;

    fn org() -> Org {
        let id = SpaceId::random();
        let now = datetime!(2026-11-23 10:00:00 UTC);
        Org {
            id,
            name: "Contract organization".to_owned(),
            doc: OrgDoc {
                billing_email: "ada@example.org".to_owned(),
                private_key: Some("2.k".to_owned()),
                public_key: Some("MIIB".to_owned()),
            },
            state: SpaceState {
                space: Space {
                    id,
                    name: b"Contract organization".to_vec(),
                    key_version: 1,
                    keys_pending_since: None,
                    created_at: now,
                    updated_at: now,
                },
                members: Vec::new(),
                groups: Vec::new(),
                collections: Vec::new(),
                grants: Vec::new(),
            },
            members: BTreeMap::new(),
            pending: Vec::new(),
            collection_docs: BTreeMap::new(),
            group_docs: BTreeMap::new(),
            policies: BTreeMap::new(),
            groups_enabled: true,
        }
    }

    fn keys(value: &Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn the_organization_has_vaultwardens_keys() {
        let settings = BwSettings::new("https://vault.test", true);
        let out = org_json(&org(), &settings);
        assert_eq!(out["object"], "organization");
        assert_eq!(out["planType"], 6);
        assert_eq!(out["maxStorageGb"], 32_767);
        assert_eq!(out["billingEmail"], "ada@example.org");
        assert_eq!(out["hasPublicAndPrivateKeys"], true);
        assert_eq!(out["useSso"], false);
        assert_eq!(out["useResetPassword"], true);
        assert_eq!(keys(&out).len(), 47);
    }

    #[test]
    fn the_profile_organization_shows_the_member_and_hides_an_empty_key() {
        let settings = BwSettings::new("https://vault.test", true);
        let org = org();
        let user = UserId::random();
        let mut doc = MemberDoc::new(OWNER, true, CONFIRMED);
        let out = profile_org_json(&org, user, &doc, &settings);
        assert_eq!(out["object"], "profileOrganization");
        assert_eq!(out["status"], 2);
        assert_eq!(out["type"], 0);
        assert_eq!(out["userId"], user.to_string());
        assert_eq!(out["organizationUserId"], user.to_string());
        assert!(
            out["key"].is_null(),
            "no key before the organization key is wrapped"
        );
        assert_eq!(out["limitCollectionCreation"], false);
        assert_eq!(out["permissions"]["createNewCollections"], false);

        doc.akey = "4.key".to_owned();
        doc.atype = MANAGER;
        let out = profile_org_json(&org, user, &doc, &settings);
        assert_eq!(out["key"], "4.key");
        assert_eq!(out["type"], 4, "a manager shows as a custom member");
        assert_eq!(out["permissions"]["editAnyCollection"], true);

        let user_doc = MemberDoc::new(USER, false, CONFIRMED);
        assert_eq!(
            profile_org_json(&org, user, &user_doc, &settings)["limitCollectionCreation"],
            true
        );
        assert_eq!(MemberDoc::new(ADMIN, true, CONFIRMED).atype, 1);
    }

    #[test]
    fn a_collection_and_a_policy_have_their_keys() {
        let mut org = org();
        let collection = Collection {
            id: CollectionId::random(),
            space: org.id,
            parent: None,
            name: b"2.encrypted".to_vec(),
            key_version: 1,
            stale_since: None,
            created_at: datetime!(2026-11-23 10:00:00 UTC),
        };
        org.state.collections.push(collection.clone());
        let out = collection_json(&org, &collection);
        assert_eq!(
            keys(&out),
            [
                "defaultUserCollectionEmail",
                "externalId",
                "id",
                "name",
                "object",
                "organizationId",
                "type"
            ]
        );
        assert_eq!(out["name"], "2.encrypted");

        let policy = PolicyDoc {
            id: "p1".to_owned(),
            enabled: true,
            data: "{\"minLength\":14}".to_owned(),
            revision_date: "2026-11-23T10:00:00.000000Z".to_owned(),
        };
        let out = policy_json("o1", 1, &policy);
        assert_eq!(out["data"]["minLength"], 14);
        assert!(out.get("canToggleState").is_none());
        assert_eq!(policy_json("o1", 8, &policy)["canToggleState"], true);
        let blank = blank_policy("o1", 3, datetime!(2026-11-23 10:00:00 UTC), "p2".to_owned());
        assert_eq!(blank["enabled"], false);
        assert!(blank["data"].is_null());
    }
}
