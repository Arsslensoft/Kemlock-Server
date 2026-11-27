//! Collections, groups and policies of an organization, with Vaultwarden's rules and messages.

use super::guard::Ctx;
use super::json::{
    collection_details_json, collection_groups_json, collection_json, collection_members_json,
    group_json, policy_json,
};
use super::members::{parse_collection, parse_group};
use super::model::{
    ACCEPTED, ADMIN, AccessDoc, CollectionDoc, GroupDoc, KIND_COLLECTION, KIND_GROUP, KIND_POLICY,
    MANAGER, Org, PolicyDoc, level, permission_of,
};
use super::policy::{FILL_ASSIST, REQUIRE_SSO, SINGLE_ORG, TWO_FACTOR, is_known};
use crate::app::{App, BwStore};
use crate::dates::format_date;
use crate::env::random_uuid;
use crate::error::{BwError, BwResult};
use crate::events::kind;
use kemlock_app::ports::TwoFactorRepo;
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_app::sso::SsoSettingsRepo;
use kemlock_domain::UserId;
use kemlock_domain::spaces::{Collection, CollectionGrant, CollectionId, Grantee, Group, GroupId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FullCollectionData {
    pub name: String,
    pub groups: Vec<AccessDoc>,
    pub users: Vec<AccessDoc>,
    pub external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BulkAccessData {
    pub collection_ids: Vec<String>,
    pub groups: Vec<AccessDoc>,
    pub users: Vec<AccessDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupRequest {
    pub name: String,
    #[serde(default)]
    pub access_all: bool,
    pub external_id: Option<String>,
    pub collections: Vec<AccessDoc>,
    pub users: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PolicyData {
    pub enabled: bool,
    pub data: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PutPolicy {
    pub policy: PolicyData,
}

fn non_empty(external_id: Option<String>) -> Option<String> {
    external_id.filter(|e| !e.is_empty())
}

fn is_member_id(org: &Org, text: &str) -> bool {
    Uuid::parse_str(text).is_ok_and(|id| {
        org.member(UserId(id)).is_some() || org.pending.iter().any(|p| p.id == text)
    })
}

impl FullCollectionData {
    fn validate(&self, org: &Org) -> BwResult<()> {
        if self
            .groups
            .iter()
            .any(|g| parse_group(&g.id).and_then(|id| org.group(id)).is_none())
        {
            return Err(BwError::msg("Invalid group"));
        }
        if self.users.iter().any(|m| !is_member_id(org, &m.id)) {
            return Err(BwError::msg("Invalid member"));
        }
        Ok(())
    }
}

/// The grants a collection's group and member selections make. A member with access to everything
/// needs none; a pending invitation has no account to grant yet.
fn collection_grants(
    org: &Org,
    collection: CollectionId,
    groups: &[AccessDoc],
    users: &[AccessDoc],
) -> BwResult<Vec<CollectionGrant>> {
    let mut grants = Vec::new();
    for group in groups {
        let Some(id) = parse_group(&group.id) else {
            return Err(BwError::msg("Invalid group"));
        };
        grants.push(CollectionGrant {
            collection,
            grantee: Grantee::Group(id),
            permission: permission_of(group.read_only, group.hide_passwords, group.manage),
        });
    }
    for user in users {
        let Some(id) = Uuid::parse_str(&user.id).ok().map(UserId) else {
            return Err(BwError::msg("User is not part of organization"));
        };
        let Some(member) = org.member(id) else {
            if org.pending.iter().any(|p| p.id == user.id) {
                continue;
            }
            return Err(BwError::msg("User is not part of organization"));
        };
        if member.access_all {
            continue;
        }
        grants.push(CollectionGrant {
            collection,
            grantee: Grantee::Member(id),
            permission: permission_of(user.read_only, user.hide_passwords, user.manage),
        });
    }
    Ok(grants)
}

impl<S: BwStore> App<S> {
    /// Writes a collection, its extras and the grants that replace its old ones.
    async fn save_collection(
        &self,
        org: &Org,
        collection: Collection,
        external_id: Option<String>,
        grants: Vec<CollectionGrant>,
    ) -> BwResult<()> {
        let id = collection.id;
        let removed = org
            .state
            .grants
            .iter()
            .filter(|g| g.collection == id)
            .map(|g| (g.collection, g.grantee))
            .collect();
        let changes = SpaceChanges {
            collections: vec![collection],
            grants_removed: removed,
            grants,
            ..SpaceChanges::new(org.id)
        };
        SpaceRepo::apply(&self.store, changes).await?;
        self.put_doc(
            org.id.0,
            KIND_COLLECTION,
            &id.to_string(),
            &CollectionDoc { external_id },
        )
        .await
    }

    /// The organization again, after a change.
    pub(crate) async fn reload(&self, org: &Org) -> BwResult<Org> {
        self.load_org(org.id)
            .await?
            .ok_or_else(|| BwError::msg("Can't find organization details"))
    }
}

/// `POST /api/organizations/{id}/collections`.
pub(crate) async fn create_collection<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    data: FullCollectionData,
) -> BwResult<Value> {
    data.validate(&ctx.org)?;
    if ctx.doc.atype == MANAGER && !ctx.doc.access_all {
        return Err(BwError::msg(
            "You don't have permission to create collections",
        ));
    }
    let collection = Collection {
        id: CollectionId(random_uuid(app.env.as_ref())),
        space: ctx.org.id,
        parent: None,
        name: data.name.clone().into_bytes(),
        key_version: 1,
        stale_since: None,
        created_at: app.now(),
    };
    let grants = collection_grants(&ctx.org, collection.id, &data.groups, &data.users)?;
    app.save_collection(
        &ctx.org,
        collection.clone(),
        non_empty(data.external_id),
        grants,
    )
    .await?;
    app.sync_members(&ctx.org).await?;
    ctx.log(app, kind::COLLECTION_CREATED, &collection.id.to_string())
        .await;
    let org = app.reload(&ctx.org).await?;
    let collection = org
        .collection(collection.id)
        .cloned()
        .ok_or_else(|| BwError::msg("Collection not found"))?;
    Ok(collection_details_json(&org, &collection, ctx.me))
}

/// `PUT /api/organizations/{id}/collections/{collection}`.
pub(crate) async fn update_collection<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    id: CollectionId,
    data: FullCollectionData,
) -> BwResult<Value> {
    data.validate(&ctx.org)?;
    let Some(existing) = ctx.org.collection(id).cloned() else {
        return Err(BwError::msg("Collection not found"));
    };
    let grants = collection_grants(&ctx.org, id, &data.groups, &data.users)?;
    let collection = Collection {
        name: data.name.clone().into_bytes(),
        ..existing
    };
    let external_id = data.external_id.filter(|e| !e.trim().is_empty());
    app.save_collection(&ctx.org, collection, external_id, grants)
        .await?;
    app.sync_members(&ctx.org).await?;
    ctx.log(app, kind::COLLECTION_UPDATED, &id.to_string())
        .await;
    let org = app.reload(&ctx.org).await?;
    let collection = org
        .collection(id)
        .cloned()
        .ok_or_else(|| BwError::msg("Collection not found"))?;
    Ok(collection_details_json(&org, &collection, ctx.me))
}

/// `POST /api/organizations/{id}/collections/bulk-access`.
pub(crate) async fn bulk_access<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    data: BulkAccessData,
) -> BwResult<()> {
    if data.groups.iter().any(|g| {
        parse_group(&g.id)
            .and_then(|id| ctx.org.group(id))
            .is_none()
    }) {
        return Err(BwError::msg("Invalid group"));
    }
    for text in &data.collection_ids {
        let Some(id) = parse_collection(text).filter(|id| ctx.org.collection(*id).is_some()) else {
            return Err(BwError::msg("Collection not found"));
        };
        if !ctx.org.collection_manageable(ctx.me, id) {
            return Err(BwError::msg("Collection not found"));
        }
        let Some(collection) = ctx.org.collection(id).cloned() else {
            return Err(BwError::msg("Collection not found"));
        };
        let grants = collection_grants(&ctx.org, id, &data.groups, &data.users)?;
        let external_id = ctx.org.external_id_of_collection(id);
        app.save_collection(&ctx.org, collection, external_id, grants)
            .await?;
        ctx.log(app, kind::COLLECTION_UPDATED, &id.to_string())
            .await;
    }
    app.sync_members(&ctx.org).await
}

/// Deletes a collection: its grants, its links to ciphers, the collection.
pub(crate) async fn delete_collection<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    id: CollectionId,
) -> BwResult<()> {
    if ctx.org.collection(id).is_none() {
        return Err(BwError::msg("Collection not found"));
    }
    let changes = SpaceChanges {
        collections_removed: vec![id],
        ..SpaceChanges::new(ctx.org.id)
    };
    SpaceRepo::apply(&app.store, changes).await?;
    app.del_doc(ctx.org.id.0, KIND_COLLECTION, &id.to_string())
        .await?;
    super::ciphers::forget_collection(app, ctx.org.id, id).await?;
    app.sync_members(&ctx.org).await?;
    ctx.log(app, kind::COLLECTION_DELETED, &id.to_string())
        .await;
    Ok(())
}

/// `GET /api/organizations/{id}/collections/details`: what an admin or manager lists.
pub(crate) fn collections_details(ctx: &Ctx) -> Vec<Value> {
    let org = &ctx.org;
    let me = ctx.me;
    let full = ctx.doc.full_access() || org.group_full_access(me);
    // Members with access to everything aren't in the grants and still can manage.
    let manage_all: Vec<Value> = org
        .members
        .iter()
        .filter(|(_, m)| m.confirmed() && m.access_all)
        .map(|(user, _)| {
            json!({
                "id": user.to_string(),
                "readOnly": false,
                "hidePasswords": false,
                "manage": true,
            })
        })
        .collect();
    let mut out = Vec::new();
    for collection in &org.state.collections {
        let assigned = full
            || org.user_grant(me, collection.id).is_some()
            || org.group_grant(me, collection.id).is_some();
        if !assigned {
            continue;
        }
        let mut users = collection_members_json(org, collection.id);
        users.extend(manage_all.iter().cloned());
        let mut object = collection_details_json(org, collection, me);
        object["assigned"] = json!(assigned);
        object["users"] = json!(users);
        object["groups"] = json!(collection_groups_json(org, collection.id));
        object["object"] = json!("collectionAccessDetails");
        object["unmanaged"] = json!(false);
        out.push(object);
    }
    out
}

/// The collections of an organization as plain `collection` objects.
pub(crate) fn collections_plain(org: &Org) -> Vec<Value> {
    org.state
        .collections
        .iter()
        .map(|c| collection_json(org, c))
        .collect()
}

fn groups_on(org: &Org) -> BwResult<()> {
    if org.groups_enabled {
        Ok(())
    } else {
        Err(BwError::msg("Group support is disabled"))
    }
}

impl GroupRequest {
    fn validate(&self, org: &Org) -> BwResult<()> {
        if self.collections.iter().any(|c| {
            parse_collection(&c.id)
                .and_then(|id| org.collection(id))
                .is_none()
        }) {
            return Err(BwError::msg("Invalid collection"));
        }
        if self.users.iter().any(|m| !is_member_id(org, m)) {
            return Err(BwError::msg("Invalid member"));
        }
        Ok(())
    }
}

/// `POST` and `PUT /api/organizations/{id}/groups`: a new group, or `existing` changed.
pub(crate) async fn save_group<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    existing: Option<GroupId>,
    data: GroupRequest,
) -> BwResult<Value> {
    groups_on(&ctx.org)?;
    let old = match existing {
        Some(id) => Some(
            ctx.org
                .group(id)
                .cloned()
                .ok_or_else(|| BwError::msg("Group not found"))?,
        ),
        None => None,
    };
    data.validate(&ctx.org)?;

    let id = old
        .as_ref()
        .map_or_else(|| GroupId(random_uuid(app.env.as_ref())), |g| g.id);
    // Only registered members are in a group row; a pending invitation joins when it registers.
    let members: BTreeSet<UserId> = data
        .users
        .iter()
        .filter_map(|m| Uuid::parse_str(m).ok().map(UserId))
        .filter(|u| ctx.org.member(*u).is_some())
        .collect();
    let group = Group {
        id,
        space: ctx.org.id,
        name: data.name.clone().into_bytes(),
        members,
        created_at: old.as_ref().map_or_else(|| app.now(), |g| g.created_at),
    };
    let removed = ctx
        .org
        .state
        .grants
        .iter()
        .filter(|g| g.grantee == Grantee::Group(id))
        .map(|g| (g.collection, g.grantee))
        .collect();
    let grants = data
        .collections
        .iter()
        .filter_map(|c| {
            parse_collection(&c.id).map(|collection| CollectionGrant {
                collection,
                grantee: Grantee::Group(id),
                permission: permission_of(c.read_only, c.hide_passwords, c.manage),
            })
        })
        .collect();
    let changes = SpaceChanges {
        groups: vec![group.clone()],
        grants_removed: removed,
        grants,
        ..SpaceChanges::new(ctx.org.id)
    };
    SpaceRepo::apply(&app.store, changes).await?;
    // A group's external id is set when it is made and never changed by an update.
    let doc = GroupDoc {
        access_all: data.access_all,
        external_id: match &old {
            Some(_) => ctx.org.group_doc(id).external_id,
            None => non_empty(data.external_id),
        },
    };
    app.put_doc(ctx.org.id.0, KIND_GROUP, &id.to_string(), &doc)
        .await?;
    app.sync_members(&ctx.org).await?;
    let made = if old.is_some() {
        kind::GROUP_UPDATED
    } else {
        kind::GROUP_CREATED
    };
    ctx.log(app, made, &id.to_string()).await;
    // Vaultwarden logs each member the request names, as updated groups.
    for member in &data.users {
        ctx.log(app, kind::MEMBER_UPDATED_GROUPS, member).await;
    }
    Ok(json!({
        "id": id.to_string(),
        "organizationId": ctx.org.id.to_string(),
        "name": data.name,
        "externalId": doc.external_id,
        "object": "group",
    }))
}

/// `DELETE /api/organizations/{id}/groups/{group}`.
pub(crate) async fn delete_group<S: BwStore>(app: &App<S>, ctx: &Ctx, id: GroupId) -> BwResult<()> {
    groups_on(&ctx.org)?;
    if ctx.org.group(id).is_none() {
        return Err(BwError::msg("Group not found"));
    }
    let changes = SpaceChanges {
        groups_removed: vec![id],
        ..SpaceChanges::new(ctx.org.id)
    };
    SpaceRepo::apply(&app.store, changes).await?;
    app.del_doc(ctx.org.id.0, KIND_GROUP, &id.to_string())
        .await?;
    app.sync_members(&ctx.org).await?;
    ctx.log(app, kind::GROUP_DELETED, &id.to_string()).await;
    Ok(())
}

/// The groups of the organization as `group` objects: empty when groups are off, as the clients
/// call this regardless.
pub(crate) fn groups_list(org: &Org, details: bool) -> Vec<Value> {
    if !org.groups_enabled {
        return Vec::new();
    }
    org.state
        .groups
        .iter()
        .map(|g| {
            if details {
                super::json::group_details_json(org, g)
            } else {
                group_json(org, g)
            }
        })
        .collect()
}

fn fill_assist_check(data: &PolicyData) -> BwResult<()> {
    let rules_url = match data.data.as_ref() {
        None | Some(Value::Null) => None,
        Some(value) => {
            let Some(object) = value.as_object() else {
                return Err(BwError::msg(
                    "Invalid data for FillAssist policy: rulesUrl has an invalid value.",
                ));
            };
            match object.get("rulesUrl").or_else(|| object.get("RulesUrl")) {
                None | Some(Value::Null) => None,
                Some(Value::String(url)) => Some(url.clone()),
                Some(_) => {
                    return Err(BwError::msg(
                        "Invalid data for FillAssist policy: rulesUrl has an invalid value.",
                    ));
                }
            }
        }
    };
    if !data.enabled {
        return Ok(());
    }
    let Some(rules_url) = rules_url.filter(|url| !url.trim().is_empty()) else {
        return Err(BwError::msg("The RulesUrl field is required."));
    };
    let invalid = || {
        BwError::msg("The RulesUrl field is not a valid fully-qualified http, https, or ftp URL.")
    };
    let Ok(parsed) = url::Url::parse(&rules_url) else {
        return Err(invalid());
    };
    if !parsed.has_host() || !matches!(parsed.scheme(), "http" | "https" | "ftp") {
        return Err(invalid());
    }
    if parsed.scheme() != "https" {
        return Err(BwError::msg("RulesUrl must use HTTPS."));
    }
    Ok(())
}

/// `PUT /api/organizations/{id}/policies/{type}`.
pub(crate) async fn put_policy<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    ptype: i32,
    data: PolicyData,
) -> BwResult<Value> {
    if !is_known(ptype) {
        return Err(BwError::msg("Invalid or unsupported policy type"));
    }
    let org = &ctx.org;
    let enabled_now = org.policy_enabled(ptype);

    // Fill Assist depends on Single Organization; the check is made when the state changes.
    if ptype == FILL_ASSIST && data.enabled && !enabled_now && !org.policy_enabled(SINGLE_ORG) {
        return Err(BwError::msg(
            "Turn on the Single organization policy because it is required for the Activate fill assist policy.",
        ));
    }
    if ptype == SINGLE_ORG && !data.enabled && enabled_now && org.policy_enabled(FILL_ASSIST) {
        return Err(BwError::msg(
            "Turn off the Activate fill assist policy because it requires the Single organization policy.",
        ));
    }
    // Require SSO closes the password to the members, so it can't be turned on where no one could
    // sign in another way, and (as Bitwarden has it) only with Single organization on.
    if ptype == REQUIRE_SSO && data.enabled && !enabled_now {
        let configured = SsoSettingsRepo::sso_settings(&app.store)
            .await?
            .is_some_and(|settings| settings.enabled);
        if !configured {
            return Err(BwError::msg(
                "Set up single sign-on on this server before turning on the Require single sign-on authentication policy.",
            ));
        }
        if !org.policy_enabled(SINGLE_ORG) {
            return Err(BwError::msg(
                "Turn on the Single organization policy because it is required for the Require single sign-on authentication policy.",
            ));
        }
    }
    if ptype == SINGLE_ORG && !data.enabled && enabled_now && org.policy_enabled(REQUIRE_SSO) {
        return Err(BwError::msg(
            "Turn off the Require single sign-on authentication policy because it requires the Single organization policy.",
        ));
    }
    if ptype == FILL_ASSIST {
        fill_assist_check(&data)?;
    }

    // Turning on two-step login revokes the members who have none.
    if ptype == TWO_FACTOR && data.enabled {
        for (user, member) in &org.members {
            if *user == ctx.me
                || level(member.atype) >= level(ADMIN)
                || member.unrevoked_status() < ACCEPTED
                || member.revoked()
            {
                continue;
            }
            if TwoFactorRepo::list(&app.store, *user).await?.is_empty() {
                let mut revoked = member.clone();
                revoked.revoke();
                app.put_member(org, *user, &revoked, ctx.me).await?;
                app.touch_quiet(*user).await?;
            }
        }
    }
    // Turning on Single organization revokes the members who are in another organization too.
    if ptype == SINGLE_ORG && data.enabled {
        for (user, member) in &org.members {
            if level(member.atype) >= level(ADMIN) || member.status < ACCEPTED {
                continue;
            }
            let elsewhere = app
                .orgs_of(*user)
                .await?
                .iter()
                .filter(|o| o.id != org.id)
                .any(|o| {
                    o.member(*user).is_some_and(|m| {
                        m.status == ACCEPTED || m.status == super::model::CONFIRMED
                    })
                });
            if elsewhere {
                let mut revoked = member.clone();
                revoked.revoke();
                app.put_member(org, *user, &revoked, ctx.me).await?;
                app.touch_quiet(*user).await?;
                ctx.log(app, kind::MEMBER_REVOKED_SINGLE_ORG, &user.to_string())
                    .await;
            }
        }
    }

    let now = app.now();
    let id = org.policy(ptype).map_or_else(
        || random_uuid(app.env.as_ref()).to_string(),
        |p| p.id.clone(),
    );
    let policy = PolicyDoc {
        id,
        enabled: data.enabled,
        data: serde_json::to_string(&data.data).map_err(|e| BwError::Server(e.to_string()))?,
        revision_date: format_date(now),
    };
    // Whether Require SSO is on lives in `space_policy_settings`, the one place the Kemlock API and
    // the sign-in checks read it; the document only keeps what Bitwarden shows of it.
    // The table and the document are written in one transaction.
    if ptype == REQUIRE_SSO {
        let text = serde_json::to_string(&policy).map_err(|e| BwError::Server(e.to_string()))?;
        app.store
            .doc_put_with_require_sso(
                org.id.0,
                KIND_POLICY,
                &ptype.to_string(),
                &text,
                data.enabled,
            )
            .await?;
    } else {
        app.put_doc(org.id.0, KIND_POLICY, &ptype.to_string(), &policy)
            .await?;
    }
    app.sync_members(org).await?;
    ctx.log(app, kind::POLICY_UPDATED, &policy.id).await;
    Ok(policy_json(&org.id.to_string(), ptype, &policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_assist_wants_an_https_url_when_on() {
        let on = |url: Value| PolicyData {
            enabled: true,
            data: Some(json!({ "rulesUrl": url })),
        };
        assert!(fill_assist_check(&on(json!("https://rules.example.org/x.json"))).is_ok());
        assert_eq!(
            fill_assist_check(&on(json!("http://rules.example.org"))),
            Err(BwError::msg("RulesUrl must use HTTPS."))
        );
        assert_eq!(
            fill_assist_check(&on(json!(" "))),
            Err(BwError::msg("The RulesUrl field is required."))
        );
        assert!(fill_assist_check(&on(json!("nonsense"))).is_err());
        assert!(
            fill_assist_check(&PolicyData {
                enabled: false,
                data: None
            })
            .is_ok()
        );
    }

    #[test]
    fn an_external_id_that_is_empty_is_none() {
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(Some("x".to_owned())), Some("x".to_owned()));
    }
}
