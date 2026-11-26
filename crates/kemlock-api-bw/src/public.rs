//! The public API, `/api/public`: what Bitwarden's Directory Connector calls with an organization
//! API key's token. Vaultwarden 1.37.5 serves one route, `POST /public/organization/import`, which
//! makes the organization's members and groups match a directory.
//!
//! The directory's own ids (`externalId`) are what the import matches on: a member or a group it
//! has seen before is found by its external id, and with `overwriteExisting` the members it no
//! longer lists are removed. An address with no account yet is invited and waits for its
//! registration, as an invitation does.

use crate::app::{App, BwStore};
use crate::error::{BwError, BwResult};
use crate::orgs::api_key;
use crate::orgs::model::{
    GroupDoc, INVITED, KIND_GROUP, KIND_PENDING, MemberDoc, OWNER, Org, PendingDoc, USER,
};
use crate::orgs::policy::check_user_allowed;
use crate::routes::{EmptyResult, empty, parse};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::routing::post;
use kemlock_app::ports::UserRepo;
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{Group, GroupId};
use kemlock_domain::{Email, SpaceId, UserId};
use serde::Deserialize;
use std::collections::{BTreeSet, HashSet};

/// The organization an API key's token is for: Vaultwarden's `PublicToken` request guard.
#[derive(Debug, Clone, Copy)]
struct PublicToken(SpaceId);

impl<S: BwStore> FromRequestParts<App<S>> for PublicToken {
    type Rejection = BwError;

    async fn from_request_parts(parts: &mut Parts, app: &App<S>) -> Result<Self, BwError> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        Ok(PublicToken(api_key::authenticate(app, header).await?))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    member_external_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportData {
    groups: Vec<OrgImportGroupData>,
    members: Vec<OrgImportUserData>,
    overwrite_existing: bool,
}

/// Sets a document's external id; whether it changed. An empty id clears it.
fn set_external(slot: &mut Option<String>, external_id: &str) -> bool {
    let wanted = Some(external_id.to_owned()).filter(|e| !e.is_empty());
    if *slot == wanted {
        return false;
    }
    *slot = wanted;
    true
}

/// Writes a member's document, and keeps the loaded organization in step with it.
async fn save_member<S: BwStore>(
    app: &App<S>,
    org: &mut Org,
    owner: Option<UserId>,
    user: UserId,
    doc: MemberDoc,
) -> BwResult<()> {
    app.put_member(org, user, &doc, owner.unwrap_or(user))
        .await?;
    app.touch_quiet(user).await?;
    org.members.insert(user, doc);
    Ok(())
}

async fn import_member<S: BwStore>(
    app: &App<S>,
    org: &mut Org,
    owner: Option<UserId>,
    data: &OrgImportUserData,
) -> BwResult<()> {
    let parsed = Email::parse(&data.email).ok();
    let account = match &parsed {
        Some(email) => UserRepo::by_email(&app.store, email).await?,
        None => None,
    };
    let existing = account
        .as_ref()
        .and_then(|u| org.member(u.id).cloned().map(|doc| (u.id, doc)));

    if data.deleted {
        // A member the directory has deleted is revoked, unless they are an owner.
        let Some((user, mut doc)) = existing else {
            return Ok(());
        };
        let revoked = doc.atype != OWNER && doc.revoke();
        let moved = set_external(&mut doc.external_id, &data.external_id);
        if revoked || moved {
            save_member(app, org, owner, user, doc).await?;
        }
        return Ok(());
    }

    if let Some((user, mut doc)) = existing {
        // A member still in the directory is restored, if the policies let them back.
        let mut restored = doc.atype != OWNER && doc.restore();
        if restored
            && check_user_allowed(app, org, user, &doc, "restore")
                .await
                .is_err()
        {
            tracing::warn!(%user, "a directory import couldn't restore a member: a policy forbids it");
            doc.revoke();
            restored = false;
        }
        let moved = set_external(&mut doc.external_id, &data.external_id);
        if restored || moved {
            save_member(app, org, owner, user, doc).await?;
        }
        return Ok(());
    }

    // Someone new: invited, and an account that exists accepts for itself. An address with no
    // account waits for its registration.
    let Some(parsed) = parsed else {
        return Err(BwError::msg(format!(
            "{} is not a valid email address",
            data.email.escape_debug()
        )));
    };
    let billing = org.doc.billing_email.clone();
    match account {
        Some(user) => {
            // Invited, as every invitation is: the account accepts for itself.
            let mut doc = MemberDoc::new(USER, false, INVITED);
            doc.invited_by_email = Some(billing.clone());
            set_external(&mut doc.external_id, &data.external_id);
            save_member(app, org, owner, user.id, doc).await?;
            crate::orgs::members::mail_invitation(app, org, &parsed, &billing).await;
            Ok(())
        }
        None => {
            if let Some(waiting) = org.pending.iter_mut().find(|p| p.email == parsed.as_str()) {
                if set_external(&mut waiting.external_id, &data.external_id) {
                    app.put_doc(org.id.0, KIND_PENDING, parsed.as_str(), &*waiting)
                        .await?;
                }
                return Ok(());
            }
            let pending = PendingDoc {
                id: crate::env::random_uuid(app.env.as_ref()).to_string(),
                email: parsed.as_str().to_owned(),
                atype: USER,
                access_all: false,
                collections: Vec::new(),
                groups: Vec::new(),
                invited_by_email: Some(billing),
                invited_by: owner.map(|u| u.to_string()).unwrap_or_default(),
                external_id: Some(data.external_id.clone()).filter(|e| !e.is_empty()),
            };
            app.put_doc(org.id.0, KIND_PENDING, parsed.as_str(), &pending)
                .await?;
            org.pending.push(pending);
            Ok(())
        }
    }
}

async fn import_group<S: BwStore>(
    app: &App<S>,
    org: &mut Org,
    data: &OrgImportGroupData,
) -> BwResult<()> {
    let found = org
        .group_docs
        .iter()
        .find(|(_, doc)| doc.external_id.as_deref() == Some(data.external_id.as_str()))
        .map(|(id, _)| *id)
        .and_then(|id| org.group(id).cloned());
    // The group's members are the ones the directory names, found by their external ids.
    let members: BTreeSet<UserId> = data
        .member_external_ids
        .iter()
        .filter_map(|external| {
            org.members
                .iter()
                .find(|(_, m)| m.external_id.as_deref() == Some(external.as_str()))
                .map(|(user, _)| *user)
        })
        .collect();
    let (group, is_new) = match found {
        Some(mut group) => {
            group.name = data.name.clone().into_bytes();
            group.members = members;
            (group, false)
        }
        None => (
            Group {
                id: GroupId(crate::env::random_uuid(app.env.as_ref())),
                space: org.id,
                name: data.name.clone().into_bytes(),
                members,
                created_at: app.now(),
            },
            true,
        ),
    };
    let changes = SpaceChanges {
        groups: vec![group.clone()],
        ..SpaceChanges::new(org.id)
    };
    SpaceRepo::apply(&app.store, changes).await?;
    if is_new {
        let doc = GroupDoc {
            access_all: false,
            external_id: Some(data.external_id.clone()),
        };
        app.put_doc(org.id.0, KIND_GROUP, &group.id.to_string(), &doc)
            .await?;
        org.group_docs.insert(group.id, doc);
    }
    // An invitation that waits for its registration joins the group then: the group is in it.
    let named = group.id.to_string();
    for waiting in org.pending.iter_mut() {
        let listed = waiting
            .external_id
            .as_deref()
            .is_some_and(|e| data.member_external_ids.iter().any(|m| m == e));
        if listed == waiting.groups.contains(&named) {
            continue;
        }
        if listed {
            waiting.groups.push(named.clone());
        } else {
            waiting.groups.retain(|g| *g != named);
        }
        app.put_doc(org.id.0, KIND_PENDING, &waiting.email, &*waiting)
            .await?;
    }
    org.state.groups.retain(|g| g.id != group.id);
    org.state.groups.push(group);
    Ok(())
}

/// With `overwriteExisting`, whoever the directory doesn't list any more goes, unless they are an
/// owner or were never imported (no external id).
async fn drop_unlisted<S: BwStore>(
    app: &App<S>,
    org: &mut Org,
    listed: &HashSet<&str>,
) -> BwResult<()> {
    let unlisted = |external: &Option<String>| {
        external
            .as_deref()
            .is_some_and(|external| !listed.contains(external))
    };
    let gone: Vec<UserId> = org
        .members
        .iter()
        .filter(|(_, m)| m.atype != OWNER && unlisted(&m.external_id))
        .map(|(user, _)| *user)
        .collect();
    for user in gone {
        app.remove_member(org, user).await?;
        app.touch_quiet(user).await?;
        org.members.remove(&user);
    }
    let waiting: Vec<PendingDoc> = org
        .pending
        .iter()
        .filter(|p| unlisted(&p.external_id))
        .cloned()
        .collect();
    for pending in waiting {
        app.del_doc(org.id.0, KIND_PENDING, &pending.email).await?;
        org.pending.retain(|p| p.email != pending.email);
    }
    Ok(())
}

async fn import<S: BwStore>(app: &App<S>, space: SpaceId, data: OrgImportData) -> BwResult<()> {
    let mut org = app
        .load_org(space)
        .await?
        .ok_or_else(|| BwError::msg("Error looking up organization"))?;
    // Who the invitations are from: the organization has no one to say, so its first owner does.
    let owner = org
        .members
        .iter()
        .find(|(_, m)| m.atype == OWNER && m.confirmed())
        .map(|(user, _)| *user);

    for member in &data.members {
        import_member(app, &mut org, owner, member).await?;
    }
    if org.groups_enabled {
        for group in &data.groups {
            import_group(app, &mut org, group).await?;
        }
    } else {
        tracing::warn!("group support is disabled, groups will not be imported");
    }
    if data.overwrite_existing {
        let listed: HashSet<&str> = data
            .members
            .iter()
            .map(|m| m.external_id.as_str())
            .collect();
        drop_unlisted(app, &mut org, &listed).await?;
    }
    app.touch_members(&org).await
}

/// `POST /api/public/organization/import`.
async fn ldap_import<S: BwStore>(
    State(app): State<App<S>>,
    token: PublicToken,
    body: Bytes,
) -> EmptyResult {
    let data: OrgImportData = parse(&body)?;
    empty(import(&app, token.0, data).await)
}

pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new().route("/api/public/organization/import", post(ldap_import::<S>))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_external_id_is_set_once_and_empty_clears_it() {
        let mut slot = None;
        assert!(set_external(&mut slot, "ext-1"));
        assert_eq!(slot.as_deref(), Some("ext-1"));
        assert!(!set_external(&mut slot, "ext-1"));
        assert!(set_external(&mut slot, "ext-2"));
        assert!(set_external(&mut slot, ""));
        assert_eq!(slot, None);
        assert!(!set_external(&mut slot, ""));
    }

    #[test]
    fn the_import_body_is_camel_case_and_complete() {
        let data: OrgImportData = serde_json::from_value(serde_json::json!({
            "groups": [{"name": "g", "externalId": "e", "memberExternalIds": ["m"]}],
            "members": [{"email": "a@example.com", "externalId": "m", "deleted": false}],
            "overwriteExisting": true,
        }))
        .expect("parses");
        assert!(data.overwrite_existing);
        assert_eq!(data.groups[0].member_external_ids, ["m"]);
        let missing = serde_json::from_value::<OrgImportData>(serde_json::json!({
            "groups": [], "members": [],
        }));
        assert!(missing.is_err());
    }
}
