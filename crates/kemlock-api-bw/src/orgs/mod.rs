//! Organizations: the Bitwarden projection of spaces.
//!
//! An organization is a space (members with a role and a state, groups, collections, grants, all
//! in the space tables) plus side documents for what Bitwarden has and spaces don't (see
//! [`model`]). The routes answer as Vaultwarden 1.37.5 does; the items stay opaque, under the
//! organization key the clients hold.
//!
//! - [`model`] holds the documents and the rules of who may see and write what;
//! - [`store`] reads and writes an organization over the space and document ports;
//! - [`guard`], [`members`], [`structure`] and [`routes`] are the routes' guards, member rules,
//!   collection, group and policy rules, and handlers;
//! - [`ciphers`] is the cipher side: sync, share, collections, delete and restore;
//! - [`api_key`] is the organization API key and the token the Directory Connector gets with it;
//! - [`policy`] has the policy types, the checks, and [`OrgMembership`], the Require SSO facts
//!   the sign-in paths read.

pub(crate) mod api_key;
pub(crate) mod ciphers;
pub(crate) mod guard;
pub(crate) mod json;
pub(crate) mod members;
pub(crate) mod model;
pub(crate) mod policy;
pub(crate) mod recovery;
pub(crate) mod routes;
pub(crate) mod store;
pub(crate) mod structure;

pub use policy::OrgMembership;

use crate::app::{App, BwStore};
use crate::error::BwResult;
use axum::Router;
use json::{collection_details_json, policy_json, profile_org_json};
use kemlock_domain::UserId;
use model::{ACCEPTED, CONFIRMED};
use serde_json::Value;

pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    routes::routes::<S>()
}

/// What `/api/sync` shows of the account's organizations.
#[derive(Debug, Default)]
pub(crate) struct SyncParts {
    pub organizations: Vec<Value>,
    pub organizations_new: Vec<Value>,
    pub collections: Vec<Value>,
    pub policies: Vec<Value>,
    pub policies_new: Vec<Value>,
    pub ciphers: Vec<Value>,
}

/// The organizations of an account for its profile: confirmed memberships, and accepted ones
/// too for `organizationsNew`.
pub(crate) async fn profile_orgs<S: BwStore>(
    app: &App<S>,
    user: UserId,
) -> BwResult<(Vec<Value>, Vec<Value>)> {
    let mut confirmed = Vec::new();
    let mut open = Vec::new();
    for org in app.orgs_of(user).await? {
        let Some(doc) = org.member(user) else {
            continue;
        };
        let shown = profile_org_json(&org, user, doc, &app.settings);
        if doc.status == CONFIRMED {
            confirmed.push(shown.clone());
        }
        if doc.status == CONFIRMED || doc.status == ACCEPTED {
            open.push(shown);
        }
    }
    Ok((confirmed, open))
}

/// Everything organization-related in one sync, from one read of the account's organizations.
pub(crate) async fn sync_parts<S: BwStore>(
    app: &App<S>,
    user: UserId,
    client_version: Option<&str>,
) -> BwResult<SyncParts> {
    let orgs = app.orgs_of(user).await?;
    let mut parts = SyncParts::default();
    for org in &orgs {
        let Some(doc) = org.member(user) else {
            continue;
        };
        let confirmed = doc.status == CONFIRMED;
        let accepted = doc.status == ACCEPTED;
        if confirmed || accepted {
            let shown = profile_org_json(org, user, doc, &app.settings);
            if confirmed {
                parts.organizations.push(shown.clone());
            }
            parts.organizations_new.push(shown);
        }
        if confirmed {
            for collection in org.collections_of(user) {
                parts
                    .collections
                    .push(collection_details_json(org, collection, user));
            }
        }
        if confirmed || accepted {
            for (ptype, policy) in &org.policies {
                let shown = policy_json(&org.id.to_string(), *ptype, policy);
                if confirmed {
                    parts.policies.push(shown.clone());
                }
                parts.policies_new.push(shown);
            }
        }
    }
    parts.ciphers = ciphers::visible_ciphers(app, user, &orgs, client_version).await?;
    Ok(parts)
}

/// Takes the account out of every organization it doesn't own: what an emergency takeover does
/// to the grantor.
pub(crate) async fn leave_unowned<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<()> {
    for org in app.orgs_of(user).await? {
        if org.member(user).is_some_and(|m| m.atype != model::OWNER) {
            app.remove_member(&org, user).await?;
        }
    }
    Ok(())
}
