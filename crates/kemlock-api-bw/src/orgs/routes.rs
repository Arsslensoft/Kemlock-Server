//! The organization routes, as Vaultwarden 1.37.5's `organizations.rs` and the organization parts
//! of `ciphers.rs` lay them out. A handler checks its guard first, then reads its body, as Rocket
//! does.

use super::api_key;
use super::ciphers;
use super::guard::{Ctx, Need, space_id};
use super::json::{
    blank_policy, collection_details_json, collection_groups_json, collection_members_json,
    group_details_json, group_json, list, member_access_json, member_admin_json, member_mini_json,
    org_json, pending_admin_json, policy_json,
};
use super::members::{
    self, EditData, InviteClaims, InviteData, bulk_line, parse_collection, parse_group,
};
use super::model::{CONFIRMED, KIND_ORG, MemberDoc, OWNER, OrgDoc, USER};
use super::policy::{MASTER_PASSWORD, SINGLE_ORG, is_applicable_to_user, is_known};
use super::recovery::{self, RecoverData};
use super::structure::{
    BulkAccessData, FullCollectionData, GroupRequest, PutPolicy, bulk_access, collections_details,
    collections_plain, create_collection, delete_collection, delete_group, groups_list, put_policy,
    save_group, update_collection,
};
use crate::app::{App, Authed, BwStore, MaybeAuthed};
use crate::cipher::{CipherData, lcase_keys};
use crate::error::{BwError, BwResult};
use crate::events::kind;
use crate::routes::{
    EmptyResult, JsonResult, Peer, SecretJsonResult, empty, ok, ok_no_store, parse, truthy,
};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{Collection, CollectionId, Space};
use kemlock_domain::{Email, SpaceId, UserId};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// Vaultwarden's id for the placeholder organization of an SSO enrolment.
const FAKE_SSO_IDENTIFIER: &str = "00000000-01DC-01DC-01DC-000000000000";

fn not_found_resource() -> BwError {
    BwError::status(StatusCode::NOT_FOUND, "Resource not found.")
}

/// A list of members: an admin sees them only with access to everything.
fn require_full_access(ctx: &Ctx) -> BwResult<()> {
    if !ctx.doc.full_access() {
        return Err(not_found_resource());
    }
    Ok(())
}

// --- the organization -------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<OrgKeyData>,
    #[allow(dead_code)]
    plan_type: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgUpdateData {
    billing_email: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

fn valid_billing_email(text: &str) -> BwResult<String> {
    Email::parse(text)
        .map(|e| e.as_str().to_owned())
        .map_err(|_| {
            BwError::msg(format!(
                "BillingEmail {} is not a valid email address",
                text.to_lowercase().escape_debug()
            ))
        })
}

async fn create_organization<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: OrgData = parse(&body)?;
    let user = authed.user.id;
    if is_applicable_to_user(&app, user, SINGLE_ORG, None).await? {
        return Err(BwError::msg(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization.",
        ));
    }
    let billing = valid_billing_email(&data.billing_email)?;
    let now = app.now();
    let id = SpaceId(crate::env::random_uuid(app.env.as_ref()));
    let space = Space {
        id,
        name: data.name.clone().into_bytes(),
        key_version: 1,
        keys_pending_since: None,
        created_at: now,
        updated_at: now,
    };
    let mut owner = MemberDoc::new(OWNER, true, CONFIRMED);
    owner.akey = data.key.clone();
    let empty_org = super::model::Org {
        id,
        name: data.name.clone(),
        doc: OrgDoc::default(),
        state: kemlock_domain::spaces::SpaceState {
            space: space.clone(),
            members: Vec::new(),
            groups: Vec::new(),
            collections: Vec::new(),
            grants: Vec::new(),
        },
        members: Default::default(),
        pending: Vec::new(),
        collection_docs: Default::default(),
        group_docs: Default::default(),
        policies: Default::default(),
        groups_enabled: app.settings.org_groups_enabled,
    };
    let row = super::store::mirror_member(&empty_org, user, &owner, user, now);
    let collection = Collection {
        id: CollectionId(crate::env::random_uuid(app.env.as_ref())),
        space: id,
        parent: None,
        name: data.collection_name.clone().into_bytes(),
        key_version: 1,
        stale_since: None,
        created_at: now,
    };
    let changes = SpaceChanges {
        space: Some(space),
        members: vec![row],
        collections: vec![collection.clone()],
        ..SpaceChanges::new(id)
    };
    SpaceRepo::create(&app.store, changes).await?;

    let (private_key, public_key) = match data.keys {
        Some(keys) => (Some(keys.encrypted_private_key), Some(keys.public_key)),
        None => (None, None),
    };
    app.put_doc(
        id.0,
        KIND_ORG,
        "",
        &OrgDoc {
            billing_email: billing,
            private_key,
            public_key,
        },
    )
    .await?;
    app.put_doc(id.0, super::model::KIND_MEMBER, &user.to_string(), &owner)
        .await?;
    app.put_doc(
        id.0,
        super::model::KIND_COLLECTION,
        &collection.id.to_string(),
        &super::model::CollectionDoc::default(),
    )
    .await?;
    app.touch(user).await?;
    let org = app
        .load_org(id)
        .await?
        .ok_or_else(|| BwError::msg("Can't find organization details"))?;
    ok(org_json(&org, &app.settings))
}

async fn get_organization<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Owner).await?;
    ok(org_json(&ctx.org, &app.settings))
}

async fn put_organization<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Owner).await?;
    let data: OrgUpdateData = parse(&body)?;
    let billing = valid_billing_email(&data.billing_email)?;
    let space = Space {
        name: data.name.clone().into_bytes(),
        updated_at: app.now(),
        ..ctx.org.state.space.clone()
    };
    let changes = SpaceChanges {
        space: Some(space),
        ..SpaceChanges::new(ctx.org.id)
    };
    SpaceRepo::apply(&app.store, changes).await?;
    let doc = OrgDoc {
        billing_email: billing,
        ..ctx.org.doc.clone()
    };
    app.put_doc(ctx.org.id.0, KIND_ORG, "", &doc).await?;
    app.sync_members(&ctx.org).await?;
    ctx.log(&app, kind::ORGANIZATION_UPDATED, &ctx.org.id.to_string())
        .await;
    let org = app.reload(&ctx.org).await?;
    ok(org_json(&org, &app.settings))
}

async fn delete_organization<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Owner).await?;
    let data: PasswordData = parse(&body)?;
    // The password or a mailed one-time code, which a right entry uses up.
    crate::protected::validate(
        &app,
        &authed,
        data.master_password_hash.as_deref(),
        data.otp.as_deref(),
        true,
    )
    .await?;
    app.sync_members(&ctx.org).await?;
    ciphers::purge_org(&app, ctx.org.id).await?;
    let changes = SpaceChanges {
        members_removed: ctx.org.members.keys().copied().collect(),
        groups_removed: ctx.org.state.groups.iter().map(|g| g.id).collect(),
        collections_removed: ctx.org.state.collections.iter().map(|c| c.id).collect(),
        ..SpaceChanges::new(ctx.org.id)
    };
    SpaceRepo::apply(&app.store, changes).await?;
    kemlock_app::bitwarden::BwOrgStore::doc_delete_scope(&app.store, ctx.org.id.0).await?;
    empty(Ok(()))
}

async fn leave_organization<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> EmptyResult {
    // Any member who is not revoked may leave: that is how an invitation, or a membership still
    // waiting for its confirmation, is turned down.
    let ctx = app.guard(&authed, &org_id, Need::Member).await?;
    if ctx.doc.confirmed() && ctx.doc.atype == OWNER && ctx.org.confirmed_owners() <= 1 {
        return Err(BwError::msg("The last owner can't leave"));
    }
    app.remove_member(&ctx.org, ctx.me).await?;
    app.touch_quiet(ctx.me).await?;
    ctx.log(&app, kind::MEMBER_LEFT, &ctx.me.to_string()).await;
    empty(Ok(()))
}

/// `GET /api/collections`: every collection the account sees, in every organization.
async fn user_collections<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    let user = authed.user.id;
    let mut out = Vec::new();
    for org in app.orgs_of(user).await? {
        if !org.member(user).is_some_and(|m| m.confirmed()) {
            continue;
        }
        for collection in org.collections_of(user) {
            out.push(super::json::collection_json(&org, collection));
        }
    }
    ok(list(out))
}

async fn auto_enroll_status<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(identifier): Path<String>,
) -> JsonResult {
    let org = if identifier == FAKE_SSO_IDENTIFIER {
        // The organization the account joined first, by role.
        let mut orgs = app.orgs_of(authed.user.id).await?;
        orgs.retain(|o| o.member(authed.user.id).is_some_and(|m| !m.revoked()));
        orgs.sort_by_key(|o| o.member(authed.user.id).map_or(USER, |m| m.atype));
        orgs.into_iter().next()
    } else {
        match space_id(&identifier) {
            Ok(space) => app.load_org(space).await?,
            Err(_) => None,
        }
    };
    let id = org
        .as_ref()
        .map_or_else(|| identifier.clone(), |o| o.id.to_string());
    // Whether joining enrols the account in account recovery by itself: the policy is on and its
    // data says so.
    let auto_enroll = org.as_ref().is_some_and(recovery::auto_enroll);
    ok(json!({
        "id": id,
        "identifier": id,
        "resetPasswordEnabled": auto_enroll,
    }))
}

async fn domain_sso_verified() -> JsonResult {
    ok(json!({
        "object": "list",
        "data": [{
            "organizationIdentifier": FAKE_SSO_IDENTIFIER,
            "organizationName": FAKE_SSO_IDENTIFIER,
            "domainName": "",
        }],
        "continuationToken": null
    }))
}

async fn plans() -> JsonResult {
    ok(json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        },{
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": null
    }))
}

async fn billing_warnings<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    app.guard(&authed, &org_id, Need::Member).await?;
    ok(json!({
        "freeTrial": null,
        "inactiveSubscription": null,
        "resellerRenewal": null,
        "taxId": null,
    }))
}

async fn self_host_metadata<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    app.guard(&authed, &org_id, Need::Member).await?;
    ok(json!({
        "isOnSecretsManagerStandalone": false,
        "organizationOccupiedSeats": 0
    }))
}

async fn post_org_keys<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: OrgKeyData = parse(&body)?;
    if ctx.org.doc.private_key.is_some() && ctx.org.doc.public_key.is_some() {
        return Err(BwError::msg("Organization Keys already exist"));
    }
    let doc = OrgDoc {
        private_key: Some(data.encrypted_private_key.clone()),
        public_key: Some(data.public_key.clone()),
        ..ctx.org.doc.clone()
    };
    app.put_doc(ctx.org.id.0, KIND_ORG, "", &doc).await?;
    ok(json!({
        "object": "organizationKeys",
        "publicKey": doc.public_key,
        "privateKey": doc.private_key,
    }))
}

async fn org_public_key<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Member).await?;
    ok(json!({
        "object": "organizationPublicKey",
        "publicKey": ctx.org.doc.public_key,
    }))
}

/// The owner's master password, as Vaultwarden's `PasswordOrOtpData::validate`.
async fn check_proof<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    data: &PasswordData,
) -> BwResult<()> {
    match (data.master_password_hash.as_deref(), data.otp.as_deref()) {
        (Some(hash), None) => {
            if app
                .password_matches(&authed.account, hash, Some(authed.ip))
                .await? {
                Ok(())
            } else {
                Err(BwError::msg("Invalid password"))
            }
        }
        (None, Some(_)) => Err(BwError::msg(
            "Protected action token not found, try sending the code again or restart the process",
        )),
        _ => Err(BwError::msg("No validation provided")),
    }
}

async fn org_api_key<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Owner).await?;
    let data: PasswordData = parse(&body)?;
    check_proof(&app, &authed, &data).await?;
    ok(api_key::api_key(&app, &ctx, false).await?)
}

async fn rotate_org_api_key<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Owner).await?;
    let data: PasswordData = parse(&body)?;
    check_proof(&app, &authed, &data).await?;
    ok(api_key::api_key(&app, &ctx, true).await?)
}

async fn org_export<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let collections = Value::Array(collections_plain(&ctx.org));
    let ciphers = Value::Array(ciphers::org_details(&app, &ctx.org, ctx.me).await?);
    ok(json!({
        "collections": lcase_keys(collections),
        "ciphers": lcase_keys(ciphers),
    }))
}

// --- members ----------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdsData {
    ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OptionalIdsData {
    ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmData {
    id: Option<String>,
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkConfirmData {
    keys: Option<Vec<ConfirmData>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
    /// The master password hash: the proof of who accepts when no one is signed in, and what a key
    /// for account recovery needs.
    master_password_hash: Option<String>,
}

#[derive(Deserialize)]
struct MemberQuery {
    #[serde(rename = "includeCollections")]
    include_collections: Option<String>,
    #[serde(rename = "includeGroups")]
    include_groups: Option<String>,
}

fn flag(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(truthy)
}

async fn get_members<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    Query(query): Query<MemberQuery>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    require_full_access(&ctx)?;
    let (collections, groups) = (
        flag(&query.include_collections),
        flag(&query.include_groups),
    );
    let mut out = Vec::new();
    for (user, doc) in &ctx.org.members {
        let info = app.user_info(*user).await?.unwrap_or_default();
        out.push(member_admin_json(
            &ctx.org,
            *user,
            doc,
            &info,
            collections,
            groups,
        ));
    }
    for pending in &ctx.org.pending {
        out.push(pending_admin_json(pending, collections, groups));
    }
    ok(list(out))
}

async fn mini_details<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    let mut out = Vec::new();
    for (user, doc) in &ctx.org.members {
        let info = app.user_info(*user).await?.unwrap_or_default();
        out.push(member_mini_json(*user, doc, &info));
    }
    ok(list(out))
}

async fn get_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
    Query(query): Query<MemberQuery>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let groups = flag(&query.include_groups);
    // Groups need the collections too, or saving would drop them.
    let collections = query.include_collections.as_deref().map_or(groups, truthy);
    if let Some(pending) = ctx.org.pending.iter().find(|p| p.id == member_id) {
        return ok(pending_admin_json(pending, collections, groups));
    }
    let Some(user) = Uuid::parse_str(&member_id)
        .ok()
        .map(UserId)
        .filter(|u| ctx.org.member(*u).is_some())
    else {
        return Err(BwError::msg(
            "The specified user isn't a member of the organization",
        ));
    };
    let doc = ctx
        .org
        .member(user)
        .cloned()
        .unwrap_or_else(|| MemberDoc::new(USER, false, 0));
    let info = app.user_info(user).await?.unwrap_or_default();
    ok(member_admin_json(
        &ctx.org,
        user,
        &doc,
        &info,
        collections,
        groups,
    ))
}

async fn invite_members<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: InviteData = parse(&body)?;
    empty(members::invite(&app, &ctx, authed.user.email.as_str(), data).await)
}

async fn reinvite_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    empty(members::reinvite(&app, &ctx, &member_id).await)
}

async fn bulk_reinvite<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: IdsData = parse(&body)?;
    let mut lines = Vec::new();
    for id in data.ids {
        let error = match members::reinvite(&app, &ctx, &id).await {
            Ok(()) => String::new(),
            Err(error) => error.bulk_line_text(),
        };
        lines.push(bulk_line(
            "OrganizationBulkConfirmResponseModel",
            &id,
            &error,
        ));
    }
    ok(list(lines))
}

async fn accept_invite<S: BwStore>(
    State(app): State<App<S>>,
    Peer(ip): Peer,
    MaybeAuthed(authed): MaybeAuthed,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> EmptyResult {
    let data: AcceptData = parse(&body)?;
    let request = members::AcceptRequest {
        org_id,
        member_id,
        token: data.token,
        reset_key: data.reset_password_key,
        password_hash: data.master_password_hash,
    };
    empty(members::accept(&app, authed.as_ref(), ip, request).await)
}

async fn invite_link_route<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
) -> SecretJsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    ok_no_store(members::pending_link(&app, &ctx, &member_id).await?)
}

async fn confirm_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: ConfirmData = parse(&body)?;
    let key = data.key.unwrap_or_default();
    empty(members::confirm(&app, &ctx, &member_id, &key).await)
}

async fn bulk_confirm<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: BulkConfirmData = parse(&body)?;
    let mut lines = Vec::new();
    for invite in data.keys.unwrap_or_default() {
        let Some(member_id) = invite.id else {
            return Err(BwError::msg("Member id is required"));
        };
        let key = invite.key.unwrap_or_default();
        let error = match members::confirm(&app, &ctx, &member_id, &key).await {
            Ok(()) => String::new(),
            Err(error) => error.bulk_line_text(),
        };
        lines.push(bulk_line(
            "OrganizationBulkConfirmResponseModel",
            &member_id,
            &error,
        ));
    }
    ok(list(lines))
}

async fn edit_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: EditData = parse(&body)?;
    empty(members::edit(&app, &ctx, &member_id, data).await)
}

async fn delete_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    empty(members::remove(&app, &ctx, &member_id).await)
}

async fn bulk_delete_members<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: IdsData = parse(&body)?;
    let mut lines = Vec::new();
    // Each removal reads the organization again: the last owner is counted as they go.
    for id in data.ids {
        let fresh = Ctx {
            org: app.reload(&ctx.org).await?,
            me: ctx.me,
            doc: ctx.doc.clone(),
            acting: ctx.acting,
        };
        let error = match members::remove(&app, &fresh, &id).await {
            Ok(()) => String::new(),
            Err(error) => error.bulk_line_text(),
        };
        lines.push(bulk_line(
            "OrganizationBulkConfirmResponseModel",
            &id,
            &error,
        ));
    }
    ok(list(lines))
}

async fn revoke_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    empty(members::revoke(&app, &ctx, &member_id).await)
}

async fn bulk_revoke<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: OptionalIdsData = parse(&body)?;
    let mut lines = Vec::new();
    for id in data.ids.unwrap_or_default() {
        let fresh = Ctx {
            org: app.reload(&ctx.org).await?,
            me: ctx.me,
            doc: ctx.doc.clone(),
            acting: ctx.acting,
        };
        let error = match members::revoke(&app, &fresh, &id).await {
            Ok(()) => String::new(),
            Err(error) => error.bulk_line_text(),
        };
        lines.push(bulk_line("OrganizationUserBulkResponseModel", &id, &error));
    }
    ok(list(lines))
}

async fn restore_member<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    empty(members::restore(&app, &ctx, &member_id).await)
}

async fn bulk_restore<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: IdsData = parse(&body)?;
    let mut lines = Vec::new();
    for id in data.ids {
        let fresh = Ctx {
            org: app.reload(&ctx.org).await?,
            me: ctx.me,
            doc: ctx.doc.clone(),
            acting: ctx.acting,
        };
        let error = match members::restore(&app, &fresh, &id).await {
            Ok(()) => String::new(),
            Err(error) => error.bulk_line_text(),
        };
        lines.push(bulk_line("OrganizationUserBulkResponseModel", &id, &error));
    }
    ok(list(lines))
}

async fn public_keys<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: IdsData = parse(&body)?;
    let mut out = Vec::new();
    for id in data.ids {
        let Some(user) = Uuid::parse_str(&id)
            .ok()
            .map(UserId)
            .filter(|u| ctx.org.member(*u).is_some())
        else {
            continue;
        };
        if let Some(account) = BwAccountRepo::get(&app.store, user).await? {
            out.push(json!({
                "object": "organizationUserPublicKeyResponseModel",
                "id": id,
                "userId": user.to_string(),
                "key": account.public_key,
            }));
        }
    }
    ok(list(out))
}

// --- account recovery -------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentData {
    reset_password_key: Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

async fn reset_password_details<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    ok(recovery::details(&app, &ctx, &member_id).await?)
}

async fn recover_account<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: RecoverData = parse(&body)?;
    empty(recovery::recover(&app, &ctx, &member_id, data, false).await)
}

/// The older form of the same call, which only sets a new password.
async fn reset_password<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: RecoverData = parse(&body)?;
    empty(recovery::recover(&app, &ctx, &member_id, data, true).await)
}

async fn reset_password_enrollment<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, user_id)): Path<(String, String)>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Member).await?;
    let data: EnrollmentData = parse(&body)?;
    if user_id != ctx.me.to_string() {
        return Err(BwError::msg(
            "User to enroll isn't member of required organization",
        ));
    }
    let proof = PasswordData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    };
    empty(
        recovery::enroll(
            &app,
            &ctx,
            data.reset_password_key,
            check_proof(&app, &authed, &proof),
        )
        .await,
    )
}

// --- collections ------------------------------------------------------------------------------

async fn org_collections<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    require_full_access(&ctx)?;
    ok(list(collections_plain(&ctx.org)))
}

async fn org_collections_details<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    ok(list(collections_details(&ctx)))
}

async fn post_collection<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    let data: FullCollectionData = parse(&body)?;
    ok(create_collection(&app, &ctx, data).await?)
}

async fn post_bulk_access<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    let data: BulkAccessData = parse(&body)?;
    empty(bulk_access(&app, &ctx, data).await)
}

async fn put_collection<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, col_id)): Path<(String, String)>,
    body: Bytes,
) -> JsonResult {
    let (ctx, id) = app.guard_collection(&authed, &org_id, &col_id).await?;
    let data: FullCollectionData = parse(&body)?;
    ok(update_collection(&app, &ctx, id, data).await?)
}

async fn delete_one_collection<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, col_id)): Path<(String, String)>,
) -> EmptyResult {
    let (ctx, id) = app.guard_collection(&authed, &org_id, &col_id).await?;
    empty(delete_collection(&app, &ctx, id).await)
}

async fn bulk_delete_collections<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Manager).await?;
    let data: IdsData = parse(&body)?;
    for text in &data.ids {
        let Ok(uuid) = Uuid::parse_str(text) else {
            return Err(BwError::msg("Collection Id is malformed!"));
        };
        if !ctx.org.collection_manageable(ctx.me, CollectionId(uuid)) {
            return Err(BwError::msg("Collection not found"));
        }
    }
    for text in &data.ids {
        let Some(id) = parse_collection(text) else {
            continue;
        };
        let fresh = Ctx {
            org: app.reload(&ctx.org).await?,
            me: ctx.me,
            doc: ctx.doc.clone(),
            acting: ctx.acting,
        };
        delete_collection(&app, &fresh, id).await?;
    }
    empty(Ok(()))
}

async fn collection_detail<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, col_id)): Path<(String, String)>,
) -> JsonResult {
    let (ctx, id) = app.guard_collection(&authed, &org_id, &col_id).await?;
    let Some(collection) = ctx.org.collection(id) else {
        return Err(BwError::msg("Collection not found"));
    };
    let assigned = ctx.org.can_access_collection(ctx.me, id);
    let mut object = collection_details_json(&ctx.org, collection, ctx.me);
    object["assigned"] = json!(assigned);
    object["users"] = json!(collection_members_json(&ctx.org, id));
    object["groups"] = json!(if ctx.org.groups_enabled {
        collection_groups_json(&ctx.org, id)
    } else {
        Vec::new()
    });
    object["object"] = json!("collectionAccessDetails");
    ok(object)
}

async fn collection_users<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, col_id)): Path<(String, String)>,
) -> JsonResult {
    let (ctx, id) = app.guard_collection(&authed, &org_id, &col_id).await?;
    if ctx.org.collection(id).is_none() {
        return Err(BwError::msg("Collection not found in Organization"));
    }
    let mut out = Vec::new();
    for user in ctx.org.members.keys() {
        if let Some(grant) = ctx.org.user_grant(*user, id) {
            out.push(member_access_json(
                *user,
                grant.read_only,
                grant.hide_passwords,
                grant.manage,
            ));
        }
    }
    ok(json!(out))
}

#[derive(Deserialize)]
struct OrgIdQuery {
    #[serde(rename = "organizationId")]
    organization_id: String,
}

async fn org_details<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Query(query): Query<OrgIdQuery>,
) -> JsonResult {
    let ctx = app
        .guard(&authed, &query.organization_id, Need::Manager)
        .await?;
    require_full_access(&ctx)?;
    ok(list(ciphers::org_details(&app, &ctx.org, ctx.me).await?))
}

// --- groups -----------------------------------------------------------------------------------

async fn groups_for_managers<S: BwStore>(
    app: &App<S>,
    authed: &Authed,
    org_id: &str,
    details: bool,
) -> JsonResult {
    let ctx = app.guard(authed, org_id, Need::Manager).await?;
    let full = ctx.doc.full_access() || ctx.org.group_full_access(ctx.me);
    let allowed = if details {
        full
    } else {
        full || ctx.org.has_manageable_collection(ctx.me)
    };
    if !allowed {
        return Err(not_found_resource());
    }
    ok(list(groups_list(&ctx.org, details)))
}

async fn get_groups<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    groups_for_managers(&app, &authed, &org_id, false).await
}

async fn get_groups_details<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    groups_for_managers(&app, &authed, &org_id, true).await
}

async fn post_group<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: GroupRequest = parse(&body)?;
    ok(save_group(&app, &ctx, None, data).await?)
}

async fn put_group<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, group_id)): Path<(String, String)>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    if !ctx.org.groups_enabled {
        return Err(BwError::msg("Group support is disabled"));
    }
    let Some(id) = parse_group(&group_id).filter(|id| ctx.org.group(*id).is_some()) else {
        return Err(BwError::msg("Group not found"));
    };
    let data: GroupRequest = parse(&body)?;
    ok(save_group(&app, &ctx, Some(id), data).await?)
}

async fn get_group<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, group_id)): Path<(String, String)>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    if !ctx.org.groups_enabled {
        return Err(BwError::msg("Group support is disabled"));
    }
    let Some(group) = parse_group(&group_id).and_then(|id| ctx.org.group(id)) else {
        return Err(BwError::msg("Group not found"));
    };
    ok(group_json(&ctx.org, group))
}

async fn get_group_details<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, group_id)): Path<(String, String)>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    if !ctx.org.groups_enabled {
        return Err(BwError::msg("Group support is disabled"));
    }
    let Some(group) = parse_group(&group_id).and_then(|id| ctx.org.group(id)) else {
        return Err(BwError::msg("Group not found"));
    };
    ok(group_details_json(&ctx.org, group))
}

async fn get_group_members<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, group_id)): Path<(String, String)>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    if !ctx.org.groups_enabled {
        return Err(BwError::msg("Group support is disabled"));
    }
    let Some(group) = parse_group(&group_id).and_then(|id| ctx.org.group(id)) else {
        return Err(BwError::msg("Group could not be found!"));
    };
    let members: Vec<String> = group.members.iter().map(ToString::to_string).collect();
    ok(json!(members))
}

async fn delete_one_group<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, group_id)): Path<(String, String)>,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let Some(id) = parse_group(&group_id) else {
        return Err(BwError::msg("Group not found"));
    };
    empty(delete_group(&app, &ctx, id).await)
}

async fn bulk_delete_groups<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    if !ctx.org.groups_enabled {
        return Err(BwError::msg("Group support is disabled"));
    }
    let data: IdsData = parse(&body)?;
    for text in data.ids {
        let Some(id) = parse_group(&text) else {
            return Err(BwError::msg("Group not found"));
        };
        let fresh = Ctx {
            org: app.reload(&ctx.org).await?,
            me: ctx.me,
            doc: ctx.doc.clone(),
            acting: ctx.acting,
        };
        delete_group(&app, &fresh, id).await?;
    }
    empty(Ok(()))
}

// --- policies ---------------------------------------------------------------------------------

fn policies_of(ctx: &Ctx) -> Vec<Value> {
    ctx.org
        .policies
        .iter()
        .map(|(ptype, policy)| policy_json(&ctx.org.id.to_string(), *ptype, policy))
        .collect()
}

async fn list_policies<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    ok(list(policies_of(&ctx)))
}

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}

async fn list_policies_token<S: BwStore>(
    State(app): State<App<S>>,
    Path(org_id): Path<String>,
    Query(query): Query<TokenQuery>,
) -> JsonResult {
    let claims: InviteClaims = app
        .keys
        .decode(&query.token, &app.settings.issuer("invite"), app.now_secs())
        .map_err(|e| BwError::msg(e.to_string()))?;
    if claims.org_id != org_id {
        return Err(BwError::msg("Token doesn't match request organization"));
    }
    let Some(org) = app.load_org(space_id(&org_id)?).await? else {
        return ok(list(Vec::new()));
    };
    let data = org
        .policies
        .iter()
        .map(|(ptype, policy)| policy_json(&org.id.to_string(), *ptype, policy))
        .collect();
    ok(list(data))
}

async fn dummy_master_password_policy<S: BwStore>(State(app): State<App<S>>) -> JsonResult {
    ok(blank_policy(
        FAKE_SSO_IDENTIFIER,
        MASTER_PASSWORD,
        app.now(),
        Uuid::nil().to_string(),
    ))
}

async fn master_password_policy<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Member).await?;
    ok(match ctx.org.policy(MASTER_PASSWORD) {
        Some(policy) => policy_json(&org_id, MASTER_PASSWORD, policy),
        None => blank_policy(&org_id, MASTER_PASSWORD, app.now(), Uuid::nil().to_string()),
    })
}

async fn get_policy<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, pol_type)): Path<(String, i32)>,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    if !is_known(pol_type) {
        return Err(BwError::msg("Invalid or unsupported policy type"));
    }
    ok(match ctx.org.policy(pol_type) {
        Some(policy) => policy_json(&org_id, pol_type, policy),
        None => blank_policy(&org_id, pol_type, app.now(), Uuid::nil().to_string()),
    })
}

async fn put_one_policy<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, pol_type)): Path<(String, i32)>,
    body: Bytes,
) -> JsonResult {
    let ctx = app.guard(&authed, &org_id, Need::Admin).await?;
    let data: PutPolicy = parse(&body)?;
    ok(put_policy(&app, &ctx, pol_type, data.policy).await?)
}

// --- ciphers of organizations -----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareData {
    #[serde(alias = "Cipher")]
    cipher: CipherData,
    #[serde(alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareSelectedData {
    ciphers: Vec<CipherData>,
    collection_ids: Vec<String>,
}

#[derive(Deserialize)]
struct CollectionsData {
    #[serde(alias = "CollectionIds", rename = "collectionIds")]
    collection_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionsData {
    organization_id: String,
    cipher_ids: Vec<String>,
    collection_ids: Vec<String>,
    remove_collections: bool,
}

#[derive(Deserialize)]
struct ImportQuery {
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
}

/// `POST /api/ciphers/import-organization?organizationId=…`.
async fn import_org_ciphers<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Query(query): Query<ImportQuery>,
    body: Bytes,
) -> EmptyResult {
    // The guard reads the organization from the query; without one it has no one to let in.
    let Some(org_id) = query.organization_id else {
        return Err(BwError::Unauthorized);
    };
    let ctx = app.guard(&authed, &org_id, Need::Member).await?;
    let data: ciphers::OrgImportData = parse(&body)?;
    empty(ciphers::import_organization(&app, &ctx, data).await)
}

async fn share_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: ShareData = parse(&body)?;
    if data.cipher.organization_id.is_none() {
        return Err(BwError::msg("Cipher OrganizationId is required."));
    }
    if data.collection_ids.is_empty() {
        return Err(BwError::msg("You must select at least one collection."));
    }
    ok(ciphers::share_one(&app, &authed, &id, data.cipher, &data.collection_ids, true).await?)
}

async fn share_selected<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: ShareSelectedData = parse(&body)?;
    ok(ciphers::share_selected(&app, &authed, data.ciphers, data.collection_ids).await?)
}

async fn cipher_collections<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: CollectionsData = parse(&body)?;
    ok(ciphers::update_collections(&app, &authed, &id, &data.collection_ids).await?)
}

async fn cipher_collections_v2<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: CollectionsData = parse(&body)?;
    let cipher = ciphers::update_collections(&app, &authed, &id, &data.collection_ids).await?;
    ok(json!({
        "object": "optionalCipherDetails",
        "unavailable": false,
        "cipher": cipher,
    }))
}

async fn bulk_collections<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: BulkCollectionsData = parse(&body)?;
    empty(
        ciphers::bulk_collections(
            &app,
            &authed,
            &data.organization_id,
            &data.cipher_ids,
            &data.collection_ids,
            data.remove_collections,
        )
        .await,
    )
}

/// `PUT /api/ciphers/{id}/admin`: only organization ciphers are edited here.
async fn admin_update_cipher<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: CipherData = parse(&body)?;
    if data.organization_id.is_none() {
        return Err(not_found_resource());
    }
    ok(crate::vault::update_cipher(&app, &authed, &id, data).await?)
}

async fn admin_delete_hard<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    empty(crate::vault::delete_cipher(&app, &authed, &id, false).await)
}

async fn admin_delete_soft<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    empty(crate::vault::delete_cipher(&app, &authed, &id, true).await)
}

async fn admin_restore<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    ok(crate::vault::restore_cipher(&app, &authed, &id).await?)
}

#[derive(Deserialize)]
struct CipherIds {
    ids: std::collections::HashSet<String>,
}

async fn admin_delete_many_hard<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: CipherIds = parse(&body)?;
    empty(crate::vault::delete_ciphers(&app, &authed, &data.ids, false).await)
}

async fn admin_delete_many_soft<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: CipherIds = parse(&body)?;
    empty(crate::vault::delete_ciphers(&app, &authed, &data.ids, true).await)
}

async fn admin_restore_many<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> JsonResult {
    let data: CipherIds = parse(&body)?;
    ok(crate::vault::restore_ciphers(&app, &authed, &data.ids).await?)
}

/// The organization routes.
pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        // the organization
        .route("/api/organizations", post(create_organization::<S>))
        .route(
            "/api/organizations/{org_id}",
            get(get_organization::<S>)
                .put(put_organization::<S>)
                .delete(delete_organization::<S>),
        )
        .route(
            "/api/organizations/{org_id}/leave",
            post(leave_organization::<S>),
        )
        .route("/api/collections", get(user_collections::<S>))
        .route(
            "/api/organizations/{org_id}/auto-enroll-status",
            get(auto_enroll_status::<S>),
        )
        .route(
            "/api/organizations/domain/sso/verified",
            post(domain_sso_verified),
        )
        .route("/api/plans", get(plans))
        .route(
            "/api/organizations/{org_id}/billing/vnext/warnings",
            get(billing_warnings::<S>),
        )
        .route(
            "/api/organizations/{org_id}/billing/vnext/self-host/metadata",
            get(self_host_metadata::<S>),
        )
        .route(
            "/api/organizations/{org_id}/keys",
            get(org_public_key::<S>).post(post_org_keys::<S>),
        )
        .route(
            "/api/organizations/{org_id}/public-key",
            get(org_public_key::<S>),
        )
        .route("/api/organizations/{org_id}/export", get(org_export::<S>))
        .route(
            "/api/organizations/{org_id}/api-key",
            post(org_api_key::<S>),
        )
        .route(
            "/api/organizations/{org_id}/rotate-api-key",
            post(rotate_org_api_key::<S>),
        )
        // members
        .route(
            "/api/organizations/{org_id}/users",
            get(get_members::<S>).delete(bulk_delete_members::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/mini-details",
            get(mini_details::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/invite",
            post(invite_members::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/reinvite",
            post(bulk_reinvite::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/confirm",
            post(bulk_confirm::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/public-keys",
            post(public_keys::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/revoke",
            put(bulk_revoke::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/restore",
            put(bulk_restore::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}",
            get(get_member::<S>)
                .put(edit_member::<S>)
                .delete(delete_member::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reinvite",
            post(reinvite_member::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/accept",
            post(accept_invite::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/invite-link",
            get(invite_link_route::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/confirm",
            post(confirm_member::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/revoke",
            put(revoke_member::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/restore",
            put(restore_member::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/restore/vnext",
            put(restore_member::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password-details",
            get(reset_password_details::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password",
            put(reset_password::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/recover-account",
            put(recover_account::<S>),
        )
        .route(
            "/api/organizations/{org_id}/users/{member_id}/reset-password-enrollment",
            put(reset_password_enrollment::<S>),
        )
        // collections
        .route(
            "/api/organizations/{org_id}/collections",
            get(org_collections::<S>)
                .post(post_collection::<S>)
                .delete(bulk_delete_collections::<S>),
        )
        .route(
            "/api/organizations/{org_id}/collections/details",
            get(org_collections_details::<S>),
        )
        .route(
            "/api/organizations/{org_id}/collections/bulk-access",
            post(post_bulk_access::<S>),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}",
            put(put_collection::<S>).delete(delete_one_collection::<S>),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/details",
            get(collection_detail::<S>),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/users",
            get(collection_users::<S>),
        )
        // groups
        .route(
            "/api/organizations/{org_id}/groups",
            get(get_groups::<S>)
                .post(post_group::<S>)
                .delete(bulk_delete_groups::<S>),
        )
        .route(
            "/api/organizations/{org_id}/groups/details",
            get(get_groups_details::<S>),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}",
            get(get_group::<S>)
                .put(put_group::<S>)
                .delete(delete_one_group::<S>),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/details",
            get(get_group_details::<S>),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/users",
            get(get_group_members::<S>),
        )
        // policies
        .route(
            "/api/organizations/{org_id}/policies",
            get(list_policies::<S>),
        )
        .route(
            "/api/organizations/{org_id}/policies/token",
            get(list_policies_token::<S>),
        )
        .route(
            "/api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password",
            get(dummy_master_password_policy::<S>),
        )
        .route(
            "/api/organizations/{org_id}/policies/master-password",
            get(master_password_policy::<S>),
        )
        .route(
            "/api/organizations/{org_id}/policies/{pol_type}",
            get(get_policy::<S>).put(put_one_policy::<S>),
        )
        // ciphers
        .route("/api/ciphers/organization-details", get(org_details::<S>))
        .route(
            "/api/ciphers/import-organization",
            post(import_org_ciphers::<S>),
        )
        .route("/api/ciphers/bulk-collections", post(bulk_collections::<S>))
        .route("/api/ciphers/share", put(share_selected::<S>))
        .route(
            "/api/ciphers/{id}/share",
            put(share_cipher::<S>).post(share_cipher::<S>),
        )
        .route(
            "/api/ciphers/{id}/collections",
            put(cipher_collections::<S>).post(cipher_collections::<S>),
        )
        .route(
            "/api/ciphers/{id}/collections-admin",
            put(cipher_collections::<S>).post(cipher_collections::<S>),
        )
        .route(
            "/api/ciphers/{id}/collections_v2",
            put(cipher_collections_v2::<S>).post(cipher_collections_v2::<S>),
        )
        .route(
            "/api/ciphers/{id}/admin",
            put(admin_update_cipher::<S>)
                .post(admin_update_cipher::<S>)
                .delete(admin_delete_hard::<S>),
        )
        .route(
            "/api/ciphers/{id}/delete-admin",
            put(admin_delete_soft::<S>).post(admin_delete_hard::<S>),
        )
        .route("/api/ciphers/{id}/restore-admin", put(admin_restore::<S>))
        .route("/api/ciphers/restore-admin", put(admin_restore_many::<S>))
        .route("/api/ciphers/admin", delete(admin_delete_many_hard::<S>))
        .route(
            "/api/ciphers/delete-admin",
            post(admin_delete_many_hard::<S>).put(admin_delete_many_soft::<S>),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_billing_email_is_lower_cased_and_checked() {
        assert_eq!(
            valid_billing_email(" Ada@Example.ORG "),
            Ok("ada@example.org".to_owned())
        );
        assert_eq!(
            valid_billing_email("nonsense"),
            Err(BwError::msg(
                "BillingEmail nonsense is not a valid email address"
            ))
        );
    }

    #[test]
    fn a_flag_follows_rockets_bool_values() {
        assert!(flag(&Some("true".to_owned())));
        assert!(flag(&Some("on".to_owned())));
        assert!(!flag(&Some("false".to_owned())));
        assert!(!flag(&None));
    }
}
