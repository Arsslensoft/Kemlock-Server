//! Emergency access: invite a contact, accept, confirm with a sealed key, ask, wait, release.
//!
//! The grantor's app seals the root key to the contact's `kx1` key (docs/crypto.md, context
//! `"emergency-access"`) and sends the box at confirmation; the server hands it to the contact
//! only once the grant is approved, by the grantor or by the timer after the wait.

use crate::dto::decode;
use crate::extract::{Authed, Body};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use kemlock_app::b64url;
use kemlock_app::emergency::{
    ContactKeys, EmergencyAccess, EmergencyOverview, EmergencyRepo, GrantView, KeyRelease,
};
use kemlock_app::notices::Notices;
use kemlock_app::ports::TokenSigner;
use kemlock_domain::unlock::{EmergencyGrant, EmergencyKind, EmergencyState, GrantId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

fn iso(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_default()
}

fn grant_id(raw: &str) -> Result<GrantId, Problem> {
    raw.parse()
        .map_err(|_| Problem::bad_request("the grant id isn't a UUID"))
}

// ---------------------------------------------------------------------------------------------
// Bodies.

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmergencyInviteRequest {
    /// The contact's email.
    pub(crate) email: String,
    /// `"view"` or `"takeover"`.
    #[schema(value_type = String)]
    pub(crate) kind: EmergencyKind,
    /// Days to wait after the contact asks, 1 to 90.
    pub(crate) wait_days: u32,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmergencyConfirmRequest {
    /// The root key sealed to the contact's `kx1` key, base64url.
    pub(crate) sealed_key: String,
    /// The key version of the root key in the box. A box for a version that is no longer the
    /// account's is refused with `409 key-version-stale`; absent (an old client) is accepted.
    pub(crate) key_version: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmergencyGrantDto {
    pub(crate) id: Uuid,
    pub(crate) grantor_id: Uuid,
    pub(crate) grantee_email: String,
    pub(crate) grantee_id: Option<Uuid>,
    /// `"view"` or `"takeover"`.
    #[schema(value_type = String)]
    pub(crate) kind: EmergencyKind,
    pub(crate) wait_days: u32,
    /// `"invited"`, `"accepted"`, `"confirmed"`, `"recovery-initiated"`, `"approved"` or
    /// `"rejected"`.
    #[schema(value_type = String)]
    pub(crate) state: EmergencyState,
    pub(crate) recovery_initiated_at: Option<String>,
    /// While a request runs: when the wait ends and the timer approves.
    pub(crate) due_at: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

impl EmergencyGrantDto {
    fn from_grant(g: &EmergencyGrant) -> Self {
        EmergencyGrantDto {
            id: g.id.0,
            grantor_id: g.grantor.0,
            grantee_email: g.grantee_email.as_str().to_owned(),
            grantee_id: g.grantee.map(|u| u.0),
            kind: g.kind,
            wait_days: g.wait_days,
            state: g.state,
            recovery_initiated_at: g.recovery_initiated_at.map(iso),
            due_at: g.due_at().map(iso),
            created_at: iso(g.created_at),
            updated_at: iso(g.updated_at),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContactKeysDto {
    /// The contact's signed public-key bundle, base64url. Compare its fingerprint, then seal to
    /// its `kx1` key.
    pub(crate) public_bundle: String,
    pub(crate) bundle_signature: String,
    pub(crate) key_version: u32,
}

impl ContactKeysDto {
    fn from_keys(keys: &ContactKeys) -> Self {
        ContactKeysDto {
            public_bundle: b64url::encode(&keys.public_bundle),
            bundle_signature: b64url::encode(&keys.bundle_signature),
            key_version: keys.key_version,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GrantViewDto {
    pub(crate) grant: EmergencyGrantDto,
    /// On the contact's side: who named them.
    pub(crate) grantor_email: Option<String>,
    /// On the grantor's side, while the contact waits for confirmation.
    pub(crate) contact_keys: Option<ContactKeysDto>,
}

impl GrantViewDto {
    fn from_view(v: &GrantView) -> Self {
        GrantViewDto {
            grant: EmergencyGrantDto::from_grant(&v.grant),
            grantor_email: v.grantor_email.as_ref().map(|e| e.as_str().to_owned()),
            contact_keys: v.contact_keys.as_ref().map(ContactKeysDto::from_keys),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OverviewResponse {
    /// Grants where the signed-in account is the grantor.
    pub(crate) trusted_contacts: Vec<GrantViewDto>,
    /// Grants that name the signed-in account as the contact.
    pub(crate) grantors: Vec<GrantViewDto>,
}

impl OverviewResponse {
    fn from_overview(o: &EmergencyOverview) -> Self {
        OverviewResponse {
            trusted_contacts: o
                .trusted_contacts
                .iter()
                .map(GrantViewDto::from_view)
                .collect(),
            grantors: o.grantors.iter().map(GrantViewDto::from_view).collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyReleaseResponse {
    pub(crate) grant_id: Uuid,
    pub(crate) grantor_id: Uuid,
    /// `"view"` or `"takeover"`.
    #[schema(value_type = String)]
    pub(crate) kind: EmergencyKind,
    /// The root key sealed to the contact's `kx1` key, base64url.
    pub(crate) sealed_key: String,
}

impl KeyReleaseResponse {
    fn from_release(r: &KeyRelease) -> Self {
        KeyReleaseResponse {
            grant_id: r.grant.0,
            grantor_id: r.grantor.0,
            kind: r.kind,
            sealed_key: b64url::encode(&r.sealed_key),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers.

impl<S: Store + EmergencyRepo, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    fn emergency_access(&self) -> EmergencyAccess<S, S, Notices, P, S> {
        EmergencyAccess {
            users: self.store.clone(),
            grants: self.store.clone(),
            notices: self.hub.notices(),
            env: self.crypto.clone(),
            events: self.store.clone(),
        }
    }

    /// `GET /kem/v1/emergency`: the account's contacts and the accounts that named it.
    pub(crate) async fn handle_emergency_overview(
        State(api): State<Self>,
        authed: Authed,
    ) -> Result<Json<OverviewResponse>, Problem> {
        let overview = api.emergency_access().list(&authed.actor).await?;
        Ok(Json(OverviewResponse::from_overview(&overview)))
    }

    /// `POST /kem/v1/emergency/grants`: names a contact.
    pub(crate) async fn handle_emergency_invite(
        State(api): State<Self>,
        authed: Authed,
        body: Body,
    ) -> Result<(StatusCode, Json<EmergencyGrantDto>), Problem> {
        let request: EmergencyInviteRequest = body.json()?;
        let grant = api
            .emergency_access()
            .invite(
                &authed.actor,
                &request.email,
                request.kind,
                request.wait_days,
            )
            .await?;
        Ok((
            StatusCode::CREATED,
            Json(EmergencyGrantDto::from_grant(&grant)),
        ))
    }

    /// `POST /kem/v1/emergency/grants/{id}/accept`: the contact accepts.
    pub(crate) async fn handle_emergency_accept(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<Json<EmergencyGrantDto>, Problem> {
        let grant = api
            .emergency_access()
            .accept(&authed.actor, grant_id(&id)?)
            .await?;
        Ok(Json(EmergencyGrantDto::from_grant(&grant)))
    }

    /// `POST /kem/v1/emergency/grants/{id}/confirm`: the grantor stores the sealed key.
    pub(crate) async fn handle_emergency_confirm(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
        body: Body,
    ) -> Result<Json<EmergencyGrantDto>, Problem> {
        let id = grant_id(&id)?;
        let request: EmergencyConfirmRequest = body.json()?;
        let grant = api
            .emergency_access()
            .confirm_at(
                &authed.actor,
                id,
                decode("sealedKey", &request.sealed_key)?,
                request.key_version,
            )
            .await?;
        Ok(Json(EmergencyGrantDto::from_grant(&grant)))
    }

    /// `POST /kem/v1/emergency/grants/{id}/initiate`: the contact asks; the wait starts.
    pub(crate) async fn handle_emergency_initiate(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<Json<EmergencyGrantDto>, Problem> {
        let grant = api
            .emergency_access()
            .initiate(&authed.actor, grant_id(&id)?)
            .await?;
        Ok(Json(EmergencyGrantDto::from_grant(&grant)))
    }

    /// `POST /kem/v1/emergency/grants/{id}/approve`: the grantor says yes before the wait ends.
    pub(crate) async fn handle_emergency_approve(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<Json<EmergencyGrantDto>, Problem> {
        let grant = api
            .emergency_access()
            .approve(&authed.actor, grant_id(&id)?)
            .await?;
        Ok(Json(EmergencyGrantDto::from_grant(&grant)))
    }

    /// `POST /kem/v1/emergency/grants/{id}/reject`: the grantor refuses.
    pub(crate) async fn handle_emergency_reject(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<Json<EmergencyGrantDto>, Problem> {
        let grant = api
            .emergency_access()
            .reject(&authed.actor, grant_id(&id)?)
            .await?;
        Ok(Json(EmergencyGrantDto::from_grant(&grant)))
    }

    /// `GET /kem/v1/emergency/grants/{id}/key`: the sealed key, for the contact, once approved.
    pub(crate) async fn handle_emergency_key(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<Json<KeyReleaseResponse>, Problem> {
        let release = api
            .emergency_access()
            .release_key(&authed.actor, grant_id(&id)?)
            .await?;
        Ok(Json(KeyReleaseResponse::from_release(&release)))
    }

    /// `DELETE /kem/v1/emergency/grants/{id}`: either party ends the grant.
    pub(crate) async fn handle_emergency_revoke(
        State(api): State<Self>,
        authed: Authed,
        Path(id): Path<String>,
    ) -> Result<StatusCode, Problem> {
        api.emergency_access()
            .revoke(&authed.actor, grant_id(&id)?)
            .await?;
        Ok(StatusCode::NO_CONTENT)
    }
}

/// The routes of this module. Merged into the main router by `service::router`.
pub(crate) fn router<S, P, K>() -> Router<Api<S, P, K>>
where
    S: Store + EmergencyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    type A<S, P, K> = Api<S, P, K>;
    Router::new()
        .route(
            "/kem/v1/emergency",
            get(A::<S, P, K>::handle_emergency_overview),
        )
        .route(
            "/kem/v1/emergency/grants",
            post(A::<S, P, K>::handle_emergency_invite),
        )
        .route(
            "/kem/v1/emergency/grants/{id}",
            delete(A::<S, P, K>::handle_emergency_revoke),
        )
        .route(
            "/kem/v1/emergency/grants/{id}/accept",
            post(A::<S, P, K>::handle_emergency_accept),
        )
        .route(
            "/kem/v1/emergency/grants/{id}/confirm",
            post(A::<S, P, K>::handle_emergency_confirm),
        )
        .route(
            "/kem/v1/emergency/grants/{id}/initiate",
            post(A::<S, P, K>::handle_emergency_initiate),
        )
        .route(
            "/kem/v1/emergency/grants/{id}/approve",
            post(A::<S, P, K>::handle_emergency_approve),
        )
        .route(
            "/kem/v1/emergency/grants/{id}/reject",
            post(A::<S, P, K>::handle_emergency_reject),
        )
        .route(
            "/kem/v1/emergency/grants/{id}/key",
            get(A::<S, P, K>::handle_emergency_key),
        )
}

// ---------------------------------------------------------------------------------------------
// OpenAPI.

#[utoipa::path(
    get, path = "/kem/v1/emergency", tag = "emergency-access",
    security(("dpop" = [])),
    responses((status = 200, description = "Both lists of the account", body = OverviewResponse))
)]
#[allow(dead_code)]
fn doc_overview() {}

#[utoipa::path(
    post, path = "/kem/v1/emergency/grants", tag = "emergency-access",
    security(("dpop" = [])),
    request_body = EmergencyInviteRequest,
    responses(
        (status = 201, description = "The contact is invited", body = EmergencyGrantDto),
        (status = 409, description = "That contact is already named", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_invite() {}

#[utoipa::path(
    delete, path = "/kem/v1/emergency/grants/{id}", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    responses((status = 204, description = "The grant is deleted, sealed key and all"))
)]
#[allow(dead_code)]
fn doc_revoke() {}

#[utoipa::path(
    post, path = "/kem/v1/emergency/grants/{id}/accept", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    responses((status = 200, description = "Accepted by the contact", body = EmergencyGrantDto))
)]
#[allow(dead_code)]
fn doc_accept() {}

#[utoipa::path(
    post, path = "/kem/v1/emergency/grants/{id}/confirm", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    request_body = EmergencyConfirmRequest,
    responses((status = 200, description = "Confirmed; the sealed key is stored", body = EmergencyGrantDto))
)]
#[allow(dead_code)]
fn doc_confirm() {}

#[utoipa::path(
    post, path = "/kem/v1/emergency/grants/{id}/initiate", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    responses((status = 200, description = "The wait has started", body = EmergencyGrantDto))
)]
#[allow(dead_code)]
fn doc_initiate() {}

#[utoipa::path(
    post, path = "/kem/v1/emergency/grants/{id}/approve", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    responses((status = 200, description = "Approved before the wait ended", body = EmergencyGrantDto))
)]
#[allow(dead_code)]
fn doc_approve() {}

#[utoipa::path(
    post, path = "/kem/v1/emergency/grants/{id}/reject", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    responses((status = 200, description = "Refused; the contact may ask again", body = EmergencyGrantDto))
)]
#[allow(dead_code)]
fn doc_reject() {}

#[utoipa::path(
    get, path = "/kem/v1/emergency/grants/{id}/key", tag = "emergency-access",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The grant id")),
    responses(
        (status = 200, description = "The sealed key", body = KeyReleaseResponse),
        (status = 403, description = "The grant isn't approved", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_key() {}

/// The documented routes of this module.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_overview,
        doc_invite,
        doc_revoke,
        doc_accept,
        doc_confirm,
        doc_initiate,
        doc_approve,
        doc_reject,
        doc_key
    ),
    components(schemas(
        EmergencyInviteRequest,
        EmergencyConfirmRequest,
        EmergencyGrantDto,
        ContactKeysDto,
        GrantViewDto,
        OverviewResponse,
        KeyReleaseResponse
    ))
)]
struct EmergencyDoc;

pub(crate) fn document() -> utoipa::openapi::OpenApi {
    EmergencyDoc::openapi()
}
