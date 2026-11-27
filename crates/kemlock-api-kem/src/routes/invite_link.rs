//! The link that accepts a Bitwarden organization's invitation:
//! `GET /kem/v1/spaces/{id}/members/{user}/invite-link`.
//!
//! A server that can't mail has no mail to carry the accept link of an invited account, so an
//! owner or admin of the organization copies it from the space page and hands it over. The link only
//! leads the invitee to sign in and accept for themselves, it accepts nothing by itself; the answer is
//! still never cached, and only
//! a confirmed owner or admin of an organization (an owner when the invitation is for a manager,
//! admin or owner) may ask, and only while the member is still invited.
//!
//! The link is made by the Bitwarden API, which the server hands over as a request extension
//! (`kemlock_app::bitwarden::SharedInviteLinks`); a server without one answers 404 as for a space
//! that isn't an organization. The route has its own small router, merged beside the spaces router.

use crate::extract::{Authed, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use kemlock_app::AppError;
use kemlock_app::bitwarden::{Asker, InviteLinkError, MemberInviteLink, SharedInviteLinks};
use kemlock_app::ports::TokenSigner;
use kemlock_domain::{SpaceId, UserId};
use serde::Serialize;
use std::convert::Infallible;
use utoipa::{OpenApi, ToSchema};

/// The Bitwarden API's invitation links, if the server provided them: it layers a
/// `SharedInviteLinks` extension on its router. Never rejects.
#[derive(Clone)]
pub struct MaybeInviteLinks(pub Option<SharedInviteLinks>);

impl std::fmt::Debug for MaybeInviteLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MaybeInviteLinks")
            .field(&self.0.is_some())
            .finish()
    }
}

impl<St: Send + Sync> FromRequestParts<St> for MaybeInviteLinks {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Infallible> {
        Ok(MaybeInviteLinks(
            parts.extensions.get::<SharedInviteLinks>().cloned(),
        ))
    }
}

/// What a refused request says: the same problems for both APIs that hand the link over.
impl From<InviteLinkError> for Problem {
    fn from(e: InviteLinkError) -> Self {
        match e {
            InviteLinkError::NotOrganization | InviteLinkError::NotFound => Problem::not_found(),
            InviteLinkError::Forbidden(why) => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed").detail(why)
            }
            InviteLinkError::NotInvited => Problem::new(
                StatusCode::CONFLICT,
                "not-invited",
                "That member isn't waiting to accept an invitation",
            )
            .detail("the member has accepted already, so there is no link to hand over"),
            InviteLinkError::Server(message) => Problem::from(AppError::Store(message)),
        }
    }
}

/// The link of an invitation.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InviteLinkDto {
    /// The address to open in the web vault. Whoever opens it accepts for the invited account.
    link: String,
    /// When the link stops working, in Unix seconds.
    expires_at: i64,
}

impl InviteLinkDto {
    fn of(link: &MemberInviteLink) -> Self {
        InviteLinkDto {
            link: link.link.clone(),
            expires_at: link.expires_at,
        }
    }
}

async fn fetch<S, P, K>(
    State(_api): State<Api<S, P, K>>,
    authed: Authed,
    links: MaybeInviteLinks,
    Path((id, user)): Path<(String, String)>,
) -> Result<([(HeaderName, &'static str); 1], Json<InviteLinkDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let space: SpaceId = id
        .parse()
        .map_err(|_| Problem::bad_request("the space id isn't a UUID"))?;
    let member: UserId = user
        .parse()
        .map_err(|_| Problem::bad_request("the member id isn't a UUID"))?;
    let links = links.0.ok_or_else(Problem::not_found)?;
    let link = links
        .member_link(space, member, Asker::Member(authed.actor.user))
        .await?;
    Ok((
        [(CACHE_CONTROL, "no-store")],
        Json(InviteLinkDto::of(&link)),
    ))
}

/// Every response carries the current DPoP nonce, as the main router's do.
async fn nonce_header<S, P, K>(
    State(api): State<Api<S, P, K>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&api.dpop.current_nonce(api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The invitation link route. Merge it beside [`crate::spaces_router`]; it has no fallback. The
/// server layers the Bitwarden API's `SharedInviteLinks` as a request extension.
///
/// ```text
/// GET  /kem/v1/spaces/{id}/members/{user}/invite-link   {"link", "expiresAt"}
/// ```
pub fn router<S, P, K>(api: Api<S, P, K>) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/spaces/{id}/members/{user}/invite-link",
            get(fetch::<S, P, K>),
        )
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/members/{user}/invite-link", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID: a Bitwarden organization"),
        ("user" = String, Path, description = "The invited member: an account id"),
    ),
    responses(
        (status = 200, description = "The link that accepts the member's invitation, for a server that can't mail it. Whoever opens it accepts for that account, so the answer is `Cache-Control: no-store`", body = InviteLinkDto),
        (status = 403, description = "The caller isn't a confirmed Owner or Admin of the organization, or is an Admin asking for the invitation of a Manager, Admin or Owner", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such space or member, the space isn't a Bitwarden organization, or the caller isn't in it", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "not-invited: the member has accepted already", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_invite_link() {}

#[derive(OpenApi)]
#[openapi(paths(doc_invite_link), components(schemas(InviteLinkDto)))]
struct InviteLinkDoc;

/// The OpenAPI document of the invitation link route alone.
pub fn openapi() -> utoipa::openapi::OpenApi {
    InviteLinkDoc::openapi()
}
