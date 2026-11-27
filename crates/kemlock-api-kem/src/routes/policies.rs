//! Space policies: `GET` and `PUT /kem/v1/spaces/{id}/policies`, `GET /kem/v1/policies`, and the
//! check that holds a person back from joining a space its policies refuse.
//!
//! - `GET /spaces/{id}/policies` gives any confirmed member the space's policies: clients need
//!   them to enforce the ones only a client can (the master password rules, the session timeout, no
//!   export of space items). `PUT` replaces them and is for owners and admins. Someone outside the
//!   space gets 404.
//! - `GET /policies` gives the caller what binds them across every space they are in: the strictest
//!   master password rules, the shortest session timeout, and which policies are on. Owners and
//!   admins are exempt from the joining, sign-in and Send policies of their own space.
//! - [`with_join_guard`] wraps the spaces router. A `POST` that accepts an invitation
//!   (`…/members/{user}/accept`) or confirms a member (`…/members/{user}/confirm`) is refused with
//!   403 when the space requires two-step login and the person has none, or when one space per
//!   member rules the join out. The guard reads the caller from the access token's signature and
//!   leaves the handler to authenticate, so a bad token passes through to be refused there.
//!
//! The routes need a policy store besides the API's own state, so they are a router of their own,
//! [`policies_router`], merged by the server beside the spaces router. Booleans are plain JSON
//! booleans, times are Unix seconds.

use crate::extract::{Authed, Body, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use kemlock_app::Actor;
use kemlock_app::AppError;
use kemlock_app::policies::{
    GetPolicies, JoinGuard, MyPolicies, PoliciesError, PolicyRepo, SetPolicies, StoredPolicies,
};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::{SpaceChainRepo, SpaceRepo};
use kemlock_app::sso::SsoSettingsRepo;
use kemlock_domain::policies::{
    EffectivePolicies, MasterPasswordPolicy, SpacePolicies, TimeoutAction,
};
use kemlock_domain::{SpaceId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

// ---- wire types ----

/// The master password rules. Clients enforce them: the server never sees a password.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct MasterPasswordDto {
    /// The fewest characters (1 to 128).
    pub min_length: Option<u32>,
    /// Bitwarden's complexity score, 0 to 4.
    pub min_complexity: Option<u8>,
    pub require_upper: bool,
    pub require_lower: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    /// Whether a client also checks the password at each sign-in.
    pub enforce_on_login: bool,
}

impl MasterPasswordDto {
    fn of(mp: &MasterPasswordPolicy) -> MasterPasswordDto {
        MasterPasswordDto {
            min_length: mp.min_length,
            min_complexity: mp.min_complexity,
            require_upper: mp.require_upper,
            require_lower: mp.require_lower,
            require_numbers: mp.require_numbers,
            require_special: mp.require_special,
            enforce_on_login: mp.enforce_on_login,
        }
    }

    fn domain(&self) -> MasterPasswordPolicy {
        MasterPasswordPolicy {
            min_length: self.min_length,
            min_complexity: self.min_complexity,
            require_upper: self.require_upper,
            require_lower: self.require_lower,
            require_numbers: self.require_numbers,
            require_special: self.require_special,
            enforce_on_login: self.enforce_on_login,
        }
    }
}

/// A space's policies. Every setting defaults to off, so a `PUT` that leaves one out turns it off.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct PoliciesDto {
    /// Members sign in through SSO only. Owners and admins are exempt.
    pub require_sso: bool,
    /// A member needs a confirmed two-step method to join. Owners and admins are exempt.
    pub two_step: bool,
    /// The master password rules; absent for none.
    pub master_password: Option<MasterPasswordDto>,
    /// A member may belong to no other space. Owners and admins are exempt.
    pub single_space: bool,
    /// Clients refuse to export the space's items. Advice only: whoever can view an item can copy
    /// it, so the server cannot make this true.
    pub disable_export: bool,
    /// Members can't make Sends. Owners and admins are exempt.
    pub disable_send: bool,
    /// "Always show the sender's email": a member's Send can't hide it. Owners and admins are
    /// exempt.
    pub always_show_email: bool,
    /// The longest session timeout clients allow, in minutes; absent for none.
    pub session_timeout_minutes: Option<u32>,
    /// `lock` or `logOut`, at the end of the timeout.
    pub session_timeout_action: Option<String>,
    pub no_pin_unlock: bool,
    /// Clients make new items in the space, not in the member's own vault.
    pub central_ownership: bool,
    pub no_card_items: bool,
}

impl PoliciesDto {
    fn of_space(p: &SpacePolicies) -> PoliciesDto {
        PoliciesDto {
            require_sso: p.require_sso,
            two_step: p.two_step,
            master_password: p.master_password.as_ref().map(MasterPasswordDto::of),
            single_space: p.single_space,
            disable_export: p.disable_export,
            disable_send: p.disable_send,
            always_show_email: p.always_show_email,
            session_timeout_minutes: p.session_timeout_minutes,
            session_timeout_action: p.session_timeout_action.map(|a| a.as_str().to_owned()),
            no_pin_unlock: p.no_pin_unlock,
            central_ownership: p.central_ownership,
            no_card_items: p.no_card_items,
        }
    }

    fn of_effective(p: &EffectivePolicies) -> PoliciesDto {
        PoliciesDto {
            require_sso: p.require_sso,
            two_step: p.two_step,
            master_password: p.master_password.as_ref().map(MasterPasswordDto::of),
            single_space: p.single_space,
            disable_export: p.disable_export,
            disable_send: p.disable_send,
            always_show_email: p.always_show_email,
            session_timeout_minutes: p.session_timeout_minutes,
            session_timeout_action: p.session_timeout_action.map(|a| a.as_str().to_owned()),
            no_pin_unlock: p.no_pin_unlock,
            central_ownership: p.central_ownership,
            no_card_items: p.no_card_items,
        }
    }

    fn domain(&self) -> Result<SpacePolicies, Problem> {
        let action = self
            .session_timeout_action
            .as_deref()
            .map(|text| {
                TimeoutAction::parse(text).ok_or_else(|| {
                    Problem::bad_request("the timeout action must be lock or logOut")
                })
            })
            .transpose()?;
        Ok(SpacePolicies {
            require_sso: self.require_sso,
            two_step: self.two_step,
            master_password: self.master_password.as_ref().map(MasterPasswordDto::domain),
            single_space: self.single_space,
            disable_export: self.disable_export,
            disable_send: self.disable_send,
            always_show_email: self.always_show_email,
            session_timeout_minutes: self.session_timeout_minutes,
            session_timeout_action: action,
            no_pin_unlock: self.no_pin_unlock,
            central_ownership: self.central_ownership,
            no_card_items: self.no_card_items,
        })
    }
}

/// A space's policies as stored.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SpacePoliciesDto {
    pub policies: PoliciesDto,
    /// When they were last set (Unix seconds); absent for a space nobody has set policies for.
    pub updated_at: Option<i64>,
    pub updated_by: Option<Uuid>,
}

impl SpacePoliciesDto {
    fn of(stored: &StoredPolicies) -> SpacePoliciesDto {
        SpacePoliciesDto {
            policies: PoliciesDto::of_space(&stored.policies),
            updated_at: stored.updated_at.map(OffsetDateTime::unix_timestamp),
            updated_by: stored.updated_by.map(|u| u.0),
        }
    }
}

// ---- errors ----

impl From<PoliciesError> for Problem {
    fn from(e: PoliciesError) -> Self {
        match e {
            PoliciesError::NotFound => Problem::not_found(),
            PoliciesError::Forbidden(why) => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed").detail(why)
            }
            PoliciesError::Invalid(why) => Problem::bad_request(why),
            PoliciesError::TwoStepRequired => Problem::new(
                StatusCode::FORBIDDEN,
                "policy-two-step-required",
                "This space requires two-step login",
            )
            .detail("set up two-step login on the account, then try again"),
            PoliciesError::SingleSpace => Problem::new(
                StatusCode::FORBIDDEN,
                "policy-single-space",
                "This space allows its members in no other space",
            )
            .detail("the account is already a member of another space"),
            PoliciesError::OtherSpaceSingle => Problem::new(
                StatusCode::FORBIDDEN,
                "policy-other-space-single",
                "A space the account belongs to allows its members in no other space",
            ),
            PoliciesError::Store(message) => {
                tracing::error!(%message, "a policy operation failed");
                Problem::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "Something went wrong on the server",
                )
            }
        }
    }
}

fn space_id(text: &str) -> Result<SpaceId, Problem> {
    text.parse()
        .map_err(|_| Problem::bad_request("the space id isn't a UUID"))
}

// ---- state ----

/// The router's state: the API's, the space store and the policy store.
struct Env<S, P, K, R, Pol> {
    api: Api<S, P, K>,
    spaces: R,
    policies: Pol,
}

impl<S, P, K, R: Clone, Pol: Clone> Clone for Env<S, P, K, R, Pol> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            spaces: self.spaces.clone(),
            policies: self.policies.clone(),
        }
    }
}

/// An authenticated request: `Authed`, extracted from this router's state.
struct Caller(Authed);

impl Caller {
    fn actor(&self) -> Actor {
        self.0.actor
    }
}

impl<S, P, K, R, Pol> FromRequestParts<Env<S, P, K, R, Pol>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: Send + Sync + 'static,
    Pol: Send + Sync + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        env: &Env<S, P, K, R, Pol>,
    ) -> Result<Self, Problem> {
        Authed::from_request_parts(parts, &env.api)
            .await
            .map(Caller)
    }
}

// ---- handlers ----

async fn get_space_policies<S, P, K, R, Pol>(
    State(env): State<Env<S, P, K, R, Pol>>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Json<SpacePoliciesDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    let stored = GetPolicies {
        spaces: env.spaces.clone(),
        policies: env.policies.clone(),
    }
    .execute(&caller.actor(), space_id(&id)?)
    .await?;
    Ok(Json(SpacePoliciesDto::of(&stored)))
}

async fn put_space_policies<S, P, K, R, Pol>(
    State(env): State<Env<S, P, K, R, Pol>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Result<Json<SpacePoliciesDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    let request: PoliciesDto = body.json()?;
    let new = request.domain()?;
    let space = space_id(&id)?;
    // Require SSO closes the password to the members, so it can't be turned on where no one could
    // sign in another way. Only a member who may see the policies is told (`GetPolicies` asks).
    if new.require_sso {
        let current = GetPolicies {
            spaces: env.spaces.clone(),
            policies: env.policies.clone(),
        }
        .execute(&caller.actor(), space)
        .await?;
        if !current.policies.require_sso {
            let configured = SsoSettingsRepo::sso_settings(&env.api.store)
                .await
                .map_err(|e| Problem::from(AppError::from(e)))?
                .is_some_and(|settings| settings.enabled);
            if !configured {
                return Err(Problem::new(
                    StatusCode::CONFLICT,
                    "sso-not-set-up",
                    "Single sign-on isn't set up",
                )
                .detail("set up single sign-on on this server before turning on Require SSO"));
            }
        }
    }
    let stored = SetPolicies {
        spaces: env.spaces.clone(),
        policies: env.policies.clone(),
        events: env.api.store.clone(),
        clock: env.api.crypto.clone(),
    }
    .execute(&caller.actor(), space, new)
    .await?;
    Ok(Json(SpacePoliciesDto::of(&stored)))
}

async fn my_policies<S, P, K, R, Pol>(
    State(env): State<Env<S, P, K, R, Pol>>,
    caller: Caller,
) -> Result<Json<PoliciesDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    let effective = MyPolicies {
        spaces: env.spaces.clone(),
        policies: env.policies.clone(),
    }
    .execute(&caller.actor())
    .await?;
    Ok(Json(PoliciesDto::of_effective(&effective)))
}

// ---- the join guard ----

/// Whose join a request is: a person by id, or `me`, the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemberRef {
    User(UserId),
    Me,
}

/// What a request is to the join guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JoinRoute {
    /// Not a request that accepts an invitation or confirms a member.
    Other,
    /// Accepting or confirming `member` in `space`.
    Join(SpaceId, MemberRef),
    /// Accepting or confirming, but the space or the member in the address can't be read. The
    /// router would read the same text its own way, so the request is refused, not passed.
    Unreadable,
}

/// A path parameter as the router hands it to a handler: percent-decoded. `None` for a `%` that
/// isn't followed by two hex digits, or for bytes that aren't UTF-8.
fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let text = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The space and the member of a request that accepts an invitation or confirms a member, from
/// its path alone: `/kem/v1/spaces/{id}/members/{user}/accept` or `…/confirm`. The literal parts
/// are matched as they came, as the router matches them; the two parameters are decoded, as the
/// router decodes them for the handler (`%6De` is `me` to it).
fn join_target(path: &str) -> JoinRoute {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        [
            "kem",
            "v1",
            "spaces",
            space,
            "members",
            member,
            "accept" | "confirm",
        ] => {
            let parsed = (|| {
                let space: SpaceId = decode_segment(space)?.parse().ok()?;
                let member = decode_segment(member)?;
                let member = if member == "me" {
                    MemberRef::Me
                } else {
                    MemberRef::User(member.parse().ok()?)
                };
                Some((space, member))
            })();
            match parsed {
                Some((space, member)) => JoinRoute::Join(space, member),
                None => JoinRoute::Unreadable,
            }
        }
        _ => JoinRoute::Other,
    }
}

impl<S, P, K, R, Pol> Env<S, P, K, R, Pol>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    /// The account an access token names, by its signature and expiry alone. No proof is checked
    /// and none is used up: the handler authenticates the request itself.
    fn token_user(&self, request: &Request) -> Option<UserId> {
        let token = request
            .headers()
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("dpop"))
            .map(|(_, token)| token.trim())?;
        self.api
            .signer
            .verify(token, self.api.crypto.now())
            .ok()
            .map(|claims| claims.user)
    }

    /// Whether the person may join `space` under its policies and those of the spaces they are in.
    /// What is not a join the guard can judge (no such member, no token) is left to the handler.
    async fn check_join(
        &self,
        caller: Option<UserId>,
        space: SpaceId,
        member: MemberRef,
    ) -> Result<(), Problem> {
        let user = match member {
            MemberRef::User(user) => user,
            MemberRef::Me => match caller {
                Some(user) => user,
                None => return Ok(()),
            },
        };
        // A store that can't be read can't say whether the join is allowed: the request waits, it
        // is not let through.
        let rows = self.spaces.memberships(user).await.map_err(|error| {
            tracing::warn!(%error, "the join check could not read the memberships");
            Problem::overloaded()
        })?;
        let Some(row) = rows.into_iter().find(|m| m.space == space) else {
            return Ok(());
        };
        let guard = JoinGuard {
            spaces: self.spaces.clone(),
            policies: self.policies.clone(),
            two_factor: self.api.store.clone(),
        };
        guard
            .check(user, space, row.role)
            .await
            .map_err(Problem::from)
    }
}

async fn join_guard<S, P, K, R, Pol>(
    State(env): State<Env<S, P, K, R, Pol>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    // Read before awaiting: the request's body isn't Sync, so a borrow of it can't cross an await.
    let target = if request.method() == Method::POST {
        join_target(request.uri().path())
    } else {
        JoinRoute::Other
    };
    let caller = env.token_user(&request);
    match target {
        JoinRoute::Other => {}
        JoinRoute::Unreadable => {
            return Problem::bad_request("the space or the member in the address isn't an id")
                .into_response();
        }
        JoinRoute::Join(space, member) => {
            if let Err(problem) = env.check_join(caller, space, member).await {
                return problem.into_response();
            }
        }
    }
    next.run(request).await
}

/// Wraps a router that serves the spaces routes so that accepting an invitation and confirming a
/// member go through the join check first. See the module's notes.
pub fn with_join_guard<S, P, K, R, Pol>(
    router: Router,
    api: Api<S, P, K>,
    spaces: R,
    policies: Pol,
) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    let env = Env {
        api,
        spaces,
        policies,
    };
    router.layer(middleware::from_fn_with_state(
        env,
        join_guard::<S, P, K, R, Pol>,
    ))
}

// ---- the router ----

/// Every response carries the current DPoP nonce, as the main router's do.
async fn nonce_header<S, P, K, R, Pol>(
    State(env): State<Env<S, P, K, R, Pol>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(env.api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The policy routes. Merge them beside the spaces router; they have no fallback.
///
/// ```text
/// GET, PUT /kem/v1/spaces/{id}/policies   a space's policies: any member reads, owners and admins set
/// GET      /kem/v1/policies               what binds the caller across their spaces
/// ```
pub fn policies_router<S, P, K, R, Pol>(api: Api<S, P, K>, spaces: R, policies: Pol) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
    Pol: PolicyRepo + Clone + 'static,
{
    let env = Env {
        api,
        spaces,
        policies,
    };
    Router::new()
        .route(
            "/kem/v1/spaces/{id}/policies",
            get(get_space_policies::<S, P, K, R, Pol>).put(put_space_policies::<S, P, K, R, Pol>),
        )
        .route("/kem/v1/policies", get(my_policies::<S, P, K, R, Pol>))
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R, Pol>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/policies", tag = "policies",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The space's id")),
    responses(
        (status = 200, description = "The space's policies; everything off for a space with none", body = SpacePoliciesDto),
        (status = 404, description = "No such space, or the caller isn't a confirmed member", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_get() {}

#[utoipa::path(
    put, path = "/kem/v1/spaces/{id}/policies", tag = "policies",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The space's id")),
    request_body = PoliciesDto,
    responses(
        (status = 200, description = "Replaced; a setting left out is off", body = SpacePoliciesDto),
        (status = 400, description = "A setting that makes no sense", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "Only an owner or an admin sets policies", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "No such space, or the caller isn't a confirmed member", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_put() {}

#[utoipa::path(
    get, path = "/kem/v1/policies", tag = "policies",
    security(("dpop" = [])),
    responses((status = 200, description = "What binds the caller across their spaces", body = PoliciesDto))
)]
#[allow(dead_code)]
fn doc_mine() {}

/// The policy routes' part of the OpenAPI document.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_get, doc_put, doc_mine),
    components(schemas(MasterPasswordDto, PoliciesDto, SpacePoliciesDto))
)]
pub struct PoliciesDoc;

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: &str = "7f3c4b1e-0000-4000-8000-000000000001";
    const USER: &str = "7f3c4b1e-0000-4000-8000-000000000002";

    #[test]
    fn only_accept_and_confirm_posts_are_join_targets() {
        let space: SpaceId = SPACE.parse().expect("a space id");
        let user: UserId = USER.parse().expect("a user id");
        assert_eq!(
            join_target(&format!("/kem/v1/spaces/{SPACE}/members/me/accept")),
            JoinRoute::Join(space, MemberRef::Me)
        );
        assert_eq!(
            join_target(&format!("/kem/v1/spaces/{SPACE}/members/{USER}/confirm")),
            JoinRoute::Join(space, MemberRef::User(user))
        );
        for other in [
            format!("/kem/v1/spaces/{SPACE}/members/{USER}/revoke"),
            format!("/kem/v1/spaces/{SPACE}/members"),
            format!("/kem/v1/spaces/{SPACE}/policies"),
            format!("/kem/v1/spaces/{SPACE}/members/{USER}"),
            format!("/kem/v1/spaces/{SPACE}/members/me/accept/more"),
        ] {
            assert_eq!(join_target(&other), JoinRoute::Other, "{other}");
        }
    }

    #[test]
    fn the_parameters_are_read_as_the_router_decodes_them() {
        let space: SpaceId = SPACE.parse().expect("a space id");
        // `%6De` is `me` to the handler: it must be to the guard too.
        assert_eq!(
            join_target(&format!("/kem/v1/spaces/{SPACE}/members/%6De/accept")),
            JoinRoute::Join(space, MemberRef::Me)
        );
        // So is an encoded digit of an id.
        let encoded = SPACE.replacen('7', "%37", 1);
        assert_eq!(
            join_target(&format!("/kem/v1/spaces/{encoded}/members/me/accept")),
            JoinRoute::Join(space, MemberRef::Me)
        );
        // What can't be read is refused, not passed on.
        for unreadable in [
            "/kem/v1/spaces/nope/members/me/accept".to_owned(),
            format!("/kem/v1/spaces/{SPACE}/members/nope/confirm"),
            format!("/kem/v1/spaces/{SPACE}/members/%zz/accept"),
            format!("/kem/v1/spaces/{SPACE}/members/%FF/accept"),
        ] {
            assert_eq!(
                join_target(&unreadable),
                JoinRoute::Unreadable,
                "{unreadable}"
            );
        }
    }

    #[test]
    fn the_wire_form_round_trips_and_a_missing_setting_is_off() {
        let dto: PoliciesDto = serde_json::from_value(serde_json::json!({
            "twoStep": true,
            "masterPassword": {"minLength": 14},
            "sessionTimeoutMinutes": 30,
            "sessionTimeoutAction": "logOut",
        }))
        .expect("parses");
        let domain = dto.domain().expect("valid");
        assert!(domain.two_step && !domain.require_sso);
        assert_eq!(
            domain.master_password,
            Some(MasterPasswordPolicy::fourteen_characters())
        );
        assert_eq!(domain.session_timeout_action, Some(TimeoutAction::LogOut));
        let back = PoliciesDto::of_space(&domain);
        assert_eq!(back.session_timeout_action.as_deref(), Some("logOut"));
        assert_eq!(back.master_password.expect("rules").min_length, Some(14));
    }

    #[test]
    fn unknown_fields_and_actions_are_refused() {
        assert!(serde_json::from_value::<PoliciesDto>(serde_json::json!({"nope": true})).is_err());
        let bad = PoliciesDto {
            session_timeout_action: Some("sleep".to_owned()),
            ..PoliciesDto::default()
        };
        assert_eq!(
            bad.domain().expect_err("refused").status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn each_refusal_has_its_own_status_and_type() {
        let status = |e: PoliciesError| Problem::from(e).status;
        assert_eq!(status(PoliciesError::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(
            status(PoliciesError::Forbidden("no")),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(PoliciesError::Invalid("no")),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(PoliciesError::TwoStepRequired),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            Problem::from(PoliciesError::SingleSpace).slug,
            "policy-single-space"
        );
        assert_eq!(
            Problem::from(PoliciesError::TwoStepRequired).slug,
            "policy-two-step-required"
        );
        assert_eq!(
            status(PoliciesError::Store("secret".to_owned())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn the_document_names_every_policy_route() {
        let json = serde_json::to_value(PoliciesDoc::openapi()).expect("serialises");
        for (path, method) in [
            ("/kem/v1/spaces/{id}/policies", "get"),
            ("/kem/v1/spaces/{id}/policies", "put"),
            ("/kem/v1/policies", "get"),
        ] {
            assert!(
                json["paths"][path][method].is_object(),
                "{method} {path} is documented"
            );
        }
        assert!(json["components"]["schemas"]["PoliciesDto"].is_object());
    }
}
