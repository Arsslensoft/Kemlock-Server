//! The duplicate cleaner: `/kem/v1/duplicates` and `PUT /kem/v1/items/{id}/tags`, and the tags
//! that ride on item writes.
//!
//! The server never makes a tag: a device sends each one, 32 bytes of base64url, made under a dedup
//! key the server doesn't have. Server matching is off until the person (or a space's owners and
//! admins) turn it on; with it off, tags that come with a write are ignored and `PUT …/tags` is a
//! 409. A write without tags clears the item's tags, through any API.
//!
//! ```text
//! PUT    /kem/v1/items/{id}/tags              backfill the tags of the current revision (If-Match)
//! GET    /kem/v1/duplicates?owner=<owner>     groups of item ids with equal tags, and how many wait
//! GET    /kem/v1/duplicates/settings?owner=   is server matching on, who turned it on, key version
//! PUT    /kem/v1/duplicates/settings?owner=   turn server matching on or off
//! POST   /kem/v1/duplicates/dismissals        save a "Not duplicates"
//! DELETE /kem/v1/duplicates/dismissals/{id}   take it back
//! DELETE /kem/v1/duplicates/tags?owner=       turn server matching off and delete the owner's tags
//! ```
//!
//! `<owner>` is `user:<uuid>` or `space:<uuid>`, as on items. These routes need a store that also
//! keeps spaces, so they have a router of their own, [`router`], merged beside the main one as the
//! spaces routes are.

use crate::dto::{BatchRequest, ItemDto, decode};
use crate::extract::{Authed, Body, DPOP_NONCE};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::routes::items::parse_revision;
use crate::state::{Api, Crypto, Store};
use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use kemlock_app::dedup::{
    BackfillTags, DedupError, Dismiss, DismissalStore, DuplicateReport, GetMatching,
    ListDuplicates, SetMatching, StoreTags, TagOutcome, TagStore, Undismiss,
};
use kemlock_app::ports::{EventLog, ItemStore, TokenSigner};
use kemlock_app::spaces::SpaceRepo;
use kemlock_app::{Actor, AppError};
use kemlock_domain::{
    DedupTag, Dismissal, DismissalId, Item, ItemId, MatchingSettings, Owner, TagSet,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use time::OffsetDateTime;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

// ---- errors ----

impl From<DedupError> for Problem {
    fn from(e: DedupError) -> Self {
        match e {
            DedupError::NotFound => Problem::not_found(),
            DedupError::Forbidden(why) => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed").detail(why)
            }
            DedupError::Invalid(why) => Problem::bad_request(why),
            DedupError::MatchingOff => Problem::new(
                StatusCode::CONFLICT,
                "server-matching-off",
                "Server matching is off for this owner",
            )
            .detail("turn it on at PUT /kem/v1/duplicates/settings first"),
            DedupError::StaleVersion { current } => Problem::new(
                StatusCode::CONFLICT,
                "stale-dedup-version",
                "The tags were made under another dedup key version",
            )
            .with("currentTagVersion", json!(current)),
            DedupError::StaleItem { item, current } => {
                Problem::from(AppError::Conflict { item, current })
            }
            DedupError::StaleAccountKeys { current } => {
                Problem::from(AppError::StaleKeyVersion { current })
            }
            DedupError::Store(message) => Problem::from(AppError::Store(message)),
        }
    }
}

// ---- tags on the wire ----

/// A tag set from its wire form: base64url tags of exactly 32 bytes and the key version.
pub(crate) fn tag_set(version: u32, tags: &[String]) -> Result<TagSet, Problem> {
    let mut parsed = Vec::with_capacity(tags.len());
    for tag in tags {
        let bytes = decode("tags", tag)?;
        parsed.push(
            DedupTag::from_slice(&bytes)
                .ok_or_else(|| Problem::bad_request("a tag is exactly 32 bytes"))?,
        );
    }
    TagSet::new(version, parsed).map_err(|e| Problem::from(DedupError::from(e)))
}

/// Takes `tags` and `tagVersion` out of an item's JSON object. Both or neither.
fn take_tags(item: &mut Value) -> Result<Option<TagSet>, Problem> {
    let Some(object) = item.as_object_mut() else {
        return Ok(None);
    };
    match (object.remove("tags"), object.remove("tagVersion")) {
        (None, None) => Ok(None),
        (Some(tags), Some(version)) => {
            let tags: Vec<String> = serde_json::from_value(tags)
                .map_err(|_| Problem::bad_request("tags must be a list of base64url strings"))?;
            let version: u32 = serde_json::from_value(version)
                .map_err(|_| Problem::bad_request("tagVersion must be a whole number"))?;
            tag_set(version, &tags).map(Some)
        }
        _ => Err(Problem::bad_request("tags and tagVersion come together")),
    }
}

fn not_the_json_expected(e: serde_json::Error) -> Problem {
    Problem::bad_request(format!("the body isn't the JSON expected: {e}"))
}

/// An item body with the tags that came beside the ciphertext.
pub(crate) fn item_with_tags(body: &Body) -> Result<(ItemDto, Option<TagSet>), Problem> {
    let mut json: Value = body.json()?;
    let tags = take_tags(&mut json)?;
    let dto = serde_json::from_value(json).map_err(not_the_json_expected)?;
    Ok((dto, tags))
}

/// A batch body with the tags of each write, by item id.
pub(crate) fn batch_with_tags(
    body: &Body,
) -> Result<(BatchRequest, HashMap<ItemId, TagSet>), Problem> {
    let mut json: Value = body.json()?;
    let mut found: Vec<Option<TagSet>> = Vec::new();
    if let Some(writes) = json.get_mut("writes").and_then(Value::as_array_mut) {
        for write in writes {
            found.push(match write.get_mut("item") {
                Some(item) => take_tags(item)?,
                None => None,
            });
        }
    }
    let request: BatchRequest = serde_json::from_value(json).map_err(not_the_json_expected)?;
    let mut tags = HashMap::new();
    for (write, set) in request.writes.iter().zip(found) {
        if let Some(set) = set {
            tags.insert(write.item.id, set);
        }
    }
    Ok((request, tags))
}

fn outcome_json(item: ItemId, outcome: &TagOutcome) -> Value {
    json!({
        "item": item.to_string(),
        "stored": outcome.stored,
        "matches": outcome.matches.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

impl<S: Store, P: Crypto, K: TokenSigner + Clone + 'static> Api<S, P, K> {
    /// Stores the tags that came with a single write and shapes the answer: the item as before,
    /// plus `tagsStored` and `matches` when the write carried tags. The item is already written, so
    /// a store failure here leaves it without tags and is only logged.
    pub(crate) async fn answer_with_tags<R: SpaceRepo>(
        &self,
        spaces: R,
        actor: &Actor,
        item: &Item,
        tags: TagSet,
    ) -> Value {
        let mut answer = json!(ItemDto::from_item(item));
        let outcome = StoreTags {
            tags: self.store.clone(),
            spaces,
        }
        .after_write(actor, item, tags)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "couldn't store an item's tags");
            TagOutcome {
                stored: false,
                matches: Vec::new(),
            }
        });
        answer["tagsStored"] = json!(outcome.stored);
        if outcome.stored {
            answer["matches"] = json!(
                outcome
                    .matches
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
        answer
    }

    /// [`answer_with_tags`](Self::answer_with_tags) for a batch: the items as before, plus `tags`
    /// (one entry per write that carried tags) when any did.
    pub(crate) async fn answer_batch_with_tags<R: SpaceRepo>(
        &self,
        spaces: R,
        actor: &Actor,
        items: &[Item],
        tags: HashMap<ItemId, TagSet>,
    ) -> Value {
        let mut answer =
            json!({ "items": items.iter().map(ItemDto::from_item).collect::<Vec<_>>() });
        if tags.is_empty() {
            return answer;
        }
        let ids: Vec<ItemId> = items
            .iter()
            .map(|i| i.id)
            .filter(|id| tags.contains_key(id))
            .collect();
        let outcomes = StoreTags {
            tags: self.store.clone(),
            spaces,
        }
        .after_batch(actor, items, tags)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "couldn't store a batch's tags");
            ids.iter()
                .map(|id| {
                    (
                        *id,
                        TagOutcome {
                            stored: false,
                            matches: Vec::new(),
                        },
                    )
                })
                .collect()
        });
        answer["tags"] = Value::Array(
            outcomes
                .iter()
                .map(|(id, o)| outcome_json(*id, o))
                .collect(),
        );
        answer
    }
}

// ---- state, authentication ----

/// The router's state: the API's and a store of every port these routes use.
struct Env<S, P, K, R, Q> {
    api: Api<S, P, K>,
    store: R,
    spaces: Q,
}

impl<S, P, K, R: Clone, Q: Clone> Clone for Env<S, P, K, R, Q> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            store: self.store.clone(),
            spaces: self.spaces.clone(),
        }
    }
}

/// Every port the duplicate routes need except the spaces': one bound. `SqlStore` implements them all.
pub trait DedupRepo: TagStore + DismissalStore + ItemStore + EventLog + Clone + 'static {}

impl<T> DedupRepo for T where T: TagStore + DismissalStore + ItemStore + EventLog + Clone + 'static {}

/// An authenticated request: `Authed`, extracted from this router's state.
struct Caller(Authed);

impl Caller {
    fn actor(&self) -> Actor {
        self.0.actor
    }
}

impl<S, P, K, R, Q> FromRequestParts<Env<S, P, K, R, Q>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        env: &Env<S, P, K, R, Q>,
    ) -> Result<Self, Problem> {
        Authed::from_request_parts(parts, &env.api)
            .await
            .map(Caller)
    }
}

// ---- wire types ----

#[derive(Debug, Deserialize)]
struct OwnerQuery {
    owner: String,
}

fn owner_of(query: Result<Query<OwnerQuery>, QueryRejection>) -> Result<Owner, Problem> {
    let Query(query) = query.map_err(|e| Problem::bad_request(e.body_text()))?;
    parse_owner(&query.owner)
}

fn parse_owner(text: &str) -> Result<Owner, Problem> {
    text.parse::<Owner>()
        .map_err(|why| Problem::bad_request(format!("owner: {why}")))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TagsRequest {
    /// The tags, 32 bytes each, base64url.
    tags: Vec<String>,
    /// The dedup key version they were made under.
    tag_version: u32,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct MatchesResponse {
    /// The other items of the owner that share a tag with this one.
    matches: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct DuplicateGroupDto {
    /// Two or more item ids. A hint: the device opens them and compares before it shows a group.
    items: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct DuplicatesResponse {
    /// `user:<uuid>` or `space:<uuid>`.
    owner: String,
    /// Whether server matching is on. When it isn't, there are no groups.
    enabled: bool,
    /// The dedup key version the groups were made under.
    tag_version: u32,
    groups: Vec<DuplicateGroupDto>,
    /// Live items still waiting for tags.
    waiting: u64,
}

impl DuplicatesResponse {
    fn of(owner: Owner, report: &DuplicateReport) -> Self {
        DuplicatesResponse {
            owner: owner.to_string(),
            enabled: report.enabled,
            tag_version: report.version,
            groups: report
                .groups
                .iter()
                .map(|g| DuplicateGroupDto {
                    items: g.items.iter().map(|i| i.0).collect(),
                })
                .collect(),
            waiting: report.waiting,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct MatchingDto {
    owner: String,
    enabled: bool,
    tag_version: u32,
    /// Who last turned it on or off, so every member of a space can be shown who allowed the server
    /// to group its tags.
    changed_by: Option<Uuid>,
    /// When, in Unix seconds.
    changed_at: Option<i64>,
}

impl MatchingDto {
    fn of(settings: &MatchingSettings) -> Self {
        MatchingDto {
            owner: settings.owner.to_string(),
            enabled: settings.enabled,
            tag_version: settings.version,
            changed_by: settings.changed_by.map(|u| u.0),
            changed_at: settings.changed_at.map(OffsetDateTime::unix_timestamp),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MatchingRequest {
    enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DismissRequest {
    /// `user:<uuid>` or `space:<uuid>`.
    owner: String,
    /// The group's item ids: two to 500.
    items: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct DismissalDto {
    id: Uuid,
    owner: String,
    items: Vec<Uuid>,
    /// Who answered.
    by: Uuid,
    /// When, in Unix seconds.
    at: i64,
}

impl DismissalDto {
    fn of(d: &Dismissal) -> Self {
        DismissalDto {
            id: d.id.0,
            owner: d.owner.to_string(),
            items: d.items.iter().map(|i| i.0).collect(),
            by: d.by.0,
            at: d.at.unix_timestamp(),
        }
    }
}

// ---- handlers ----

async fn put_tags<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<MatchesResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let id: ItemId = id
        .parse()
        .map_err(|_| Problem::bad_request("the item id isn't a UUID"))?;
    let expected = parse_revision(headers.get(header::IF_MATCH).ok_or_else(|| {
        Problem::precondition_required("send If-Match: <revision> of the item the tags are for")
    })?)?;
    let request: TagsRequest = body.json()?;
    let tags = tag_set(request.tag_version, &request.tags)?;
    let matches = BackfillTags {
        tags: env.store.clone(),
        items: env.store.clone(),
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), id, expected, tags)
    .await?;
    Ok(Json(MatchesResponse {
        matches: matches.iter().map(|i| i.0).collect(),
    }))
}

async fn get_duplicates<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    query: Result<Query<OwnerQuery>, QueryRejection>,
) -> Result<Json<DuplicatesResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let owner = owner_of(query)?;
    let report = ListDuplicates {
        tags: env.store.clone(),
        dismissals: env.store.clone(),
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), owner)
    .await?;
    Ok(Json(DuplicatesResponse::of(owner, &report)))
}

async fn get_settings<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    query: Result<Query<OwnerQuery>, QueryRejection>,
) -> Result<Json<MatchingDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let owner = owner_of(query)?;
    let settings = GetMatching {
        tags: env.store.clone(),
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), owner)
    .await?;
    Ok(Json(MatchingDto::of(&settings)))
}

fn set_matching_case<S, P, K, R, Q>(env: &Env<S, P, K, R, Q>) -> SetMatching<R, Q, R, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    SetMatching {
        tags: env.store.clone(),
        spaces: env.spaces.clone(),
        events: env.store.clone(),
        clock: env.api.crypto.clone(),
    }
}

async fn put_settings<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    query: Result<Query<OwnerQuery>, QueryRejection>,
    body: Body,
) -> Result<Json<MatchingDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let owner = owner_of(query)?;
    let request: MatchingRequest = body.json()?;
    let settings = set_matching_case(&env)
        .execute(&caller.actor(), owner, request.enabled)
        .await?;
    Ok(Json(MatchingDto::of(&settings)))
}

async fn delete_tags<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    query: Result<Query<OwnerQuery>, QueryRejection>,
) -> Result<Json<MatchingDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let owner = owner_of(query)?;
    let settings = set_matching_case(&env)
        .execute(&caller.actor(), owner, false)
        .await?;
    Ok(Json(MatchingDto::of(&settings)))
}

async fn post_dismissal<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    body: Body,
) -> Result<(StatusCode, Json<DismissalDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let request: DismissRequest = body.json()?;
    let owner = parse_owner(&request.owner)?;
    let items = request.items.into_iter().map(ItemId).collect();
    let dismissal = Dismiss {
        tags: env.store.clone(),
        dismissals: env.store.clone(),
        items: env.store.clone(),
        spaces: env.spaces.clone(),
        clock: env.api.crypto.clone(),
    }
    .execute(&caller.actor(), owner, items)
    .await?;
    Ok((StatusCode::CREATED, Json(DismissalDto::of(&dismissal))))
}

async fn delete_dismissal<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let id: DismissalId = id
        .parse()
        .map_err(|_| Problem::bad_request("the answer's id isn't a UUID"))?;
    Undismiss {
        dismissals: env.store.clone(),
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), id)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- the router ----

/// Every response carries the current DPoP nonce, as the main router's do.
async fn nonce_header<S, P, K, R, Q>(
    State(env): State<Env<S, P, K, R, Q>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(env.api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The duplicate-cleaner routes. Merge it beside [`crate::router`]; it has no fallback.
pub fn router<S, P, K, R, Q>(api: Api<S, P, K>, store: R, spaces: Q) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: DedupRepo,
    Q: SpaceRepo + Clone + 'static,
{
    let env = Env { api, store, spaces };
    Router::new()
        .route("/kem/v1/items/{id}/tags", put(put_tags::<S, P, K, R, Q>))
        .route("/kem/v1/duplicates", get(get_duplicates::<S, P, K, R, Q>))
        .route(
            "/kem/v1/duplicates/settings",
            get(get_settings::<S, P, K, R, Q>).put(put_settings::<S, P, K, R, Q>),
        )
        .route(
            "/kem/v1/duplicates/dismissals",
            post(post_dismissal::<S, P, K, R, Q>),
        )
        .route(
            "/kem/v1/duplicates/dismissals/{id}",
            delete(delete_dismissal::<S, P, K, R, Q>),
        )
        .route(
            "/kem/v1/duplicates/tags",
            delete(delete_tags::<S, P, K, R, Q>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R, Q>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    put, path = "/kem/v1/items/{id}/tags", tag = "duplicates",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The item id"), ("If-Match" = u64, Header, description = "The item's current revision")),
    request_body = TagsRequest,
    responses(
        (status = 200, description = "Stored; the other items that share a tag", body = MatchesResponse),
        (status = 409, description = "Server matching is off, the key version is old, or the revision is stale", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_put_tags() {}

#[utoipa::path(
    get, path = "/kem/v1/duplicates", tag = "duplicates",
    security(("dpop" = [])),
    params(("owner" = String, Query, description = "user:<uuid> or space:<uuid>")),
    responses((status = 200, description = "Groups of items with equal tags", body = DuplicatesResponse))
)]
#[allow(dead_code)]
fn doc_get_duplicates() {}

#[utoipa::path(
    get, path = "/kem/v1/duplicates/settings", tag = "duplicates",
    security(("dpop" = [])),
    params(("owner" = String, Query, description = "user:<uuid> or space:<uuid>")),
    responses((status = 200, description = "Whether server matching is on", body = MatchingDto))
)]
#[allow(dead_code)]
fn doc_get_settings() {}

#[utoipa::path(
    put, path = "/kem/v1/duplicates/settings", tag = "duplicates",
    security(("dpop" = [])),
    params(("owner" = String, Query, description = "user:<uuid> or space:<uuid>")),
    request_body = MatchingRequest,
    responses((status = 200, description = "The new setting; off deletes the owner's tags", body = MatchingDto))
)]
#[allow(dead_code)]
fn doc_put_settings() {}

#[utoipa::path(
    post, path = "/kem/v1/duplicates/dismissals", tag = "duplicates",
    security(("dpop" = [])),
    request_body = DismissRequest,
    responses((status = 201, description = "The saved answer", body = DismissalDto))
)]
#[allow(dead_code)]
fn doc_post_dismissal() {}

#[utoipa::path(
    delete, path = "/kem/v1/duplicates/dismissals/{id}", tag = "duplicates",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The answer's id")),
    responses((status = 204, description = "Taken back"))
)]
#[allow(dead_code)]
fn doc_delete_dismissal() {}

#[utoipa::path(
    delete, path = "/kem/v1/duplicates/tags", tag = "duplicates",
    security(("dpop" = [])),
    params(("owner" = String, Query, description = "user:<uuid> or space:<uuid>")),
    responses((status = 200, description = "Server matching is off and the owner's tags are deleted", body = MatchingDto))
)]
#[allow(dead_code)]
fn doc_delete_tags() {}

#[derive(OpenApi)]
#[openapi(
    paths(
        doc_put_tags,
        doc_get_duplicates,
        doc_get_settings,
        doc_put_settings,
        doc_post_dismissal,
        doc_delete_dismissal,
        doc_delete_tags
    ),
    components(schemas(
        TagsRequest,
        MatchesResponse,
        DuplicateGroupDto,
        DuplicatesResponse,
        MatchingDto,
        MatchingRequest,
        DismissRequest,
        DismissalDto
    ))
)]
struct DuplicatesDoc;

/// The OpenAPI document of the duplicate-cleaner routes alone.
pub fn openapi() -> utoipa::openapi::OpenApi {
    DuplicatesDoc::openapi()
}
