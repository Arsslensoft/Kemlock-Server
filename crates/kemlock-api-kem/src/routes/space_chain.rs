//! The space chain: `/kem/v1/spaces/{id}/chain` (docs/crypto.md, "Space chain": "What the server
//! stores, serves and checks").
//!
//! ```text
//! GET    /kem/v1/spaces/{id}/chain?from=n        the chain from `seq` n (default 0), as wire-form objects
//! POST   /kem/v1/spaces/{id}/chain               append 1 to 16 records with the boxes and names they commit
//! GET    /kem/v1/spaces/{id}/chain/{seq}/seals   the seal hashes record `seq` committed
//! GET    /kem/v1/spaces/{id}/chain/pending       outside changes queued for an Owner or Admin to sign
//! POST   /kem/v1/spaces/{id}/chain/pending/{n}   answer one: append the record that makes that change
//! DELETE /kem/v1/spaces/{id}/chain/pending/{n}   drop one (recorded in the space's event log)
//! ```
//!
//! A record travels as its exact bytes, base64url, never re-encoded: `{"entry", "signature"}`, and a
//! `rekey` adds `"cosignature"`. The append route answers `201` with the new head `{"link", "seq"}`,
//! `409` with the current head when `seq` or `prev` isn't the next, and `422` with the reason of
//! "Verification" otherwise. Only an invited or confirmed member reads the chain; anyone else,
//! a removed member included, gets `404` as for every other space route.
//!
//! An `invite` record, appended or answered from a queued change, mails the invitee the same
//! "you were invited to a space" notice as `POST /kem/v1/spaces/{id}/members`.
//!
//! These routes need a store that keeps chains ([`SpaceChainRepo`]), so they have a router of
//! their own, merged beside the spaces router.

use crate::dto::decode;
use crate::problem::Problem;
use crate::routes::spaces::{Caller, Env, mail_invitations, nonce_header};
use crate::state::{Api, Crypto, Store};
use axum::body::Bytes;
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::routing::post;
use axum::{Json, Router};
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::{
    AppendChain, AppendError, AppendRequest, ChainHead, ChainReadError, GetChain, GetChainSeals,
    NameIn, PendingChange, PendingChanges, PendingExternal, SealIn, SpaceChainRepo, SpaceRepo,
    StoredRecord, StoredSeal, invitees,
};
use kemlock_app::{AppError, b64url};
use kemlock_crypto::space_chain::{KeyRef, NameTarget, Reason, SignedRecord};
use kemlock_domain::spaces::CustomPermissions;
use kemlock_domain::{ItemId, SpaceId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// The most a request to the append route may weigh: 16 records of 192 KiB, base64url, with their
/// signatures, boxes and names.
const MAX_CHAIN_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The raw body of an append, read up to [`MAX_CHAIN_BODY_BYTES`]. The ordinary body limit is
/// 2 MiB, which a request of large records exceeds.
#[derive(Debug)]
struct ChainBody(Bytes);

impl<S: Send + Sync> FromRequest<S> for ChainBody {
    type Rejection = Problem;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Problem> {
        axum::body::to_bytes(req.into_body(), MAX_CHAIN_BODY_BYTES)
            .await
            .map(ChainBody)
            .map_err(|_| Problem::payload_too_large())
    }
}

fn bad(why: &'static str) -> Problem {
    Problem::bad_request(why)
}

fn space_id(text: &str) -> Result<SpaceId, Problem> {
    text.parse().map_err(|_| bad("the space id isn't a UUID"))
}

// ---- wire types ----

/// A signed record: its bytes and signatures, base64url.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WireRecordDto {
    /// The record's canonical bytes.
    entry: String,
    /// The signer's `sig1` signature, 3373 bytes.
    signature: String,
    /// A `rekey`'s second signature, by the key of the bundle the record installs; on no other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cosignature: Option<String>,
}

impl WireRecordDto {
    fn of(record: &StoredRecord) -> Self {
        WireRecordDto {
            entry: b64url::encode(&record.entry),
            signature: b64url::encode(&record.signature),
            cosignature: record.cosignature.as_deref().map(b64url::encode),
        }
    }
}

/// A sealed key the request carries, for a commitment of record `seq`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SealDto {
    /// The 1661-byte sealed box, base64url.
    #[serde(rename = "box")]
    sealed: String,
    /// `space` or `collection:<uuid>`.
    key: String,
    member: Uuid,
    seq: u64,
    version: u32,
}

/// A sealed name the request carries, for a name hash of record `seq`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NameDto {
    /// The sealed name (a `kem1` envelope), 28 to 4096 bytes, base64url.
    name: String,
    seq: u64,
    /// `space`, `collection:<uuid>` or `group:<uuid>`.
    target: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AppendRequestDto {
    /// 1 to 16 records to append in order.
    records: Vec<WireRecordDto>,
    /// The boxes their commitments cover.
    #[serde(default)]
    seals: Vec<SealDto>,
    /// The sealed names their hashes cover.
    #[serde(default)]
    names: Vec<NameDto>,
    /// Live items a `keys` record in the request leaves held.
    #[serde(default)]
    held: Vec<Uuid>,
}

/// The head of a chain.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeadDto {
    /// The last record's link, base64url.
    link: String,
    seq: u64,
}

impl HeadDto {
    fn of(head: &ChainHead) -> Self {
        HeadDto {
            link: b64url::encode(&head.link),
            seq: head.seq,
        }
    }
}

/// The hash of a box a record committed.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealHashDto {
    bundle_version: u32,
    key: String,
    member: Uuid,
    /// `SHA-256` of the box, base64url.
    seal_hash: String,
    version: u32,
}

impl SealHashDto {
    fn of(seal: &StoredSeal) -> Self {
        SealHashDto {
            bundle_version: seal.bundle_version,
            key: seal.key.text(),
            member: seal.member.0,
            seal_hash: b64url::encode(&kemlock_crypto::space_chain::seal_hash(&seal.sealed)),
            version: seal.version,
        }
    }
}

/// A grant, in a queued change.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingGrantDto {
    collection: Uuid,
    permission: String,
}

/// What a queued change would do.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingChangeDto {
    /// `add-member` (an `invite` record), `remove-member` (`remove`), `role` (`role`),
    /// `grant-set` (`grant`) or `grant-remove` (`ungrant`).
    kind: &'static str,
    /// The account it is about.
    account: Uuid,
    email: Option<String>,
    /// For `add-member` and `role`.
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    /// For `add-member` and `role`: the custom permissions, when the role is `custom`.
    #[serde(skip_serializing_if = "Option::is_none")]
    custom: Option<Vec<&'static str>>,
    /// For `grant-set` and `grant-remove`.
    #[serde(skip_serializing_if = "Option::is_none")]
    collection: Option<Uuid>,
    /// For `grant-set`.
    #[serde(skip_serializing_if = "Option::is_none")]
    permission: Option<&'static str>,
    /// For `add-member`: the grants they would start with.
    #[serde(skip_serializing_if = "Option::is_none")]
    grants: Option<Vec<PendingGrantDto>>,
}

/// Who or what asked for a queued change.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestedByDto {
    account: Option<Uuid>,
    email: Option<String>,
    /// `Bitwarden-compatible API` or `SSO group rule`.
    via: String,
}

/// A change from outside Kemlock clients, kept for an Owner or Admin to sign as a record.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingDto {
    id: Uuid,
    /// `bitwarden` or `sso`.
    source: &'static str,
    /// Unix seconds.
    queued_at: i64,
    requested_by: RequestedByDto,
    change: PendingChangeDto,
}

fn custom_names(custom: CustomPermissions) -> Vec<&'static str> {
    [
        ("manage-users", CustomPermissions::MANAGE_USERS),
        ("manage-groups", CustomPermissions::MANAGE_GROUPS),
        ("create-collections", CustomPermissions::CREATE_COLLECTIONS),
    ]
    .into_iter()
    .filter(|(_, p)| custom.contains(*p))
    .map(|(n, _)| n)
    .collect()
}

impl PendingDto {
    fn of(p: &PendingExternal) -> Self {
        let mut change = PendingChangeDto {
            kind: p.change.kind(),
            account: p.account.0,
            email: p.email.clone(),
            role: None,
            custom: None,
            collection: None,
            permission: None,
            grants: None,
        };
        match &p.change {
            PendingChange::AddMember {
                role,
                custom,
                grants,
            } => {
                change.role = Some(role.as_str());
                change.custom = Some(custom_names(*custom));
                change.grants = Some(
                    grants
                        .iter()
                        .map(|(c, perm)| PendingGrantDto {
                            collection: c.0,
                            permission: perm.as_str().to_owned(),
                        })
                        .collect(),
                );
            }
            PendingChange::RemoveMember => {}
            PendingChange::Role { role, custom } => {
                change.role = Some(role.as_str());
                change.custom = Some(custom_names(*custom));
            }
            PendingChange::GrantSet {
                collection,
                permission,
            } => {
                change.collection = Some(collection.0);
                change.permission = Some(permission.as_str());
            }
            PendingChange::GrantRemove { collection } => change.collection = Some(collection.0),
        }
        PendingDto {
            id: p.id,
            source: p.source.as_str(),
            queued_at: p.queued_at.unix_timestamp(),
            requested_by: RequestedByDto {
                account: p.requested_by.map(|u| u.0),
                email: None,
                via: p.via.clone(),
            },
            change,
        }
    }
}

// ---- errors ----

fn refused(reason: Reason, seq: Option<u64>, detail: String) -> Problem {
    Problem::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "space-chain-refused",
        "The record was refused",
    )
    .detail(detail)
    .with("reason", json!(reason.as_str()))
    .with("seq", json!(seq))
}

impl From<AppendError> for Problem {
    fn from(e: AppendError) -> Self {
        match e {
            AppendError::Conflict(head) => Problem::new(
                StatusCode::CONFLICT,
                "space-chain-conflict",
                "The chain's head isn't the one the records follow",
            )
            .with("head", json!(head.as_ref().map(HeadDto::of))),
            AppendError::Refused { error, detail } => refused(
                error.reason,
                error.seq,
                detail.map_or_else(|| error.reason.as_str().to_owned(), str::to_owned),
            ),
            AppendError::Invalid(why) => bad(why),
            AppendError::Mismatch(why) => Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "pending-change-mismatch",
                "The records aren't the queued change",
            )
            .detail(why),
            AppendError::HeldNotRotated(why) => Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "held-not-rotated",
                "A held item isn't in a collection the request rotates",
            )
            .detail(why),
            AppendError::NotFound => Problem::not_found(),
            AppendError::Store(message) => Problem::from(AppError::Store(message)),
        }
    }
}

impl From<ChainReadError> for Problem {
    fn from(e: ChainReadError) -> Self {
        match e {
            ChainReadError::NotFound => Problem::not_found(),
            ChainReadError::Forbidden => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed")
                    .detail("only an owner or an admin of the space reads its pending changes")
            }
            ChainReadError::Store(message) => Problem::from(AppError::Store(message)),
        }
    }
}

// ---- the use cases of one request ----

fn append_use_case<S, P, K, R>(env: &Env<S, P, K, R>) -> AppendChain<R, S, S, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    AppendChain {
        spaces: env.spaces.clone(),
        users: env.api.store.clone(),
        events: env.api.store.clone(),
        clock: env.api.crypto.clone(),
    }
}

// ---- handlers ----

/// Reads an append request's JSON into what the use case takes.
fn read_request(body: &ChainBody) -> Result<AppendRequest, Problem> {
    let request: AppendRequestDto = serde_json::from_slice(&body.0)
        .map_err(|e| Problem::bad_request(format!("the body isn't the JSON expected: {e}")))?;
    let mut records = Vec::with_capacity(request.records.len());
    for (i, record) in request.records.iter().enumerate() {
        let signed = SignedRecord::from_wire(
            &record.entry,
            &record.signature,
            record.cosignature.as_deref(),
        )
        .map_err(|reason| {
            refused(
                reason,
                u64::try_from(i).ok(),
                "a record's wire form is its entry and signature, base64url, and a rekey's cosignature"
                    .to_owned(),
            )
        })?;
        records.push(signed);
    }
    let mut seals = Vec::with_capacity(request.seals.len());
    for seal in &request.seals {
        seals.push(SealIn {
            seq: seal.seq,
            key: KeyRef::parse(&seal.key)
                .ok_or_else(|| bad("a box's key is space or collection:<uuid>"))?,
            member: UserId(seal.member),
            version: seal.version,
            sealed: decode("box", &seal.sealed)?,
        });
    }
    let mut names = Vec::with_capacity(request.names.len());
    for name in &request.names {
        names.push(NameIn {
            seq: name.seq,
            target: NameTarget::parse(&name.target).ok_or_else(|| {
                bad("a name's target is space, collection:<uuid> or group:<uuid>")
            })?,
            sealed: decode("name", &name.name)?,
        });
    }
    Ok(AppendRequest {
        records,
        seals,
        names,
        held: request.held.iter().map(|id| ItemId(*id)).collect(),
    })
}

async fn append_chain<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: ChainBody,
) -> Result<(StatusCode, Json<HeadDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let request = read_request(&body)?;
    let actor = caller.actor();
    let invited = invitees(&request);
    let head = append_use_case(&env)
        .execute(&actor, space, request)
        .await?;
    mail_invitations(&env, actor.user, &invited, space).await;
    Ok((StatusCode::CREATED, Json(HeadDto::of(&head))))
}

async fn answer_pending<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, pending)): Path<(String, String)>,
    body: ChainBody,
) -> Result<(StatusCode, Json<HeadDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let pending: Uuid = pending.parse().map_err(|_| bad("the id isn't a UUID"))?;
    let request = read_request(&body)?;
    let actor = caller.actor();
    let invited = invitees(&request);
    let head = append_use_case(&env)
        .answer(&actor, space, pending, request)
        .await?;
    mail_invitations(&env, actor.user, &invited, space).await;
    Ok((StatusCode::CREATED, Json(HeadDto::of(&head))))
}

/// `?from=<seq>`: an integer from 0.
#[derive(Debug, Deserialize)]
struct FromQuery {
    from: Option<String>,
}

async fn get_chain<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    Query(query): Query<FromQuery>,
) -> Result<Json<Vec<WireRecordDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let from = match query.from {
        None => 0,
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| bad("from is an integer from 0"))?,
    };
    let records = GetChain {
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), space, from)
    .await?;
    Ok(Json(records.iter().map(WireRecordDto::of).collect()))
}

async fn get_seals<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, seq)): Path<(String, String)>,
) -> Result<Json<Vec<SealHashDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let seq: u64 = seq.parse().map_err(|_| bad("seq is an integer from 0"))?;
    let seals = GetChainSeals {
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), space, seq)
    .await?;
    Ok(Json(seals.iter().map(SealHashDto::of).collect()))
}

fn pending_use_case<S, P, K, R>(env: &Env<S, P, K, R>) -> PendingChanges<R, S, S, P>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    PendingChanges {
        spaces: env.spaces.clone(),
        users: env.api.store.clone(),
        events: env.api.store.clone(),
        clock: env.api.crypto.clone(),
    }
}

async fn list_pending<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Json<Vec<PendingDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let list = pending_use_case(&env)
        .list(&caller.actor(), space_id(&id)?)
        .await?;
    Ok(Json(list.iter().map(PendingDto::of).collect()))
}

async fn dismiss_pending<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, pending)): Path<(String, String)>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let pending: Uuid = pending.parse().map_err(|_| bad("the id isn't a UUID"))?;
    let gone = pending_use_case(&env)
        .dismiss(&caller.actor(), space_id(&id)?, pending)
        .await?;
    if gone {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(Problem::not_found())
    }
}

/// The routes of the space chain. Merge it beside [`crate::spaces_router`]; it has no fallback.
pub fn router<S, P, K, R>(api: Api<S, P, K>, spaces: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let env = Env { api, spaces };
    Router::new()
        .route(
            "/kem/v1/spaces/{id}/chain",
            get(get_chain::<S, P, K, R>).post(append_chain::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/chain/pending",
            get(list_pending::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/chain/pending/{pending}",
            post(answer_pending::<S, P, K, R>).delete(dismiss_pending::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/chain/{seq}/seals",
            get(get_seals::<S, P, K, R>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/chain", tag = "space-chain",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("from" = Option<u64>, Query, description = "The first seq to return; default 0"),
    ),
    responses(
        (status = 200, description = "The records with seq >= from, in ascending seq, as signed wire forms", body = Vec<WireRecordDto>),
        (status = 400, description = "from isn't an integer from 0"),
        (status = 404, description = "No such space, or the caller isn't an invited or confirmed member"),
    )
)]
#[allow(dead_code)]
fn doc_get_chain() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/chain", tag = "space-chain",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The space's UUID")),
    request_body = AppendRequestDto,
    responses(
        (status = 201, description = "Appended; the new head", body = HeadDto),
        (status = 409, description = "seq or prev isn't the next; the problem carries the current head"),
        (status = 422, description = "A record was refused; the problem carries the reason and the seq"),
    )
)]
#[allow(dead_code)]
fn doc_append_chain() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/chain/{seq}/seals", tag = "space-chain",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("seq" = u64, Path, description = "The record's seq"),
    ),
    responses(
        (status = 200, description = "The seal hashes the record committed, sorted by key then member", body = Vec<SealHashDto>),
        (status = 404, description = "No such space or record, or the caller isn't a member"),
    )
)]
#[allow(dead_code)]
fn doc_get_seals() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/chain/pending", tag = "space-chain",
    security(("dpop" = [])),
    params(("id" = String, Path, description = "The space's UUID")),
    responses(
        (status = 200, description = "Outside changes (Bitwarden-compatible API, SSO group rules) queued for the space's admins to sign", body = Vec<PendingDto>),
        (status = 403, description = "The caller is not an owner or admin"),
    )
)]
#[allow(dead_code)]
fn doc_list_pending() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/chain/pending/{pending}", tag = "space-chain",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("pending" = String, Path, description = "The queued change's id"),
    ),
    request_body = AppendRequestDto,
    responses(
        (status = 201, description = "The record is appended, the change is applied and the entry is done; the new head", body = HeadDto),
        (status = 404, description = "No such pending change, or the caller isn't an owner or admin of the space"),
        (status = 409, description = "seq or prev isn't the next; the problem carries the current head"),
        (status = 422, description = "The record was refused, or isn't exactly the queued change (pending-change-mismatch)"),
    )
)]
#[allow(dead_code)]
fn doc_answer_pending() {}

#[utoipa::path(
    delete, path = "/kem/v1/spaces/{id}/chain/pending/{pending}", tag = "space-chain",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("pending" = String, Path, description = "The queued change's id"),
    ),
    responses(
        (status = 204, description = "Dropped; recorded in the space's event log"),
        (status = 403, description = "The caller is not an owner or admin"),
        (status = 404, description = "No such pending change"),
    )
)]
#[allow(dead_code)]
fn doc_drop_pending() {}

#[derive(OpenApi)]
#[openapi(
    paths(
        doc_get_chain,
        doc_append_chain,
        doc_get_seals,
        doc_list_pending,
        doc_answer_pending,
        doc_drop_pending
    ),
    components(schemas(
        WireRecordDto,
        SealDto,
        NameDto,
        AppendRequestDto,
        HeadDto,
        SealHashDto,
        PendingDto,
        PendingChangeDto,
        PendingGrantDto,
        RequestedByDto
    ))
)]
struct SpaceChainDoc;

/// The OpenAPI document of the space chain routes alone.
pub fn openapi() -> utoipa::openapi::OpenApi {
    SpaceChainDoc::openapi()
}
