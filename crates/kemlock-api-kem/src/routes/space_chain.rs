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
use super::large_bodies::{LargeBodies, LargeBody};
use crate::problem::Problem;
use crate::routes::spaces::{Caller, Env, mail_invitations, nonce_header};
use crate::state::{Api, Crypto, Store};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::routing::post;
use axum::{Extension, Json, Router};
use futures_util::StreamExt;
use kemlock_app::authenticate::Actor;
use kemlock_app::ports::TokenSigner;
use kemlock_app::spaces::{
    AppendChain, AppendError, AppendRequest, ChainHead, ChainReadError, GetChain, GetChainSeals,
    NameIn, PendingChange, PendingChanges, PendingExternal, SealIn, SpaceChainRepo, SpaceRepo,
    StoredRecord, StoredSeal, invitees,
};
use kemlock_app::{AppError, b64url};
use kemlock_crypto::space_chain::{
    Body as RecordBody, Id, KeyRef, NameTarget, Reason, Record, SignedRecord, State as ChainState,
};
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::spaces::CustomPermissions;
use kemlock_domain::{ItemError, ItemId, Revision, SpaceId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// The most a request to the append route may weigh, whoever sends it: 16 records of 192 KiB,
/// base64url, with their signatures, boxes and names.
const MAX_CHAIN_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The most a request may weigh when it replaces keys. A key replacement writes every live item of
/// the replaced collections again in the same request, and each carries its signature ("Signed item
/// writes", 3,373 bytes, 4.5 KiB in base64url), so the request grows with the items: this is room
/// for about 5,000 items of ordinary size.
const MAX_REPLACEMENT_BODY_BYTES: usize = 32 * 1024 * 1024;

/// The most items one request re-writes: more than [`MAX_REPLACEMENT_BODY_BYTES`] can hold.
const MAX_REWRITES: usize = 6_000;

/// A body has this long to arrive, from its first byte, and one more second for each
/// [`BODY_RATE`] bytes it has by then: the floor is [`BODY_RATE`] a second, after this start.
const BODY_GRACE: Duration = Duration::from_secs(30);
const BODY_RATE: u64 = 256 * 1024;

/// The longest a large body may go without a chunk.
const CHUNK_WAIT: Duration = Duration::from_secs(15);

/// The raw body of an append, and the place among the large bodies it holds, if it is one.
#[derive(Debug)]
struct ChainBody {
    bytes: Bytes,
    large: Option<LargeBody>,
}

/// The collection keys the chain's state marks that `me` may replace, as the worker's
/// `replace_marked` decides: a confirmed member entitled to the key, with edit on the collection.
fn replaceable_marked(state: &ChainState, me: &Id) -> BTreeSet<Id> {
    state
        .keys()
        .iter()
        .filter_map(|key| match key {
            KeyRef::Collection(id)
                if state.key_marked(key)
                    && state.entitled(key).contains(me)
                    && state.access(me, id).is_some_and(|rights| rights.edit) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .collect()
}

/// Whether `actor` may send more than the ordinary limit to `space` now: the chain's state has a
/// collection key marked that they may replace. Nothing else needs a body that large: the items of
/// a key replacement are the only thing that does.
async fn may_send_large<S, P, K, R>(env: &Env<S, P, K, R>, actor: &Actor, space: SpaceId) -> bool
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let Ok(Some((_, state))) = env.spaces.chain_state(space).await else {
        return false;
    };
    !replaceable_marked(&state, actor.user.as_bytes()).is_empty()
}

fn too_slow() -> Problem {
    Problem::new(
        StatusCode::REQUEST_TIMEOUT,
        "request-timeout",
        "The request body arrived too slowly",
    )
    .detail("A body has 30 seconds, and a second more for each 256 KiB of it, to arrive")
}

/// Reads an append's body after the caller is authenticated, as a stream. At most 8 MiB is held
/// unless `large_ok` and [`may_send_large`] say the caller may send more and a place among the
/// large bodies is free: `413` answers otherwise (a stranger, a plain member, a space with no key
/// to replace), and nothing past 8 MiB was buffered. Every body must keep up [`BODY_RATE`] from
/// its first byte, and one that doesn't gives its place back.
async fn read_chain_body<S, P, K, R>(
    env: &Env<S, P, K, R>,
    places: &LargeBodies,
    actor: &Actor,
    space: SpaceId,
    body: Body,
    large_ok: bool,
) -> Result<ChainBody, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    // A place taken is dropped, and counted against the account, whatever becomes of the body.
    let mut large: Option<LargeBody> = None;
    let bytes = read_stream(env, places, actor, space, body, large_ok, &mut large).await?;
    Ok(ChainBody {
        bytes: Bytes::from(bytes),
        large,
    })
}

async fn read_stream<S, P, K, R>(
    env: &Env<S, P, K, R>,
    places: &LargeBodies,
    actor: &Actor,
    space: SpaceId,
    body: Body,
    large_ok: bool,
    large: &mut Option<LargeBody>,
) -> Result<Vec<u8>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let mut stream = body.into_data_stream();
    let mut bytes: Vec<u8> = Vec::new();
    let started = Instant::now();
    loop {
        // What is allowed so far is the start and a second for each 256 KiB that arrived: a chunk
        // may not take longer than that to come, nor more than [`CHUNK_WAIT`].
        let allowed = BODY_GRACE + Duration::from_secs(bytes.len() as u64 / BODY_RATE);
        let wait = allowed.saturating_sub(started.elapsed()).min(CHUNK_WAIT);
        let next = tokio::time::timeout(wait, stream.next())
            .await
            .map_err(|_| too_slow())?;
        let Some(chunk) = next else {
            return Ok(bytes);
        };
        let chunk = chunk.map_err(|_| bad("the body couldn't be read"))?;
        let total = bytes.len().saturating_add(chunk.len());
        if large.is_none() && total > MAX_CHAIN_BODY_BYTES {
            if !large_ok || !may_send_large(env, actor, space).await {
                return Err(Problem::payload_too_large());
            }
            *large = Some(places.take(*actor.user.as_bytes(), *space.as_bytes()).await?);
        }
        if total > MAX_REPLACEMENT_BODY_BYTES {
            return Err(Problem::payload_too_large());
        }
        bytes.extend_from_slice(&chunk);
        let allowed = BODY_GRACE + Duration::from_secs(bytes.len() as u64 / BODY_RATE);
        if started.elapsed() > allowed {
            return Err(too_slow());
        }
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
    /// Items a `keys` record in the request re-writes under the collection's new key version.
    #[serde(default)]
    writes: Vec<super::spaces::ReplacementWriteDto>,
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
            AppendError::SignatureRequired => {
                Problem::from(AppError::Item(ItemError::SignatureRequired))
            }
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

fn append_use_case<S, P, K, R>(
    env: &Env<S, P, K, R>,
) -> AppendChain<R, S, S, P, S, S, crate::LiveHub>
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
        items: env.api.store.clone(),
        tags: env.api.store.clone(),
        limits: env.api.auth_config().item_limits,
        push: env.api.hub.clone(),
    }
}

// ---- handlers ----

/// Reads an append request's JSON into what the use case takes.
fn read_request(body: &ChainBody) -> Result<AppendRequest, Problem> {
    let request: AppendRequestDto = serde_json::from_slice(&body.bytes)
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
    if request.writes.len() > MAX_REWRITES {
        return Err(bad("a request re-writes at most 6,000 items"));
    }
    let mut written = BTreeSet::new();
    let mut writes = Vec::with_capacity(request.writes.len());
    for write in request.writes {
        if !written.insert(write.item.id) {
            return Err(bad("an item is re-written once in a request"));
        }
        let item = write
            .item
            .into_write(Some(Revision(write.expected_revision)))?;
        writes.push((CollectionId(write.collection), item));
    }
    Ok(AppendRequest {
        records,
        seals,
        names,
        held: request.held.iter().map(|id| ItemId(*id)).collect(),
        writes,
    })
}

/// The re-written items of a key replacement, checked before anything is stored. First, cheaply,
/// that the caller is a confirmed member of the space with edit on the collection of each item,
/// from the chain's state: a stranger's request costs no signature check. Then each signature, as
/// any item write's is (docs/crypto.md, "Signed item writes"): by the signed-in account, over the
/// statement rebuilt from the write and the collection it names, on a blocking thread. An unsigned
/// re-write is left to the use case, which knows whether the space takes signed writes only.
async fn check_rewrites<S, P, K, R>(
    env: &Env<S, P, K, R>,
    actor: UserId,
    space: SpaceId,
    request: &mut AppendRequest,
) -> Result<(), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    if request.writes.is_empty() {
        return Ok(());
    }
    let Some((_, state)) = env
        .spaces
        .chain_state(space)
        .await
        .map_err(|e| Problem::from(AppError::Store(e.to_string())))?
    else {
        return Err(Problem::not_found());
    };
    let me = *actor.as_bytes();
    if state.confirmed(&me).is_none() {
        return Err(Problem::not_found());
    }
    for (collection, _) in &request.writes {
        if !state
            .access(&me, collection.0.as_bytes())
            .is_some_and(|rights| rights.edit)
        {
            return Err(refused(
                Reason::NotAllowed,
                None,
                "only a member with edit on a collection re-writes its items".to_owned(),
            ));
        }
    }
    // The writes go to the blocking task and come back, so none is copied.
    let writes = std::mem::take(&mut request.writes);
    request.writes = super::write_sig::verify_writes_blocking(&env.api.store, actor, writes).await?;
    Ok(())
}

/// What an append does once its body is read: the same for a new request and for the answer to a
/// queued change (`pending`).
async fn append_read<S, P, K, R>(
    env: &Env<S, P, K, R>,
    actor: &Actor,
    space: SpaceId,
    pending: Option<Uuid>,
    body: &ChainBody,
    replaced: &mut bool,
) -> Result<(StatusCode, Json<HeadDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let mut request = read_request(body)?;
    check_rewrites(env, actor.user, space, &mut request).await?;
    // For a large body: the marked collection keys the caller may replace now, to tell afterwards
    // whether the request replaced one.
    let mut may_replace = BTreeSet::new();
    if body.large.is_some()
        && let Ok(Some((_, state))) = env.spaces.chain_state(space).await
    {
        may_replace = replaceable_marked(&state, actor.user.as_bytes());
    }
    let rotates = request
        .records
        .iter()
        .filter_map(|record| Record::parse(&record.entry).ok())
        .any(|record| match record.body {
            RecordBody::Keys { rotate, .. } => rotate.iter().any(
                |commitment| matches!(commitment.key, KeyRef::Collection(id) if may_replace.contains(&id)),
            ),
            _ => false,
        });
    let invited = invitees(&request);
    let append = append_use_case(env);
    let head = match pending {
        None => append.execute(actor, space, request).await?,
        Some(pending) => append.answer(actor, space, pending, request).await?,
    };
    *replaced = rotates;
    mail_invitations(env, actor.user, &invited, space).await;
    Ok((StatusCode::CREATED, Json(HeadDto::of(&head))))
}

impl ChainBody {
    /// Notes how the request ended. A large body counts against the account whatever came of it,
    /// unless it was stored and replaced a marked collection key.
    fn settle<T>(&mut self, result: &Result<T, Problem>, replaced: bool) {
        if let (Some(place), Ok(_), true) = (self.large.as_mut(), result, replaced) {
            place.replaced();
        }
    }
}

async fn append_chain<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    Extension(places): Extension<LargeBodies>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Result<(StatusCode, Json<HeadDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let actor = caller.actor();
    let mut body = read_chain_body(&env, &places, &actor, space, body, true).await?;
    let mut replaced = false;
    let result = append_read(&env, &actor, space, None, &body, &mut replaced).await;
    body.settle(&result, replaced);
    result
}

/// A queued change is answered with the records that apply it, which are small: no queued change
/// is a `keys` record, so this route reads 8 MiB at most, from anyone.
async fn answer_pending<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    Extension(places): Extension<LargeBodies>,
    caller: Caller,
    Path((id, pending)): Path<(String, String)>,
    body: Body,
) -> Result<(StatusCode, Json<HeadDto>), Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + SpaceChainRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let pending: Uuid = pending.parse().map_err(|_| bad("the id isn't a UUID"))?;
    let actor = caller.actor();
    let mut body = read_chain_body(&env, &places, &actor, space, body, false).await?;
    let mut replaced = false;
    let result = append_read(&env, &actor, space, Some(pending), &body, &mut replaced).await;
    body.settle(&result, replaced);
    result
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
    router_with(api, spaces, LargeBodies::default())
}

/// [`router`] over the given places for large bodies, which the router owns: one is made for each
/// router, and a test that wants to fill them passes its own.
pub fn router_with<S, P, K, R>(api: Api<S, P, K>, spaces: R, places: LargeBodies) -> Router
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
        .layer(Extension(places))
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
