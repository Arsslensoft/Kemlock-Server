//! Rotating the root key (docs/crypto.md, "Rotating the root key").
//!
//! ```text
//! GET    /kem/v1/account/rotation                  what the account holds that a rotation covers
//! PUT    /kem/v1/account/rotation/items            stages re-encrypted items, out of sight
//! DELETE /kem/v1/account/rotation                  abandons: drops the staged items
//! POST   /kem/v1/account/rotation                  installs the new keys, in one transaction
//! DELETE /kem/v1/account/rotation/previous-keys    the spaces have moved: drops the old keys
//! ```
//!
//! The browser makes the new root key and re-encrypts everything; the server opens none of it. The
//! install asks for the password again, as changing it does (`reauth.rs`), and a fresh proof of the
//! second step when one is on. It ends every other session (a new security stamp) and answers the
//! asking device's new tokens. The routes need the rotation store, so they have a router of their
//! own, as the profile does: see [`rotation_router`].

use super::devices::token_response;
use super::profile::{account_of, other_devices, proof_needed, record};
use super::reauth::reauthenticate;
use super::two_step::{nonce_header, require_proof_via_api};
use crate::dto::{FreshProof, TokenResponse, decode};
use crate::extract::{Authed, Body};
use crate::openapi::ProblemDoc;
use crate::problem::Problem;
use crate::state::{Api, Crypto, Store};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router, middleware};
use kemlock_app::AppError;
use kemlock_app::b64url;
use kemlock_app::devices::KeyCopyRepo;
use kemlock_app::ports::TokenSigner;
use kemlock_app::rotation::{
    InstallRequest, Plan, Rotation, RotationError, RotationStore, StagedItem,
};
use kemlock_domain::sends::SendId;
use kemlock_domain::unlock::{GrantId, KeyProtection};
use kemlock_domain::{ItemId, PasskeyId, Revision, SpaceId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// The rotation store, `SqlStore` in the server.
struct Repos<R>(R);

// ---- problems ----

impl From<RotationError> for Problem {
    fn from(e: RotationError) -> Self {
        let conflict = |slug, title| Problem::new(StatusCode::CONFLICT, slug, title);
        match e {
            RotationError::Incomplete(detail) => conflict(
                "rotation-incomplete",
                "The account changed since the plan was read: read it again and redo what changed",
            )
            .detail(detail),
            RotationError::StaleVersion => conflict(
                "rotation-stale-version",
                "The key version is not the account's: read the plan again",
            ),
            RotationError::SpacesNeedRekey => conflict(
                "spaces-need-rekey",
                "The account is in a space whose keys must move to the new keys too",
            ),
            RotationError::UnsupportedItems => conflict(
                "rotation-unsupported-items",
                "An item of the vault is in a format that can't be rotated",
            ),
            RotationError::CompatibleAccount => Problem::new(
                StatusCode::FORBIDDEN,
                "compatible-account",
                "This account is shared with Bitwarden apps, which hold its root key",
            ),
            RotationError::AccountChanged => conflict(
                "account-changed",
                "The account changed while this was being saved: nothing was written, try again",
            ),
            RotationError::App(e) => Problem::from(e),
        }
    }
}

// ---- wire types ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KitHeld {
    kit_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasskeyHeld {
    id: Uuid,
    /// The WebAuthn credential id, base64url.
    credential_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceHeld {
    device_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GrantHeld {
    id: Uuid,
    state: String,
    /// The contact's account, once they accepted.
    grantee_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryHeld {
    space: Uuid,
    /// The `seq` of the chain record that set the recovery key the box is sealed to.
    key_seq: u64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SendHeld {
    id: Uuid,
    /// `text` or `file`.
    kind: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemsHeld {
    count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreviousKeysDto {
    key_version: u32,
    /// The old private keys sealed under the new user key, base64url.
    sealed: String,
}

/// What a rotation has to cover.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanDto {
    key_version: u32,
    has_password: bool,
    /// The account's public bundle, base64url.
    public_bundle: String,
    kit: Option<KitHeld>,
    /// Passkeys that have a PRF wrap.
    passkeys: Vec<PasskeyHeld>,
    device_copies: Vec<DeviceHeld>,
    /// Grants that hold a box.
    emergency: Vec<GrantHeld>,
    recovery: Vec<RecoveryHeld>,
    sends: Vec<SendHeld>,
    items: ItemsHeld,
    /// How many spaces the account is a member of.
    spaces: u64,
    previous_keys: Option<PreviousKeysDto>,
}

impl PlanDto {
    fn of(plan: &Plan) -> PlanDto {
        let holdings = &plan.holdings;
        PlanDto {
            key_version: plan.account.key_version,
            has_password: !plan.account.wrapped_root_key.is_empty(),
            public_bundle: b64url::encode(&plan.account.public_bundle),
            kit: holdings.kit.clone().map(|kit_id| KitHeld { kit_id }),
            passkeys: holdings
                .passkeys
                .iter()
                .map(|(id, credential)| PasskeyHeld {
                    id: id.0,
                    credential_id: b64url::encode(credential),
                })
                .collect(),
            device_copies: holdings
                .device_copies
                .iter()
                .map(|device| DeviceHeld { device_id: device.0 })
                .collect(),
            emergency: holdings
                .emergency
                .iter()
                .map(|(id, state, grantee)| GrantHeld {
                    id: id.0,
                    state: state.as_str().to_owned(),
                    grantee_id: grantee.map(|user| user.0),
                })
                .collect(),
            recovery: holdings
                .recovery
                .iter()
                .map(|(space, key_seq)| RecoveryHeld {
                    space: space.0,
                    key_seq: *key_seq,
                })
                .collect(),
            sends: holdings
                .sends
                .iter()
                .map(|(id, kind)| SendHeld {
                    id: id.0,
                    kind: if *kind == 1 { "file" } else { "text" },
                })
                .collect(),
            items: ItemsHeld {
                count: holdings.live_items.len(),
            },
            spaces: holdings.spaces,
            previous_keys: plan.previous_keys.as_ref().map(|previous| PreviousKeysDto {
                key_version: previous.key_version,
                sealed: b64url::encode(&previous.sealed),
            }),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StagedItemDto {
    id: Uuid,
    /// The revision the client read; the item is written at the next one.
    base_revision: u64,
    /// `nonce ‖ ciphertext ‖ tag`, base64url, sealed at `baseRevision + 1`.
    ciphertext: String,
    /// The new item key wrapped under the new item-wrap key, base64url, 60 bytes.
    item_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StageRequest {
    /// 16 random bytes naming this attempt, base64url.
    rotation_id: String,
    /// The key version the rotation installs: the account's plus one.
    to_version: u32,
    /// 1 to 200 items, and few enough to fit the JSON body limit.
    items: Vec<StagedItemDto>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StagedDto {
    /// How many items this attempt has staged now.
    staged: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KitDto {
    kit_id: String,
    wrapped_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceCopyDto {
    wrapped_key: String,
    /// `secure-enclave`, `keystore`, `web-crypto`, `software` or `browser`.
    protection: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasskeyWrapDto {
    id: Uuid,
    wrapped_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmergencyBoxDto {
    id: Uuid,
    sealed_key: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryBoxDto {
    space: Uuid,
    key_seq: u64,
    #[serde(rename = "box")]
    sealed: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SendWrapDto {
    id: Uuid,
    sealed_key: String,
    meta: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstallRequestDto {
    /// 16 random bytes naming the attempt that staged the items, base64url.
    rotation_id: String,
    from_version: u32,
    to_version: u32,
    /// What `POST /auth/opaque/start` answered, unread. Needed when the account has a password.
    login_state: Option<String>,
    /// The client's OPAQUE `CredentialFinalization`, with the current password.
    finalization: Option<String>,
    /// A fresh proof of the second step, needed beside the password when one is on.
    proof: Option<FreshProof>,
    public_bundle: String,
    bundle_signature: String,
    sealed_private_keys: String,
    /// The old private keys sealed under the new user key at the old key version.
    sealed_previous_private_keys: String,
    /// The new root key's password wrap, 92 bytes; present exactly when the account has one.
    wrapped_root_key: Option<String>,
    kit: Option<KitDto>,
    #[serde(default)]
    drop_kit: bool,
    device_copy: Option<DeviceCopyDto>,
    #[serde(default)]
    passkeys: Vec<PasskeyWrapDto>,
    #[serde(default)]
    drop_passkeys: Vec<Uuid>,
    #[serde(default)]
    emergency: Vec<EmergencyBoxDto>,
    #[serde(default)]
    drop_emergency: Vec<Uuid>,
    #[serde(default)]
    recovery: Vec<RecoveryBoxDto>,
    #[serde(default)]
    drop_recovery: Vec<Uuid>,
    #[serde(default)]
    sends: Vec<SendWrapDto>,
    /// The client moves the account's spaces to the new keys itself.
    #[serde(default)]
    spaces_handled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RotatedDto {
    /// The account's key version now.
    key_version: u32,
    /// New tokens for the device that asked, bound to its DPoP key: the new security stamp ended
    /// the ones it held. Null when they could not be made: it signs in again.
    tokens: Option<TokenResponse>,
}

fn rotation_id(text: &str) -> Result<[u8; 16], Problem> {
    decode("rotationId", text)?
        .try_into()
        .map_err(|_| Problem::bad_request("rotationId must be 16 bytes"))
}

impl InstallRequestDto {
    /// The request as the use case takes it, every value decoded.
    fn decoded(&self) -> Result<InstallRequest, Problem> {
        let kit = match &self.kit {
            Some(kit) => Some((kit.kit_id.clone(), decode("kit.wrappedKey", &kit.wrapped_key)?)),
            None => None,
        };
        let device_copy = match &self.device_copy {
            Some(copy) => Some((
                decode("deviceCopy.wrappedKey", &copy.wrapped_key)?,
                KeyProtection::parse(&copy.protection)
                    .ok_or_else(|| Problem::bad_request("deviceCopy.protection is not known"))?,
            )),
            None => None,
        };
        Ok(InstallRequest {
            rotation: rotation_id(&self.rotation_id)?,
            from_version: self.from_version,
            to_version: self.to_version,
            public_bundle: decode("publicBundle", &self.public_bundle)?,
            bundle_signature: decode("bundleSignature", &self.bundle_signature)?,
            sealed_private_keys: decode("sealedPrivateKeys", &self.sealed_private_keys)?,
            sealed_previous_private_keys: decode(
                "sealedPreviousPrivateKeys",
                &self.sealed_previous_private_keys,
            )?,
            wrapped_root_key: self
                .wrapped_root_key
                .as_deref()
                .map(|wrap| decode("wrappedRootKey", wrap))
                .transpose()?,
            kit,
            drop_kit: self.drop_kit,
            device_copy,
            passkeys: self
                .passkeys
                .iter()
                .map(|p| Ok((PasskeyId(p.id), decode("passkeys.wrappedKey", &p.wrapped_key)?)))
                .collect::<Result<_, Problem>>()?,
            drop_passkeys: self.drop_passkeys.iter().copied().map(PasskeyId).collect(),
            emergency: self
                .emergency
                .iter()
                .map(|g| Ok((GrantId(g.id), decode("emergency.sealedKey", &g.sealed_key)?)))
                .collect::<Result<_, Problem>>()?,
            drop_emergency: self.drop_emergency.iter().copied().map(GrantId).collect(),
            recovery: self
                .recovery
                .iter()
                .map(|r| Ok((SpaceId(r.space), r.key_seq, decode("recovery.box", &r.sealed)?)))
                .collect::<Result<_, Problem>>()?,
            drop_recovery: self.drop_recovery.iter().copied().map(SpaceId).collect(),
            sends: self
                .sends
                .iter()
                .map(|s| {
                    Ok((
                        SendId(s.id),
                        decode("sends.sealedKey", &s.sealed_key)?,
                        decode("sends.meta", &s.meta)?,
                    ))
                })
                .collect::<Result<_, Problem>>()?,
            spaces_handled: self.spaces_handled,
        })
    }
}

// ---- wiring ----

fn rotation<S, P, K, R>(
    api: &Api<S, P, K>,
    repos: &Repos<R>,
) -> Rotation<S, S, R, P, crate::LiveHub>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    Rotation {
        users: api.store.clone(),
        items: api.store.clone(),
        store: repos.0.clone(),
        env: api.crypto.clone(),
        push: api.hub.clone(),
        notices: api.hub.notices(),
        config: api.auth_config(),
    }
}

// ---- handlers ----

async fn handle_plan<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<Json<PlanDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    let plan = rotation(&api, &repos).plan(authed.actor.user).await?;
    Ok(Json(PlanDto::of(&plan)))
}

async fn handle_stage<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<StagedDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    let request: StageRequest = body.json()?;
    let rotation_id = rotation_id(&request.rotation_id)?;
    let items = request
        .items
        .iter()
        .map(|item| {
            Ok(StagedItem {
                id: ItemId(item.id),
                base_revision: Revision(item.base_revision),
                ciphertext: decode("ciphertext", &item.ciphertext)?,
                item_key: decode("itemKey", &item.item_key)?,
            })
        })
        .collect::<Result<Vec<_>, Problem>>()?;
    let staged = rotation(&api, &repos)
        .stage(authed.actor.user, rotation_id, request.to_version, items)
        .await?;
    Ok(Json(StagedDto { staged }))
}

async fn handle_abandon<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<StatusCode, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    rotation(&api, &repos).discard(authed.actor.user).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_previous_keys_done<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
) -> Result<StatusCode, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    rotation(&api, &repos)
        .finish_spaces(authed.actor.user)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_install<S, P, K, R>(
    State(api): State<Api<S, P, K>>,
    Extension(repos): Extension<Arc<Repos<R>>>,
    authed: Authed,
    body: Body,
) -> Result<Json<RotatedDto>, Problem>
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    let dto: InstallRequestDto = body.json()?;
    let request = dto.decoded()?;
    let user = authed.actor.user;
    let rotation = rotation(&api, &repos);
    // What can be known to be wrong is said before the password is spent.
    let account = rotation.check(user, &request).await?;
    let proof = proof_needed(&api, user, dto.proof.as_ref()).await?;
    if !account.wrapped_root_key.is_empty() {
        let (Some(login_state), Some(finalization)) = (&dto.login_state, &dto.finalization) else {
            return Err(AppError::Invalid("the password is needed to rotate the keys").into());
        };
        let account = account_of(&api, &authed).await?;
        reauthenticate(&api, &authed, &account, login_state, finalization).await?;
    }
    // With a second step on, the password alone is not enough: a stolen session and a guessed
    // password must not replace the account's keys.
    if let Some(proof) = proof {
        require_proof_via_api(&api, user, proof, true).await?;
    }
    let after = rotation.install(&authed.actor, request).await?;
    // The keys are rotated: nothing from here on can say they were not. The new security stamp
    // ended every session, this device's too, so it gets new ones.
    let tokens = other_devices(&api)
        .renew(&authed.actor, &after, &authed.jkt)
        .await;
    record(
        &api,
        user,
        Some(authed.actor.device),
        "account.keys_rotated",
        Some(format!("key version {}", after.key_version)),
    )
    .await;
    Ok(Json(RotatedDto {
        key_version: after.key_version,
        tokens: tokens.map(|tokens| token_response(&tokens, api.now())),
    }))
}

/// The rotation routes. Merge the result into the main router, with the rotation store:
///
/// ```ignore
/// router(api.clone()).merge(rotation_router(api, store))
/// ```
pub fn rotation_router<S, P, K, R>(api: Api<S, P, K>, store: R) -> Router
where
    S: Store + KeyCopyRepo,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: RotationStore + Clone + 'static,
{
    Router::new()
        .route(
            "/kem/v1/account/rotation",
            get(handle_plan::<S, P, K, R>)
                .post(handle_install::<S, P, K, R>)
                .delete(handle_abandon::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/rotation/items",
            put(handle_stage::<S, P, K, R>),
        )
        .route(
            "/kem/v1/account/rotation/previous-keys",
            delete(handle_previous_keys_done::<S, P, K, R>),
        )
        .layer(Extension(Arc::new(Repos(store))))
        .layer(middleware::from_fn_with_state(
            api.clone(),
            nonce_header::<S, P, K>,
        ))
        .with_state(api)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/account/rotation", tag = "account",
    security(("dpop" = [])),
    responses(
        (status = 200, description = "What the account holds that a rotation of its root key must cover", body = PlanDto),
        (status = 403, description = "`compatible-account`", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 404, description = "The account has no keys yet", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_plan() {}

#[utoipa::path(
    put, path = "/kem/v1/account/rotation/items", tag = "account",
    security(("dpop" = [])),
    request_body = StageRequest,
    responses(
        (status = 200, description = "The items are staged, out of sight of every reader; a row for the same item is replaced", body = StagedDto),
        (status = 400, description = "A sealed value or the request is malformed", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "`rotation-incomplete` (an item changed since it was read) or `rotation-stale-version`", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_stage() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/rotation", tag = "account",
    security(("dpop" = [])),
    responses((status = 204, description = "The staged items are dropped"))
)]
#[allow(dead_code)]
fn doc_abandon() {}

#[utoipa::path(
    post, path = "/kem/v1/account/rotation", tag = "account",
    security(("dpop" = [])),
    request_body = InstallRequestDto,
    responses(
        (status = 200, description = "The new root key is installed and every wrap of the old one is gone, in one transaction; every other session ended with the new security stamp", body = RotatedDto),
        (status = 400, description = "Something sent is malformed", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 401, description = "Wrong password, or not signed in", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 403, description = "`compatible-account`", body = ProblemDoc, content_type = "application/problem+json"),
        (status = 409, description = "`rotation-incomplete`, `rotation-stale-version`, `rotation-unsupported-items`, `spaces-need-rekey` or `account-changed`; nothing was written", body = ProblemDoc, content_type = "application/problem+json"),
    )
)]
#[allow(dead_code)]
fn doc_install() {}

#[utoipa::path(
    delete, path = "/kem/v1/account/rotation/previous-keys", tag = "account",
    security(("dpop" = [])),
    responses((status = 204, description = "The previous private keys are deleted, also when there were none"))
)]
#[allow(dead_code)]
fn doc_previous_keys() {}

/// The rotation routes' part of `/kem/v1/openapi.json`.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(doc_plan, doc_stage, doc_abandon, doc_install, doc_previous_keys),
    components(schemas(
        PlanDto,
        KitHeld,
        PasskeyHeld,
        DeviceHeld,
        GrantHeld,
        RecoveryHeld,
        SendHeld,
        ItemsHeld,
        PreviousKeysDto,
        StageRequest,
        StagedItemDto,
        StagedDto,
        InstallRequestDto,
        KitDto,
        DeviceCopyDto,
        PasskeyWrapDto,
        EmergencyBoxDto,
        RecoveryBoxDto,
        SendWrapDto,
        RotatedDto
    ))
)]
pub struct RotationApiDoc;
