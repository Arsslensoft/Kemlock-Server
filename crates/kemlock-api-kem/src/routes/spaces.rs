//! Spaces: `/kem/v1/spaces`. Members (invite, accept, confirm, role, revoke, restore, remove),
//! collections, groups, grants and the key replacement that follows an offboarding.
//!
//! These routes need a store that also keeps spaces (`SpaceRepo`), which `SqlStore` does and the
//! shared [`Store`] bound doesn't say, so they have a router of their own: [`router`] takes the
//! [`Api`] and the space store, authenticates with the same DPoP-bound tokens, and is merged beside
//! the main router (`kemlock-server`'s `app.rs`). It has no fallback, so merging keeps the main
//! router's.
//!
//! Binary values are base64url without padding, ids are UUIDs, times are Unix seconds. A person
//! outside a space gets 404 for it, as for a space that doesn't exist. Writes while a space waits
//! for its keys to be replaced are 423.

use crate::dto::{BatchResponse, ItemDto, decode};
use crate::extract::{Authed, Body, DPOP_NONCE};
use crate::problem::{Problem, rate_limited};
use crate::routes::guard;
use crate::routes::invite_link::MaybeInviteLinks;
use crate::state::{Api, Crypto, RESEND_WINDOW_SECS, Store};
use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use kemlock_app::notices::{InvitationNotice, Notice};
use kemlock_app::ports::{TokenSigner, UserRepo};
use kemlock_app::spaces::{
    AcceptInvitation, BundleFingerprints, ChangeRole, CollectionRekey, ConfirmInput, ConfirmMember,
    ConfirmationFacts, CreateCollection, CreateCollectionInput, CreateGroup, CreateGroupInput,
    CreateSpace, CreateSpaceInput, DeleteCollection, DeleteGroup, EditCollection,
    EditCollectionInput, EditGroup, EditGroupInput, GetSpace, GrantAccess, InviteInput,
    InviteMember, KeyBoxFacts, KeyBoxKey, KeyBoxVerifier, ListMembers, ListSpaces, LookupAccount,
    NewCollection, Offboard, ReplaceKeys, ReplacementInput, ResealKeys, ResealMember,
    ResendInvitation, RevokeGrant, SealedCollectionKey, SealedSpaceKey, SpaceRepo, SpacesError,
};
use kemlock_app::{Actor, AppError, b64url};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, CustomPermissions, Grantee,
    Group, GroupId, KeyBoxSignature, KeyCopy, Member, Space, SpaceError, SpaceRole,
};
use kemlock_domain::{ItemWrite, Revision, SpaceId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

// ---- state, authentication and errors ----

/// The router's state: the API's and the space store.
pub(crate) struct Env<S, P, K, R> {
    pub(crate) api: Api<S, P, K>,
    pub(crate) spaces: R,
}

impl<S, P, K, R: Clone> Clone for Env<S, P, K, R> {
    fn clone(&self) -> Self {
        Env {
            api: self.api.clone(),
            spaces: self.spaces.clone(),
        }
    }
}

/// An authenticated request: `Authed`, extracted from this router's state.
pub(crate) struct Caller(pub(crate) Authed);

impl Caller {
    pub(crate) fn actor(&self) -> Actor {
        self.0.actor
    }
}

impl<S, P, K, R> FromRequestParts<Env<S, P, K, R>> for Caller
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, env: &Env<S, P, K, R>) -> Result<Self, Problem> {
        Authed::from_request_parts(parts, &env.api)
            .await
            .map(Caller)
    }
}

/// The public-key bundle's fingerprint, and the check of a confirmation's signature, from
/// `kemlock-crypto`.
#[derive(Clone, Copy, Debug)]
struct CryptoFingerprints;

impl BundleFingerprints for CryptoFingerprints {
    fn fingerprint(&self, bundle: &[u8]) -> Option<[u8; 64]> {
        kemlock_crypto::bundle::Bundle::from_bytes(bundle)
            .ok()
            .map(|b| b.fingerprint())
    }

    fn verify_confirmation(
        &self,
        confirmer_bundle: &[u8],
        facts: &ConfirmationFacts<'_>,
        statement: &[u8],
        signature: &[u8],
    ) -> bool {
        let Ok(confirmer) = kemlock_crypto::bundle::Bundle::from_bytes(confirmer_bundle) else {
            return false;
        };
        let Ok(fingerprint) = <&[u8; 64]>::try_from(facts.fingerprint) else {
            return false;
        };
        kemlock_crypto::confirm::Statement {
            space: *facts.space.as_bytes(),
            member: *facts.member.as_bytes(),
            member_key_version: facts.member_key_version,
            fingerprint,
            confirmer: *facts.confirmer.as_bytes(),
        }
        .verify(&confirmer.sig1_public, statement, signature)
        .is_ok()
    }
}

/// Checks a key box signature against the sealing account's registered bundle: the statement is
/// rebuilt from the route's facts and the bundle's own key version, never from the request.
#[derive(Clone, Debug)]
struct StoreKeyBoxes<S> {
    users: S,
}

impl<S: UserRepo> KeyBoxVerifier for StoreKeyBoxes<S> {
    async fn verify(&self, facts: &KeyBoxFacts<'_>, signature: &[u8]) -> Result<u32, SpacesError> {
        let refused = || {
            SpacesError::Rule(SpaceError::Invalid(
                "the key's signature isn't the sealing member's over this box",
            ))
        };
        let sealer = self
            .users
            .by_id(facts.sealer)
            .await?
            .ok_or(SpacesError::NotFound)?;
        let bundle = kemlock_crypto::bundle::Bundle::from_bytes(&sealer.public_bundle)
            .map_err(|_| refused())?;
        if sealer.key_version == 0
            || bundle.account_id != *facts.sealer.as_bytes()
            || bundle.key_version != sealer.key_version
        {
            return Err(refused());
        }
        let (kind, aad) = match facts.key {
            KeyBoxKey::Space => (
                kemlock_crypto::key_box::Kind::Space,
                kemlock_crypto::key_box::space_aad(
                    facts.space.as_bytes(),
                    facts.key_version,
                    facts.recipient.as_bytes(),
                ),
            ),
            KeyBoxKey::Collection(collection) => (
                kemlock_crypto::key_box::Kind::Collection,
                kemlock_crypto::key_box::collection_aad(
                    facts.space.as_bytes(),
                    collection.as_bytes(),
                    facts.key_version,
                    facts.recipient.as_bytes(),
                ),
            ),
        };
        kemlock_crypto::key_box::Statement {
            kind,
            aad: &aad,
            sealed_box: facts.sealed_box,
            sealer: *facts.sealer.as_bytes(),
            sealer_key_version: bundle.key_version,
        }
        .verify(&bundle.sig1_public, signature)
        .map_err(|_| refused())?;
        Ok(bundle.key_version)
    }
}

impl From<SpacesError> for Problem {
    fn from(e: SpacesError) -> Self {
        match e {
            // Someone outside a space learns nothing about it.
            SpacesError::Rule(SpaceError::NotAMember) | SpacesError::NotFound => {
                Problem::not_found()
            }
            SpacesError::Rule(SpaceError::Forbidden(why)) => {
                Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed").detail(why)
            }
            SpacesError::Rule(SpaceError::Invalid(why)) => Problem::bad_request(why),
            SpacesError::Rule(SpaceError::State(why)) => Problem::new(
                StatusCode::CONFLICT,
                "wrong-state",
                "That isn't possible in the member's or the space's current state",
            )
            .detail(why),
            SpacesError::Rule(SpaceError::KeysPending) => Problem::new(
                StatusCode::LOCKED,
                "space-keys-pending",
                "The space waits for its keys to be replaced",
            )
            .detail("replace the keys at POST /kem/v1/spaces/{id}/key-replacement"),
            SpacesError::Rule(SpaceError::StaleKeyVersion { current }) => Problem::new(
                StatusCode::CONFLICT,
                "stale-key-version",
                "The collection's key has been replaced",
            )
            .with("currentKeyVersion", json!(current)),
            SpacesError::Rule(SpaceError::FingerprintMismatch) => Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "fingerprint-mismatch",
                "The fingerprint is not the one of the member's key bundle",
            ),
            SpacesError::Rule(SpaceError::LastOwner) => Problem::new(
                StatusCode::CONFLICT,
                "last-owner",
                "A space needs at least one confirmed owner",
            ),
            SpacesError::Duplicate => Problem::from(AppError::Duplicate),
            SpacesError::StaleItem { item, current } => {
                Problem::from(AppError::Conflict { item, current })
            }
            SpacesError::Item(e) => Problem::from(AppError::Item(e)),
            SpacesError::Store(message) => Problem::from(AppError::Store(message)),
        }
    }
}

// ---- wire types ----

fn secs(time: OffsetDateTime) -> i64 {
    time.unix_timestamp()
}

fn bad(why: &'static str) -> Problem {
    Problem::bad_request(why)
}

const CUSTOM_NAMES: [(&str, CustomPermissions); 3] = [
    ("manage-users", CustomPermissions::MANAGE_USERS),
    ("manage-groups", CustomPermissions::MANAGE_GROUPS),
    ("create-collections", CustomPermissions::CREATE_COLLECTIONS),
];

fn custom_from(names: &[String]) -> Result<CustomPermissions, Problem> {
    let mut all = CustomPermissions::NONE;
    for name in names {
        let (_, permission) = CUSTOM_NAMES
            .iter()
            .find(|(known, _)| *known == name.as_str())
            .ok_or_else(|| bad("an unknown custom permission"))?;
        all = all.union(*permission);
    }
    Ok(all)
}

fn custom_names(custom: CustomPermissions) -> Vec<String> {
    CUSTOM_NAMES
        .iter()
        .filter(|(_, permission)| custom.contains(*permission))
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

fn role_from(text: &str) -> Result<SpaceRole, Problem> {
    SpaceRole::parse(text).ok_or_else(|| bad("the role must be owner, admin, custom or member"))
}

fn permission_from(text: &str) -> Result<CollectionPermission, Problem> {
    CollectionPermission::parse(text).ok_or_else(|| {
        bad("the permission must be view, view-hide-passwords, edit, edit-hide-passwords or manage")
    })
}

fn grantee_from(text: &str) -> Result<Grantee, Problem> {
    text.parse::<Grantee>().map_err(Problem::bad_request)
}

fn space_id(text: &str) -> Result<SpaceId, Problem> {
    text.parse().map_err(|_| bad("the space id isn't a UUID"))
}

fn collection_id(text: &str) -> Result<CollectionId, Problem> {
    text.parse()
        .map_err(|_| bad("the collection id isn't a UUID"))
}

fn group_id(text: &str) -> Result<GroupId, Problem> {
    text.parse().map_err(|_| bad("the group id isn't a UUID"))
}

/// A member in a path: an account id, or `me` for the caller.
fn member_ref(text: &str, me: UserId) -> Result<UserId, Problem> {
    if text == "me" {
        Ok(me)
    } else {
        text.parse().map_err(|_| bad("the member id isn't a UUID"))
    }
}

/// `{ user, sealed }`: a key sealed to one member.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UserKeyDto {
    user: Uuid,
    /// The key sealed to the member (a `kx1` sealed box), base64url.
    sealed: String,
    /// The sealer's `sig1` signature over the box (context `"key-box"`), base64url; the sealer is the
    /// signed-in account (docs/crypto.md, "Signed key boxes").
    signature: String,
}

/// `{ collection, user, sealed }`: a collection key sealed to one member.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CollectionKeyDto {
    collection: Uuid,
    user: Uuid,
    sealed: String,
    signature: String,
}

/// `{ collection, sealed }`: a collection key, in a confirmation (the member is the path's).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OwnKeyDto {
    collection: Uuid,
    sealed: String,
    signature: String,
}

fn user_keys(
    collection: CollectionId,
    keys: Vec<UserKeyDto>,
) -> Result<Vec<SealedCollectionKey>, Problem> {
    keys.into_iter()
        .map(|k| {
            Ok::<_, Problem>(SealedCollectionKey {
                collection,
                user: UserId(k.user),
                sealed: decode("sealed", &k.sealed)?,
                signature: decode("signature", &k.signature)?,
            })
        })
        .collect()
}

fn collection_keys(keys: Vec<CollectionKeyDto>) -> Result<Vec<SealedCollectionKey>, Problem> {
    keys.into_iter()
        .map(|k| {
            Ok::<_, Problem>(SealedCollectionKey {
                collection: CollectionId(k.collection),
                user: UserId(k.user),
                sealed: decode("sealed", &k.sealed)?,
                signature: decode("signature", &k.signature)?,
            })
        })
        .collect()
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpaceDto {
    id: Uuid,
    /// The name, encrypted under the space key, base64url.
    name: String,
    key_version: u32,
    /// Set while the space waits for its keys to be replaced; writes are paused.
    keys_pending_since: Option<i64>,
    created_at: i64,
}

impl SpaceDto {
    fn of(space: &Space) -> Self {
        SpaceDto {
            id: space.id.0,
            name: b64url::encode(&space.name),
            key_version: space.key_version,
            keys_pending_since: space.keys_pending_since.map(secs),
            created_at: secs(space.created_at),
        }
    }
}

/// Who sealed a key copy and their signature over the box (docs/crypto.md, "Signed key boxes").
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SealedByDto {
    account: Uuid,
    key_version: u32,
    signature: String,
}

impl SealedByDto {
    fn of(signature: &KeyBoxSignature) -> Self {
        SealedByDto {
            account: signature.by.0,
            key_version: signature.key_version,
            signature: b64url::encode(&signature.signature),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmationDto {
    by: Uuid,
    at: i64,
    fingerprint: String,
    member_key_version: u32,
    statement: String,
    signature: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberDto {
    user: Uuid,
    role: String,
    custom: Vec<String>,
    /// `invited`, `accepted`, `confirmed` or `revoked`.
    state: String,
    invited_by: Uuid,
    invited_at: i64,
    accepted_at: Option<i64>,
    /// The space key sealed to this member, base64url. Present only while confirmed.
    sealed_space_key: Option<String>,
    /// Who sealed `sealedSpaceKey` and their signature over it; null for a copy made before keys were
    /// signed and for a space with a chain.
    sealed_by: Option<SealedByDto>,
    key_version: Option<u32>,
    confirmation: Option<ConfirmationDto>,
    revoked_at: Option<i64>,
}

impl MemberDto {
    fn of(member: &Member) -> Self {
        MemberDto {
            user: member.user.0,
            role: member.role.as_str().to_owned(),
            custom: custom_names(member.custom),
            state: member.state.as_str().to_owned(),
            invited_by: member.invited_by.0,
            invited_at: secs(member.invited_at),
            accepted_at: member.accepted_at.map(secs),
            sealed_space_key: member.sealed_space_key.as_deref().map(b64url::encode),
            sealed_by: member.sealed_by.as_ref().map(SealedByDto::of),
            key_version: member.key_version,
            confirmation: member.confirmation.as_ref().map(|c| ConfirmationDto {
                by: c.by.0,
                at: secs(c.at),
                fingerprint: b64url::encode(&c.fingerprint),
                member_key_version: c.member_key_version,
                statement: b64url::encode(&c.statement),
                signature: b64url::encode(&c.signature),
            }),
            revoked_at: member.revoked_at.map(secs),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberViewDto {
    #[serde(flatten)]
    member: MemberDto,
    email: String,
    name: Option<String>,
    /// The account's public-key bundle (docs/crypto.md), base64url: what the fingerprint is of.
    public_bundle: String,
    bundle_signature: String,
    user_key_version: u32,
    /// A confirmed member whose account changed key version since: confirm them again.
    needs_reconfirmation: bool,
    /// An invited member of a Bitwarden organization who has a Bitwarden invitation, so an owner or
    /// admin can copy its link. False for a member invited through the Kemlock API alone.
    bitwarden_invitation: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CollectionDto {
    id: Uuid,
    parent: Option<Uuid>,
    /// The name, encrypted under the space key, base64url.
    name: String,
    key_version: u32,
    /// Set while the collection's key waits to be replaced; its writes are paused.
    stale_since: Option<i64>,
}

impl CollectionDto {
    fn of(collection: &Collection) -> Self {
        CollectionDto {
            id: collection.id.0,
            parent: collection.parent.map(|p| p.0),
            name: b64url::encode(&collection.name),
            key_version: collection.key_version,
            stale_since: collection.stale_since.map(secs),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupDto {
    id: Uuid,
    name: String,
    members: Vec<Uuid>,
}

impl GroupDto {
    fn of(group: &Group) -> Self {
        GroupDto {
            id: group.id.0,
            name: b64url::encode(&group.name),
            members: group.members.iter().map(|u| u.0).collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GrantDto {
    collection: Uuid,
    /// `user:<uuid>` or `group:<uuid>`.
    grantee: String,
    /// `view`, `view-hide-passwords`, `edit`, `edit-hide-passwords` or `manage`.
    permission: String,
}

impl GrantDto {
    fn of(grant: &CollectionGrant) -> Self {
        GrantDto {
            collection: grant.collection.0,
            grantee: grant.grantee.to_string(),
            permission: grant.permission.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyCopyDto {
    collection: Uuid,
    key_version: u32,
    sealed: String,
    /// Who sealed this copy and their signature over it; null for a copy made before keys were signed.
    sealed_by: Option<SealedByDto>,
}

impl KeyCopyDto {
    fn of(copy: &KeyCopy) -> Self {
        KeyCopyDto {
            collection: copy.collection.0,
            key_version: copy.key_version,
            sealed: b64url::encode(&copy.sealed),
            sealed_by: copy.sealed_by.as_ref().map(SealedByDto::of),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpaceSummaryDto {
    space: SpaceDto,
    member: MemberDto,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpaceViewDto {
    space: SpaceDto,
    me: MemberDto,
    collections: Vec<CollectionDto>,
    groups: Vec<GroupDto>,
    grants: Vec<GrantDto>,
    /// The collection keys sealed to the caller.
    collection_keys: Vec<KeyCopyDto>,
    /// Whether the space is a Bitwarden organization, so the page offers an invited member's
    /// invitation link only where it applies. Always false in the answer to a create.
    bitwarden_organization: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExposureDto {
    collection: Uuid,
    live_items: usize,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OffboardedDto {
    /// The collections the member could open: treat their items as seen.
    exposed: Vec<ExposureDto>,
    /// Whether the space now waits for its keys to be replaced.
    keys_pending: bool,
}

// ---- requests ----

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NewCollectionDto {
    id: Uuid,
    /// The name under the space key, base64url.
    name: String,
    /// The collection key sealed to the maker, base64url.
    sealed_key: String,
    /// The maker's signature over that box, base64url.
    sealed_key_signature: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateSpaceRequest {
    id: Uuid,
    name: String,
    sealed_space_key: String,
    sealed_space_key_signature: String,
    collection: NewCollectionDto,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GrantRefDto {
    collection: Uuid,
    permission: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InviteRequest {
    email: String,
    role: String,
    /// For the `custom` role: `manage-users`, `manage-groups`, `create-collections`.
    #[serde(default)]
    custom: Vec<String>,
    /// Collections the invitee is granted once confirmed.
    #[serde(default)]
    grants: Vec<GrantRefDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConfirmRequest {
    /// The 64-byte fingerprint the confirmer compared, base64url.
    fingerprint: String,
    /// What the confirmer signed, base64url: the 134 bytes of docs/crypto.md "Member confirmation".
    /// The server rebuilds them and refuses a different statement.
    statement: String,
    /// The confirmer's `sig1` signature over the statement (context `"confirm"`), base64url. The
    /// server verifies it with the key in the confirmer's bundle; 400 when it doesn't verify.
    signature: String,
    /// The space key sealed to the member, base64url.
    sealed_space_key: String,
    /// The confirmer's signature over that box, base64url.
    sealed_space_key_signature: String,
    /// The key of every collection the member is granted, sealed to them.
    #[serde(default)]
    collection_keys: Vec<OwnKeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RoleRequest {
    role: String,
    #[serde(default)]
    custom: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GranteeGrantDto {
    /// `user:<uuid>` or `group:<uuid>`.
    grantee: String,
    permission: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateCollectionRequest {
    id: Uuid,
    parent: Option<Uuid>,
    name: String,
    /// Who is granted it; the maker gets Manage when not listed.
    #[serde(default)]
    grants: Vec<GranteeGrantDto>,
    /// The collection key sealed to each confirmed grantee, the maker included.
    #[serde(default)]
    keys: Vec<UserKeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EditCollectionRequest {
    name: Option<String>,
    /// Nests the collection under this one.
    parent: Option<Uuid>,
    /// Moves the collection to the top level.
    #[serde(default)]
    move_to_top: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateGroupRequest {
    id: Uuid,
    name: String,
    #[serde(default)]
    members: Vec<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EditGroupRequest {
    name: Option<String>,
    /// The group's whole new member list.
    members: Option<Vec<Uuid>>,
    /// The keys the new members need for the collections the group is granted.
    #[serde(default)]
    keys: Vec<CollectionKeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GrantRequest {
    collection: Uuid,
    /// `user:<uuid>` or `group:<uuid>`.
    grantee: String,
    permission: String,
    /// The collection key sealed to each confirmed member the grant newly reaches.
    #[serde(default)]
    keys: Vec<UserKeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NamedDto {
    id: Uuid,
    name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RekeyDto {
    collection: Uuid,
    key_version: u32,
    keys: Vec<UserKeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReplacementWriteDto {
    collection: Uuid,
    /// The revision being replaced; the item is written as the next one.
    expected_revision: u64,
    item: ItemDto,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KeyReplacementRequest {
    /// The space key's version after the replacement: the current plus one when the space key is
    /// replaced, the current when only collection keys are.
    space_key_version: u32,
    space_name: Option<String>,
    #[serde(default)]
    sealed_space_keys: Vec<UserKeyDto>,
    #[serde(default)]
    collection_names: Vec<NamedDto>,
    #[serde(default)]
    group_names: Vec<NamedDto>,
    #[serde(default)]
    collections: Vec<RekeyDto>,
    #[serde(default)]
    writes: Vec<ReplacementWriteDto>,
}

/// One member's keys sealed again (`POST .../reseal`).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResealMemberDto {
    user: Uuid,
    /// The current space key sealed to the member, base64url.
    sealed_space_key: String,
    /// The sealer's signature over that box, base64url.
    sealed_space_key_signature: String,
    /// The current key of each collection the member already holds a copy of, sealed to them.
    #[serde(default)]
    collection_keys: Vec<OwnKeyDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResealRequest {
    members: Vec<ResealMemberDto>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResealedDto {
    /// How many members got new boxes.
    resealed: usize,
}

// ---- the use cases over this router's state ----

impl<S, P, K, R> Env<S, P, K, R>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    fn key_boxes(&self) -> StoreKeyBoxes<S> {
        StoreKeyBoxes {
            users: self.api.store.clone(),
        }
    }

    fn create_space(&self) -> CreateSpace<R, S, P, StoreKeyBoxes<S>> {
        CreateSpace {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
            boxes: self.key_boxes(),
        }
    }

    fn invite(&self) -> InviteMember<R, S, S, P> {
        InviteMember {
            spaces: self.spaces.clone(),
            users: self.api.store.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn accept(&self) -> AcceptInvitation<R, S, P> {
        AcceptInvitation {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn confirm(&self) -> ConfirmMember<R, S, CryptoFingerprints, S, P, StoreKeyBoxes<S>> {
        ConfirmMember {
            spaces: self.spaces.clone(),
            users: self.api.store.clone(),
            fingerprints: CryptoFingerprints,
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
            boxes: self.key_boxes(),
        }
    }

    fn change_role(&self) -> ChangeRole<R, S, P> {
        ChangeRole {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn offboard(&self) -> Offboard<R, S, P> {
        Offboard {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn create_collection(&self) -> CreateCollection<R, S, P, StoreKeyBoxes<S>> {
        CreateCollection {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
            boxes: self.key_boxes(),
        }
    }

    fn edit_collection(&self) -> EditCollection<R, S, P> {
        EditCollection {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn delete_collection(&self) -> DeleteCollection<R, S, P> {
        DeleteCollection {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn create_group(&self) -> CreateGroup<R, S, P> {
        CreateGroup {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn edit_group(&self) -> EditGroup<R, S, P, StoreKeyBoxes<S>> {
        EditGroup {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
            boxes: self.key_boxes(),
        }
    }

    fn delete_group(&self) -> DeleteGroup<R, S, P> {
        DeleteGroup {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn grant(&self) -> GrantAccess<R, S, P, StoreKeyBoxes<S>> {
        GrantAccess {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
            boxes: self.key_boxes(),
        }
    }

    fn revoke_grant(&self) -> RevokeGrant<R, S, P> {
        RevokeGrant {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
        }
    }

    fn reseal(&self) -> ResealKeys<R, S, P, StoreKeyBoxes<S>> {
        ResealKeys {
            spaces: self.spaces.clone(),
            events: self.api.store.clone(),
            clock: self.api.crypto.clone(),
            boxes: self.key_boxes(),
        }
    }

    fn replace_keys(&self) -> ReplaceKeys<R, S, S, S, crate::LiveHub, P, StoreKeyBoxes<S>> {
        ReplaceKeys {
            spaces: self.spaces.clone(),
            items: self.api.store.clone(),
            tags: self.api.store.clone(),
            events: self.api.store.clone(),
            push: self.api.hub.clone(),
            clock: self.api.crypto.clone(),
            config: self.api.auth_config(),
            boxes: self.key_boxes(),
        }
    }
}

// ---- handlers ----

type Created<T> = Result<(StatusCode, Json<T>), Problem>;

async fn list_spaces<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
) -> Result<Json<Vec<SpaceSummaryDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let list = ListSpaces {
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor())
    .await?;
    Ok(Json(
        list.iter()
            .map(|s| SpaceSummaryDto {
                space: SpaceDto::of(&s.space),
                member: MemberDto::of(&s.member),
            })
            .collect(),
    ))
}

async fn create_space<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    body: Body,
) -> Created<SpaceViewDto>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: CreateSpaceRequest = body.json()?;
    let input = CreateSpaceInput {
        id: SpaceId(request.id),
        name: decode("name", &request.name)?,
        sealed_space_key: decode("sealedSpaceKey", &request.sealed_space_key)?,
        space_key_signature: decode(
            "sealedSpaceKeySignature",
            &request.sealed_space_key_signature,
        )?,
        collection: NewCollection {
            id: CollectionId(request.collection.id),
            name: decode("collection.name", &request.collection.name)?,
            sealed_key: decode("collection.sealedKey", &request.collection.sealed_key)?,
            key_signature: decode(
                "collection.sealedKeySignature",
                &request.collection.sealed_key_signature,
            )?,
        },
    };
    let actor = caller.actor();
    let state = env.create_space().execute(&actor, input).await?;
    let me = state
        .member(actor.user)
        .map(MemberDto::of)
        .ok_or_else(|| bad("the maker is missing from the new space"))?;
    let keys = env
        .spaces
        .key_copies(state.space.id, actor.user)
        .await
        .map_err(SpacesError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(SpaceViewDto {
            space: SpaceDto::of(&state.space),
            me,
            collections: state.collections.iter().map(CollectionDto::of).collect(),
            groups: Vec::new(),
            grants: state.grants.iter().map(GrantDto::of).collect(),
            collection_keys: keys.iter().map(KeyCopyDto::of).collect(),
            bitwarden_organization: false,
        }),
    ))
}

async fn get_space<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Json<SpaceViewDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let view = GetSpace {
        spaces: env.spaces.clone(),
    }
    .execute(&caller.actor(), space_id(&id)?)
    .await?;
    Ok(Json(SpaceViewDto {
        space: SpaceDto::of(&view.space),
        me: MemberDto::of(&view.me),
        collections: view.collections.iter().map(CollectionDto::of).collect(),
        groups: view.groups.iter().map(GroupDto::of).collect(),
        grants: view.grants.iter().map(GrantDto::of).collect(),
        collection_keys: view.collection_keys.iter().map(KeyCopyDto::of).collect(),
        bitwarden_organization: false,
    }))
}

/// `GET /kem/v1/spaces/{id}`: the space as its member sees it, and whether it is a Bitwarden
/// organization (the Bitwarden API's side of the space, read through the request extension; a
/// server without it says no).
async fn get_space_view<S, P, K, R>(
    state: State<Env<S, P, K, R>>,
    caller: Caller,
    links: MaybeInviteLinks,
    Path(id): Path<String>,
) -> Result<Json<SpaceViewDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let Json(mut view) = get_space(state, caller, Path(id)).await?;
    if let Some(links) = links.0 {
        view.bitwarden_organization = links.is_organization(space).await;
    }
    Ok(Json(view))
}

async fn list_collections<S, P, K, R>(
    state: State<Env<S, P, K, R>>,
    caller: Caller,
    path: Path<String>,
) -> Result<Json<Vec<CollectionDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let Json(view) = get_space(state, caller, path).await?;
    Ok(Json(view.collections))
}

async fn list_groups<S, P, K, R>(
    state: State<Env<S, P, K, R>>,
    caller: Caller,
    path: Path<String>,
) -> Result<Json<Vec<GroupDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let Json(view) = get_space(state, caller, path).await?;
    Ok(Json(view.groups))
}

async fn list_grants<S, P, K, R>(
    state: State<Env<S, P, K, R>>,
    caller: Caller,
    path: Path<String>,
) -> Result<Json<Vec<GrantDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let Json(view) = get_space(state, caller, path).await?;
    Ok(Json(view.grants))
}

async fn list_members<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    links: MaybeInviteLinks,
    Path(id): Path<String>,
) -> Result<Json<Vec<MemberViewDto>>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let space = space_id(&id)?;
    let views = ListMembers {
        spaces: env.spaces.clone(),
        users: env.api.store.clone(),
    }
    .execute(&caller.actor(), space)
    .await?;
    // Who has a Bitwarden invitation to copy the link of: none on a server without the
    // Bitwarden API, and none in a space that is not one of its organizations.
    let pending = match links.0 {
        Some(links) => links.pending_invitations(space).await.unwrap_or_default(),
        None => Vec::new(),
    };
    Ok(Json(
        views
            .iter()
            .map(|v| MemberViewDto {
                member: MemberDto::of(&v.member),
                email: v.email.clone(),
                name: v.name.clone(),
                public_bundle: b64url::encode(&v.public_bundle),
                bundle_signature: b64url::encode(&v.bundle_signature),
                user_key_version: v.user_key_version,
                needs_reconfirmation: v.needs_reconfirmation,
                bitwarden_invitation: pending.contains(&v.member.user),
            })
            .collect(),
    ))
}

/// `?email=`: the account to look up.
#[derive(Debug, Deserialize)]
struct LookupQuery {
    email: String,
}

/// The account an admin may invite.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountLookupDto {
    /// The account's id, hyphenated.
    account: String,
    /// The account's signed public-key bundle, base64url: what the chain's `create` and `invite`
    /// records carry, and what the fingerprint is made of.
    bundle: String,
    /// The account's signature over its bundle, base64url, so the inviter can check it first.
    bundle_signature: String,
    /// The account's key version.
    key_version: u32,
}

/// `GET /kem/v1/spaces/{id}/lookup?email=`: the account an admin may invite, for the chain's `invite`
/// record.
///
/// This tells anyone who manages users in some space whether an email has an account, and anyone
/// signed in can make a space and so manage its users. That is inherent to inviting by email: the
/// inviter needs the invitee's id and key bundle, and the server can't say "no account" any other
/// way. What limits it: the caller must manage users of the space (checked before the email is
/// looked at), it is limited per caller (`Limits::lookup`, 10 in 10 minutes with doubling delays),
/// and an account with no published keys reads as absent.
async fn lookup_account<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    query: Result<Query<LookupQuery>, QueryRejection>,
) -> Result<Json<AccountLookupDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let Query(query) = query.map_err(|e| Problem::bad_request(e.body_text()))?;
    let actor = caller.actor();
    guard(
        &env.api.limits.lookup,
        &format!("lookup:{}", actor.user),
        env.api.now(),
    )?;
    let found = LookupAccount {
        spaces: env.spaces.clone(),
        users: env.api.store.clone(),
    }
    .execute(&actor, space_id(&id)?, &query.email)
    .await?
    .ok_or_else(|| {
        Problem::new(
            StatusCode::NOT_FOUND,
            "no-account",
            "There is no account with that email",
        )
    })?;
    Ok(Json(AccountLookupDto {
        account: found.account.to_string(),
        bundle: b64url::encode(&found.public_bundle),
        bundle_signature: b64url::encode(&found.bundle_signature),
        key_version: found.key_version,
    }))
}

async fn invite_member<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Created<MemberDto>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: InviteRequest = body.json()?;
    let grants = request
        .grants
        .iter()
        .map(|g| Ok::<_, Problem>((CollectionId(g.collection), permission_from(&g.permission)?)))
        .collect::<Result<Vec<_>, Problem>>()?;
    let input = InviteInput {
        email: request.email,
        role: role_from(&request.role)?,
        custom: custom_from(&request.custom)?,
        grants,
    };
    let space = space_id(&id)?;
    let actor = caller.actor();
    let member = env.invite().execute(&actor, space, input).await?;
    mail_invitations(&env, actor.user, &[member.user], space).await;
    Ok((StatusCode::CREATED, Json(MemberDto::of(&member))))
}

/// Mails each of `invitees` that `inviter` invited them to `space`. The mail names the inviter by
/// their email and nothing sealed: the server can't read the space's name, so it says "a shared
/// space". It carries the link to sign in and accept. Each mail goes from a task of its own, so
/// the invitation doesn't wait for SMTP; an account that can't be read is skipped.
pub(crate) async fn mail_invitations<S, P, K, R>(
    env: &Env<S, P, K, R>,
    inviter: UserId,
    invitees: &[UserId],
    space: SpaceId,
) where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let inviter = match UserRepo::by_id(&env.api.store, inviter).await {
        Ok(user) => user.map(|u| u.email.as_str().to_owned()),
        Err(error) => {
            tracing::warn!(%error, "couldn't read the inviter's email");
            None
        }
    };
    for invitee in invitees {
        let to = match UserRepo::by_id(&env.api.store, *invitee).await {
            Ok(Some(user)) => user.email,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%error, "couldn't read an invitee's email");
                continue;
            }
        };
        let notices = env.api.hub.notices();
        let notice = InvitationNotice {
            to,
            space: None,
            inviter: inviter.clone(),
            space_id: Some(space),
        };
        tokio::spawn(async move {
            notices.send(Notice::Invitation(notice)).await;
        });
    }
}

/// `POST /kem/v1/spaces/{id}/members/{user}/resend`: mails an invitee their invitation again.
/// Only for a member who is still invited, by someone who manages users, and at most once in 10
/// minutes per member (429 with `Retry-After` otherwise). Refused requests don't use the turn.
async fn resend_invitation<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let actor = caller.actor();
    let space = space_id(&id)?;
    let target = member_ref(&user, actor.user)?;
    ResendInvitation {
        spaces: env.spaces.clone(),
    }
    .execute(&actor, space, target)
    .await?;
    let turn = format!("{space}/{target}");
    if !matches!(
        env.api
            .resent_invitations
            .insert(turn.as_bytes(), env.api.now()),
        Ok(true)
    ) {
        return Err(rate_limited(RESEND_WINDOW_SECS.unsigned_abs()));
    }
    mail_invitations(&env, actor.user, &[target], space).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn accept_invitation<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<Json<MemberDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let actor = caller.actor();
    // Only the invitee accepts, for themselves.
    if member_ref(&user, actor.user)? != actor.user {
        return Err(
            Problem::new(StatusCode::FORBIDDEN, "forbidden", "This isn't allowed")
                .detail("only the invited person accepts an invitation"),
        );
    }
    let member = env.accept().execute(&actor, space_id(&id)?).await?;
    Ok(Json(MemberDto::of(&member)))
}

async fn confirm_member<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
    body: Body,
) -> Result<Json<MemberDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: ConfirmRequest = body.json()?;
    let actor = caller.actor();
    let member = member_ref(&user, actor.user)?;
    let collection_keys = request
        .collection_keys
        .into_iter()
        .map(|k| {
            Ok::<_, Problem>(SealedCollectionKey {
                collection: CollectionId(k.collection),
                user: member,
                sealed: decode("sealed", &k.sealed)?,
                signature: decode("signature", &k.signature)?,
            })
        })
        .collect::<Result<Vec<_>, Problem>>()?;
    let input = ConfirmInput {
        fingerprint: decode("fingerprint", &request.fingerprint)?,
        statement: decode("statement", &request.statement)?,
        signature: decode("signature", &request.signature)?,
        sealed_space_key: decode("sealedSpaceKey", &request.sealed_space_key)?,
        space_key_signature: decode(
            "sealedSpaceKeySignature",
            &request.sealed_space_key_signature,
        )?,
        collection_keys,
    };
    let confirmed = env
        .confirm()
        .execute(&actor, space_id(&id)?, member, input)
        .await?;
    Ok(Json(MemberDto::of(&confirmed)))
}

async fn change_role<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
    body: Body,
) -> Result<Json<MemberDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: RoleRequest = body.json()?;
    let actor = caller.actor();
    let member = env
        .change_role()
        .execute(
            &actor,
            space_id(&id)?,
            member_ref(&user, actor.user)?,
            role_from(&request.role)?,
            custom_from(&request.custom)?,
        )
        .await?;
    Ok(Json(MemberDto::of(&member)))
}

fn offboarded(outcome: &kemlock_app::spaces::Offboarded) -> OffboardedDto {
    OffboardedDto {
        exposed: outcome
            .exposed
            .iter()
            .map(|e| ExposureDto {
                collection: e.collection.0,
                live_items: e.live_items,
            })
            .collect(),
        keys_pending: outcome.keys_pending,
    }
}

async fn revoke_member<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<Json<OffboardedDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let actor = caller.actor();
    let outcome = env
        .offboard()
        .revoke(&actor, space_id(&id)?, member_ref(&user, actor.user)?)
        .await?;
    Ok(Json(offboarded(&outcome)))
}

async fn restore_member<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<Json<MemberDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let actor = caller.actor();
    let member = env
        .offboard()
        .restore(&actor, space_id(&id)?, member_ref(&user, actor.user)?)
        .await?;
    Ok(Json(MemberDto::of(&member)))
}

async fn remove_member<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, user)): Path<(String, String)>,
) -> Result<Json<OffboardedDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let actor = caller.actor();
    let outcome = env
        .offboard()
        .remove(&actor, space_id(&id)?, member_ref(&user, actor.user)?)
        .await?;
    Ok(Json(offboarded(&outcome)))
}

async fn create_collection<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Created<CollectionDto>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: CreateCollectionRequest = body.json()?;
    let collection = CollectionId(request.id);
    let grants = request
        .grants
        .iter()
        .map(|g| Ok::<_, Problem>((grantee_from(&g.grantee)?, permission_from(&g.permission)?)))
        .collect::<Result<Vec<_>, Problem>>()?;
    let input = CreateCollectionInput {
        id: collection,
        parent: request.parent.map(CollectionId),
        name: decode("name", &request.name)?,
        grants,
        keys: user_keys(collection, request.keys)?,
    };
    let made = env
        .create_collection()
        .execute(&caller.actor(), space_id(&id)?, input)
        .await?;
    Ok((StatusCode::CREATED, Json(CollectionDto::of(&made))))
}

async fn edit_collection<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, collection)): Path<(String, String)>,
    body: Body,
) -> Result<Json<CollectionDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: EditCollectionRequest = body.json()?;
    let parent = match (request.move_to_top, request.parent) {
        (true, None) => Some(None),
        (true, Some(_)) => return Err(bad("send parent or moveToTop, not both")),
        (false, Some(parent)) => Some(Some(CollectionId(parent))),
        (false, None) => None,
    };
    let input = EditCollectionInput {
        name: request
            .name
            .as_deref()
            .map(|n| decode("name", n))
            .transpose()?,
        parent,
    };
    let edited = env
        .edit_collection()
        .execute(
            &caller.actor(),
            space_id(&id)?,
            collection_id(&collection)?,
            input,
        )
        .await?;
    Ok(Json(CollectionDto::of(&edited)))
}

async fn delete_collection<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, collection)): Path<(String, String)>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    env.delete_collection()
        .execute(&caller.actor(), space_id(&id)?, collection_id(&collection)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_group<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Created<GroupDto>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: CreateGroupRequest = body.json()?;
    let input = CreateGroupInput {
        id: GroupId(request.id),
        name: decode("name", &request.name)?,
        members: request.members.into_iter().map(UserId).collect(),
    };
    let group = env
        .create_group()
        .execute(&caller.actor(), space_id(&id)?, input)
        .await?;
    Ok((StatusCode::CREATED, Json(GroupDto::of(&group))))
}

async fn edit_group<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, group)): Path<(String, String)>,
    body: Body,
) -> Result<Json<GroupDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: EditGroupRequest = body.json()?;
    let input = EditGroupInput {
        name: request
            .name
            .as_deref()
            .map(|n| decode("name", n))
            .transpose()?,
        members: request.members.map(|m| m.into_iter().map(UserId).collect()),
        keys: collection_keys(request.keys)?,
    };
    let edited = env
        .edit_group()
        .execute(&caller.actor(), space_id(&id)?, group_id(&group)?, input)
        .await?;
    Ok(Json(GroupDto::of(&edited)))
}

async fn delete_group<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, group)): Path<(String, String)>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    env.delete_group()
        .execute(&caller.actor(), space_id(&id)?, group_id(&group)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn grant_access<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Result<Json<GrantDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: GrantRequest = body.json()?;
    let collection = CollectionId(request.collection);
    let grant = env
        .grant()
        .execute(
            &caller.actor(),
            space_id(&id)?,
            collection,
            grantee_from(&request.grantee)?,
            permission_from(&request.permission)?,
            user_keys(collection, request.keys)?,
        )
        .await?;
    Ok(Json(GrantDto::of(&grant)))
}

async fn revoke_grant<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path((id, collection, grantee)): Path<(String, String, String)>,
) -> Result<StatusCode, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    env.revoke_grant()
        .execute(
            &caller.actor(),
            space_id(&id)?,
            collection_id(&collection)?,
            grantee_from(&grantee)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reseal_keys<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Result<Json<ResealedDto>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: ResealRequest = body.json()?;
    let members = request
        .members
        .into_iter()
        .map(|m| {
            let user = UserId(m.user);
            let collection_keys = m
                .collection_keys
                .into_iter()
                .map(|k| {
                    Ok::<_, Problem>(SealedCollectionKey {
                        collection: CollectionId(k.collection),
                        user,
                        sealed: decode("sealed", &k.sealed)?,
                        signature: decode("signature", &k.signature)?,
                    })
                })
                .collect::<Result<Vec<_>, Problem>>()?;
            Ok::<_, Problem>(ResealMember {
                user,
                sealed_space_key: decode("sealedSpaceKey", &m.sealed_space_key)?,
                space_key_signature: decode(
                    "sealedSpaceKeySignature",
                    &m.sealed_space_key_signature,
                )?,
                collection_keys,
            })
        })
        .collect::<Result<Vec<_>, Problem>>()?;
    let resealed = env
        .reseal()
        .execute(&caller.actor(), space_id(&id)?, members)
        .await?;
    Ok(Json(ResealedDto { resealed }))
}

async fn replace_keys<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    caller: Caller,
    Path(id): Path<String>,
    body: Body,
) -> Result<Json<BatchResponse>, Problem>
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let request: KeyReplacementRequest = body.json()?;
    let named = |list: Vec<NamedDto>| -> Result<Vec<(Uuid, Vec<u8>)>, Problem> {
        list.into_iter()
            .map(|n| Ok::<_, Problem>((n.id, decode("name", &n.name)?)))
            .collect()
    };
    let mut collections = Vec::with_capacity(request.collections.len());
    for rekey in request.collections {
        let collection = CollectionId(rekey.collection);
        collections.push(CollectionRekey {
            collection,
            key_version: rekey.key_version,
            keys: user_keys(collection, rekey.keys)?,
        });
    }
    let writes = request
        .writes
        .into_iter()
        .map(|w| {
            let write: ItemWrite = w.item.into_write(Some(Revision(w.expected_revision)))?;
            Ok::<_, Problem>((CollectionId(w.collection), write))
        })
        .collect::<Result<Vec<_>, Problem>>()?;
    let input = ReplacementInput {
        space_key_version: request.space_key_version,
        space_name: request
            .space_name
            .as_deref()
            .map(|n| decode("spaceName", n))
            .transpose()?,
        sealed_space_keys: request
            .sealed_space_keys
            .into_iter()
            .map(|k| {
                Ok::<_, Problem>(SealedSpaceKey {
                    user: UserId(k.user),
                    sealed: decode("sealed", &k.sealed)?,
                    signature: decode("signature", &k.signature)?,
                })
            })
            .collect::<Result<Vec<_>, Problem>>()?,
        collection_names: named(request.collection_names)?
            .into_iter()
            .map(|(id, name)| (CollectionId(id), name))
            .collect(),
        group_names: named(request.group_names)?
            .into_iter()
            .map(|(id, name)| (GroupId(id), name))
            .collect(),
        collections,
        writes,
    };
    let stored = env
        .replace_keys()
        .execute(&caller.actor(), space_id(&id)?, input)
        .await?;
    Ok(Json(BatchResponse {
        items: stored.iter().map(ItemDto::from_item).collect(),
    }))
}

// ---- the router ----

/// Every response carries the current DPoP nonce, as the main router's do.
pub(crate) async fn nonce_header<S, P, K, R>(
    State(env): State<Env<S, P, K, R>>,
    request: Request,
    next: Next,
) -> Response
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&env.api.dpop.current_nonce(env.api.now())) {
        response.headers_mut().insert(DPOP_NONCE, value);
    }
    response
}

/// The routes of `/kem/v1/spaces`. Merge it beside [`crate::router`]; it has no fallback.
///
/// ```text
/// GET, POST  /kem/v1/spaces                                       list mine, make one
/// GET        /kem/v1/spaces/{id}                                  one space as its member sees it
/// GET, POST  /kem/v1/spaces/{id}/members                          list, invite
/// GET        /kem/v1/spaces/{id}/lookup?email=                    find an account to invite
/// POST       /kem/v1/spaces/{id}/members/{user}/accept            accept (user is `me`)
/// POST       /kem/v1/spaces/{id}/members/{user}/resend            mail an invitation again (once in 10 minutes)
/// POST       /kem/v1/spaces/{id}/members/{user}/confirm           confirm with a fingerprint
/// PUT        /kem/v1/spaces/{id}/members/{user}/role              change a role
/// POST       /kem/v1/spaces/{id}/members/{user}/revoke            revoke (keys must be replaced)
/// POST       /kem/v1/spaces/{id}/members/{user}/restore           restore a revoked member
/// DELETE     /kem/v1/spaces/{id}/members/{user}                   remove, or leave with `me`
/// GET, POST  /kem/v1/spaces/{id}/collections                      list, make
/// PUT, DELETE /kem/v1/spaces/{id}/collections/{collection}        rename or move, delete
/// GET, POST  /kem/v1/spaces/{id}/groups                           list, make
/// PUT, DELETE /kem/v1/spaces/{id}/groups/{group}                  change, delete
/// GET, PUT   /kem/v1/spaces/{id}/grants                           list, grant
/// DELETE     /kem/v1/spaces/{id}/grants/{collection}/{grantee}    revoke a grant
/// POST       /kem/v1/spaces/{id}/key-replacement                  land new keys and re-wrapped items
/// POST       /kem/v1/spaces/{id}/reseal                           seal the current keys again, signed
/// ```
pub fn router<S, P, K, R>(api: Api<S, P, K>, spaces: R) -> Router
where
    S: Store,
    P: Crypto,
    K: TokenSigner + Clone + 'static,
    R: SpaceRepo + Clone + 'static,
{
    let env = Env { api, spaces };
    Router::new()
        .route(
            "/kem/v1/spaces",
            get(list_spaces::<S, P, K, R>).post(create_space::<S, P, K, R>),
        )
        .route("/kem/v1/spaces/{id}", get(get_space_view::<S, P, K, R>))
        .route(
            "/kem/v1/spaces/{id}/members",
            get(list_members::<S, P, K, R>).post(invite_member::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/lookup",
            get(lookup_account::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}/accept",
            post(accept_invitation::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}/resend",
            post(resend_invitation::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}/confirm",
            post(confirm_member::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}/role",
            put(change_role::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}/revoke",
            post(revoke_member::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}/restore",
            post(restore_member::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/members/{user}",
            delete(remove_member::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/collections",
            get(list_collections::<S, P, K, R>).post(create_collection::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/collections/{collection}",
            put(edit_collection::<S, P, K, R>).delete(delete_collection::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/groups",
            get(list_groups::<S, P, K, R>).post(create_group::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/groups/{group}",
            put(edit_group::<S, P, K, R>).delete(delete_group::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/grants",
            get(list_grants::<S, P, K, R>).put(grant_access::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/grants/{collection}/{grantee}",
            delete(revoke_grant::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/key-replacement",
            post(replace_keys::<S, P, K, R>),
        )
        .route(
            "/kem/v1/spaces/{id}/reseal",
            post(reseal_keys::<S, P, K, R>),
        )
        .layer(middleware::from_fn_with_state(
            env.clone(),
            nonce_header::<S, P, K, R>,
        ))
        .with_state(env)
}

// ---- OpenAPI ----

#[utoipa::path(
    get, path = "/kem/v1/spaces", tag = "spaces",
    security(("dpop" = [])),
    responses((status = 200, description = "The spaces the account is in or invited to", body = Vec<SpaceSummaryDto>))
)]
#[allow(dead_code)]
fn doc_list_spaces() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces", tag = "spaces",
    security(("dpop" = [])),
    request_body = CreateSpaceRequest,
    responses(
        (status = 201, description = "The space, with the maker as its confirmed owner", body = SpaceViewDto),
        (status = 409, description = "The space id is taken"),
    )
)]
#[allow(dead_code)]
fn doc_create_space() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses(
        (status = 200, description = "The space as its member sees it. `bitwardenOrganization` says whether it is a Bitwarden organization, so the page offers an invited member's invitation link (`.../members/{user}/invite-link`) only there", body = SpaceViewDto),
        (status = 404, description = "No such space, or the caller isn't in it"),
    )
)]
#[allow(dead_code)]
fn doc_get_space() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/members", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "The members the caller's role may see. `bitwardenInvitation` is true for an invited member of a Bitwarden organization who has a Bitwarden invitation, whose link `.../members/{user}/invite-link` can be copied", body = Vec<MemberViewDto>))
)]
#[allow(dead_code)]
fn doc_list_members() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/lookup", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("email" = String, Query, description = "The email of the account to invite"),
    ),
    responses(
        (status = 200, description = "The account's id and signed public-key bundle", body = AccountLookupDto),
        (status = 403, description = "The caller is a member of the space but not an owner, an admin or a Custom member with Manage users"),
        (status = 404, description = "No account has that email (`no-account`), or no such space, or the caller isn't a confirmed member of it"),
        (status = 429, description = "The caller looked up too many emails; slow down"),
    )
)]
#[allow(dead_code)]
fn doc_lookup() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/members", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = InviteRequest,
    responses(
        (status = 201, description = "Invited; nothing is sealed to them yet", body = MemberDto),
        (status = 403, description = "The caller's role can't invite that role"),
    )
)]
#[allow(dead_code)]
fn doc_invite() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/members/{user}/resend", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "The space's UUID"),
        ("user" = String, Path, description = "The invited member's account UUID"),
    ),
    responses(
        (status = 204, description = "The invitation notice was sent again"),
        (status = 403, description = "The caller doesn't manage users, or may not manage this member"),
        (status = 404, description = "No such space, or the caller isn't a confirmed member"),
        (status = 409, description = "The person isn't in the space, or isn't invited any more: they accepted, are confirmed or were revoked"),
        (status = 429, description = "This member's invitation was sent again in the last 10 minutes; `Retry-After` is at most 600 seconds"),
    )
)]
#[allow(dead_code)]
fn doc_resend() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/members/{user}/accept", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("user" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "The invitation is accepted; the member waits to be confirmed", body = MemberDto))
)]
#[allow(dead_code)]
fn doc_accept() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/members/{user}/confirm", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("user" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = ConfirmRequest,
    responses(
        (status = 200, description = "Confirmed, with the signed statement kept", body = MemberDto),
        (status = 422, description = "The fingerprint is not the one of the member's bundle"),
        (status = 423, description = "The space waits for its keys to be replaced"),
    )
)]
#[allow(dead_code)]
fn doc_confirm() {}

#[utoipa::path(
    put, path = "/kem/v1/spaces/{id}/members/{user}/role", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("user" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = RoleRequest,
    responses(
        (status = 200, description = "The member with their new role", body = MemberDto),
        (status = 403, description = "Only an owner makes an owner"),
        (status = 409, description = "The new owner isn't confirmed, or this is the last owner"),
    )
)]
#[allow(dead_code)]
fn doc_role() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/members/{user}/revoke", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("user" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "Revoked; the keys they held must be replaced", body = OffboardedDto))
)]
#[allow(dead_code)]
fn doc_revoke() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/members/{user}/restore", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("user" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "Restored as accepted; confirm them again", body = MemberDto))
)]
#[allow(dead_code)]
fn doc_restore() {}

#[utoipa::path(
    delete, path = "/kem/v1/spaces/{id}/members/{user}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("user" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "Removed, or left", body = OffboardedDto))
)]
#[allow(dead_code)]
fn doc_remove() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/collections", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "The collections the caller may see", body = Vec<CollectionDto>))
)]
#[allow(dead_code)]
fn doc_list_collections() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/collections", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = CreateCollectionRequest,
    responses((status = 201, description = "The collection, with keys sealed to each grantee", body = CollectionDto))
)]
#[allow(dead_code)]
fn doc_create_collection() {}

#[utoipa::path(
    put, path = "/kem/v1/spaces/{id}/collections/{collection}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("collection" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = EditCollectionRequest,
    responses((status = 200, description = "Renamed or moved", body = CollectionDto))
)]
#[allow(dead_code)]
fn doc_edit_collection() {}

#[utoipa::path(
    delete, path = "/kem/v1/spaces/{id}/collections/{collection}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("collection" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 204, description = "Deleted: it was empty and had no nested collections"))
)]
#[allow(dead_code)]
fn doc_delete_collection() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/groups", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "The groups the caller may see", body = Vec<GroupDto>))
)]
#[allow(dead_code)]
fn doc_list_groups() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/groups", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = CreateGroupRequest,
    responses((status = 201, description = "The group", body = GroupDto))
)]
#[allow(dead_code)]
fn doc_create_group() {}

#[utoipa::path(
    put, path = "/kem/v1/spaces/{id}/groups/{group}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("group" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = EditGroupRequest,
    responses((status = 200, description = "Renamed or given new members, with the keys they need", body = GroupDto))
)]
#[allow(dead_code)]
fn doc_edit_group() {}

#[utoipa::path(
    delete, path = "/kem/v1/spaces/{id}/groups/{group}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("group" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 204, description = "Deleted, with the grants made to it"))
)]
#[allow(dead_code)]
fn doc_delete_group() {}

#[utoipa::path(
    get, path = "/kem/v1/spaces/{id}/grants", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 200, description = "The grants on the collections the caller may see", body = Vec<GrantDto>))
)]
#[allow(dead_code)]
fn doc_list_grants() {}

#[utoipa::path(
    put, path = "/kem/v1/spaces/{id}/grants", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = GrantRequest,
    responses((status = 200, description = "The grant, with the key sealed to each member it newly reaches", body = GrantDto))
)]
#[allow(dead_code)]
fn doc_grant() {}

#[utoipa::path(
    delete, path = "/kem/v1/spaces/{id}/grants/{collection}/{grantee}", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("collection" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
        ("grantee" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    responses((status = 204, description = "The grant is gone; keys the member held must be replaced"))
)]
#[allow(dead_code)]
fn doc_revoke_grant() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/key-replacement", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID, or `me` for the caller where a member is meant"),
    ),
    request_body = KeyReplacementRequest,
    responses(
        (status = 200, description = "New keys, names and re-wrapped items landed as one transaction", body = BatchResponse),
        (status = 400, description = "The replacement is incomplete"),
    )
)]
#[allow(dead_code)]
fn doc_key_replacement() {}

#[utoipa::path(
    post, path = "/kem/v1/spaces/{id}/reseal", tag = "spaces",
    security(("dpop" = [])),
    params(
        ("id" = String, Path, description = "A UUID"),
    ),
    request_body = ResealRequest,
    responses(
        (status = 200, description = "The listed members hold the current keys in boxes signed by the caller", body = ResealedDto),
        (status = 400, description = "A box or its signature isn't what the server rebuilds"),
        (status = 403, description = "Only an owner or admin re-seals keys"),
        (status = 409, description = "The space has a chain"),
        (status = 423, description = "The space waits for its keys to be replaced"),
    )
)]
#[allow(dead_code)]
fn doc_reseal() {}

/// The OpenAPI paths and schemas of the spaces routes, for merging into the main document.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        doc_list_spaces,
        doc_create_space,
        doc_get_space,
        doc_list_members,
        doc_lookup,
        doc_invite,
        doc_resend,
        doc_accept,
        doc_confirm,
        doc_role,
        doc_revoke,
        doc_restore,
        doc_remove,
        doc_list_collections,
        doc_create_collection,
        doc_edit_collection,
        doc_delete_collection,
        doc_list_groups,
        doc_create_group,
        doc_edit_group,
        doc_delete_group,
        doc_list_grants,
        doc_grant,
        doc_revoke_grant,
        doc_key_replacement,
        doc_reseal
    ),
    components(schemas(
        SpaceDto,
        MemberDto,
        SealedByDto,
        ConfirmationDto,
        MemberViewDto,
        AccountLookupDto,
        CollectionDto,
        GroupDto,
        GrantDto,
        KeyCopyDto,
        SpaceSummaryDto,
        SpaceViewDto,
        ExposureDto,
        OffboardedDto,
        NewCollectionDto,
        CreateSpaceRequest,
        GrantRefDto,
        InviteRequest,
        ConfirmRequest,
        OwnKeyDto,
        RoleRequest,
        GranteeGrantDto,
        UserKeyDto,
        CollectionKeyDto,
        CreateCollectionRequest,
        EditCollectionRequest,
        CreateGroupRequest,
        EditGroupRequest,
        GrantRequest,
        NamedDto,
        RekeyDto,
        ReplacementWriteDto,
        KeyReplacementRequest,
        ResealMemberDto,
        ResealRequest,
        ResealedDto
    ))
)]
struct SpacesDoc;

/// The OpenAPI document of the spaces routes alone.
pub fn openapi() -> utoipa::openapi::OpenApi {
    SpacesDoc::openapi()
}
