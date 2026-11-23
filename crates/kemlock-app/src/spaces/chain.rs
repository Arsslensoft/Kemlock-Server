//! The space chain's storage port and the types around it (docs/crypto.md, "Space chain": "What the
//! server stores, serves and checks").
//!
//! A space with a chain keeps its signed records in an append-only list, indexed by `seq` from 0:
//! the exact bytes it accepted and the signatures that came with them. Its members, roles,
//! collections, groups, grants, key versions, sealed keys, names, policies and recovery key change
//! only by accepting records, in the transaction that appends them (S1, S2). The boxes and sealed
//! names a record's commitments cover are kept by `seq` (S3).

use super::error::SpacesError;
use super::ports::{SpaceChanges, SpaceRepo};
use crate::ports::StoreError;
use kemlock_crypto::space_chain::{KeyRef, NameTarget, SignedRecord, State, Status};
use kemlock_domain::spaces::{
    CollectionId, CollectionPermission, CustomPermissions, Grantee, MemberState, SpaceError,
    SpaceRole, SpaceState,
};
use kemlock_domain::{ItemId, SpaceId, UserId};
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// What a change from outside a Kemlock client does to a space that has a chain, as the setting
/// `space_chain_external_changes` says (docs/crypto.md, "Changes from outside Kemlock clients").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExternalChangeMode {
    /// Kept for an Owner's or Admin's app to read and sign as a record. The default.
    #[default]
    Queue,
    /// Refused.
    Refuse,
    /// Refused, and the chained space isn't shown to Bitwarden-compatible apps at all: they keep
    /// their own, unchained spaces.
    Unchained,
}

impl ExternalChangeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalChangeMode::Queue => "queue",
            ExternalChangeMode::Refuse => "refuse",
            ExternalChangeMode::Unchained => "unchained",
        }
    }

    /// The mode a setting's text names; anything else is the default.
    pub fn parse(text: &str) -> ExternalChangeMode {
        match text.trim().to_ascii_lowercase().as_str() {
            "refuse" => ExternalChangeMode::Refuse,
            "unchained" => ExternalChangeMode::Unchained,
            _ => ExternalChangeMode::Queue,
        }
    }

    /// Whether Bitwarden-compatible apps see a space that has a chain, read-only.
    pub fn exposes_chained_spaces(self) -> bool {
        self != ExternalChangeMode::Unchained
    }
}

/// What the server tells a caller whose change needs a record instead.
pub const CHAIN_REQUIRED: &str = "this space's members, roles, keys and policies change only by \
     signed records of its chain: POST /kem/v1/spaces/{id}/chain";

/// The error of a change that needs a record.
pub fn chain_required() -> SpacesError {
    SpacesError::Rule(SpaceError::State(CHAIN_REQUIRED))
}

/// Where a queued change came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalSource {
    /// The Bitwarden-compatible organisation routes.
    Bitwarden,
    /// SSO group sync at sign-in.
    Sso,
}

impl ExternalSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalSource::Bitwarden => "bitwarden",
            ExternalSource::Sso => "sso",
        }
    }

    pub fn parse(text: &str) -> Option<ExternalSource> {
        match text {
            "bitwarden" => Some(ExternalSource::Bitwarden),
            "sso" => Some(ExternalSource::Sso),
            _ => None,
        }
    }
}

/// What a queued change would do. The Admin's app signs the matching record: `invite`,
/// `remove`, `role`, `grant` or `ungrant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingChange {
    /// Add a member (an `invite`), with the grants they would start with.
    AddMember {
        role: SpaceRole,
        custom: CustomPermissions,
        grants: Vec<(CollectionId, CollectionPermission)>,
    },
    /// Remove or revoke a member (a `remove`).
    RemoveMember,
    /// Give a member another role (a `role`).
    Role {
        role: SpaceRole,
        custom: CustomPermissions,
    },
    /// Give a member a permission on a collection (a `grant`).
    GrantSet {
        collection: CollectionId,
        permission: CollectionPermission,
    },
    /// Take a member's grant on a collection away (an `ungrant`).
    GrantRemove { collection: CollectionId },
}

impl PendingChange {
    /// The name the API uses.
    pub fn kind(&self) -> &'static str {
        match self {
            PendingChange::AddMember { .. } => "add-member",
            PendingChange::RemoveMember => "remove-member",
            PendingChange::Role { .. } => "role",
            PendingChange::GrantSet { .. } => "grant-set",
            PendingChange::GrantRemove { .. } => "grant-remove",
        }
    }
}

/// A change from outside Kemlock clients, kept for an Owner's or Admin's app to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingExternal {
    pub id: Uuid,
    pub space: SpaceId,
    pub source: ExternalSource,
    pub queued_at: OffsetDateTime,
    /// The account that asked, when the source knows one.
    pub requested_by: Option<UserId>,
    /// Who or what asked, in words: "Bitwarden-compatible API", "SSO group rule".
    pub via: String,
    /// The account the change is about.
    pub account: UserId,
    /// Their email, when the source knew it; the list fills it in from the account.
    pub email: Option<String>,
    pub change: PendingChange,
}

/// `(seq, link, epoch)` of the last record of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub seq: u64,
    pub link: [u8; 32],
    pub epoch: u32,
}

/// A record as stored: its exact bytes and signatures, and what was derived from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    pub seq: u64,
    pub link: [u8; 32],
    pub epoch: u32,
    pub by: UserId,
    /// The record's `at`, in Unix seconds.
    pub at: u64,
    pub entry: Vec<u8>,
    pub signature: Vec<u8>,
    pub cosignature: Option<Vec<u8>>,
}

impl StoredRecord {
    /// The record as the chain's verifier takes it.
    pub fn signed(&self) -> SignedRecord {
        SignedRecord {
            entry: self.entry.clone(),
            signature: self.signature.clone(),
            cosignature: self.cosignature.clone(),
        }
    }
}

/// A sealed key a record committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSeal {
    pub seq: u64,
    pub key: KeyRef,
    pub version: u32,
    pub member: UserId,
    /// The bundle key version the box is sealed to.
    pub bundle_version: u32,
    pub sealed: Vec<u8>,
}

/// A sealed name a record committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredName {
    pub seq: u64,
    pub target: NameTarget,
    /// The space key version it is sealed under.
    pub version: u32,
    pub hash: [u8; 32],
    pub sealed: Vec<u8>,
}

/// Everything one accepted request stores, in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainAppend {
    /// The head the records were checked against: `None` for a new chain. The append fails
    /// without changing anything when the stored head isn't this one.
    pub expected: Option<ChainHead>,
    pub records: Vec<StoredRecord>,
    pub seals: Vec<StoredSeal>,
    pub names: Vec<StoredName>,
    /// The space's tables after the records, as the chain derives them.
    pub changes: SpaceChanges,
    /// The first record is a `create`: the changes make the space.
    pub creating: bool,
    /// Live items a `keys` record leaves held (I3): kept, but not served as live.
    pub held: Vec<ItemId>,
    /// The queued outside change these records answer: marked done in the same transaction.
    pub answers: Option<Uuid>,
    /// The verified state the records lead to, which is the state at the new head. A store may
    /// keep it under the new head's link, so the next append applies only its own records and a
    /// read of who is confirmed doesn't replay the chain (`SpaceChainRepo::chain_state`). `None`
    /// when the caller doesn't have it: the store then keeps nothing and replays when asked.
    pub state: Option<Arc<State>>,
}

/// How an append went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended(ChainHead),
    /// The stored head isn't the one the records follow; nothing was stored.
    Stale(Option<ChainHead>),
}

/// What federation says about this server and a space, when the space is federated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeGate {
    /// Whether this server is the space's home. Only the home accepts records.
    pub is_home: bool,
    /// The space's current federation epoch.
    pub epoch: u32,
    /// This server's id, which a `fence` to this server names as the new home.
    pub server: [u8; 16],
    /// `SHA-256` of the signed promotion record that made the current epoch, if any.
    pub promotion: Option<[u8; 32]>,
}

/// The chain's storage.
pub trait SpaceChainRepo: Send + Sync {
    /// The head of a space's chain, or `None` when it has none.
    fn chain_head(
        &self,
        space: SpaceId,
    ) -> impl Future<Output = Result<Option<ChainHead>, StoreError>> + Send;

    /// The records with `seq >= from`, in ascending `seq`.
    fn chain_records(
        &self,
        space: SpaceId,
        from: u64,
    ) -> impl Future<Output = Result<Vec<StoredRecord>, StoreError>> + Send;

    /// The sealed keys record `seq` committed.
    fn chain_seals(
        &self,
        space: SpaceId,
        seq: u64,
    ) -> impl Future<Output = Result<Vec<StoredSeal>, StoreError>> + Send;

    /// Appends records, their boxes and names, and applies `changes`, all or none, if the stored
    /// head is the one expected (A3: of two racing appends one wins and the other is `Stale`).
    fn chain_append(
        &self,
        space: SpaceId,
        append: ChainAppend,
    ) -> impl Future<Output = Result<AppendOutcome, StoreError>> + Send;

    /// The chain's head and the verified state at it, or `None` for a space with no chain. The
    /// default replays the whole chain ([`replay_state`]). A store that keeps the state of the
    /// head it last saw (`ChainAppend::state`) answers from it when its link is the stored head's,
    /// and replays only when it has none or the link differs. Either way the answer is the same.
    fn chain_state(
        &self,
        space: SpaceId,
    ) -> impl Future<Output = Result<Option<(ChainHead, Arc<State>)>, StoreError>> + Send {
        replay_state(self, space)
    }

    /// Federation's view of the space, or `None` for a space that isn't federated.
    fn chain_home_gate(
        &self,
        _space: SpaceId,
    ) -> impl Future<Output = Result<Option<HomeGate>, StoreError>> + Send {
        async { Ok(None) }
    }

    /// The external changes kept for the space's admins, oldest first.
    fn pending_external(
        &self,
        _space: SpaceId,
    ) -> impl Future<Output = Result<Vec<PendingExternal>, StoreError>> + Send {
        async { Ok(Vec::new()) }
    }

    /// One kept external change that is still pending.
    fn pending_external_one(
        &self,
        _space: SpaceId,
        _id: Uuid,
    ) -> impl Future<Output = Result<Option<PendingExternal>, StoreError>> + Send {
        async { Ok(None) }
    }

    /// Forgets one kept external change. False when there was none.
    fn dismiss_external(
        &self,
        _space: SpaceId,
        _id: Uuid,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async { Ok(false) }
    }
}

/// What a `SpaceChanges` from outside Kemlock clients would do to a chained space, as queued
/// changes: members added, removed or revoked, role changes, and grants set or taken away. The
/// second value says whether the changes also touch anything the queue has no shape for (groups,
/// collections, keys, the space row), which are never applied. A change that only moves a member
/// along the server's own steps (invited, accepted) gives nothing.
pub fn pending_from_changes(
    state: &SpaceState,
    changes: &SpaceChanges,
) -> (Vec<(UserId, PendingChange)>, bool) {
    let mut out: Vec<(UserId, PendingChange)> = Vec::new();
    let mut used: Vec<(CollectionId, Grantee)> = Vec::new();
    for member in &changes.members {
        match state.member(member.user) {
            None => {
                let mut grants = Vec::new();
                for g in &changes.grants {
                    if g.grantee == Grantee::Member(member.user) {
                        grants.push((g.collection, g.permission));
                        used.push((g.collection, g.grantee));
                    }
                }
                out.push((
                    member.user,
                    PendingChange::AddMember {
                        role: member.role,
                        custom: member.custom,
                        grants,
                    },
                ));
            }
            Some(old) => {
                if member.state == MemberState::Revoked && old.state != MemberState::Revoked {
                    out.push((member.user, PendingChange::RemoveMember));
                } else if old.role != member.role || old.custom != member.custom {
                    out.push((
                        member.user,
                        PendingChange::Role {
                            role: member.role,
                            custom: member.custom,
                        },
                    ));
                }
            }
        }
    }
    for user in &changes.members_removed {
        if state.member(*user).is_some() {
            out.push((*user, PendingChange::RemoveMember));
        }
    }
    let mut other = !changes.groups.is_empty()
        || !changes.groups_removed.is_empty()
        || !changes.collections.is_empty()
        || !changes.collections_removed.is_empty()
        || !changes.key_copies.is_empty()
        || changes.space.is_some();
    for grant in &changes.grants {
        if used.contains(&(grant.collection, grant.grantee)) {
            continue;
        }
        let Grantee::Member(user) = grant.grantee else {
            other = true;
            continue;
        };
        let same = state.grants.iter().any(|g| {
            g.collection == grant.collection
                && g.grantee == grant.grantee
                && g.permission == grant.permission
        });
        if !same {
            out.push((
                user,
                PendingChange::GrantSet {
                    collection: grant.collection,
                    permission: grant.permission,
                },
            ));
        }
    }
    for (collection, grantee) in &changes.grants_removed {
        match grantee {
            Grantee::Member(user) => out.push((
                *user,
                PendingChange::GrantRemove {
                    collection: *collection,
                },
            )),
            Grantee::Group(_) => other = true,
        }
    }
    (out, other)
}

/// The accounts a space's chain holds as confirmed members: the creator, and everyone a `confirm`
/// record confirmed and no later record removed. `None` for a space with no chain.
///
/// The members table says "confirmed" too, but on a chained space only the chain may: an outside
/// change (a Bitwarden-compatible confirm) can leave a row confirmed that no record confirmed.
/// Whatever asks "is this member confirmed" of a chained space asks here. The server verified
/// every stored record when it appended it, so replaying skips the signatures.
///
/// It reads the state a store keeps at the head ([`SpaceChainRepo::chain_state`]), which is not a
/// replay each time.
pub async fn chain_confirmed<R: SpaceChainRepo>(
    chain: &R,
    space: SpaceId,
) -> Result<Option<BTreeSet<UserId>>, StoreError> {
    Ok(chain
        .chain_state(space)
        .await?
        .map(|(_, state)| confirmed_of(&state)))
}

/// The accounts a chain state holds as confirmed members.
pub fn confirmed_of(state: &State) -> BTreeSet<UserId> {
    state
        .members
        .iter()
        .filter(|(_, m)| m.status == Status::Confirmed)
        .map(|(id, _)| UserId(Uuid::from_bytes(*id)))
        .collect()
}

/// The chain's head and the state at it, by replaying every stored record: what a store with
/// nothing kept does, and what a kept state must equal. The server verified every stored record
/// when it appended it, so replaying skips the signatures.
pub async fn replay_state<R: SpaceChainRepo + ?Sized>(
    chain: &R,
    space: SpaceId,
) -> Result<Option<(ChainHead, Arc<State>)>, StoreError> {
    let records = chain.chain_records(space, 0).await?;
    let Some(last) = records.last() else {
        return Ok(None);
    };
    let head = ChainHead {
        seq: last.seq,
        link: last.link,
        epoch: last.epoch,
    };
    let bytes = *space.as_bytes();
    let mut state = State::empty();
    for row in &records {
        state = state
            .apply_stored(&bytes, &row.signed())
            .map_err(|e| StoreError::Backend(format!("a stored record no longer applies: {e}")))?
            .state;
    }
    Ok(Some((head, Arc::new(state))))
}

/// Refuses a change that a chained space takes only as a record.
pub async fn ensure_unchained<R: SpaceRepo>(spaces: &R, space: SpaceId) -> Result<(), SpacesError> {
    if spaces.is_chained(space).await? {
        return Err(chain_required());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space_state() -> (SpaceState, UserId) {
        use kemlock_domain::spaces::{Member, Space};
        let now = OffsetDateTime::UNIX_EPOCH;
        let id = SpaceId(Uuid::from_u128(1));
        let sam = UserId(Uuid::from_u128(2));
        let mut owner =
            Member::invited(id, sam, SpaceRole::Owner, CustomPermissions::NONE, sam, now);
        owner.state = MemberState::Confirmed;
        let mut ana = Member::invited(
            id,
            UserId(Uuid::from_u128(3)),
            SpaceRole::Member,
            CustomPermissions::NONE,
            sam,
            now,
        );
        ana.state = MemberState::Confirmed;
        (
            SpaceState {
                space: Space {
                    id,
                    name: vec![],
                    key_version: 1,
                    keys_pending_since: None,
                    created_at: now,
                    updated_at: now,
                },
                members: vec![owner, ana],
                groups: vec![],
                collections: vec![],
                grants: vec![],
            },
            sam,
        )
    }

    #[test]
    fn outside_changes_become_the_queued_changes_they_would_make() {
        use kemlock_domain::spaces::{CollectionGrant, Member};
        let (state, sam) = space_state();
        let id = state.space.id;
        let ana = UserId(Uuid::from_u128(3));
        let zed = UserId(Uuid::from_u128(9));
        let collection = CollectionId(Uuid::from_u128(20));
        let now = OffsetDateTime::UNIX_EPOCH;

        // A new member with a grant: one change, the grant folded into it.
        let mut changes = SpaceChanges::new(id);
        changes.members = vec![Member::invited(
            id,
            zed,
            SpaceRole::Admin,
            CustomPermissions::NONE,
            sam,
            now,
        )];
        changes.grants = vec![CollectionGrant {
            collection,
            grantee: Grantee::Member(zed),
            permission: CollectionPermission::Edit,
        }];
        let (queued, other) = pending_from_changes(&state, &changes);
        assert!(!other);
        assert_eq!(
            queued,
            vec![(
                zed,
                PendingChange::AddMember {
                    role: SpaceRole::Admin,
                    custom: CustomPermissions::NONE,
                    grants: vec![(collection, CollectionPermission::Edit)],
                }
            )]
        );

        // A role change, a revoke, a removal, a grant and an ungrant.
        let mut changes = SpaceChanges::new(id);
        let mut promoted = state.member(ana).cloned().expect("ana");
        promoted.role = SpaceRole::Admin;
        changes.members = vec![promoted];
        changes.members_removed = vec![sam];
        changes.grants = vec![CollectionGrant {
            collection,
            grantee: Grantee::Member(ana),
            permission: CollectionPermission::View,
        }];
        changes.grants_removed = vec![(collection, Grantee::Member(sam))];
        let (queued, other) = pending_from_changes(&state, &changes);
        assert!(!other);
        let kinds: Vec<&str> = queued.iter().map(|(_, c)| c.kind()).collect();
        assert_eq!(
            kinds,
            vec!["role", "remove-member", "grant-set", "grant-remove"]
        );

        let mut revoked = state.member(ana).cloned().expect("ana");
        revoked.state = MemberState::Revoked;
        let mut changes = SpaceChanges::new(id);
        changes.members = vec![revoked];
        assert_eq!(
            pending_from_changes(&state, &changes).0,
            vec![(ana, PendingChange::RemoveMember)]
        );

        // The server's own step (accepting) gives nothing; a group change is "other".
        let mut accepted = state.member(ana).cloned().expect("ana");
        accepted.accepted_at = Some(now);
        let mut changes = SpaceChanges::new(id);
        changes.members = vec![accepted];
        assert_eq!(pending_from_changes(&state, &changes), (vec![], false));
        let mut changes = SpaceChanges::new(id);
        changes.groups_removed = vec![kemlock_domain::spaces::GroupId(Uuid::from_u128(30))];
        assert_eq!(pending_from_changes(&state, &changes), (vec![], true));
    }

    #[test]
    fn the_mode_reads_its_three_words_and_defaults_to_refuse() {
        assert_eq!(
            ExternalChangeMode::parse("queue"),
            ExternalChangeMode::Queue
        );
        assert_eq!(
            ExternalChangeMode::parse(" Unchained "),
            ExternalChangeMode::Unchained
        );
        assert_eq!(
            ExternalChangeMode::parse("refuse"),
            ExternalChangeMode::Refuse
        );
        assert_eq!(
            ExternalChangeMode::parse("whatever"),
            ExternalChangeMode::Queue
        );
        assert_eq!(ExternalChangeMode::default(), ExternalChangeMode::Queue);
        for mode in [
            ExternalChangeMode::Refuse,
            ExternalChangeMode::Queue,
            ExternalChangeMode::Unchained,
        ] {
            assert_eq!(ExternalChangeMode::parse(mode.as_str()), mode);
        }
        assert!(ExternalChangeMode::Refuse.exposes_chained_spaces());
        assert_eq!(ExternalSource::parse("sso"), Some(ExternalSource::Sso));
        assert_eq!(ExternalSource::parse("x"), None);
        assert!(ExternalChangeMode::Queue.exposes_chained_spaces());
        assert!(!ExternalChangeMode::Unchained.exposes_chained_spaces());
    }
}
