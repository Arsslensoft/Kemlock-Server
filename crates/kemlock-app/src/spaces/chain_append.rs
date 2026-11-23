//! Accepting records into a space's chain (docs/crypto.md, "Space chain": "Accepting records").
//!
//! The server holds no member's signing key, so it can't make a record, and one bad record makes a
//! space "Can't be checked" for every member for good: it must never accept one a client would
//! refuse. So it takes the verified state at the stored head (a store keeps it; without one the
//! chain is replayed), applies each new record to it
//! with the verifier `kemlock-crypto` shares with the apps (signature, hash link, the signer's
//! authority per the chain, size limits), checks the rules only a server can (the authenticated
//! account is the signer, the record's time, the federation epoch, the boxes and names the
//! commitments cover) and appends all of the request or none of it, deriving the server's own
//! tables from the chain in the same transaction (S2).

use super::chain::{
    AppendOutcome, ChainAppend, ChainHead, HomeGate, PendingChange, PendingExternal,
    SpaceChainRepo, StoredName, StoredRecord, StoredSeal,
};
use super::chain_project::{Batch, custom_of, id_of, permission_of, project, role_of, user_of};
use super::error::SpacesError;
use super::ports::SpaceRepo;
use super::support::record;
use crate::authenticate::Actor;
use crate::ports::{Clock, EventLog, StoreError, UserRepo};
use kemlock_crypto::space_chain::{
    self as sc, Body, ChainError, KeyRef, Limits, NameTarget, Reason, Record, SignedRecord,
};
use kemlock_domain::spaces::{CollectionId, MemberState, SpaceRole};
use kemlock_domain::{ItemId, SpaceId, UserId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use uuid::Uuid;

/// A sealed key a request carries: the box of the commitment of record `seq` for `member`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealIn {
    pub seq: u64,
    pub key: KeyRef,
    pub member: UserId,
    pub version: u32,
    pub sealed: Vec<u8>,
}

/// A sealed name a request carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameIn {
    pub seq: u64,
    pub target: NameTarget,
    pub sealed: Vec<u8>,
}

/// What `POST /kem/v1/spaces/{id}/chain` takes: records to append in order, the boxes their
/// commitments cover and the sealed names their hashes cover.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppendRequest {
    pub records: Vec<SignedRecord>,
    pub seals: Vec<SealIn>,
    pub names: Vec<NameIn>,
    /// Live items a `keys` record in this request leaves **held**: kept, but not served as live,
    /// and counted as covered by the key replacement (I3).
    pub held: Vec<ItemId>,
}

/// Why records weren't appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendError {
    /// `seq` or `prev` isn't the next: the head is what the chain holds now (`409`).
    Conflict(Option<ChainHead>),
    /// A record is refused with a reason of "Verification" (`422`).
    Refused {
        error: ChainError,
        /// A server-side rule's own words, when one refused it.
        detail: Option<&'static str>,
    },
    /// The request itself is wrong (`400`).
    Invalid(&'static str),
    /// The records are fine but aren't the queued change they were sent to answer (`422`).
    Mismatch(&'static str),
    /// The request holds an item that isn't in a collection whose key one of its `keys` records
    /// replaces (`422`).
    HeldNotRotated(&'static str),
    /// The space isn't there for this caller.
    NotFound,
    Store(String),
}

impl From<StoreError> for AppendError {
    fn from(e: StoreError) -> Self {
        AppendError::Store(e.to_string())
    }
}

impl From<SpacesError> for AppendError {
    fn from(e: SpacesError) -> Self {
        match e {
            SpacesError::NotFound => AppendError::NotFound,
            other => AppendError::Store(other.to_string()),
        }
    }
}

fn refuse(seq: Option<u64>, reason: Reason, detail: &'static str) -> AppendError {
    AppendError::Refused {
        error: ChainError { seq, reason },
        detail: Some(detail),
    }
}

/// How far a record's `at` may be from the server's clock (A6), in seconds.
const CLOCK_SLACK: u64 = 600;

/// Appends records to a space's chain.
#[derive(Debug)]
pub struct AppendChain<R, U, V, C> {
    pub spaces: R,
    pub users: U,
    pub events: V,
    pub clock: C,
}

impl<R, U, V, C> AppendChain<R, U, V, C>
where
    R: SpaceRepo + SpaceChainRepo,
    U: UserRepo,
    V: EventLog,
    C: Clock,
{
    /// Appends `request`'s records, all or none, and returns the new head. A request is 1 to 16
    /// records, in order, all signed and sent by `actor`.
    pub async fn execute(
        &self,
        actor: &Actor,
        space: SpaceId,
        request: AppendRequest,
    ) -> Result<ChainHead, AppendError> {
        self.run(actor, space, request, None).await
    }

    /// Answers a queued outside change: the request is verified like any append, must record
    /// exactly that change (one record, the matching kind, the same account, role or grant), and
    /// when it is appended the queue entry is marked done in the same transaction. Only an Owner
    /// or Admin answers.
    pub async fn answer(
        &self,
        actor: &Actor,
        space: SpaceId,
        pending: Uuid,
        request: AppendRequest,
    ) -> Result<ChainHead, AppendError> {
        let row = self
            .spaces
            .memberships(actor.user)
            .await?
            .into_iter()
            .find(|m| m.space == space && m.state == MemberState::Confirmed)
            .ok_or(AppendError::NotFound)?;
        if !matches!(row.role, SpaceRole::Owner | SpaceRole::Admin) {
            return Err(AppendError::Invalid(
                "only an owner or admin answers a pending change",
            ));
        }
        let queued = self
            .spaces
            .pending_external_one(space, pending)
            .await?
            .ok_or(AppendError::NotFound)?;
        self.run(actor, space, request, Some(&queued)).await
    }

    async fn run(
        &self,
        actor: &Actor,
        space: SpaceId,
        request: AppendRequest,
        answering: Option<&PendingExternal>,
    ) -> Result<ChainHead, AppendError> {
        if request.records.is_empty() {
            return Err(AppendError::Invalid(
                "a request carries at least one record",
            ));
        }
        if request.records.len() > Limits::REQUEST_RECORDS {
            return Err(refuse(
                None,
                Reason::TooLarge,
                "at most 16 records in one request",
            ));
        }
        let space_bytes = *space.as_bytes();

        // The verified state at the stored head: a store keeps it, so this applies only the new
        // records and doesn't replay the chain (which one member could make long).
        let (head, mut state) = match self.spaces.chain_state(space).await? {
            Some((head, state)) => (Some(head), (*state).clone()),
            None => (None, sc::State::empty()),
        };

        // A3: the first record must follow the head. This is a conflict, not a refusal: the
        // caller learns the head and tries again.
        let first =
            Record::parse(&request.records[0].entry).map_err(|reason| AppendError::Refused {
                error: ChainError {
                    seq: Some(0),
                    reason,
                },
                detail: None,
            })?;
        let next_seq = head.map_or(0, |h| h.seq + 1);
        let next_prev = head.map_or([0u8; 32], |h| h.link);
        if first.seq != next_seq || first.prev != next_prev {
            return Err(AppendError::Conflict(head));
        }

        let now = self.clock.now();
        let now_secs = u64::try_from(now.unix_timestamp()).unwrap_or(0);
        let gate = self.spaces.chain_home_gate(space).await?;
        let existing = self.spaces.load(space).await?;
        let me = id_of(actor.user);

        let mut accepted: Vec<(Record, sc::Applied, &SignedRecord)> = Vec::new();
        for signed in &request.records {
            let rec = Record::parse(&signed.entry).map_err(|reason| AppendError::Refused {
                error: ChainError {
                    seq: Some(next_seq + accepted.len() as u64),
                    reason,
                },
                detail: None,
            })?;
            let at = Some(rec.seq);
            // A5.
            if rec.by != me {
                return Err(refuse(
                    at,
                    Reason::NotAllowed,
                    "a record is sent by the account that signed it",
                ));
            }
            // A6.
            if rec.at.abs_diff(now_secs) > CLOCK_SLACK {
                return Err(refuse(
                    at,
                    Reason::Invalid,
                    "the record's time is more than 10 minutes from the server's clock",
                ));
            }
            // A4.
            check_home(gate.as_ref(), &state, &rec)?;
            // A9, and the registered bundle of what a record carries (A10).
            match &rec.body {
                Body::Create { bundle, .. } => {
                    if head.is_some() || existing.is_some() || !accepted.is_empty() {
                        return Err(refuse(
                            at,
                            Reason::Invalid,
                            "a create comes only with the request that makes the space",
                        ));
                    }
                    self.registered(actor.user, bundle, at).await?;
                }
                Body::Confirm { bundle, member, .. } => {
                    self.registered(user_of(member), bundle, at).await?;
                }
                Body::Rekey { bundle, .. } => {
                    self.registered(actor.user, bundle, at).await?;
                }
                _ => {}
            }
            let applied =
                state
                    .apply(&space_bytes, signed)
                    .map_err(|error| AppendError::Refused {
                        error,
                        detail: None,
                    })?;
            state = applied.state.clone();
            accepted.push((rec, applied, signed));
        }

        if let Some(queued) = answering
            && !matches_pending(accepted.iter().map(|(rec, _, _)| rec), queued)
        {
            return Err(AppendError::Mismatch(
                "the records aren't exactly the queued change: send one record of its kind for the same account, role or grant",
            ));
        }

        // A11: exactly the boxes and names the commitments cover.
        let (seals, names) = self.cover(&space_bytes, &accepted, &request)?;
        let held = self.held(space, &accepted, &request).await?;

        let holders = self.spaces.holders(space).await?;
        let changes = project(
            space,
            existing.as_ref(),
            &holders,
            &state,
            Batch {
                seals: &seals,
                names: &names,
            },
            now,
        );
        let creating = matches!(accepted[0].0.body, Body::Create { .. });
        let state_after = Arc::new(state.clone());
        let records: Vec<StoredRecord> = accepted
            .iter()
            .map(|(rec, applied, signed)| StoredRecord {
                seq: rec.seq,
                link: applied.link,
                epoch: rec.epoch,
                by: actor.user,
                at: rec.at,
                entry: signed.entry.clone(),
                signature: signed.signature.clone(),
                cosignature: signed.cosignature.clone(),
            })
            .collect();
        let kinds: Vec<&str> = accepted
            .iter()
            .map(|(rec, _, _)| rec.kind().as_str())
            .collect();
        let outcome = self
            .spaces
            .chain_append(
                space,
                ChainAppend {
                    expected: head,
                    records,
                    seals,
                    names,
                    changes,
                    creating,
                    held,
                    answers: answering.map(|p| p.id),
                    state: Some(state_after),
                },
            )
            .await?;
        match outcome {
            AppendOutcome::Appended(new_head) => {
                record(
                    &self.events,
                    actor,
                    "space.chain.append",
                    format!("{space}: {} (head {})", kinds.join(","), new_head.seq),
                    now,
                )
                .await;
                Ok(new_head)
            }
            AppendOutcome::Stale(current) => Err(AppendError::Conflict(current)),
        }
    }

    /// A10: a bundle a record carries is byte for byte the account's registered bundle.
    async fn registered(
        &self,
        account: UserId,
        bundle: &[u8],
        seq: Option<u64>,
    ) -> Result<(), AppendError> {
        let user = self.users.by_id(account).await?;
        match user {
            Some(u) if u.public_bundle == bundle => Ok(()),
            _ => Err(refuse(
                seq,
                Reason::BadBundle,
                "a bundle in a record is the account's registered bundle, byte for byte",
            )),
        }
    }

    /// A11: the request carries exactly one box per recipient each commitment derives, and the
    /// sealed name each name hash covers, and their hashes give the committed digest and hashes.
    fn cover(
        &self,
        space: &[u8; 16],
        accepted: &[(Record, sc::Applied, &SignedRecord)],
        request: &AppendRequest,
    ) -> Result<(Vec<StoredSeal>, Vec<StoredName>), AppendError> {
        let mut boxes: BTreeMap<(u64, KeyRef, u32, UserId), &Vec<u8>> = BTreeMap::new();
        for seal in &request.seals {
            if boxes
                .insert(
                    (seal.seq, seal.key, seal.version, seal.member),
                    &seal.sealed,
                )
                .is_some()
            {
                return Err(AppendError::Invalid("a box is sent twice"));
            }
        }
        let mut sealed_names: BTreeMap<(u64, NameTarget), &Vec<u8>> = BTreeMap::new();
        for name in &request.names {
            if sealed_names
                .insert((name.seq, name.target), &name.sealed)
                .is_some()
            {
                return Err(AppendError::Invalid("a name is sent twice"));
            }
        }
        let mut seals = Vec::new();
        let mut names = Vec::new();
        for (rec, applied, _) in accepted {
            let at = Some(rec.seq);
            for commit in &applied.seals {
                let mut entries = Vec::with_capacity(commit.recipients.len());
                for (member, bundle_version) in &commit.recipients {
                    let user = user_of(member);
                    let sealed = boxes
                        .remove(&(rec.seq, commit.key, commit.version, user))
                        .ok_or_else(|| {
                            refuse(
                                at,
                                Reason::Invalid,
                                "one box for each recipient of a commitment",
                            )
                        })?;
                    if sealed.len() != Limits::BOX_LEN || sealed.first() != Some(&1) {
                        return Err(refuse(
                            at,
                            Reason::Invalid,
                            "a sealed key is a 1661-byte kx1 sealed box",
                        ));
                    }
                    entries.push((*member, *bundle_version, sc::seal_hash(sealed)));
                    seals.push(StoredSeal {
                        seq: rec.seq,
                        key: commit.key,
                        version: commit.version,
                        member: user,
                        bundle_version: *bundle_version,
                        sealed: sealed.clone(),
                    });
                }
                if sc::seal_digest(space, &commit.key, commit.version, &entries) != commit.digest {
                    return Err(refuse(
                        at,
                        Reason::Invalid,
                        "the boxes don't give the digest the record committed",
                    ));
                }
            }
            for name in &applied.names {
                let sealed = sealed_names
                    .remove(&(rec.seq, name.target))
                    .ok_or_else(|| {
                        refuse(at, Reason::Invalid, "the sealed name of each name hash")
                    })?;
                if !(Limits::SEALED_NAME_MIN..=Limits::SEALED_NAME_MAX).contains(&sealed.len())
                    || kemlock_crypto::hash::sha256(sealed) != name.hash
                {
                    return Err(refuse(
                        at,
                        Reason::Invalid,
                        "a sealed name is 28 to 4096 bytes and hashes to the committed hash",
                    ));
                }
                names.push(StoredName {
                    seq: rec.seq,
                    target: name.target,
                    version: name.version,
                    hash: name.hash,
                    sealed: sealed.clone(),
                });
            }
        }
        if !boxes.is_empty() || !sealed_names.is_empty() {
            return Err(AppendError::Invalid(
                "a box or a name that no record of the request committed",
            ));
        }
        Ok((seals, names))
    }

    /// I3: items a `keys` record leaves held are live items of collections whose key a `keys`
    /// record of the request replaces, and the request has a `keys` record.
    async fn held(
        &self,
        space: SpaceId,
        accepted: &[(Record, sc::Applied, &SignedRecord)],
        request: &AppendRequest,
    ) -> Result<Vec<ItemId>, AppendError> {
        if request.held.is_empty() {
            return Ok(Vec::new());
        }
        if !accepted
            .iter()
            .any(|(rec, _, _)| matches!(rec.body, Body::Keys { .. }))
        {
            return Err(AppendError::Invalid("only a keys record leaves items held"));
        }
        let rotated: BTreeSet<CollectionId> = accepted
            .iter()
            .filter_map(|(rec, _, _)| match &rec.body {
                Body::Keys { rotate, .. } => Some(rotate),
                _ => None,
            })
            .flatten()
            .filter_map(|c| match c.key {
                KeyRef::Collection(id) => Some(CollectionId(Uuid::from_bytes(id))),
                KeyRef::Space => None,
            })
            .collect();
        let live: BTreeMap<ItemId, Option<CollectionId>> = self
            .spaces
            .space_items(space)
            .await?
            .into_iter()
            .filter(|i| !i.deleted)
            .map(|i| (i.id, i.collection))
            .collect();
        let held: BTreeSet<ItemId> = request.held.iter().copied().collect();
        if held.len() != request.held.len() || !held.iter().all(|i| live.contains_key(i)) {
            return Err(AppendError::Invalid(
                "hold live items of the space, each once",
            ));
        }
        if !held
            .iter()
            .all(|i| live[i].is_some_and(|c| rotated.contains(&c)))
        {
            return Err(AppendError::HeldNotRotated(
                "hold only live items of a collection whose key a keys record of the request replaces",
            ));
        }
        Ok(held.into_iter().collect())
    }
}

/// The accounts the `invite` records of an accepted request invite, in order. For the API to
/// mail them once the request has landed: a record that doesn't parse names no one, since an
/// accepted request has none.
pub fn invitees(request: &AppendRequest) -> Vec<UserId> {
    request
        .records
        .iter()
        .filter_map(|signed| Record::parse(&signed.entry).ok())
        .filter_map(|rec| match rec.body {
            Body::Invite { member, .. } => Some(user_of(&member)),
            _ => None,
        })
        .collect()
}

/// Whether the records are exactly the queued change.
fn matches_pending<'a>(
    records: impl Iterator<Item = &'a Record>,
    queued: &PendingExternal,
) -> bool {
    let all: Vec<&Record> = records.collect();
    let [rec] = all.as_slice() else {
        return false;
    };
    let account = id_of(queued.account);
    match (&queued.change, &rec.body) {
        (
            PendingChange::AddMember {
                role,
                custom,
                grants,
            },
            Body::Invite {
                custom: c,
                grants: g,
                member,
                role: r,
            },
        ) => {
            let signed_custom = custom_of(&c.iter().copied().collect());
            let mut want: Vec<(sc::Id, kemlock_domain::spaces::CollectionPermission)> = grants
                .iter()
                .map(|(c, p)| (id_of_collection(*c), *p))
                .collect();
            want.sort_by_key(|g| g.0);
            let got: Vec<_> = g.iter().map(|(c, p)| (*c, permission_of(*p))).collect();
            *member == account && role_of(*r) == *role && signed_custom == *custom && got == want
        }
        (PendingChange::RemoveMember, Body::Remove { member, .. }) => *member == account,
        (
            PendingChange::Role { role, custom },
            Body::Role {
                custom: c,
                member,
                role: r,
            },
        ) => {
            *member == account
                && role_of(*r) == *role
                && custom_of(&c.iter().copied().collect()) == *custom
        }
        (
            PendingChange::GrantSet {
                collection,
                permission,
            },
            Body::Grant {
                collection: c,
                grantee,
                permission: p,
            },
        ) => {
            *c == id_of_collection(*collection)
                && *grantee == sc::Grantee::User(account)
                && permission_of(*p) == *permission
        }
        (
            PendingChange::GrantRemove { collection },
            Body::Ungrant {
                collection: c,
                grantee,
                ..
            },
        ) => *c == id_of_collection(*collection) && *grantee == sc::Grantee::User(account),
        _ => false,
    }
}

fn id_of_collection(id: kemlock_domain::spaces::CollectionId) -> sc::Id {
    *id.as_bytes()
}

/// A4: only the home accepts records, and after a promotion only the `fence` that names this
/// server and the promotion, then records of that epoch.
fn check_home(gate: Option<&HomeGate>, state: &sc::State, rec: &Record) -> Result<(), AppendError> {
    let Some(gate) = gate else {
        return Ok(());
    };
    let bad = |detail: &'static str| refuse(Some(rec.seq), Reason::BadEpoch, detail);
    if !gate.is_home {
        return Err(bad("only the home of the space accepts records"));
    }
    if state.head.is_none() {
        return if gate.epoch == 1 {
            Ok(())
        } else {
            Err(bad(
                "a space that has moved homes can't start its chain here",
            ))
        };
    }
    let is_fence = matches!(rec.body, Body::Fence { .. });
    match state.epoch.cmp(&gate.epoch) {
        std::cmp::Ordering::Equal if !is_fence => Ok(()),
        std::cmp::Ordering::Equal => Err(bad("a fence follows a promotion of the home")),
        std::cmp::Ordering::Less => match &rec.body {
            Body::Fence { home, promotion }
                if rec.epoch == gate.epoch
                    && *home == gate.server
                    && gate.promotion.is_none_or(|p| p == *promotion) =>
            {
                Ok(())
            }
            _ => Err(bad(
                "after a promotion this server takes only the fence that names it and the \
                 promotion, signed by an Owner",
            )),
        },
        std::cmp::Ordering::Greater => Err(bad(
            "the chain's epoch is ahead of the space's federation epoch",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(body: Body, epoch: u32) -> Record {
        Record {
            space: [1; 16],
            seq: 3,
            prev: [0; 32],
            epoch,
            at: 0,
            by: [2; 16],
            body,
        }
    }

    fn fence(home: [u8; 16], promotion: [u8; 32]) -> Body {
        Body::Fence { home, promotion }
    }

    fn state_at(epoch: u32) -> sc::State {
        let mut s = sc::State::empty();
        s.head = Some(sc::Head {
            seq: 2,
            link: [9; 32],
        });
        s.epoch = epoch;
        s
    }

    const GATE: HomeGate = HomeGate {
        is_home: true,
        epoch: 2,
        server: [7; 16],
        promotion: Some([8; 32]),
    };

    fn reason(r: Result<(), AppendError>) -> Option<Reason> {
        match r {
            Err(AppendError::Refused { error, .. }) => Some(error.reason),
            _ => None,
        }
    }

    #[test]
    fn a_space_that_isnt_federated_has_no_gate() {
        assert!(check_home(None, &state_at(1), &rec(Body::RecoveryKeyClear, 1)).is_ok());
    }

    #[test]
    fn only_the_home_accepts_records() {
        let replica = HomeGate {
            is_home: false,
            ..GATE
        };
        let r = check_home(
            Some(&replica),
            &state_at(2),
            &rec(Body::RecoveryKeyClear, 2),
        );
        assert_eq!(reason(r), Some(Reason::BadEpoch));
    }

    #[test]
    fn after_a_promotion_a_new_home_takes_only_the_fence_that_names_it() {
        // The chain is at epoch 1; the promotion made the space's epoch 2.
        let state = state_at(1);
        let ok = rec(fence([7; 16], [8; 32]), 2);
        assert!(check_home(Some(&GATE), &state, &ok).is_ok());
        // Any other record, a fence to another home, another promotion, or another epoch.
        for bad in [
            rec(Body::RecoveryKeyClear, 1),
            rec(fence([6; 16], [8; 32]), 2),
            rec(fence([7; 16], [5; 32]), 2),
            rec(fence([7; 16], [8; 32]), 3),
        ] {
            assert_eq!(
                reason(check_home(Some(&GATE), &state, &bad)),
                Some(Reason::BadEpoch)
            );
        }
        // Once the fence is in, records of that epoch are taken, and another fence isn't.
        let state = state_at(2);
        assert!(check_home(Some(&GATE), &state, &rec(Body::RecoveryKeyClear, 2)).is_ok());
        assert_eq!(
            reason(check_home(
                Some(&GATE),
                &state,
                &rec(fence([7; 16], [8; 32]), 3)
            )),
            Some(Reason::BadEpoch)
        );
        // A chain ahead of federation is refused.
        assert_eq!(
            reason(check_home(
                Some(&GATE),
                &state_at(3),
                &rec(Body::RecoveryKeyClear, 3)
            )),
            Some(Reason::BadEpoch)
        );
    }

    #[test]
    fn a_chain_starts_at_epoch_1_only() {
        let first = rec(Body::RecoveryKeyClear, 1);
        let fresh = sc::State::empty();
        assert!(check_home(Some(&HomeGate { epoch: 1, ..GATE }), &fresh, &first).is_ok());
        assert_eq!(
            reason(check_home(Some(&GATE), &fresh, &first)),
            Some(Reason::BadEpoch)
        );
    }
}
