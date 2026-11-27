//! The verifier: applying one record to a state, and verifying a whole chain against an anchor
//! (docs/crypto.md, "Space chain": "Kinds", "Authority", "Verification").
//!
//! Everything here is a pure function of its inputs. The checks of one record run in the order the
//! spec fixes, so a record that breaks several rules gets the reason the spec names.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    backend::{Active, Backend},
    bundle::{self, Bundle},
    confirm::Statement,
    kx1,
    sig1::{
        self,
        context::{BUNDLE, CONFIRM, SPACE_CHAIN},
    },
};

use super::{
    Limits,
    model::{
        Body, ChainError, CollectionPerm, Commitment, CustomPerm, Grantee, Hash, Id, KeyRef, Kind,
        NameTarget, Reason, Record, Rights, Role, SignedRecord,
    },
    seals::link_in,
    state::{
        CollectionInfo, Committed, Confirmation, GroupInfo, Head, Home, Member, SealEntry,
        SpaceInfo, State, Status,
    },
};

/// The seals a record committed for one key version, with the recipients the chain derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealCommit {
    pub key: KeyRef,
    pub version: u32,
    /// Present exactly when the record makes the key version.
    pub check: Option<Hash>,
    pub count: u32,
    pub digest: Hash,
    /// The members the commitment is to, in ascending order of id, with the bundle key version
    /// each seal must be to.
    pub recipients: Vec<(Id, u32)>,
}

/// A name hash a record committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameCommit {
    pub target: NameTarget,
    pub hash: Hash,
    /// The space key version the name is sealed under.
    pub version: u32,
}

/// What applying one record gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The state after the record.
    pub state: State,
    /// The record's link.
    pub link: Hash,
    pub seals: Vec<SealCommit>,
    pub names: Vec<NameCommit>,
}

#[derive(Default)]
struct Effects {
    seals: Vec<SealCommit>,
    names: Vec<NameCommit>,
}

/// One member's access to one collection, before and after a record.
#[derive(Clone, Copy, Debug)]
struct AccessChange {
    collection: Id,
    member: Id,
    before: Option<Rights>,
    after: Option<Rights>,
}

type R<T> = Result<T, Reason>;

const BAD: Reason = Reason::Invalid;

fn is_admin(role: Role) -> bool {
    matches!(role, Role::Owner | Role::Admin)
}

/// Whether `new` is no wider than `old`: a lower rank, or the same rank and (for `custom`) a
/// subset of the permissions.
fn not_wider(new: (Role, &BTreeSet<CustomPerm>), old: (Role, &BTreeSet<CustomPerm>)) -> bool {
    if new.0 != old.0 {
        return new.0 < old.0;
    }
    new.0 != Role::Custom || new.1.is_subset(old.1)
}

/// Whether `new` is narrower than `old`: a lower rank, or both `custom` with a strict subset.
fn narrower(new: (Role, &BTreeSet<CustomPerm>), old: (Role, &BTreeSet<CustomPerm>)) -> bool {
    if new.0 != old.0 {
        return new.0 < old.0;
    }
    new.0 == Role::Custom && new.1.is_subset(old.1) && new.1 != old.1
}

impl State {
    /// Applies one signed record to this state, checking it as "Verification" says. `space` is
    /// the space being verified.
    pub fn apply(&self, space: &Id, signed: &SignedRecord) -> Result<Applied, ChainError> {
        self.apply_in::<Active>(space, signed)
    }

    pub(crate) fn apply_in<B: Backend>(
        &self,
        space: &Id,
        signed: &SignedRecord,
    ) -> Result<Applied, ChainError> {
        let record =
            Record::parse(&signed.entry).map_err(|reason| ChainError { seq: None, reason })?;
        self.apply_record::<B>(space, signed, &record, true)
    }

    /// Applies a record this caller checked in full when it stored it, so replaying its own chain
    /// costs the kind, state and authority rules but no signature checks. Never for records that
    /// came from anywhere else.
    pub fn apply_stored(&self, space: &Id, signed: &SignedRecord) -> Result<Applied, ChainError> {
        let record =
            Record::parse(&signed.entry).map_err(|reason| ChainError { seq: None, reason })?;
        self.apply_record::<Active>(space, signed, &record, false)
    }

    /// Steps 1.2 to 1.7 for a record that has been read. `verify` is `false` only for a record the
    /// caller already verified.
    pub(crate) fn apply_record<B: Backend>(
        &self,
        space: &Id,
        signed: &SignedRecord,
        rec: &Record,
        verify: bool,
    ) -> Result<Applied, ChainError> {
        let fail = |reason: Reason| ChainError {
            seq: Some(rec.seq),
            reason,
        };
        // The wire form: a cosignature on a `rekey` and on nothing else.
        if signed.cosignature.is_some() != (rec.kind() == Kind::Rekey) {
            return Err(fail(Reason::Malformed));
        }
        let link = link_in::<B>(&signed.entry);
        self.check_position(space, rec).map_err(fail)?;
        let signer = self.signer(rec).map_err(fail)?;
        if verify {
            Self::check_signatures::<B>(rec, signed, &signer).map_err(fail)?;
        }
        let (mut next, effects) = self.apply_kind::<B>(rec).map_err(fail)?;
        let changes = self.access_changes(&next);
        self.check_rules(rec, &next, &changes).map_err(fail)?;
        self.check_authority(rec, &next, &changes).map_err(fail)?;
        next.head = Some(Head { seq: rec.seq, link });
        next.epoch = rec.epoch;
        Ok(Applied {
            state: next,
            link,
            seals: effects.seals,
            names: effects.names,
        })
    }

    // ---- step 2: position ------------------------------------------------------------------

    fn check_position(&self, space: &Id, rec: &Record) -> R<()> {
        if &rec.space != space {
            return Err(Reason::WrongSpace);
        }
        let expected_seq = self.head.map_or(0, |h| h.seq + 1);
        if rec.seq != expected_seq {
            return Err(Reason::BadSequence);
        }
        let expected_prev = self.head.map_or([0u8; 32], |h| h.link);
        if rec.prev != expected_prev {
            return Err(Reason::BadLink);
        }
        let is_fence = rec.kind() == Kind::Fence;
        let epoch_ok = if self.head.is_none() {
            rec.epoch == 1
        } else if is_fence {
            self.epoch.checked_add(1) == Some(rec.epoch)
        } else {
            rec.epoch == self.epoch
        };
        if !epoch_ok {
            return Err(Reason::BadEpoch);
        }
        if (rec.kind() == Kind::Create) != (rec.seq == 0) {
            return Err(BAD);
        }
        Ok(())
    }

    // ---- step 3: the signer ----------------------------------------------------------------

    fn signer(&self, rec: &Record) -> R<sig1::PublicKey> {
        if let Body::Create { bundle, .. } = &rec.body {
            let b = Bundle::from_bytes(bundle).map_err(|_| Reason::BadBundle)?;
            if b.account_id != rec.by {
                return Err(Reason::BadBundle);
            }
            return Ok(b.sig1_public);
        }
        self.confirmed(&rec.by)
            .and_then(|m| m.bundle.as_ref())
            .map(|b| b.sig1_public.clone())
            .ok_or(Reason::UnknownSigner)
    }

    // ---- step 4: signatures ----------------------------------------------------------------

    fn check_signatures<B: Backend>(
        rec: &Record,
        signed: &SignedRecord,
        signer: &sig1::PublicKey,
    ) -> R<()> {
        sig1::verify_in::<B>(signer, SPACE_CHAIN, &signed.entry, &signed.signature)
            .map_err(|_| Reason::BadSignature)?;
        if let Body::Rekey { bundle, .. } = &rec.body {
            let new = Bundle::from_bytes(bundle).map_err(|_| Reason::BadBundle)?;
            let cosignature = signed.cosignature.as_deref().ok_or(Reason::Malformed)?;
            sig1::verify_in::<B>(&new.sig1_public, SPACE_CHAIN, &signed.entry, cosignature)
                .map_err(|_| Reason::BadSignature)?;
        }
        match &rec.body {
            Body::Create {
                bundle,
                bundle_signature,
                ..
            }
            | Body::Confirm {
                bundle,
                bundle_signature,
                ..
            }
            | Body::Rekey {
                bundle,
                bundle_signature,
            } => {
                let carried = Bundle::from_bytes(bundle).map_err(|_| Reason::BadBundle)?;
                sig1::verify_in::<B>(&carried.sig1_public, BUNDLE, bundle, bundle_signature)
                    .map_err(|_| Reason::BadBundle)?;
            }
            _ => {}
        }
        if let Body::Confirm {
            statement,
            statement_signature,
            ..
        } = &rec.body
        {
            sig1::verify_in::<B>(signer, CONFIRM, statement, statement_signature)
                .map_err(|_| Reason::BadConfirmation)?;
        }
        Ok(())
    }

    // ---- step 5: the kind rules ------------------------------------------------------------

    /// A grantee a grant may name: a member in the space, or a group that exists.
    fn check_grantee(&self, grantee: &Grantee) -> R<()> {
        let ok = match grantee {
            Grantee::User(id) => self.in_space(id),
            Grantee::Group(id) => self.groups.contains_key(id),
        };
        if ok { Ok(()) } else { Err(BAD) }
    }

    /// Records the seals one commitment covers in `self` (the state after) and checks its count.
    fn commit(&mut self, c: &Commitment, recipients: Vec<(Id, u32)>, seq: u64) -> R<SealCommit> {
        if usize::try_from(c.count).ok() != Some(recipients.len()) {
            return Err(BAD);
        }
        for (member, bundle_version) in &recipients {
            self.seals.insert(
                (c.key, c.version, *member),
                SealEntry {
                    bundle_version: *bundle_version,
                    seq,
                },
            );
        }
        self.commitments.insert(
            (c.key, c.version, seq),
            Committed {
                count: c.count,
                digest: c.digest,
                recipients: recipients.clone(),
            },
        );
        if let Some(check) = c.check {
            self.key_checks.insert((c.key, c.version), check);
        }
        Ok(SealCommit {
            key: c.key,
            version: c.version,
            check: c.check,
            count: c.count,
            digest: c.digest,
            recipients,
        })
    }

    /// The packed names of a `keys` record that replaces the space key.
    fn read_names(&self, packed: &[u8], space: &Id) -> R<Vec<(NameTarget, Hash)>> {
        if !packed.len().is_multiple_of(49) {
            return Err(BAD);
        }
        let mut out = Vec::with_capacity(packed.len() / 49);
        let mut previous: Option<&[u8]> = None;
        for chunk in packed.as_chunks::<49>().0 {
            let key = &chunk[..17];
            if previous.is_some_and(|p| p >= key) {
                return Err(BAD);
            }
            previous = Some(key);
            let id: Id = chunk[1..17].try_into().map_err(|_| BAD)?;
            let hash: Hash = chunk[17..49].try_into().map_err(|_| BAD)?;
            let target = match chunk[0] {
                1 if id == *space => NameTarget::Space,
                2 => NameTarget::Collection(id),
                3 => NameTarget::Group(id),
                _ => return Err(BAD),
            };
            out.push((target, hash));
        }
        let mut expected: BTreeSet<NameTarget> = BTreeSet::from([NameTarget::Space]);
        expected.extend(
            self.collections
                .keys()
                .map(|id| NameTarget::Collection(*id)),
        );
        expected.extend(self.groups.keys().map(|id| NameTarget::Group(*id)));
        let got: BTreeSet<NameTarget> = out.iter().map(|(t, _)| *t).collect();
        if got != expected || out.len() != expected.len() {
            return Err(BAD);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_kind<B: Backend>(&self, rec: &Record) -> R<(State, Effects)> {
        let mut next = self.clone();
        let mut fx = Effects::default();
        let by = rec.by;
        let seq = rec.seq;
        match &rec.body {
            Body::Create {
                bundle,
                bundle_signature,
                collection,
                collection_name,
                member,
                name_hash,
                seals,
            } => {
                if *member != by {
                    return Err(BAD);
                }
                let b = Bundle::from_bytes(bundle).map_err(|_| Reason::BadBundle)?;
                if b.account_id != *member {
                    return Err(Reason::BadBundle);
                }
                let ckey = KeyRef::Collection(*collection);
                let [first, second] = seals.as_slice() else {
                    return Err(BAD);
                };
                let shaped = first.key == ckey
                    && second.key == KeyRef::Space
                    && [first, second]
                        .iter()
                        .all(|c| c.version == 1 && c.count == 1 && c.check.is_some());
                if !shaped {
                    return Err(BAD);
                }
                next.members.insert(
                    *member,
                    Member {
                        role: Role::Owner,
                        custom: BTreeSet::new(),
                        status: Status::Confirmed,
                        invited_by: *member,
                        bundle: Some(b.clone()),
                        bundle_signature: bundle_signature.clone(),
                        confirmation: None,
                        rekey_seq: None,
                        reconfirmed_seq: None,
                    },
                );
                next.space = SpaceInfo {
                    key_version: 1,
                    marked: false,
                    name_hash: *name_hash,
                    name_version: 1,
                };
                next.collections.insert(
                    *collection,
                    CollectionInfo {
                        parent: None,
                        name_hash: *collection_name,
                        name_version: 1,
                        key_version: 1,
                        marked: false,
                    },
                );
                next.grants.insert(
                    (*collection, Grantee::User(*member)),
                    CollectionPerm::Manage,
                );
                let recipients = vec![(*member, b.key_version)];
                for c in [first, second] {
                    fx.seals.push(next.commit(c, recipients.clone(), seq)?);
                }
                fx.names.push(NameCommit {
                    target: NameTarget::Space,
                    hash: *name_hash,
                    version: 1,
                });
                fx.names.push(NameCommit {
                    target: NameTarget::Collection(*collection),
                    hash: *collection_name,
                    version: 1,
                });
            }
            Body::Invite {
                custom,
                grants,
                member,
                role,
            } => {
                if self.in_space(member) || *role == Role::Owner {
                    return Err(BAD);
                }
                if *role != Role::Custom && !custom.is_empty() {
                    return Err(BAD);
                }
                if grants
                    .iter()
                    .any(|(c, _)| !self.collections.contains_key(c))
                {
                    return Err(BAD);
                }
                next.members.insert(
                    *member,
                    Member {
                        role: *role,
                        custom: custom.iter().copied().collect(),
                        status: Status::Invited,
                        invited_by: by,
                        bundle: None,
                        bundle_signature: Vec::new(),
                        confirmation: None,
                        rekey_seq: None,
                        reconfirmed_seq: None,
                    },
                );
                for (collection, permission) in grants {
                    next.grants
                        .insert((*collection, Grantee::User(*member)), *permission);
                }
            }
            Body::Confirm {
                bundle,
                bundle_signature,
                member,
                statement,
                statement_signature,
            } => {
                let current = self
                    .members
                    .get(member)
                    .filter(|m| m.status != Status::Removed)
                    .ok_or(BAD)?;
                if *member == by {
                    return Err(BAD);
                }
                let b = Bundle::from_bytes(bundle).map_err(|_| Reason::BadBundle)?;
                if b.account_id != *member {
                    return Err(Reason::BadBundle);
                }
                if current.status == Status::Confirmed && b.key_version <= current.bundle_version()
                {
                    return Err(BAD);
                }
                let fingerprint = bundle::fingerprint_in::<B>(bundle);
                let expected = Statement {
                    space: rec.space,
                    member: *member,
                    member_key_version: b.key_version,
                    fingerprint: &fingerprint,
                    confirmer: by,
                }
                .to_bytes();
                if *statement != expected {
                    return Err(Reason::BadConfirmation);
                }
                let m = next.members.get_mut(member).ok_or(BAD)?;
                m.status = Status::Confirmed;
                m.bundle = Some(b);
                m.bundle_signature = bundle_signature.clone();
                m.confirmation = Some(Confirmation {
                    by,
                    statement: statement.clone(),
                    signature: statement_signature.clone(),
                    seq,
                });
                m.rekey_seq = None;
                // A member already confirmed, confirmed again under a newer bundle by someone else:
                // nothing the member signed vouches for the bundle, so a client asks for its
                // fingerprint to be compared again.
                m.reconfirmed_seq = (current.status == Status::Confirmed).then_some(seq);
            }
            Body::Rekey {
                bundle,
                bundle_signature,
            } => {
                let b = Bundle::from_bytes(bundle).map_err(|_| Reason::BadBundle)?;
                if b.account_id != by {
                    return Err(Reason::BadBundle);
                }
                let current = self.confirmed(&by).ok_or(Reason::UnknownSigner)?;
                if b.key_version <= current.bundle_version() {
                    return Err(BAD);
                }
                let m = next.members.get_mut(&by).ok_or(BAD)?;
                m.bundle = Some(b);
                m.bundle_signature = bundle_signature.clone();
                m.confirmation = None;
                m.rekey_seq = Some(seq);
                m.reconfirmed_seq = None;
            }
            Body::Role {
                custom,
                member,
                role,
            } => {
                let current = self
                    .members
                    .get(member)
                    .filter(|m| m.status != Status::Removed)
                    .ok_or(BAD)?;
                if *role != Role::Custom && !custom.is_empty() {
                    return Err(BAD);
                }
                if *role == Role::Owner
                    && (current.status != Status::Confirmed || !custom.is_empty())
                {
                    return Err(BAD);
                }
                let set: BTreeSet<CustomPerm> = custom.iter().copied().collect();
                if current.role == *role && current.custom == set {
                    return Err(BAD);
                }
                let m = next.members.get_mut(member).ok_or(BAD)?;
                m.role = *role;
                m.custom = set;
            }
            Body::Remove { member, replace } => {
                if !self.in_space(member) {
                    return Err(BAD);
                }
                let m = next.members.get_mut(member).ok_or(BAD)?;
                m.status = Status::Removed;
                m.role = Role::Member;
                m.custom.clear();
                m.bundle = None;
                m.bundle_signature.clear();
                m.confirmation = None;
                m.rekey_seq = None;
                m.reconfirmed_seq = None;
                next.grants
                    .retain(|(_, grantee), _| *grantee != Grantee::User(*member));
                for group in next.groups.values_mut() {
                    group.members.remove(member);
                }
                let lost = self.lost(&next);
                if replace.iter().copied().collect::<BTreeSet<_>>() != lost {
                    return Err(BAD);
                }
                next.mark(&lost);
            }
            Body::Grant {
                collection,
                grantee,
                permission,
            } => {
                if !self.collections.contains_key(collection) {
                    return Err(BAD);
                }
                self.check_grantee(grantee)?;
                if self.grants.get(&(*collection, *grantee)) == Some(permission) {
                    return Err(BAD);
                }
                next.grants.insert((*collection, *grantee), *permission);
            }
            Body::Ungrant {
                collection,
                grantee,
                replace,
            } => {
                if next.grants.remove(&(*collection, *grantee)).is_none() {
                    return Err(BAD);
                }
                let lost = self.lost(&next);
                if replace.iter().copied().collect::<BTreeSet<_>>() != lost {
                    return Err(BAD);
                }
                next.mark(&lost);
            }
            Body::Collection {
                collection,
                grants,
                name_hash,
                parent,
                seals,
            } => {
                if self.collections.contains_key(collection) || self.retired.contains(collection) {
                    return Err(BAD);
                }
                if let Some(p) = parent
                    && (!self.collections.contains_key(p) || self.depth(p) + 1 > Limits::DEPTH)
                {
                    return Err(BAD);
                }
                if !grants.iter().any(|(g, _)| *g == Grantee::User(by)) {
                    return Err(BAD);
                }
                for (grantee, _) in grants {
                    self.check_grantee(grantee)?;
                }
                next.collections.insert(
                    *collection,
                    CollectionInfo {
                        parent: *parent,
                        name_hash: *name_hash,
                        name_version: self.space.key_version,
                        key_version: 1,
                        marked: false,
                    },
                );
                for (grantee, permission) in grants {
                    next.grants.insert((*collection, *grantee), *permission);
                }
                let [commitment] = seals.as_slice() else {
                    return Err(BAD);
                };
                let key = KeyRef::Collection(*collection);
                if commitment.key != key || commitment.version != 1 || commitment.check.is_none() {
                    return Err(BAD);
                }
                let recipients = next.recipients(&next.entitled(&key));
                fx.seals.push(next.commit(commitment, recipients, seq)?);
                fx.names.push(NameCommit {
                    target: NameTarget::Collection(*collection),
                    hash: *name_hash,
                    version: self.space.key_version,
                });
            }
            Body::Move { collection, parent } => {
                let current = self.collections.get(collection).ok_or(BAD)?;
                if current.parent == *parent {
                    return Err(BAD);
                }
                if let Some(p) = parent {
                    if !self.collections.contains_key(p) {
                        return Err(BAD);
                    }
                    // The parent can't be the collection or below it.
                    let mut at = Some(*p);
                    let mut steps = 0;
                    while let Some(id) = at {
                        if id == *collection {
                            return Err(BAD);
                        }
                        steps += 1;
                        if steps > 64 {
                            return Err(BAD);
                        }
                        at = self.collections.get(&id).and_then(|c| c.parent);
                    }
                }
                next.collections.get_mut(collection).ok_or(BAD)?.parent = *parent;
                if next
                    .collections
                    .keys()
                    .any(|id| next.depth(id) > Limits::DEPTH)
                {
                    return Err(BAD);
                }
            }
            Body::CollectionDelete { collection } => {
                if !self.collections.contains_key(collection)
                    || self
                        .collections
                        .values()
                        .any(|c| c.parent == Some(*collection))
                {
                    return Err(BAD);
                }
                next.collections.remove(collection);
                next.grants.retain(|(c, _), _| c != collection);
                let key = KeyRef::Collection(*collection);
                next.seals.retain(|(k, _, _), _| *k != key);
                next.key_checks.retain(|(k, _), _| *k != key);
                next.commitments.retain(|(k, _, _), _| *k != key);
                next.retired.insert(*collection);
            }
            Body::Group { group, name_hash } => {
                if self.groups.contains_key(group) || self.retired.contains(group) {
                    return Err(BAD);
                }
                next.groups.insert(
                    *group,
                    GroupInfo {
                        name_hash: *name_hash,
                        name_version: self.space.key_version,
                        members: BTreeSet::new(),
                    },
                );
                fx.names.push(NameCommit {
                    target: NameTarget::Group(*group),
                    hash: *name_hash,
                    version: self.space.key_version,
                });
            }
            Body::GroupMembers {
                add,
                group,
                remove,
                replace,
            } => {
                let current = self.groups.get(group).ok_or(BAD)?;
                if add
                    .iter()
                    .any(|a| !self.in_space(a) || current.members.contains(a))
                    || remove.iter().any(|r| !current.members.contains(r))
                {
                    return Err(BAD);
                }
                let g = next.groups.get_mut(group).ok_or(BAD)?;
                g.members.extend(add.iter().copied());
                for r in remove {
                    g.members.remove(r);
                }
                let lost = self.lost(&next);
                if replace.iter().copied().collect::<BTreeSet<_>>() != lost {
                    return Err(BAD);
                }
                next.mark(&lost);
            }
            Body::GroupDelete { group, replace } => {
                if next.groups.remove(group).is_none() {
                    return Err(BAD);
                }
                next.grants
                    .retain(|(_, grantee), _| *grantee != Grantee::Group(*group));
                next.retired.insert(*group);
                let lost = self.lost(&next);
                if replace.iter().copied().collect::<BTreeSet<_>>() != lost {
                    return Err(BAD);
                }
                next.mark(&lost);
            }
            Body::Rename { name_hash, target } => {
                let version = self.space.key_version;
                match target {
                    NameTarget::Space => {
                        if self.space.name_hash == *name_hash {
                            return Err(BAD);
                        }
                        next.space.name_hash = *name_hash;
                        next.space.name_version = version;
                    }
                    NameTarget::Collection(id) => {
                        let current = self.collections.get(id).ok_or(BAD)?;
                        if current.name_hash == *name_hash {
                            return Err(BAD);
                        }
                        let c = next.collections.get_mut(id).ok_or(BAD)?;
                        c.name_hash = *name_hash;
                        c.name_version = version;
                    }
                    NameTarget::Group(id) => {
                        let current = self.groups.get(id).ok_or(BAD)?;
                        if current.name_hash == *name_hash {
                            return Err(BAD);
                        }
                        let g = next.groups.get_mut(id).ok_or(BAD)?;
                        g.name_hash = *name_hash;
                        g.name_version = version;
                    }
                }
                fx.names.push(NameCommit {
                    target: *target,
                    hash: *name_hash,
                    version,
                });
            }
            Body::Seal { seals } => {
                if self.space.marked {
                    return Err(BAD);
                }
                for c in seals {
                    if self.key_version(&c.key) != Some(c.version) || self.key_marked(&c.key) {
                        return Err(BAD);
                    }
                    let awaiting = self.awaiting(&c.key);
                    if awaiting.is_empty() {
                        return Err(BAD);
                    }
                    let recipients = self.recipients(&awaiting);
                    fx.seals.push(next.commit(c, recipients, seq)?);
                }
            }
            Body::Keys { names, rotate } => {
                let has_space = rotate.iter().any(|c| c.key == KeyRef::Space);
                if has_space != names.is_some() {
                    return Err(BAD);
                }
                for c in rotate {
                    let current = self.key_version(&c.key).ok_or(BAD)?;
                    if current.checked_add(1) != Some(c.version) {
                        return Err(BAD);
                    }
                    match c.key {
                        KeyRef::Space => {
                            next.space.key_version = c.version;
                            next.space.marked = false;
                        }
                        KeyRef::Collection(id) => {
                            let info = next.collections.get_mut(&id).ok_or(BAD)?;
                            info.key_version = c.version;
                            info.marked = false;
                        }
                    }
                    let recipients = self.recipients(&self.entitled(&c.key));
                    fx.seals.push(next.commit(c, recipients, seq)?);
                }
                if let Some(packed) = names {
                    let version = next.space.key_version;
                    for (target, hash) in self.read_names(packed, &rec.space)? {
                        match target {
                            NameTarget::Space => {
                                next.space.name_hash = hash;
                                next.space.name_version = version;
                            }
                            NameTarget::Collection(id) => {
                                if let Some(c) = next.collections.get_mut(&id) {
                                    c.name_hash = hash;
                                    c.name_version = version;
                                }
                            }
                            NameTarget::Group(id) => {
                                if let Some(g) = next.groups.get_mut(&id) {
                                    g.name_hash = hash;
                                    g.name_version = version;
                                }
                            }
                        }
                        fx.names.push(NameCommit {
                            target,
                            hash,
                            version,
                        });
                    }
                }
            }
            Body::Policies { policies } => {
                let timeout = policies.session_timeout;
                if (timeout.action == super::model::TimeoutAction::None) != (timeout.minutes == 0) {
                    return Err(BAD);
                }
                if policies.account_recovery && self.recovery_key.is_none() {
                    return Err(BAD);
                }
                if *policies == self.policies {
                    return Err(BAD);
                }
                next.policies = *policies;
            }
            Body::RecoveryKey { key } => {
                let public = kx1::PublicKey::from_bytes(key).map_err(|_| BAD)?;
                // A trial encapsulation: it refuses an invalid ML-KEM key and a low-order X25519 half.
                kx1::encapsulate_in::<B>(&public).map_err(|_| BAD)?;
                if self.recovery_key.as_deref() == Some(key.as_slice()) {
                    return Err(BAD);
                }
                next.recovery_key = Some(key.clone());
                next.recovery_key_seq = Some(rec.seq);
            }
            Body::RecoveryKeyClear => {
                if self.recovery_key.is_none() || self.policies.account_recovery {
                    return Err(BAD);
                }
                next.recovery_key = None;
                next.recovery_key_seq = None;
            }
            Body::Fence { home, promotion } => {
                next.home = Some(Home {
                    server: *home,
                    promotion: *promotion,
                });
                next.epoch = rec.epoch;
            }
        }
        // Every record must change the state.
        if next == *self {
            return Err(BAD);
        }
        Ok((next, fx))
    }

    // ---- access ------------------------------------------------------------------------------

    /// Every member whose access to a collection that exists in both states differs.
    fn access_changes(&self, next: &State) -> Vec<AccessChange> {
        let mut out = Vec::new();
        for collection in self.collections.keys() {
            if !next.collections.contains_key(collection) {
                continue;
            }
            let before = self.access_map(collection);
            let after = next.access_map(collection);
            let members: BTreeSet<&Id> = before.keys().chain(after.keys()).collect();
            for member in members {
                let (a, b) = (before.get(member).copied(), after.get(member).copied());
                if a != b {
                    out.push(AccessChange {
                        collection: *collection,
                        member: *member,
                        before: a,
                        after: b,
                    });
                }
            }
        }
        out
    }

    // ---- step 5, after the kind: marks, rule 4 and the state limits ---------------------------

    fn check_rules(&self, rec: &Record, next: &State, changes: &[AccessChange]) -> R<()> {
        // "Removal and replacement".
        if self.space.marked
            && matches!(
                rec.kind(),
                Kind::Confirm | Kind::Collection | Kind::Group | Kind::Rename | Kind::Seal
            )
        {
            return Err(BAD);
        }
        for change in changes {
            let guarded =
                self.space.marked || self.key_marked(&KeyRef::Collection(change.collection));
            if guarded && Rights::widens(change.before, change.after) {
                return Err(BAD);
            }
        }
        // Rule 4 of "Authority": a confirmed Owner remains.
        if !next
            .members
            .values()
            .any(|m| m.status == Status::Confirmed && m.role == Role::Owner)
        {
            return Err(BAD);
        }
        // The state limits.
        let members = next
            .members
            .values()
            .filter(|m| m.status != Status::Removed)
            .count();
        if members > Limits::MEMBERS
            || next.collections.len() > Limits::COLLECTIONS
            || next.groups.len() > Limits::GROUPS
        {
            return Err(BAD);
        }
        let mut per_collection: BTreeMap<&Id, usize> = BTreeMap::new();
        for (collection, _) in next.grants.keys() {
            *per_collection.entry(collection).or_default() += 1;
        }
        if per_collection
            .values()
            .any(|n| *n > Limits::GRANTS_PER_COLLECTION)
        {
            return Err(BAD);
        }
        Ok(())
    }

    // ---- step 6: authority ---------------------------------------------------------------------

    /// Whether the record touches an Owner: it changes an Owner's role, permissions, status,
    /// bundle, group memberships, or access to a collection that exists in both states.
    fn touches_owner(&self, next: &State, changes: &[AccessChange]) -> bool {
        let owners: BTreeSet<Id> = self
            .members
            .iter()
            .chain(next.members.iter())
            .filter(|(_, m)| m.status != Status::Removed && m.role == Role::Owner)
            .map(|(id, _)| *id)
            .collect();
        owners.iter().any(|o| {
            let (a, b) = (self.members.get(o), next.members.get(o));
            let same = match (a, b) {
                (Some(a), Some(b)) => {
                    a.role == b.role
                        && a.custom == b.custom
                        && a.status == b.status
                        && a.bundle == b.bundle
                }
                _ => false,
            };
            !same
                || self.groups_of(o) != next.groups_of(o)
                || changes.iter().any(|c| c.member == *o)
        })
    }

    fn check_authority(&self, rec: &Record, next: &State, changes: &[AccessChange]) -> R<()> {
        const NO: Reason = Reason::NotAllowed;
        if rec.kind() == Kind::Create {
            return Ok(());
        }
        let s = rec.by;
        let me = self.confirmed(&s).ok_or(Reason::UnknownSigner)?;
        let role = me.role;
        let perms = &me.custom;
        let has = |p: CustomPerm| perms.contains(&p);

        // The end of the chain is kept for Owners ("Limits"): a member can't fill the chain to its
        // cap and leave no room for a `remove` or a `keys` record.
        let reserved = if rec.seq >= Limits::OWNER_ONLY_FROM {
            role != Role::Owner
        } else if rec.seq >= Limits::OPEN_RECORDS {
            role != Role::Owner && !matches!(rec.kind(), Kind::Remove | Kind::Keys)
        } else {
            false
        };
        if reserved {
            return Err(NO);
        }

        // Rule 1: owners change Owners.
        if role != Role::Owner && self.touches_owner(next, changes) {
            return Err(NO);
        }
        // Rule 2: nobody widens themselves.
        if let Some(after) = next.members.get(&s)
            && !not_wider((after.role, &after.custom), (role, perms))
        {
            return Err(NO);
        }
        if changes
            .iter()
            .any(|c| c.member == s && Rights::widens(c.before, c.after))
        {
            return Err(NO);
        }
        // Rule 3: access changes need MayGrant. The access of a removed member is Manage's.
        let removed = match &rec.body {
            Body::Remove { member, .. } => Some(*member),
            _ => None,
        };
        let mut manages: BTreeMap<Id, bool> = BTreeMap::new();
        let mut may_grant = |collection: &Id| -> bool {
            if is_admin(role) {
                return true;
            }
            *manages
                .entry(*collection)
                .or_insert_with(|| self.access(&s, collection).is_some_and(|r| r.manage))
        };
        for change in changes {
            if Some(change.member) == removed {
                continue;
            }
            if !may_grant(&change.collection) {
                return Err(NO);
            }
        }

        let manage = |target: &Id| -> bool {
            if *target == s {
                return false;
            }
            let Some(t) = self.members.get(target) else {
                return false;
            };
            match role {
                Role::Owner => true,
                Role::Admin => t.role != Role::Owner,
                Role::Custom => {
                    has(CustomPerm::ManageUsers)
                        && matches!(t.role, Role::Custom | Role::Member)
                        && t.custom.is_subset(perms)
                }
                Role::Member => false,
            }
        };
        let assign = |target_role: Role, set: &BTreeSet<CustomPerm>| -> bool {
            match role {
                Role::Owner => true,
                Role::Admin => target_role != Role::Owner,
                Role::Custom => {
                    has(CustomPerm::ManageUsers)
                        && (target_role == Role::Member
                            || (target_role == Role::Custom && set.is_subset(perms)))
                }
                Role::Member => false,
            }
        };
        let group_admin = is_admin(role) || (role == Role::Custom && has(CustomPerm::ManageGroups));

        let allowed = match &rec.body {
            Body::Create { .. } => true,
            Body::Invite { custom, role, .. } => assign(*role, &custom.iter().copied().collect()),
            Body::Confirm { member, .. } => manage(member),
            Body::Rekey { .. } => true,
            Body::Role {
                custom,
                member,
                role: new_role,
            } => {
                let set: BTreeSet<CustomPerm> = custom.iter().copied().collect();
                if *member == s {
                    narrower((*new_role, &set), (role, perms))
                } else {
                    manage(member) && assign(*new_role, &set)
                }
            }
            Body::Remove { member, .. } => *member == s || manage(member),
            Body::Grant { collection, .. }
            | Body::Ungrant { collection, .. }
            | Body::Move { collection, .. }
            | Body::CollectionDelete { collection } => may_grant(collection),
            Body::Collection { .. } => {
                is_admin(role) || (role == Role::Custom && has(CustomPerm::CreateCollections))
            }
            Body::Group { .. } | Body::GroupMembers { .. } | Body::GroupDelete { .. } => {
                group_admin
            }
            Body::Rename { target, .. } => match target {
                NameTarget::Space => is_admin(role),
                NameTarget::Collection(id) => may_grant(id),
                NameTarget::Group(_) => group_admin,
            },
            Body::Seal { seals } => seals.iter().all(|c| self.holds(&s, &c.key)),
            Body::Keys { rotate, .. } => rotate.iter().all(|c| match c.key {
                KeyRef::Space => is_admin(role),
                KeyRef::Collection(id) => {
                    self.entitled(&c.key).contains(&s)
                        && (is_admin(role)
                            || self.access(&s, &id).is_some_and(|r| r.manage)
                            || self.key_marked(&c.key))
                }
            }),
            Body::Policies { policies } => {
                is_admin(role)
                    && (policies.account_recovery == self.policies.account_recovery
                        || role == Role::Owner)
            }
            Body::RecoveryKey { .. } | Body::RecoveryKeyClear | Body::Fence { .. } => {
                role == Role::Owner
            }
        };
        if allowed { Ok(()) } else { Err(NO) }
    }
}

// ---- a whole chain ---------------------------------------------------------------------------

/// What a device keeps for a space: the `seq` and `epoch` of the last record it accepted, and the
/// link of every record from `seq` 0 to that one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub epoch: u32,
    pub links: Vec<Hash>,
    /// The Owners of the state the device accepted at `seq`, when it keeps that state. A `fence`
    /// that parts the served chain from the anchor is taken only when its signer is one of them, or
    /// the device holds the promotion it names: an Owner the device's own records removed or
    /// demoted can't sign a fence that drops those records.
    pub owners: Option<BTreeSet<Id>>,
    /// `(home, promotion)` of each federation promotion record the device holds and verified: the
    /// `home` a `fence` names and `SHA-256` of the promotion record's envelope.
    pub promotions: Vec<(Id, Hash)>,
}

impl Anchor {
    /// Whether the device lets this `fence` part the chain from its anchor.
    fn vouches_for(&self, fence: &Record) -> bool {
        let Body::Fence { home, promotion } = &fence.body else {
            return false;
        };
        self.promotions.contains(&(*home, *promotion))
            || self
                .owners
                .as_ref()
                .is_some_and(|owners| owners.contains(&fence.by))
    }
}

/// A chain that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The state at the head.
    pub state: State,
    /// The link of every record, from `seq` 0: the new anchor's links.
    pub links: Vec<Hash>,
    /// The `seq` of the `fence` where the chain parts from the device's anchor, when it does. The
    /// device's own records from there to its anchor are dropped.
    pub divergence: Option<u64>,
}

/// Verifies a whole chain of `space` against a device's anchor, as "Verification" says.
pub fn verify_chain(
    space: &Id,
    chain: &[SignedRecord],
    anchor: Option<&Anchor>,
) -> Result<Verified, ChainError> {
    verify_chain_in::<Active>(space, chain, anchor)
}

pub(crate) fn verify_chain_in<B: Backend>(
    space: &Id,
    chain: &[SignedRecord],
    anchor: Option<&Anchor>,
) -> Result<Verified, ChainError> {
    let too_large = ChainError {
        seq: None,
        reason: Reason::TooLarge,
    };
    // Step 0: reading. The chain's size first, then every element, before any is applied.
    if u64::try_from(chain.len()).unwrap_or(u64::MAX) > Limits::CHAIN_RECORDS {
        return Err(too_large);
    }
    let bytes: usize = chain.iter().map(|s| s.entry.len()).sum();
    if bytes > Limits::CHAIN_BYTES {
        return Err(too_large);
    }
    let mut records = Vec::with_capacity(chain.len());
    for (i, signed) in chain.iter().enumerate() {
        let at = u64::try_from(i).ok();
        let record =
            Record::parse(&signed.entry).map_err(|reason| ChainError { seq: at, reason })?;
        if signed.cosignature.is_some() != (record.kind() == Kind::Rekey) {
            return Err(ChainError {
                seq: at,
                reason: Reason::Malformed,
            });
        }
        records.push(record);
    }

    // Step 1: each record, from the empty state.
    let mut state = State::empty();
    let mut links = Vec::with_capacity(chain.len());
    let mut divergence: Option<u64> = None;
    let mut fence_epoch = 0u32;
    for (signed, record) in chain.iter().zip(&records) {
        if divergence.is_none()
            && let Some(anchor) = anchor
            && let Some(kept) = usize::try_from(record.seq)
                .ok()
                .and_then(|i| anchor.links.get(i))
            && *kept != link_in::<B>(&signed.entry)
        {
            // A divergence is allowed only at a `fence` the device vouches for (M17).
            if record.kind() != Kind::Fence || !anchor.vouches_for(record) {
                return Err(ChainError {
                    seq: Some(record.seq),
                    reason: Reason::Forked,
                });
            }
            divergence = Some(record.seq);
            fence_epoch = record.epoch;
        }
        let applied = state.apply_record::<B>(space, signed, record, true)?;
        links.push(applied.link);
        state = applied.state;
    }

    // Step 2: after the last record.
    if let Some(anchor) = anchor {
        match divergence {
            Some(at) => {
                if anchor.epoch >= fence_epoch {
                    return Err(ChainError {
                        seq: Some(at),
                        reason: Reason::Forked,
                    });
                }
            }
            None => {
                let behind = state.head.is_none_or(|h| anchor.seq > h.seq);
                if behind {
                    return Err(ChainError {
                        seq: state.head.map(|h| h.seq),
                        reason: Reason::RolledBack,
                    });
                }
            }
        }
    }
    Ok(Verified {
        state,
        links,
        divergence,
    })
}
