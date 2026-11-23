//! The state a chain gives (docs/crypto.md, "Space chain", "State"), and the questions the rules
//! ask of it.

use std::collections::{BTreeMap, BTreeSet};

use super::model::{CollectionPerm, CustomPerm, Grantee, Hash, Id, KeyRef, Policies, Rights, Role};
use crate::bundle::Bundle;

/// `(seq, link)` of the last record of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub link: Hash,
}

/// The server and promotion hash of the last `fence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Home {
    pub server: Id,
    pub promotion: Hash,
}

/// Where a member stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Invited,
    Confirmed,
    Removed,
}

/// Who confirmed a member and what they signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub by: Id,
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
    pub seq: u64,
}

/// One member of the space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub role: Role,
    pub custom: BTreeSet<CustomPerm>,
    pub status: Status,
    pub invited_by: Id,
    /// Once confirmed: the member's bundle, its self-signature, and either the confirmation or
    /// the `seq` of the member's last `rekey`.
    pub bundle: Option<Bundle>,
    pub bundle_signature: Vec<u8>,
    pub confirmation: Option<Confirmation>,
    pub rekey_seq: Option<u64>,
}

impl Member {
    /// The bundle's key version, or `0` when there is no bundle.
    pub fn bundle_version(&self) -> u32 {
        self.bundle.as_ref().map_or(0, |b| b.key_version)
    }
}

/// The space's own key and name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceInfo {
    pub key_version: u32,
    pub marked: bool,
    pub name_hash: Hash,
    pub name_version: u32,
}

/// One collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectionInfo {
    pub parent: Option<Id>,
    pub name_hash: Hash,
    pub name_version: u32,
    pub key_version: u32,
    pub marked: bool,
}

/// One group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    pub name_hash: Hash,
    pub name_version: u32,
    pub members: BTreeSet<Id>,
}

/// A seal the chain committed: the bundle key version it is to, and the `seq` of the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealEntry {
    pub bundle_version: u32,
    pub seq: u64,
}

/// What a record committed for one key version: the count, the digest, and the recipients the
/// verifier derived for it, in ascending order of id with the bundle key version of each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    pub count: u32,
    pub digest: Hash,
    pub recipients: Vec<(Id, u32)>,
}

/// The state of a space, as its chain gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub head: Option<Head>,
    pub epoch: u32,
    pub home: Option<Home>,
    pub members: BTreeMap<Id, Member>,
    pub space: SpaceInfo,
    pub collections: BTreeMap<Id, CollectionInfo>,
    pub groups: BTreeMap<Id, GroupInfo>,
    pub grants: BTreeMap<(Id, Grantee), CollectionPerm>,
    pub key_checks: BTreeMap<(KeyRef, u32), Hash>,
    pub seals: BTreeMap<(KeyRef, u32, Id), SealEntry>,
    pub commitments: BTreeMap<(KeyRef, u32, u64), Committed>,
    pub retired: BTreeSet<Id>,
    pub policies: Policies,
    pub recovery_key: Option<Vec<u8>>,
    /// The `seq` of the `recovery-key` record that set `recovery_key`; `None` with it.
    pub recovery_key_seq: Option<u64>,
}

impl State {
    /// The state before the first record.
    pub fn empty() -> State {
        State {
            head: None,
            epoch: 0,
            home: None,
            members: BTreeMap::new(),
            space: SpaceInfo {
                key_version: 0,
                marked: false,
                name_hash: [0; 32],
                name_version: 0,
            },
            collections: BTreeMap::new(),
            groups: BTreeMap::new(),
            grants: BTreeMap::new(),
            key_checks: BTreeMap::new(),
            seals: BTreeMap::new(),
            commitments: BTreeMap::new(),
            retired: BTreeSet::new(),
            policies: Policies::default(),
            recovery_key: None,
            recovery_key_seq: None,
        }
    }

    /// A member whose status is `invited` or `confirmed`.
    pub fn in_space(&self, id: &Id) -> bool {
        self.members
            .get(id)
            .is_some_and(|m| m.status != Status::Removed)
    }

    /// The member, when confirmed.
    pub fn confirmed(&self, id: &Id) -> Option<&Member> {
        self.members
            .get(id)
            .filter(|m| m.status == Status::Confirmed)
    }

    pub fn is_owner(&self, id: &Id) -> bool {
        self.members
            .get(id)
            .is_some_and(|m| m.status != Status::Removed && m.role == Role::Owner)
    }

    /// The current version of a key, or `None` when the key doesn't exist.
    pub fn key_version(&self, key: &KeyRef) -> Option<u32> {
        match key {
            KeyRef::Space => self.head.is_some().then_some(self.space.key_version),
            KeyRef::Collection(id) => self.collections.get(id).map(|c| c.key_version),
        }
    }

    /// Whether the key is marked and waits to be replaced.
    pub fn key_marked(&self, key: &KeyRef) -> bool {
        match key {
            KeyRef::Space => self.space.marked,
            KeyRef::Collection(id) => self.collections.get(id).is_some_and(|c| c.marked),
        }
    }

    /// Every key that exists: the space key and each collection's.
    pub fn keys(&self) -> Vec<KeyRef> {
        let mut keys: Vec<KeyRef> = self
            .collections
            .keys()
            .map(|id| KeyRef::Collection(*id))
            .collect();
        if self.head.is_some() {
            keys.push(KeyRef::Space);
        }
        keys
    }

    /// Every member's access to one collection, from the grants to them and to the groups that
    /// hold them. A member with no grant has no entry; status isn't looked at.
    pub fn access_map(&self, collection: &Id) -> BTreeMap<Id, Rights> {
        let mut out: BTreeMap<Id, Rights> = BTreeMap::new();
        let mut add = |who: Id, rights: Rights| {
            out.entry(who)
                .and_modify(|r| *r = r.combine(rights))
                .or_insert(rights);
        };
        let range =
            (*collection, Grantee::Group([0; 16]))..=(*collection, Grantee::User([0xff; 16]));
        for ((_, grantee), perm) in self.grants.range(range) {
            let rights = perm.rights();
            match grantee {
                Grantee::User(id) => add(*id, rights),
                Grantee::Group(id) => {
                    if let Some(group) = self.groups.get(id) {
                        for member in &group.members {
                            add(*member, rights);
                        }
                    }
                }
            }
        }
        out
    }

    /// One member's access to one collection.
    pub fn access(&self, member: &Id, collection: &Id) -> Option<Rights> {
        self.access_map(collection).get(member).copied()
    }

    /// The members entitled to a key: every confirmed member for the space key, and the confirmed
    /// members with access for a collection's.
    pub fn entitled(&self, key: &KeyRef) -> BTreeSet<Id> {
        match key {
            KeyRef::Space => self
                .members
                .iter()
                .filter(|(_, m)| m.status == Status::Confirmed)
                .map(|(id, _)| *id)
                .collect(),
            KeyRef::Collection(id) => self
                .access_map(id)
                .into_keys()
                .filter(|m| self.confirmed(m).is_some())
                .collect(),
        }
    }

    /// Whether the member holds the key's current version, sealed to any bundle version.
    pub fn holds(&self, member: &Id, key: &KeyRef) -> bool {
        self.key_version(key)
            .is_some_and(|v| self.seals.contains_key(&(*key, v, *member)))
    }

    /// Whether the key's current version is sealed to the member's current bundle version.
    pub fn covered(&self, member: &Id, key: &KeyRef) -> bool {
        let Some(version) = self.key_version(key) else {
            return false;
        };
        match (
            self.seals.get(&(*key, version, *member)),
            self.members.get(member),
        ) {
            (Some(seal), Some(m)) => seal.bundle_version == m.bundle_version(),
            _ => false,
        }
    }

    /// The members entitled to the key who aren't covered for it.
    pub fn awaiting(&self, key: &KeyRef) -> BTreeSet<Id> {
        self.entitled(key)
            .into_iter()
            .filter(|m| !self.covered(m, key))
            .collect()
    }

    /// The members with their current bundle key versions, in ascending order of id: the
    /// recipients of a commitment.
    pub fn recipients(&self, members: &BTreeSet<Id>) -> Vec<(Id, u32)> {
        members
            .iter()
            .map(|id| (*id, self.members.get(id).map_or(0, Member::bundle_version)))
            .collect()
    }

    /// How deep a collection is: `1` at the top level.
    pub fn depth(&self, collection: &Id) -> usize {
        let mut depth = 0;
        let mut at = Some(*collection);
        while let Some(id) = at {
            depth += 1;
            if depth > 64 {
                break;
            }
            at = self.collections.get(&id).and_then(|c| c.parent);
        }
        depth
    }

    /// The groups that hold a member.
    pub fn groups_of(&self, member: &Id) -> BTreeSet<Id> {
        self.groups
            .iter()
            .filter(|(_, g)| g.members.contains(member))
            .map(|(id, _)| *id)
            .collect()
    }

    /// The keys across a record from `self` to `next` that a member held and is no longer entitled
    /// to ("Lost"), for keys at the same version in both.
    pub fn lost(&self, next: &State) -> BTreeSet<KeyRef> {
        let mut out = BTreeSet::new();
        for key in self.keys() {
            if next.key_version(&key) != self.key_version(&key) {
                continue;
            }
            let after = next.entitled(&key);
            if self
                .entitled(&key)
                .iter()
                .any(|m| self.holds(m, &key) && !after.contains(m))
            {
                out.insert(key);
            }
        }
        out
    }

    /// Marks keys for replacement.
    pub fn mark(&mut self, keys: &BTreeSet<KeyRef>) {
        for key in keys {
            match key {
                KeyRef::Space => self.space.marked = true,
                KeyRef::Collection(id) => {
                    if let Some(c) = self.collections.get_mut(id) {
                        c.marked = true;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(status: Status) -> Member {
        Member {
            role: Role::Member,
            custom: BTreeSet::new(),
            status,
            invited_by: [0; 16],
            bundle: None,
            bundle_signature: Vec::new(),
            confirmation: None,
            rekey_seq: None,
        }
    }

    #[test]
    fn access_combines_user_and_group_grants() {
        let (c, u, g) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let mut s = State::empty();
        s.members.insert(u, member(Status::Confirmed));
        s.groups.insert(
            g,
            GroupInfo {
                name_hash: [0; 32],
                name_version: 1,
                members: BTreeSet::from([u]),
            },
        );
        assert_eq!(s.access(&u, &c), None);
        s.grants
            .insert((c, Grantee::User(u)), CollectionPerm::ViewHidePasswords);
        let r = s.access(&u, &c).expect("access");
        assert!(r.hide_passwords && !r.edit);
        s.grants
            .insert((c, Grantee::Group(g)), CollectionPerm::Edit);
        let r = s.access(&u, &c).expect("access");
        assert!(r.edit && !r.hide_passwords && !r.manage);
        // Another collection's grants don't leak in.
        s.grants
            .insert(([2u8; 16], Grantee::User(u)), CollectionPerm::Manage);
        assert!(!s.access(&u, &c).expect("access").manage);
    }

    #[test]
    fn entitlement_needs_confirmation() {
        let (c, a, b) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let mut s = State::empty();
        s.members.insert(a, member(Status::Confirmed));
        s.members.insert(b, member(Status::Invited));
        s.grants.insert((c, Grantee::User(a)), CollectionPerm::View);
        s.grants.insert((c, Grantee::User(b)), CollectionPerm::View);
        assert_eq!(s.entitled(&KeyRef::Collection(c)), BTreeSet::from([a]));
        assert_eq!(s.entitled(&KeyRef::Space), BTreeSet::from([a]));
        assert!(s.in_space(&b));
        assert!(s.confirmed(&b).is_none());
    }

    #[test]
    fn depth_counts_from_the_top() {
        let (a, b, c) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let mut s = State::empty();
        for (id, parent) in [(a, None), (b, Some(a)), (c, Some(b))] {
            s.collections.insert(
                id,
                CollectionInfo {
                    parent,
                    name_hash: [0; 32],
                    name_version: 1,
                    key_version: 1,
                    marked: false,
                },
            );
        }
        assert_eq!((s.depth(&a), s.depth(&b), s.depth(&c)), (1, 2, 3));
    }
}
