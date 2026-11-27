//! The server's tables as a chain derives them (S2): turns the state a chain gives, and the boxes
//! and sealed names its newest records committed, into the [`SpaceChanges`] that make the stored
//! space match it.
//!
//! The chain doesn't hold what the server stores for its own sake (when someone was invited,
//! whether they accepted), so those come from the rows that exist and are kept as they are. A
//! member who is `removed` has no row: the chain says "removed" and the server forgets them, as
//! its own remove does. Everything else follows the chain.

use super::chain::{StoredName, StoredSeal};
use super::ports::SpaceChanges;
use kemlock_crypto::space_chain as sc;
use kemlock_domain::policies::{MasterPasswordPolicy, SpacePolicies, TimeoutAction};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CollectionPermission, Confirmation,
    CustomPermissions, Grantee, Group, GroupId, KeyCopy, Member, MemberState, Space, SpaceRole,
    SpaceState,
};
use kemlock_domain::{SpaceId, UserId};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) fn user_of(id: &sc::Id) -> UserId {
    UserId(Uuid::from_bytes(*id))
}

pub(crate) fn id_of(user: UserId) -> sc::Id {
    *user.0.as_bytes()
}

fn collection_of(id: &sc::Id) -> CollectionId {
    CollectionId(Uuid::from_bytes(*id))
}

fn group_of(id: &sc::Id) -> GroupId {
    GroupId(Uuid::from_bytes(*id))
}

pub(crate) fn role_of(role: sc::Role) -> SpaceRole {
    match role {
        sc::Role::Owner => SpaceRole::Owner,
        sc::Role::Admin => SpaceRole::Admin,
        sc::Role::Custom => SpaceRole::Custom,
        sc::Role::Member => SpaceRole::Member,
    }
}

pub(crate) fn custom_of(set: &BTreeSet<sc::CustomPerm>) -> CustomPermissions {
    set.iter().fold(CustomPermissions::NONE, |all, p| {
        all.union(match p {
            sc::CustomPerm::CreateCollections => CustomPermissions::CREATE_COLLECTIONS,
            sc::CustomPerm::ManageGroups => CustomPermissions::MANAGE_GROUPS,
            sc::CustomPerm::ManageUsers => CustomPermissions::MANAGE_USERS,
        })
    })
}

pub(crate) fn permission_of(permission: sc::CollectionPerm) -> CollectionPermission {
    match permission {
        sc::CollectionPerm::View => CollectionPermission::View,
        sc::CollectionPerm::ViewHidePasswords => CollectionPermission::ViewHidePasswords,
        sc::CollectionPerm::Edit => CollectionPermission::Edit,
        sc::CollectionPerm::EditHidePasswords => CollectionPermission::EditHidePasswords,
        sc::CollectionPerm::Manage => CollectionPermission::Manage,
    }
}

fn grantee_of(grantee: &sc::Grantee) -> Grantee {
    match grantee {
        sc::Grantee::User(id) => Grantee::Member(user_of(id)),
        sc::Grantee::Group(id) => Grantee::Group(group_of(id)),
    }
}

/// The server's policy settings the chain's `policies` record sets (docs/crypto.md, "Space chain",
/// `policies`): one to one, with `0` and `false` everywhere in `masterPassword` for no rules, a
/// `minLength` or `minComplexity` of `0` for none, and `minutes: 0` for no timeout. The chain's
/// account recovery and duplicate matching switches have no setting here.
pub fn policies_of(policies: &sc::Policies) -> SpacePolicies {
    let mp = &policies.master_password;
    let master_password =
        (*mp != sc::MasterPasswordPolicy::default()).then(|| MasterPasswordPolicy {
            min_length: (mp.min_length > 0).then_some(u32::from(mp.min_length)),
            min_complexity: (mp.min_complexity > 0).then_some(mp.min_complexity),
            require_upper: mp.require_upper,
            require_lower: mp.require_lower,
            require_numbers: mp.require_numbers,
            require_special: mp.require_special,
            enforce_on_login: mp.enforce_on_login,
        });
    let timeout = &policies.session_timeout;
    let (minutes, action) = if timeout.minutes == 0 {
        (None, None)
    } else {
        (
            Some(timeout.minutes),
            match timeout.action {
                sc::TimeoutAction::None => None,
                sc::TimeoutAction::Lock => Some(TimeoutAction::Lock),
                sc::TimeoutAction::LogOut => Some(TimeoutAction::LogOut),
            },
        )
    };
    SpacePolicies {
        require_sso: policies.require_sso,
        two_step: policies.two_step,
        master_password,
        single_space: policies.single_space,
        disable_export: policies.disable_export,
        disable_send: policies.disable_send,
        always_show_email: policies.always_show_email,
        session_timeout_minutes: minutes,
        session_timeout_action: action,
        no_pin_unlock: policies.no_pin_unlock,
        central_ownership: policies.central_ownership,
        no_card_items: policies.no_card_items,
    }
}

/// The boxes and names the records being stored committed, in the order they were committed: a
/// later one for the same thing replaces an earlier one.
#[derive(Clone, Copy, Debug)]
pub struct Batch<'a> {
    pub seals: &'a [StoredSeal],
    pub names: &'a [StoredName],
}

impl Batch<'_> {
    fn name(&self, target: sc::NameTarget) -> Option<Vec<u8>> {
        self.names
            .iter()
            .rev()
            .find(|n| n.target == target)
            .map(|n| n.sealed.clone())
    }

    fn space_key(&self, member: UserId, version: u32) -> Option<Vec<u8>> {
        self.seals
            .iter()
            .rev()
            .find(|s| s.key == sc::KeyRef::Space && s.member == member && s.version == version)
            .map(|s| s.sealed.clone())
    }
}

/// The changes that make `existing` (the stored space, `None` for a new one) match `after`, and
/// give every collection key sealed in `batch` to its member. `holders` are the key copies stored
/// now. Rows that already match are left out.
pub fn project(
    space: SpaceId,
    existing: Option<&SpaceState>,
    holders: &[(CollectionId, UserId)],
    after: &sc::State,
    batch: Batch<'_>,
    now: OffsetDateTime,
) -> SpaceChanges {
    let mut changes = SpaceChanges::new(space);

    // The space.
    let old_space = existing.map(|s| &s.space);
    let mut row = Space {
        id: space,
        name: batch
            .name(sc::NameTarget::Space)
            .or_else(|| old_space.map(|s| s.name.clone()))
            .unwrap_or_default(),
        key_version: after.space.key_version,
        keys_pending_since: if after.space.marked {
            old_space.and_then(|s| s.keys_pending_since).or(Some(now))
        } else {
            None
        },
        created_at: old_space.map_or(now, |s| s.created_at),
        updated_at: old_space.map_or(now, |s| s.updated_at),
    };
    let space_changed = old_space.is_none_or(|old| {
        old.name != row.name
            || old.key_version != row.key_version
            || old.keys_pending_since != row.keys_pending_since
    });
    if space_changed {
        row.updated_at = now;
        changes.space = Some(row);
    }

    // The members.
    let old_members: BTreeMap<UserId, &Member> = existing
        .into_iter()
        .flat_map(|s| s.members.iter())
        .map(|m| (m.user, m))
        .collect();
    // The members whose row is confirmed once these changes land: only they are sealed keys.
    let mut confirmed_rows: BTreeSet<UserId> = BTreeSet::new();
    for (id, member) in &after.members {
        let user = user_of(id);
        if member.status == sc::Status::Removed {
            if old_members.contains_key(&user) {
                changes.members_removed.push(user);
            }
            continue;
        }
        let old = old_members.get(&user).copied();
        // The invitee's own step, "accepted", is the server's and isn't in the chain: a member the
        // chain holds as confirmed but whose row is still `invited` hasn't consented, so they
        // stay invited. No policy binds them and no key is sealed to them until they accept.
        let consented = old.is_none_or(|o| o.state != MemberState::Invited);
        let confirmed = member.status == sc::Status::Confirmed && consented;
        let state = match (confirmed, old.map(|o| o.state)) {
            (true, _) => MemberState::Confirmed,
            (false, Some(MemberState::Accepted)) => MemberState::Accepted,
            (false, _) => MemberState::Invited,
        };
        let new_box = if confirmed {
            batch.space_key(user, after.space.key_version)
        } else {
            None
        };
        // A box the chain commits is authenticated by the chain and carries no key box signature.
        let (sealed_space_key, sealed_by, key_version) = match (new_box, old) {
            (Some(sealed), _) => (Some(sealed), None, Some(after.space.key_version)),
            (None, Some(o)) if confirmed => (
                o.sealed_space_key.clone(),
                o.sealed_by.clone(),
                o.key_version,
            ),
            _ => (None, None, None),
        };
        let confirmation = match (&member.confirmation, &member.bundle) {
            (Some(c), Some(bundle)) if confirmed => Some(Confirmation {
                by: user_of(&c.by),
                at: old
                    .and_then(|o| o.confirmation.as_ref())
                    .filter(|oc| oc.statement == c.statement)
                    .map_or(now, |oc| oc.at),
                fingerprint: bundle.fingerprint().to_vec(),
                member_key_version: bundle.key_version,
                statement: c.statement.clone(),
                signature: c.signature.clone(),
            }),
            _ => old
                .and_then(|o| o.confirmation.clone())
                .filter(|_| confirmed),
        };
        if state == MemberState::Confirmed {
            confirmed_rows.insert(user);
        }
        let row = Member {
            space,
            user,
            role: role_of(member.role),
            custom: custom_of(&member.custom),
            state,
            invited_by: user_of(&member.invited_by),
            invited_at: old.map_or(now, |o| o.invited_at),
            accepted_at: if state == MemberState::Invited {
                None
            } else {
                old.and_then(|o| o.accepted_at).or(Some(now))
            },
            sealed_space_key,
            sealed_by,
            key_version,
            confirmation,
            revoked_at: None,
        };
        if old != Some(&row) {
            changes.members.push(row);
        }
    }

    // The collections.
    for (id, info) in &after.collections {
        let cid = collection_of(id);
        let old = existing.and_then(|s| s.collection(cid));
        let row = Collection {
            id: cid,
            space,
            parent: info.parent.as_ref().map(collection_of),
            name: batch
                .name(sc::NameTarget::Collection(*id))
                .or_else(|| old.map(|o| o.name.clone()))
                .unwrap_or_default(),
            key_version: info.key_version,
            stale_since: if info.marked {
                old.and_then(|o| o.stale_since).or(Some(now))
            } else {
                None
            },
            created_at: old.map_or(now, |o| o.created_at),
        };
        if old != Some(&row) {
            changes.collections.push(row);
        }
    }
    if let Some(state) = existing {
        for old in &state.collections {
            if !after.collections.contains_key(old.id.as_bytes()) {
                changes.collections_removed.push(old.id);
            }
        }
    }

    // The groups.
    for (id, info) in &after.groups {
        let gid = group_of(id);
        let old = existing.and_then(|s| s.group(gid));
        let row = Group {
            id: gid,
            space,
            name: batch
                .name(sc::NameTarget::Group(*id))
                .or_else(|| old.map(|o| o.name.clone()))
                .unwrap_or_default(),
            members: info.members.iter().map(user_of).collect(),
            created_at: old.map_or(now, |o| o.created_at),
        };
        if old != Some(&row) {
            changes.groups.push(row);
        }
    }
    if let Some(state) = existing {
        for old in &state.groups {
            if !after.groups.contains_key(old.id.as_bytes()) {
                changes.groups_removed.push(old.id);
            }
        }
    }

    // The grants.
    let old_grants: BTreeMap<(CollectionId, Grantee), CollectionPermission> = existing
        .into_iter()
        .flat_map(|s| s.grants.iter())
        .map(|g| ((g.collection, g.grantee), g.permission))
        .collect();
    let mut new_grants: BTreeMap<(CollectionId, Grantee), CollectionPermission> = BTreeMap::new();
    for ((collection, grantee), permission) in &after.grants {
        new_grants.insert(
            (collection_of(collection), grantee_of(grantee)),
            permission_of(*permission),
        );
    }
    for ((collection, grantee), permission) in &new_grants {
        if old_grants.get(&(*collection, *grantee)) != Some(permission) {
            changes.grants.push(CollectionGrant {
                collection: *collection,
                grantee: *grantee,
                permission: *permission,
            });
        }
    }
    for (collection, grantee) in old_grants.keys() {
        if !new_grants.contains_key(&(*collection, *grantee))
            && after.collections.contains_key(collection.as_bytes())
        {
            changes.grants_removed.push((*collection, *grantee));
        }
    }

    // The collection keys: a copy for every member the chain sealed the current version to, and
    // none for anyone else.
    let mut desired: BTreeSet<(CollectionId, UserId)> = BTreeSet::new();
    for (key, version, member) in after.seals.keys() {
        let sc::KeyRef::Collection(id) = key else {
            continue;
        };
        let current = after
            .collections
            .get(id)
            .is_some_and(|c| c.key_version == *version);
        let present = after
            .members
            .get(member)
            .is_some_and(|m| m.status != sc::Status::Removed)
            && confirmed_rows.contains(&user_of(member));
        if current && present {
            desired.insert((collection_of(id), user_of(member)));
        }
    }
    let mut copies: BTreeMap<(CollectionId, UserId), KeyCopy> = BTreeMap::new();
    for seal in batch.seals {
        let sc::KeyRef::Collection(id) = &seal.key else {
            continue;
        };
        let pair = (collection_of(id), seal.member);
        let current = after
            .collections
            .get(id)
            .is_some_and(|c| c.key_version == seal.version);
        if current && desired.contains(&pair) {
            copies.insert(
                pair,
                KeyCopy {
                    collection: pair.0,
                    user: pair.1,
                    key_version: seal.version,
                    sealed: seal.sealed.clone(),
                    sealed_by: None,
                },
            );
        }
    }
    changes.key_copies = copies.into_values().collect();
    for (collection, user) in holders {
        if after.collections.contains_key(collection.as_bytes())
            && !desired.contains(&(*collection, *user))
        {
            changes.key_copies_removed.push((*collection, *user));
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_roles_map_both_ways() {
        let user = UserId(Uuid::from_u128(7));
        assert_eq!(user_of(&id_of(user)), user);
        assert_eq!(role_of(sc::Role::Owner), SpaceRole::Owner);
        assert_eq!(role_of(sc::Role::Member), SpaceRole::Member);
        let set: BTreeSet<sc::CustomPerm> = [
            sc::CustomPerm::ManageUsers,
            sc::CustomPerm::CreateCollections,
        ]
        .into();
        let bits = custom_of(&set);
        assert!(bits.contains(CustomPermissions::MANAGE_USERS));
        assert!(bits.contains(CustomPermissions::CREATE_COLLECTIONS));
        assert!(!bits.contains(CustomPermissions::MANAGE_GROUPS));
        assert_eq!(custom_of(&BTreeSet::new()), CustomPermissions::NONE);
    }

    #[test]
    fn the_chains_policies_map_to_the_servers_settings() {
        let none = policies_of(&sc::Policies::default());
        assert_eq!(none, SpacePolicies::default());

        let set = sc::Policies {
            require_sso: true,
            two_step: true,
            single_space: true,
            master_password: sc::MasterPasswordPolicy {
                min_length: 14,
                require_numbers: true,
                ..sc::MasterPasswordPolicy::default()
            },
            session_timeout: sc::SessionTimeoutPolicy {
                action: sc::TimeoutAction::LogOut,
                minutes: 30,
            },
            ..sc::Policies::default()
        };
        let mapped = policies_of(&set);
        assert!(mapped.require_sso && mapped.two_step && mapped.single_space);
        assert!(!mapped.disable_send);
        assert_eq!(
            mapped.master_password,
            Some(MasterPasswordPolicy {
                min_length: Some(14),
                min_complexity: None,
                require_numbers: true,
                ..MasterPasswordPolicy::default()
            })
        );
        assert_eq!(mapped.session_timeout_minutes, Some(30));
        assert_eq!(mapped.session_timeout_action, Some(TimeoutAction::LogOut));
        assert!(mapped.validate().is_ok());
    }

    #[test]
    fn an_empty_state_projects_to_an_empty_space() {
        let space = SpaceId(Uuid::from_u128(1));
        let now = OffsetDateTime::UNIX_EPOCH;
        let state = sc::State::empty();
        let batch = Batch {
            seals: &[],
            names: &[],
        };
        let changes = project(space, None, &[], &state, batch, now);
        assert!(changes.members.is_empty() && changes.collections.is_empty());
        assert!(changes.grants.is_empty() && changes.key_copies.is_empty());
    }
}
