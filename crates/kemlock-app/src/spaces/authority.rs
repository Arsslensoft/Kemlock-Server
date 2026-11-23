//! The chain's authority rules (docs/crypto.md, "Space chain": "Authority") for spaces that have no
//! chain, so a plain space can't be talked into what a chained one refuses.
//!
//! The rules in `kemlock_domain::spaces` say who may make each kind of change. These three say
//! what no change may do whoever makes it, and each use case that changes members, roles, groups
//! or grants asks them with the state before and the state after:
//!
//! 1. **Owners change Owners.** A change that touches an Owner (their role, permissions or state,
//!    their group seats, or their access to a collection that exists before and after) is an
//!    Owner's.
//! 2. **Nobody widens themselves.** A change doesn't widen the actor's own role or permissions,
//!    nor their access to a collection.
//! 3. **Access changes need MayGrant.** Anyone's access to a collection that exists before and
//!    after changes only when the actor is an Owner or Admin or has `manage` on it. The access of a
//!    member being removed is left out: the right to remove them covers it.

use kemlock_domain::UserId;
use kemlock_domain::spaces::{
    Access, CollectionId, CustomPermissions, Grantee, MemberState, SpaceError, SpaceRole,
    SpaceState,
};
use std::collections::{BTreeMap, BTreeSet};

/// Every member's access to one collection: their grants, and the grants to the groups that hold
/// them, combined. Status isn't looked at.
fn access_map(state: &SpaceState, collection: CollectionId) -> BTreeMap<UserId, Access> {
    let mut out: BTreeMap<UserId, Access> = BTreeMap::new();
    let mut add = |user: UserId, access: Access| {
        out.entry(user)
            .and_modify(|a| *a = a.combine(access))
            .or_insert(access);
    };
    for grant in state.grants.iter().filter(|g| g.collection == collection) {
        let access = grant.permission.access();
        match grant.grantee {
            Grantee::Member(user) => add(user, access),
            Grantee::Group(group) => {
                if let Some(group) = state.group(group) {
                    for user in &group.members {
                        add(*user, access);
                    }
                }
            }
        }
    }
    out
}

/// One member's access to one collection before and after a change.
struct Change {
    collection: CollectionId,
    user: UserId,
    before: Option<Access>,
    after: Option<Access>,
}

fn widens(before: Option<Access>, after: Option<Access>) -> bool {
    match (before, after) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(a), Some(b)) => {
            (b.edit && !a.edit)
                || (b.manage && !a.manage)
                || (a.hide_passwords && !b.hide_passwords)
        }
    }
}

fn rank(role: SpaceRole) -> u8 {
    match role {
        SpaceRole::Owner => 3,
        SpaceRole::Admin => 2,
        SpaceRole::Custom => 1,
        SpaceRole::Member => 0,
    }
}

/// Whether the role and permissions after are no wider than before.
fn not_wider(
    after: (SpaceRole, CustomPermissions),
    before: (SpaceRole, CustomPermissions),
) -> bool {
    if after.0 != before.0 {
        return rank(after.0) < rank(before.0);
    }
    after.0 != SpaceRole::Custom || after.1.is_subset_of(before.1)
}

fn access_changes(before: &SpaceState, after: &SpaceState) -> Vec<Change> {
    let mut out = Vec::new();
    for collection in &before.collections {
        if after.collection(collection.id).is_none() {
            continue;
        }
        let was = access_map(before, collection.id);
        let now = access_map(after, collection.id);
        let users: BTreeSet<UserId> = was.keys().chain(now.keys()).copied().collect();
        for user in users {
            let (b, a) = (was.get(&user).copied(), now.get(&user).copied());
            if b != a {
                out.push(Change {
                    collection: collection.id,
                    user,
                    before: b,
                    after: a,
                });
            }
        }
    }
    out
}

fn groups_of(state: &SpaceState, user: UserId) -> BTreeSet<kemlock_domain::spaces::GroupId> {
    state
        .groups
        .iter()
        .filter(|g| g.members.contains(&user))
        .map(|g| g.id)
        .collect()
}

/// Checks a change from `before` to `after` made by `actor`, a confirmed member of `before`.
/// `removed` is the member the change takes out, if it does.
pub(crate) fn check(
    before: &SpaceState,
    after: &SpaceState,
    actor: UserId,
    removed: Option<UserId>,
) -> Result<(), SpaceError> {
    let me = before.confirmed_actor(actor)?;
    let changes = access_changes(before, after);

    // Rule 1.
    if me.role != SpaceRole::Owner {
        let owners: BTreeSet<UserId> = before
            .members
            .iter()
            .chain(after.members.iter())
            .filter(|m| m.state != MemberState::Revoked && m.role == SpaceRole::Owner)
            .map(|m| m.user)
            .collect();
        let touched = owners.iter().any(|owner| {
            let (was, now) = (before.member(*owner), after.member(*owner));
            let same = match (was, now) {
                (Some(a), Some(b)) => {
                    a.role == b.role && a.custom == b.custom && a.state == b.state
                }
                _ => false,
            };
            !same
                || groups_of(before, *owner) != groups_of(after, *owner)
                || changes.iter().any(|c| c.user == *owner)
        });
        if touched {
            return Err(SpaceError::Forbidden("only an owner changes an owner"));
        }
    }

    // Rule 2.
    if let Some(now) = after.member(actor)
        && !not_wider((now.role, now.custom), (me.role, me.custom))
    {
        return Err(SpaceError::Forbidden(
            "nobody widens their own role or permissions",
        ));
    }
    if changes
        .iter()
        .any(|c| c.user == actor && widens(c.before, c.after))
    {
        return Err(SpaceError::Forbidden("nobody widens their own access"));
    }

    // Rule 3.
    let privileged = matches!(me.role, SpaceRole::Owner | SpaceRole::Admin);
    let mut manages: BTreeMap<CollectionId, bool> = BTreeMap::new();
    for change in &changes {
        if Some(change.user) == removed || privileged {
            continue;
        }
        let may = *manages.entry(change.collection).or_insert_with(|| {
            access_map(before, change.collection)
                .get(&actor)
                .is_some_and(|a| a.manage)
        });
        if !may {
            return Err(SpaceError::Forbidden(
                "only an owner, an admin or someone who manages a collection changes who can open it",
            ));
        }
    }
    Ok(())
}

/// Whether a Custom member may manage a target: the target's permissions must all be among theirs
/// ("Manage" in the authority table).
pub(crate) fn custom_may_manage(actor: CustomPermissions, target: CustomPermissions) -> bool {
    target.is_subset_of(actor)
}

/// Refuses a Custom actor who manages a member holding a permission they lack themselves. Owners
/// and admins, and a member acting on themselves, pass.
pub(crate) fn ensure_manage(
    state: &SpaceState,
    actor: UserId,
    target: UserId,
) -> Result<(), SpaceError> {
    let me = state.confirmed_actor(actor)?;
    if me.role != SpaceRole::Custom || target == actor {
        return Ok(());
    }
    match state.member(target) {
        Some(t) if !custom_may_manage(me.custom, t.custom) => Err(SpaceError::Forbidden(
            "a custom member manages only members whose permissions they hold themselves",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::SpaceId;
    use kemlock_domain::spaces::{
        Collection, CollectionGrant, CollectionPermission, Group, GroupId, Member, Space,
    };
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn member(n: u128, role: SpaceRole, custom: CustomPermissions) -> Member {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut m = Member::invited(
            SpaceId(id(1)),
            UserId(id(n)),
            role,
            custom,
            UserId(id(10)),
            now,
        );
        m.state = MemberState::Confirmed;
        m
    }

    fn base() -> SpaceState {
        let now = OffsetDateTime::UNIX_EPOCH;
        SpaceState {
            space: Space {
                id: SpaceId(id(1)),
                name: vec![],
                key_version: 1,
                keys_pending_since: None,
                created_at: now,
                updated_at: now,
            },
            members: vec![
                member(10, SpaceRole::Owner, CustomPermissions::NONE),
                member(11, SpaceRole::Owner, CustomPermissions::NONE),
                member(12, SpaceRole::Admin, CustomPermissions::NONE),
                member(13, SpaceRole::Custom, CustomPermissions::MANAGE_GROUPS),
                member(14, SpaceRole::Member, CustomPermissions::NONE),
            ],
            groups: vec![Group {
                id: GroupId(id(30)),
                space: SpaceId(id(1)),
                name: vec![],
                members: BTreeSet::new(),
                created_at: now,
            }],
            collections: vec![Collection {
                id: CollectionId(id(20)),
                space: SpaceId(id(1)),
                parent: None,
                name: vec![],
                key_version: 1,
                stale_since: None,
                created_at: now,
            }],
            grants: vec![CollectionGrant {
                collection: CollectionId(id(20)),
                grantee: Grantee::Group(GroupId(id(30))),
                permission: CollectionPermission::View,
            }],
        }
    }

    fn user(n: u128) -> UserId {
        UserId(id(n))
    }

    fn join(state: &mut SpaceState, who: u128) {
        state.groups[0].members.insert(user(who));
    }

    #[test]
    fn a_group_manager_may_not_add_themselves_to_a_granted_group() {
        let before = base();
        let mut after = before.clone();
        join(&mut after, 13);
        assert!(check(&before, &after, user(13), None).is_err());
        // Adding someone else needs MayGrant too.
        let mut after = before.clone();
        join(&mut after, 14);
        assert!(check(&before, &after, user(13), None).is_err());
        // An admin may.
        assert!(check(&before, &after, user(12), None).is_ok());
    }

    #[test]
    fn a_group_with_no_grants_changes_no_access() {
        let mut before = base();
        before.grants.clear();
        let mut after = before.clone();
        join(&mut after, 13);
        assert!(check(&before, &after, user(13), None).is_ok());
    }

    #[test]
    fn managing_the_collection_lets_a_custom_member_add_to_its_group() {
        let mut before = base();
        before.grants.push(CollectionGrant {
            collection: CollectionId(id(20)),
            grantee: Grantee::Member(user(13)),
            permission: CollectionPermission::Manage,
        });
        let mut after = before.clone();
        join(&mut after, 14);
        assert!(check(&before, &after, user(13), None).is_ok());
    }

    #[test]
    fn only_an_owner_changes_an_owner() {
        let before = base();
        // Demoting an owner.
        let mut after = before.clone();
        after.members[1].role = SpaceRole::Admin;
        assert_eq!(
            check(&before, &after, user(12), None),
            Err(SpaceError::Forbidden("only an owner changes an owner"))
        );
        assert!(check(&before, &after, user(10), None).is_ok());
        // Taking an owner out of a group.
        let mut with_owner = before.clone();
        join(&mut with_owner, 11);
        let mut without = with_owner.clone();
        without.groups[0].members.clear();
        assert!(check(&with_owner, &without, user(12), None).is_err());
        assert!(check(&with_owner, &without, user(10), None).is_ok());
    }

    #[test]
    fn nobody_widens_their_own_role() {
        let before = base();
        let mut after = before.clone();
        after.members[2].role = SpaceRole::Owner;
        assert!(check(&before, &after, user(12), None).is_err());
        let mut after = before.clone();
        after.members[3].custom =
            CustomPermissions::MANAGE_GROUPS.union(CustomPermissions::MANAGE_USERS);
        assert!(check(&before, &after, user(13), None).is_err());
        // A narrower set is fine.
        let mut after = before.clone();
        after.members[3].custom = CustomPermissions::NONE;
        assert!(check(&before, &after, user(13), None).is_ok());
    }

    #[test]
    fn a_removed_members_access_is_the_removers_to_take() {
        let mut before = base();
        before.groups[0].members.insert(user(14));
        let mut after = before.clone();
        after.groups[0].members.remove(&user(14));
        after.members.retain(|m| m.user != user(14));
        // Not allowed as a plain access change by someone who can't grant, allowed when it is the
        // removal of that member.
        assert!(check(&before, &after, user(13), None).is_err());
        assert!(check(&before, &after, user(13), Some(user(14))).is_ok());
    }

    #[test]
    fn ensure_manage_looks_at_the_targets_permissions() {
        let mut state = base();
        state.members[4].role = SpaceRole::Custom;
        state.members[4].custom = CustomPermissions::CREATE_COLLECTIONS;
        // Member 13 holds manage-groups only.
        assert!(ensure_manage(&state, user(13), user(14)).is_err());
        assert!(ensure_manage(&state, user(13), user(13)).is_ok());
        assert!(ensure_manage(&state, user(12), user(14)).is_ok());
        state.members[4].custom = CustomPermissions::NONE;
        assert!(ensure_manage(&state, user(13), user(14)).is_ok());
    }

    #[test]
    fn a_custom_member_manages_only_what_they_hold() {
        let users = CustomPermissions::MANAGE_USERS;
        let creator = CustomPermissions::CREATE_COLLECTIONS;
        assert!(custom_may_manage(users.union(creator), creator));
        assert!(!custom_may_manage(users, creator));
        assert!(custom_may_manage(users, CustomPermissions::NONE));
    }
}
