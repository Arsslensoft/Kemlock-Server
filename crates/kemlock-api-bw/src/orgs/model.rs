//! An organization as the Bitwarden API sees it: a space, plus the side documents that hold what
//! Bitwarden has and a space doesn't.
//!
//! Spaces keep the structure Kemlock's own rules need: members with a role and a state, groups,
//! collections and grants. The documents (`bw_docs`, see [`kemlock_app::bitwarden::BwOrgStore`])
//! keep the rest: the organization's RSA key pair, each member's wrapped organization key,
//! policies, external ids, the links between ciphers and collections. A space with no `org`
//! document is not an organization to a Bitwarden app.
//!
//! A member's id on the wire is their account's id, so a member and an account never need a
//! mapping. Someone invited by an email that has no account yet has a pending invitation instead,
//! with a fresh id, which the registration of that email turns into a member.

use kemlock_domain::spaces::{
    Collection, CollectionId, CollectionPermission, Grantee, Group, GroupId, SpaceState,
};
use kemlock_domain::{SpaceId, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) const KIND_ORG: &str = "org";
pub(crate) const KIND_MEMBER: &str = "member";
pub(crate) const KIND_PENDING: &str = "pending";
pub(crate) const KIND_COLLECTION: &str = "collection";
pub(crate) const KIND_GROUP: &str = "group";
pub(crate) const KIND_POLICY: &str = "policy";
/// Scope: the organization; key: empty; body: its API key.
pub(crate) const KIND_API_KEY: &str = "apikey";
/// Scope: the organization; key: a cipher id; body: the ids of the collections it is in.
pub(crate) const KIND_LINKS: &str = "cc";
/// Scope: an account; key: a cipher id; body: that account's folder, favourite and archive of it.
pub(crate) const KIND_PREFS: &str = "orgpref";

/// Vaultwarden's `MembershipType`.
pub(crate) const OWNER: i32 = 0;
pub(crate) const ADMIN: i32 = 1;
pub(crate) const USER: i32 = 2;
pub(crate) const MANAGER: i32 = 3;

/// Vaultwarden's `MembershipStatus`.
pub(crate) const REVOKED: i32 = -1;
pub(crate) const INVITED: i32 = 0;
pub(crate) const ACCEPTED: i32 = 1;
pub(crate) const CONFIRMED: i32 = 2;

/// A revoked member keeps their status minus this, so a restore brings it back.
pub(crate) const REVOKE_DIFF: i32 = 128;

/// Where an access level stands: owner above admin above manager above user (Vaultwarden's `Ord`
/// of `MembershipType`).
pub(crate) fn level(atype: i32) -> i32 {
    match atype {
        OWNER => 3,
        ADMIN => 2,
        MANAGER => 1,
        _ => 0,
    }
}

/// Vaultwarden's `MembershipType::from_str`: a name or a number; Custom (4) becomes Manager.
pub(crate) fn parse_type(raw: &str) -> Option<i32> {
    match raw {
        "0" | "Owner" => Some(OWNER),
        "1" | "Admin" => Some(ADMIN),
        "2" | "User" => Some(USER),
        "3" | "Manager" | "4" | "Custom" => Some(MANAGER),
        _ => None,
    }
}

/// `organization`'s own document: the key pair and the billing address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OrgDoc {
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

/// One account's Bitwarden membership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberDoc {
    /// The organization key wrapped to this member's RSA key; empty until confirmed.
    pub akey: String,
    pub access_all: bool,
    pub atype: i32,
    /// Vaultwarden's status: 0 to 2, and that minus 128 while revoked.
    pub status: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
    pub invited_by_email: Option<String>,
}

impl MemberDoc {
    pub(crate) fn new(atype: i32, access_all: bool, status: i32) -> Self {
        MemberDoc {
            akey: String::new(),
            access_all,
            atype,
            status,
            reset_password_key: None,
            external_id: None,
            invited_by_email: None,
        }
    }

    pub(crate) fn revoked(&self) -> bool {
        self.status < INVITED
    }

    /// The status the member has when not revoked.
    pub(crate) fn unrevoked_status(&self) -> i32 {
        if self.status <= REVOKED {
            self.status + REVOKE_DIFF
        } else {
            self.status
        }
    }

    /// The status on the wire: every revoked member is -1.
    pub(crate) fn wire_status(&self) -> i32 {
        if self.status < REVOKED {
            REVOKED
        } else {
            self.status
        }
    }

    pub(crate) fn confirmed(&self) -> bool {
        self.status == CONFIRMED
    }

    /// Confirmed, and either access to everything or at least an admin.
    pub(crate) fn full_access(&self) -> bool {
        (self.access_all || level(self.atype) >= level(ADMIN)) && self.confirmed()
    }

    pub(crate) fn revoke(&mut self) -> bool {
        if self.status > REVOKED {
            self.status -= REVOKE_DIFF;
            return true;
        }
        false
    }

    pub(crate) fn restore(&mut self) -> bool {
        if self.status < INVITED {
            self.status += REVOKE_DIFF;
            return true;
        }
        false
    }

    /// Manager as Custom, the way clients see it.
    pub(crate) fn wire_type(&self) -> i32 {
        if self.atype == MANAGER { 4 } else { self.atype }
    }
}

/// What a collection or group is given to one member, or one group, as Bitwarden's three flags.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessDoc {
    pub id: String,
    pub read_only: bool,
    pub hide_passwords: bool,
    #[serde(default)]
    pub manage: bool,
}

/// An invitation to an email with no account yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingDoc {
    /// The id the member shows as until they register.
    pub id: String,
    pub email: String,
    pub atype: i32,
    pub access_all: bool,
    pub collections: Vec<AccessDoc>,
    pub groups: Vec<String>,
    pub invited_by_email: Option<String>,
    pub invited_by: String,
    /// The directory's id for the person, when the public API's import invited them.
    #[serde(default)]
    pub external_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CollectionDoc {
    pub external_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupDoc {
    pub access_all: bool,
    pub external_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyDoc {
    pub id: String,
    pub enabled: bool,
    /// The policy's data as JSON text, `null` when it has none.
    pub data: String,
    pub revision_date: String,
}

/// The organization's API key (Vaultwarden's `organization_api_key`): what the Directory Connector
/// signs in with, to the public API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiKeyDoc {
    /// The key's own id, which a token made from it names as its subject.
    pub id: String,
    pub api_key: String,
    /// Vaultwarden's `atype`: 0, the default key.
    pub atype: i32,
    pub revision_date: String,
}

/// One account's folder, favourite and archive of an organization cipher: per account in
/// Bitwarden, so they can't live in the cipher.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrefDoc {
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub archived_date: Option<String>,
}

/// Bitwarden's three collection flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Restrict {
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

impl Restrict {
    /// Nothing restricted, and the right to manage.
    pub(crate) const FULL: Restrict = Restrict {
        read_only: false,
        hide_passwords: false,
        manage: true,
    };

    pub(crate) fn from_permission(permission: CollectionPermission) -> Restrict {
        let access = permission.access();
        Restrict {
            read_only: !access.edit,
            hide_passwords: access.hide_passwords,
            manage: access.manage,
        }
    }

    /// Whether the flags allow changing the cipher.
    pub(crate) fn writable(&self) -> bool {
        !self.read_only || self.manage
    }

    /// Whether the flags allow changing which collections the cipher is in.
    pub(crate) fn editable(&self) -> bool {
        (!self.read_only && !self.hide_passwords) || self.manage
    }
}

/// The space permission closest to Bitwarden's flags; `manage` wins over the others.
pub(crate) fn permission_of(
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
) -> CollectionPermission {
    if manage {
        return CollectionPermission::Manage;
    }
    match (read_only, hide_passwords) {
        (true, false) => CollectionPermission::View,
        (true, true) => CollectionPermission::ViewHidePasswords,
        (false, false) => CollectionPermission::Edit,
        (false, true) => CollectionPermission::EditHidePasswords,
    }
}

/// An organization with everything its routes read.
#[derive(Debug)]
pub(crate) struct Org {
    pub id: SpaceId,
    pub name: String,
    pub doc: OrgDoc,
    pub state: SpaceState,
    /// Registered members' documents, by account.
    pub members: BTreeMap<UserId, MemberDoc>,
    pub pending: Vec<PendingDoc>,
    pub collection_docs: BTreeMap<CollectionId, CollectionDoc>,
    pub group_docs: BTreeMap<GroupId, GroupDoc>,
    /// By Bitwarden policy type.
    pub policies: BTreeMap<i32, PolicyDoc>,
    pub groups_enabled: bool,
}

impl Org {
    pub(crate) fn member(&self, user: UserId) -> Option<&MemberDoc> {
        self.members.get(&user)
    }

    pub(crate) fn collection(&self, id: CollectionId) -> Option<&Collection> {
        self.state.collections.iter().find(|c| c.id == id)
    }

    pub(crate) fn group(&self, id: GroupId) -> Option<&Group> {
        self.state.groups.iter().find(|g| g.id == id)
    }

    pub(crate) fn collection_name(collection: &Collection) -> String {
        String::from_utf8_lossy(&collection.name).into_owned()
    }

    pub(crate) fn group_name(group: &Group) -> String {
        String::from_utf8_lossy(&group.name).into_owned()
    }

    pub(crate) fn external_id_of_collection(&self, id: CollectionId) -> Option<String> {
        self.collection_docs
            .get(&id)
            .and_then(|d| d.external_id.clone())
    }

    pub(crate) fn group_doc(&self, id: GroupId) -> GroupDoc {
        self.group_docs.get(&id).cloned().unwrap_or_default()
    }

    fn grant(&self, collection: CollectionId, grantee: Grantee) -> Option<CollectionPermission> {
        self.state
            .grants
            .iter()
            .find(|g| g.collection == collection && g.grantee == grantee)
            .map(|g| g.permission)
    }

    /// The groups the account is in, when groups are on.
    pub(crate) fn groups_of(&self, user: UserId) -> Vec<&Group> {
        if !self.groups_enabled {
            return Vec::new();
        }
        self.state
            .groups
            .iter()
            .filter(|g| g.members.contains(&user))
            .collect()
    }

    /// Whether one of the account's groups has access to every collection.
    pub(crate) fn group_full_access(&self, user: UserId) -> bool {
        self.groups_of(user)
            .iter()
            .any(|g| self.group_doc(g.id).access_all)
    }

    /// What the account was given on a collection directly.
    pub(crate) fn user_grant(&self, user: UserId, collection: CollectionId) -> Option<Restrict> {
        self.grant(collection, Grantee::Member(user))
            .map(Restrict::from_permission)
    }

    /// What the account's groups give it on a collection: the most permissive of them.
    pub(crate) fn group_grant(&self, user: UserId, collection: CollectionId) -> Option<Restrict> {
        let mut found: Option<Restrict> = None;
        for group in self.groups_of(user) {
            let Some(permission) = self.grant(collection, Grantee::Group(group.id)) else {
                continue;
            };
            let next = Restrict::from_permission(permission);
            found = Some(match found {
                None => next,
                Some(prev) => Restrict {
                    read_only: prev.read_only && next.read_only,
                    hide_passwords: prev.hide_passwords && next.hide_passwords,
                    manage: prev.manage || next.manage,
                },
            });
        }
        found
    }

    /// Whether the account sees the collection at all.
    pub(crate) fn can_access_collection(&self, user: UserId, collection: CollectionId) -> bool {
        let Some(member) = self.member(user).filter(|m| m.confirmed()) else {
            return false;
        };
        member.full_access()
            || self.group_full_access(user)
            || self.user_grant(user, collection).is_some()
            || self.group_grant(user, collection).is_some()
    }

    /// The collections the account sees.
    pub(crate) fn collections_of(&self, user: UserId) -> Vec<&Collection> {
        self.state
            .collections
            .iter()
            .filter(|c| self.can_access_collection(user, c.id))
            .collect()
    }

    /// The flags a collection shows the account (`Collection::to_json_details`).
    pub(crate) fn collection_flags(&self, user: UserId, collection: CollectionId) -> Restrict {
        let Some(member) = self.member(user).filter(|m| m.confirmed()) else {
            return Restrict {
                read_only: true,
                hide_passwords: true,
                manage: false,
            };
        };
        if member.full_access() {
            return Restrict {
                read_only: false,
                hide_passwords: false,
                manage: level(member.atype) >= level(MANAGER),
            };
        }
        let is_manager = member.atype == MANAGER;
        match self
            .user_grant(user, collection)
            .or_else(|| self.group_grant(user, collection))
        {
            Some(r) => Restrict {
                read_only: r.read_only,
                hide_passwords: r.hide_passwords,
                manage: is_manager && (r.manage || (!r.read_only && !r.hide_passwords)),
            },
            None => Restrict {
                read_only: false,
                hide_passwords: false,
                manage: false,
            },
        }
    }

    /// What the account may do with a cipher in these collections (`get_access_restrictions`);
    /// `None` when it can't see the cipher.
    pub(crate) fn cipher_restrictions(
        &self,
        user: UserId,
        collections: &[CollectionId],
    ) -> Option<Restrict> {
        let member = self.member(user).filter(|m| m.confirmed())?;
        if member.full_access() || self.group_full_access(user) {
            return Some(Restrict::FULL);
        }
        let mut rows: Vec<Restrict> = collections
            .iter()
            .filter_map(|c| self.user_grant(user, *c))
            .collect();
        if rows.is_empty() {
            rows = collections
                .iter()
                .filter_map(|c| self.group_grant(user, *c))
                .collect();
        }
        if rows.is_empty() {
            return None;
        }
        // A flag holds for a cipher only when it holds in every collection the cipher is in; the
        // right to manage in any.
        let mut out = Restrict {
            read_only: true,
            hide_passwords: true,
            manage: false,
        };
        for row in rows {
            out.read_only &= row.read_only;
            out.hide_passwords &= row.hide_passwords;
            out.manage |= row.manage;
        }
        Some(out)
    }

    /// Whether the account may write to the collection (`Collection::is_writable_by_user`).
    pub(crate) fn collection_writable(&self, user: UserId, collection: CollectionId) -> bool {
        let Some(member) = self.member(user).filter(|m| m.confirmed()) else {
            return false;
        };
        level(member.atype) >= level(ADMIN)
            || member.access_all
            || self.group_full_access(user)
            || self
                .user_grant(user, collection)
                .is_some_and(|r| !r.read_only)
            || self
                .group_grant(user, collection)
                .is_some_and(|r| !r.read_only)
    }

    /// Whether the account manages the collection (`Collection::is_coll_manageable_by_user`).
    pub(crate) fn collection_manageable(&self, user: UserId, collection: CollectionId) -> bool {
        let Some(member) = self.member(user).filter(|m| m.confirmed()) else {
            return false;
        };
        level(member.atype) >= level(ADMIN)
            || member.access_all
            || self.group_full_access(user)
            || self.user_grant(user, collection).is_some_and(|r| r.manage)
            || self.group_grant(user, collection).is_some_and(|r| r.manage)
    }

    /// Whether the account manages at least one collection of the organization.
    pub(crate) fn has_manageable_collection(&self, user: UserId) -> bool {
        self.state
            .collections
            .iter()
            .any(|c| self.collection_manageable(user, c.id))
    }

    pub(crate) fn confirmed_owners(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.atype == OWNER && m.confirmed())
            .count()
    }

    /// The policy of a type, enabled or not.
    pub(crate) fn policy(&self, ptype: i32) -> Option<&PolicyDoc> {
        self.policies.get(&ptype)
    }

    pub(crate) fn policy_enabled(&self, ptype: i32) -> bool {
        self.policy(ptype).is_some_and(|p| p.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::spaces::{CollectionGrant, Space};
    use time::macros::datetime;

    fn space(id: SpaceId) -> SpaceState {
        let now = datetime!(2026-11-23 10:00:00 UTC);
        SpaceState {
            space: Space {
                id,
                name: b"Org".to_vec(),
                key_version: 1,
                keys_pending_since: None,
                created_at: now,
                updated_at: now,
            },
            members: Vec::new(),
            groups: Vec::new(),
            collections: Vec::new(),
            grants: Vec::new(),
        }
    }

    fn collection(space: SpaceId) -> Collection {
        Collection {
            id: CollectionId::random(),
            space,
            parent: None,
            name: b"2.name".to_vec(),
            key_version: 1,
            stale_since: None,
            created_at: datetime!(2026-11-23 10:00:00 UTC),
        }
    }

    fn org() -> Org {
        let id = SpaceId::random();
        Org {
            id,
            name: "Org".to_owned(),
            doc: OrgDoc::default(),
            state: space(id),
            members: BTreeMap::new(),
            pending: Vec::new(),
            collection_docs: BTreeMap::new(),
            group_docs: BTreeMap::new(),
            policies: BTreeMap::new(),
            groups_enabled: true,
        }
    }

    fn member(atype: i32, access_all: bool, status: i32) -> MemberDoc {
        MemberDoc::new(atype, access_all, status)
    }

    #[test]
    fn revoking_and_restoring_move_the_status_by_128() {
        let mut m = member(USER, false, CONFIRMED);
        assert!(m.revoke());
        assert_eq!(m.status, -126);
        assert_eq!(m.wire_status(), REVOKED);
        assert_eq!(m.unrevoked_status(), CONFIRMED);
        assert!(!m.revoke(), "already revoked");
        assert!(m.restore());
        assert_eq!(m.status, CONFIRMED);
        assert!(!m.restore(), "already active");
    }

    #[test]
    fn a_custom_role_is_a_manager_and_shows_as_custom() {
        assert_eq!(parse_type("4"), Some(MANAGER));
        assert_eq!(parse_type("Custom"), Some(MANAGER));
        assert_eq!(parse_type("5"), None);
        assert_eq!(member(MANAGER, false, CONFIRMED).wire_type(), 4);
        assert_eq!(member(OWNER, true, CONFIRMED).wire_type(), 0);
    }

    #[test]
    fn levels_put_a_manager_between_a_user_and_an_admin() {
        assert!(level(OWNER) > level(ADMIN));
        assert!(level(ADMIN) > level(MANAGER));
        assert!(level(MANAGER) > level(USER));
    }

    #[test]
    fn flags_map_to_the_nearest_permission_and_back() {
        for permission in [
            CollectionPermission::View,
            CollectionPermission::ViewHidePasswords,
            CollectionPermission::Edit,
            CollectionPermission::EditHidePasswords,
            CollectionPermission::Manage,
        ] {
            let r = Restrict::from_permission(permission);
            assert_eq!(
                permission_of(r.read_only, r.hide_passwords, r.manage),
                permission
            );
        }
    }

    #[test]
    fn an_admin_sees_every_collection_and_a_member_only_what_was_granted() {
        let mut org = org();
        let admin = UserId::random();
        let reader = UserId::random();
        let outsider = UserId::random();
        org.members.insert(admin, member(ADMIN, true, CONFIRMED));
        org.members.insert(reader, member(USER, false, CONFIRMED));
        org.members.insert(outsider, member(USER, false, CONFIRMED));
        let one = collection(org.id);
        let two = collection(org.id);
        org.state.grants.push(CollectionGrant {
            collection: one.id,
            grantee: Grantee::Member(reader),
            permission: CollectionPermission::ViewHidePasswords,
        });
        org.state.collections = vec![one.clone(), two.clone()];

        assert_eq!(org.collections_of(admin).len(), 2);
        let seen: Vec<CollectionId> = org.collections_of(reader).iter().map(|c| c.id).collect();
        assert_eq!(seen, vec![one.id]);
        assert!(org.collections_of(outsider).is_empty());

        let flags = org.collection_flags(reader, one.id);
        assert!(flags.read_only && flags.hide_passwords && !flags.manage);
        assert!(!org.collection_writable(reader, one.id));
        assert!(org.collection_writable(admin, two.id));
    }

    #[test]
    fn a_group_gives_access_and_a_user_grant_wins_over_it() {
        let mut org = org();
        let user = UserId::random();
        org.members.insert(user, member(USER, false, CONFIRMED));
        let col = collection(org.id);
        let group = Group {
            id: GroupId::random(),
            space: org.id,
            name: b"Ops".to_vec(),
            members: [user].into_iter().collect(),
            created_at: datetime!(2026-11-23 10:00:00 UTC),
        };
        org.state.grants.push(CollectionGrant {
            collection: col.id,
            grantee: Grantee::Group(group.id),
            permission: CollectionPermission::Edit,
        });
        org.state.collections = vec![col.clone()];
        org.state.groups = vec![group];

        assert!(org.can_access_collection(user, col.id));
        assert!(org.collection_writable(user, col.id));
        let by_group = org.cipher_restrictions(user, &[col.id]).expect("access");
        assert!(!by_group.read_only);

        org.state.grants.push(CollectionGrant {
            collection: col.id,
            grantee: Grantee::Member(user),
            permission: CollectionPermission::View,
        });
        let direct = org.cipher_restrictions(user, &[col.id]).expect("access");
        assert!(
            direct.read_only,
            "the account's own grant overrules its group's"
        );

        org.groups_enabled = false;
        org.state
            .grants
            .retain(|g| g.grantee == Grantee::Member(user));
        assert!(org.group_grant(user, col.id).is_none());
    }

    #[test]
    fn a_flag_holds_for_a_cipher_only_when_every_collection_has_it() {
        let mut org = org();
        let user = UserId::random();
        org.members.insert(user, member(USER, false, CONFIRMED));
        let (one, two) = (collection(org.id), collection(org.id));
        org.state.grants.push(CollectionGrant {
            collection: one.id,
            grantee: Grantee::Member(user),
            permission: CollectionPermission::View,
        });
        org.state.grants.push(CollectionGrant {
            collection: two.id,
            grantee: Grantee::Member(user),
            permission: CollectionPermission::Edit,
        });
        org.state.collections = vec![one.clone(), two.clone()];
        let both = org
            .cipher_restrictions(user, &[one.id, two.id])
            .expect("access");
        assert!(!both.read_only, "one collection can write");
        assert!(org.cipher_restrictions(user, &[]).is_none());
    }

    #[test]
    fn only_confirmed_members_have_access() {
        let mut org = org();
        let user = UserId::random();
        org.members.insert(user, member(OWNER, true, ACCEPTED));
        let col = collection(org.id);
        org.state.collections = vec![col.clone()];
        assert!(!org.can_access_collection(user, col.id));
        assert!(!org.collection_manageable(user, col.id));
        assert_eq!(org.confirmed_owners(), 0);
        org.members.insert(user, member(OWNER, true, CONFIRMED));
        assert_eq!(org.confirmed_owners(), 1);
        assert!(org.collection_manageable(user, col.id));
    }
}
