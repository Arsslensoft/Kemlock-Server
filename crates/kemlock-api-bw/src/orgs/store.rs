//! Reading and writing an organization: the space tables through `SpaceRepo`, the side documents
//! through `BwOrgStore`.

use super::json::UserInfo;
use super::model::{
    ACCEPTED, ADMIN, CONFIRMED, CollectionDoc, GroupDoc, INVITED, KIND_COLLECTION, KIND_GROUP,
    KIND_MEMBER, KIND_ORG, KIND_PENDING, KIND_POLICY, MANAGER, MemberDoc, OWNER, Org, OrgDoc,
    PendingDoc, PolicyDoc, REVOKE_DIFF, USER, level,
};
use crate::app::{App, BwStore};
use crate::error::{BwError, BwResult};
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::bw_events::UserSync;
use kemlock_app::ports::{StoreError, TwoFactorRepo, UserRepo};
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{
    Collection, CollectionGrant, CollectionId, CustomPermissions, Group, GroupId, Member,
    MemberState, SpaceRole,
};
use kemlock_domain::{SpaceId, User, UserId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// The space role closest to a Bitwarden type.
fn role_of(atype: i32) -> SpaceRole {
    match atype {
        OWNER => SpaceRole::Owner,
        ADMIN => SpaceRole::Admin,
        MANAGER => SpaceRole::Custom,
        _ => SpaceRole::Member,
    }
}

/// The Bitwarden type closest to a space role: the other way of [`role_of`].
fn type_of(role: SpaceRole) -> i32 {
    match role {
        SpaceRole::Owner => OWNER,
        SpaceRole::Admin => ADMIN,
        SpaceRole::Custom => MANAGER,
        SpaceRole::Member => USER,
    }
}

fn custom_of(doc: &MemberDoc) -> CustomPermissions {
    if doc.atype == MANAGER && doc.access_all {
        CustomPermissions::CREATE_COLLECTIONS
    } else {
        CustomPermissions::NONE
    }
}

/// The space row that mirrors a member's document.
pub(crate) fn mirror_member(
    org: &Org,
    user: UserId,
    doc: &MemberDoc,
    invited_by: UserId,
    now: OffsetDateTime,
) -> Member {
    let mut row = org
        .state
        .members
        .iter()
        .find(|m| m.user == user)
        .cloned()
        .unwrap_or_else(|| {
            Member::invited(
                org.id,
                user,
                role_of(doc.atype),
                custom_of(doc),
                invited_by,
                now,
            )
        });
    row.role = role_of(doc.atype);
    row.custom = custom_of(doc);
    // A member the row confirmed stays confirmed when the document says they are only invited or
    // accepted (what they have to do on the Bitwarden side): the document is about the Bitwarden
    // key, and writing it back must not take away what the Kemlock side confirmed.
    let confirmed_there = row.state == MemberState::Confirmed;
    row.state = if doc.revoked() {
        MemberState::Revoked
    } else {
        match doc.status {
            CONFIRMED => MemberState::Confirmed,
            _ if confirmed_there => MemberState::Confirmed,
            ACCEPTED => MemberState::Accepted,
            _ => MemberState::Invited,
        }
    };
    if doc.unrevoked_status() >= ACCEPTED && row.accepted_at.is_none() {
        row.accepted_at = Some(now);
    }
    row.revoked_at = if doc.revoked() {
        row.revoked_at.or(Some(now))
    } else {
        None
    };
    row
}

/// A member's document as the space's own row says they stand now. The row is what the Kemlock
/// API, the admin console and SSO group sync change, so it decides whether they are revoked, how
/// far along they are and which role they hold; the document keeps what only Bitwarden has (the
/// wrapped key, external ids), and `access_all` only while the row agrees with it. A member the
/// row has demoted or taken out never keeps the access the document remembers.
pub(crate) fn reconcile(doc: &MemberDoc, row: &Member) -> MemberDoc {
    let mut out = doc.clone();

    if role_of(doc.atype) != row.role {
        out.atype = type_of(row.role);
        out.access_all = level(out.atype) >= level(ADMIN);
    }
    match out.atype {
        // A custom member has every collection only with the permission that says so.
        MANAGER => {
            out.access_all =
                out.access_all && row.custom.contains(CustomPermissions::CREATE_COLLECTIONS);
        }
        USER => out.access_all = false,
        _ => {}
    }

    let held = doc.unrevoked_status();
    let state = match row.state {
        MemberState::Revoked => held,
        MemberState::Invited => INVITED,
        MemberState::Accepted => ACCEPTED,
        // A member the row confirmed while the Bitwarden side still has them invited has not
        // accepted there: the invitee's own acceptance is what a Bitwarden member needs, so they stay
        // invited, and an administrator is not made to look as if they had accepted. (A member who
        // accepted holds ACCEPTED or CONFIRMED already, and the row's state adds nothing.)
        MemberState::Confirmed => held,
    };
    out.status = if row.state == MemberState::Revoked {
        state - REVOKE_DIFF
    } else {
        state
    };
    // A key left from an earlier membership is not this one's.
    if row.state != MemberState::Revoked && state < CONFIRMED {
        out.akey.clear();
    }
    out
}

fn damaged(kind: &str, error: &serde_json::Error) -> BwError {
    BwError::Server(format!("a stored {kind} document is damaged: {error}"))
}

fn uuid_of(key: &str) -> Option<Uuid> {
    Uuid::parse_str(key).ok()
}

impl<S: BwStore> App<S> {
    pub(crate) async fn doc<T: DeserializeOwned>(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
    ) -> BwResult<Option<T>> {
        match self.store.doc_get(scope, kind, key).await? {
            None => Ok(None),
            Some(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| damaged(kind, &e)),
        }
    }

    pub(crate) async fn put_doc<T: Serialize>(
        &self,
        scope: Uuid,
        kind: &str,
        key: &str,
        value: &T,
    ) -> BwResult<()> {
        let text = serde_json::to_string(value).map_err(|e| damaged(kind, &e))?;
        self.store.doc_put(scope, kind, key, &text).await?;
        Ok(())
    }

    pub(crate) async fn del_doc(&self, scope: Uuid, kind: &str, key: &str) -> BwResult<bool> {
        Ok(self.store.doc_delete(scope, kind, key).await?)
    }

    /// Every document of a kind in a scope that parses; a damaged one is left out and logged.
    pub(crate) async fn docs<T: DeserializeOwned>(
        &self,
        scope: Uuid,
        kind: &str,
    ) -> BwResult<Vec<(String, T)>> {
        let mut out = Vec::new();
        for (key, text) in self.store.doc_list(scope, kind).await? {
            match serde_json::from_str(&text) {
                Ok(value) => out.push((key, value)),
                Err(e) => tracing::warn!(%kind, %key, error = %e, "leaving a damaged document out"),
            }
        }
        Ok(out)
    }

    /// The organization with this id, or `None` when there is none, or the space isn't one.
    pub(crate) async fn load_org(&self, id: SpaceId) -> BwResult<Option<Org>> {
        let Some(doc) = self.doc::<OrgDoc>(id.0, KIND_ORG, "").await? else {
            return Ok(None);
        };
        let Some(state) = SpaceRepo::load(&self.store, id).await? else {
            return Ok(None);
        };
        let mut members = BTreeMap::new();
        for (key, member) in self.docs::<MemberDoc>(id.0, KIND_MEMBER).await? {
            let Some(uuid) = uuid_of(&key) else {
                continue;
            };
            let user = UserId(uuid);
            // Someone with no row in the space is not a member, whatever their document says.
            let Some(row) = state.members.iter().find(|m| m.user == user) else {
                continue;
            };
            members.insert(user, reconcile(&member, row));
        }
        let pending = self
            .docs::<PendingDoc>(id.0, KIND_PENDING)
            .await?
            .into_iter()
            .map(|(_, p)| p)
            .collect();
        let mut collection_docs = BTreeMap::new();
        for (key, doc) in self.docs::<CollectionDoc>(id.0, KIND_COLLECTION).await? {
            if let Some(uuid) = uuid_of(&key) {
                collection_docs.insert(CollectionId(uuid), doc);
            }
        }
        let mut group_docs = BTreeMap::new();
        for (key, doc) in self.docs::<GroupDoc>(id.0, KIND_GROUP).await? {
            if let Some(uuid) = uuid_of(&key) {
                group_docs.insert(GroupId(uuid), doc);
            }
        }
        let mut policies = BTreeMap::new();
        for (key, doc) in self.docs::<PolicyDoc>(id.0, KIND_POLICY).await? {
            if let Ok(ptype) = key.parse::<i32>() {
                policies.insert(ptype, doc);
            }
        }
        // Require SSO is kept in `space_policy_settings`, which the Kemlock API, the console and the
        // sign-in checks read and write; the document of this type only carries what Bitwarden shows
        // of it, so whether it is on is the table's word.
        let sso_on = SpaceRepo::require_sso_of(&self.store, &[id])
            .await?
            .contains(&id);
        match policies.get_mut(&super::policy::REQUIRE_SSO) {
            Some(doc) => doc.enabled = sso_on,
            None if sso_on => {
                policies.insert(
                    super::policy::REQUIRE_SSO,
                    PolicyDoc {
                        id: Uuid::from_u128(id.0.as_u128() ^ 5).to_string(),
                        enabled: true,
                        data: "null".to_owned(),
                        revision_date: crate::dates::format_date(OffsetDateTime::UNIX_EPOCH),
                    },
                );
            }
            None => {}
        }
        Ok(Some(Org {
            id,
            name: String::from_utf8_lossy(&state.space.name).into_owned(),
            doc,
            state,
            members,
            pending,
            collection_docs,
            group_docs,
            policies,
            groups_enabled: self.settings.org_groups_enabled,
        }))
    }

    /// The organizations the account has a membership in, in any status.
    pub(crate) async fn orgs_of(&self, user: UserId) -> BwResult<Vec<Org>> {
        let mut out = Vec::new();
        for member in SpaceRepo::memberships(&self.store, user).await? {
            if let Some(org) = self.load_org(member.space).await?
                && org.members.contains_key(&user)
            {
                out.push(org);
            }
        }
        Ok(out)
    }

    /// Moves an account's revision date so its clients sync; an account with no Bitwarden record
    /// has nothing to move.
    pub(crate) async fn touch_quiet(&self, user: UserId) -> BwResult<()> {
        match BwAccountRepo::touch(&self.store, user, crate::dates::epoch_millis(self.now())).await
        {
            Ok(_) | Err(StoreError::NotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Every member's clients should sync.
    pub(crate) async fn touch_members(&self, org: &Org) -> BwResult<()> {
        for user in org.members.keys() {
            self.touch_quiet(*user).await?;
        }
        Ok(())
    }

    /// Every member's clients should sync, and are told so: a change to the organization's
    /// members, collections, groups or policies.
    pub(crate) async fn sync_members(&self, org: &Org) -> BwResult<()> {
        self.touch_members(org).await?;
        self.members_synced(org, UserSync::Vault, None);
        Ok(())
    }

    /// Writes a member's document and the space row that mirrors it.
    pub(crate) async fn put_member(
        &self,
        org: &Org,
        user: UserId,
        doc: &MemberDoc,
        invited_by: UserId,
    ) -> BwResult<()> {
        let row = mirror_member(org, user, doc, invited_by, self.now());
        let changes = SpaceChanges {
            members: vec![row],
            ..SpaceChanges::new(org.id)
        };
        SpaceRepo::apply(&self.store, changes).await?;
        self.put_doc(org.id.0, KIND_MEMBER, &user.to_string(), doc)
            .await
    }

    /// Removes a member: their row, grants, group places and document.
    pub(crate) async fn remove_member(&self, org: &Org, user: UserId) -> BwResult<()> {
        let changes = SpaceChanges {
            members_removed: vec![user],
            ..SpaceChanges::new(org.id)
        };
        SpaceRepo::apply(&self.store, changes).await?;
        self.del_doc(org.id.0, KIND_MEMBER, &user.to_string())
            .await?;
        Ok(())
    }

    /// Replaces the grants of one member: the ones they had in this organization go, `grants`
    /// come.
    pub(crate) async fn set_member_grants(
        &self,
        org: &Org,
        user: UserId,
        grants: Vec<CollectionGrant>,
    ) -> BwResult<()> {
        let removed = org
            .state
            .grants
            .iter()
            .filter(|g| g.grantee == kemlock_domain::spaces::Grantee::Member(user))
            .map(|g| (g.collection, g.grantee))
            .collect();
        let changes = SpaceChanges {
            grants_removed: removed,
            grants,
            ..SpaceChanges::new(org.id)
        };
        SpaceRepo::apply(&self.store, changes).await?;
        Ok(())
    }

    /// Replaces the group places of one member.
    pub(crate) async fn set_member_groups(
        &self,
        org: &Org,
        user: UserId,
        groups: &[GroupId],
    ) -> BwResult<()> {
        let mut changed = Vec::new();
        for group in &org.state.groups {
            let wanted = groups.contains(&group.id);
            let has = group.members.contains(&user);
            if wanted != has {
                let mut next: Group = group.clone();
                if wanted {
                    next.members.insert(user);
                } else {
                    next.members.remove(&user);
                }
                changed.push(next);
            }
        }
        if changed.is_empty() {
            return Ok(());
        }
        let changes = SpaceChanges {
            groups: changed,
            ..SpaceChanges::new(org.id)
        };
        SpaceRepo::apply(&self.store, changes).await?;
        Ok(())
    }

    /// Writes a collection and its extras.
    pub(crate) async fn put_collection(
        &self,
        org: &Org,
        collection: Collection,
        external_id: Option<String>,
    ) -> BwResult<()> {
        let id = collection.id;
        let changes = SpaceChanges {
            collections: vec![collection],
            ..SpaceChanges::new(org.id)
        };
        SpaceRepo::apply(&self.store, changes).await?;
        self.put_doc(
            org.id.0,
            KIND_COLLECTION,
            &id.to_string(),
            &CollectionDoc { external_id },
        )
        .await
    }

    /// The account's name, email and two-step state for a member list; `None` when it is gone.
    pub(crate) async fn user_info(&self, user: UserId) -> BwResult<Option<UserInfo>> {
        let Some(account) = UserRepo::by_id(&self.store, user).await? else {
            return Ok(None);
        };
        Ok(Some(self.user_info_of(&account).await?))
    }

    pub(crate) async fn user_info_of(&self, user: &User) -> BwResult<UserInfo> {
        let bw = BwAccountRepo::get(&self.store, user.id).await?;
        let two_factor = !TwoFactorRepo::list(&self.store, user.id).await?.is_empty();
        Ok(UserInfo {
            email: user.email.as_str().to_owned(),
            name: user.name.clone(),
            avatar_color: bw.as_ref().and_then(|a| a.avatar_color.clone()),
            two_factor,
            has_password: bw.is_some_and(|a| !a.password_hash.is_empty()),
        })
    }

    /// Turns the invitations of this email into memberships, as an account that has just been
    /// made takes the place of the invited address. Invitations to the email wait in `pending`
    /// documents of every organization.
    pub(crate) async fn adopt_invitations(&self, user: &User) -> BwResult<()> {
        let found = self
            .store
            .doc_find(KIND_PENDING, user.email.as_str())
            .await?;
        for (scope, text) in found {
            let Ok(pending) = serde_json::from_str::<PendingDoc>(&text) else {
                continue;
            };
            let Some(org) = self.load_org(SpaceId(scope)).await? else {
                continue;
            };
            let invited_by = Uuid::parse_str(&pending.invited_by)
                .map(UserId)
                .unwrap_or(user.id);
            // The person who registers the address may not be the one who was invited (an address
            // is only proven when the server verifies sign-ups), so they only become invited, and
            // accept for themselves, as any invitee does.
            // (An operator who asked for Vaultwarden's mail-off behaviour has them accepted.)
            let status = if self.settings.bw_invites_auto_accept() && !self.notices.mails() {
                ACCEPTED
            } else {
                INVITED
            };
            let mut member = MemberDoc::new(pending.atype, pending.access_all, status);
            member.invited_by_email = pending.invited_by_email.clone();
            member.external_id = pending.external_id.clone();
            self.put_member(&org, user.id, &member, invited_by).await?;

            let grants: Vec<CollectionGrant> = pending
                .collections
                .iter()
                .filter_map(|c| {
                    Uuid::parse_str(&c.id).ok().map(|id| CollectionGrant {
                        collection: CollectionId(id),
                        grantee: kemlock_domain::spaces::Grantee::Member(user.id),
                        permission: super::model::permission_of(
                            c.read_only,
                            c.hide_passwords,
                            c.manage,
                        ),
                    })
                })
                .filter(|g| org.collection(g.collection).is_some())
                .collect();
            if !grants.is_empty() && !pending.access_all {
                self.set_member_grants(&org, user.id, grants).await?;
            }
            let groups: Vec<GroupId> = pending
                .groups
                .iter()
                .filter_map(|g| Uuid::parse_str(g).ok().map(GroupId))
                .filter(|g| org.group(*g).is_some())
                .collect();
            self.set_member_groups(&org, user.id, &groups).await?;
            self.del_doc(scope, KIND_PENDING, user.email.as_str())
                .await?;
        }
        Ok(())
    }

    /// Whether an invitation to this email waits in some organization: it lets the address
    /// register when sign-ups are closed, as Vaultwarden's invitations do.
    pub(crate) async fn has_invitation(&self, email: &str) -> BwResult<bool> {
        Ok(!self.store.doc_find(KIND_PENDING, email).await?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn row(role: SpaceRole, custom: CustomPermissions, state: MemberState) -> Member {
        let mut row = Member::invited(
            SpaceId::random(),
            UserId::random(),
            role,
            custom,
            UserId::random(),
            datetime!(2026-11-26 10:00:00 UTC),
        );
        row.state = state;
        row
    }

    fn doc(atype: i32, access_all: bool, status: i32) -> MemberDoc {
        let mut doc = MemberDoc::new(atype, access_all, status);
        if status == CONFIRMED {
            doc.akey = "4.wrapped".to_owned();
        }
        doc
    }

    #[test]
    fn a_row_that_agrees_changes_nothing() {
        let owner = doc(OWNER, true, CONFIRMED);
        let same = reconcile(
            &owner,
            &row(
                SpaceRole::Owner,
                CustomPermissions::NONE,
                MemberState::Confirmed,
            ),
        );
        assert_eq!(same, owner);
        let custom = doc(MANAGER, true, CONFIRMED);
        let same = reconcile(
            &custom,
            &row(
                SpaceRole::Custom,
                CustomPermissions::CREATE_COLLECTIONS,
                MemberState::Confirmed,
            ),
        );
        assert_eq!(same, custom);
    }

    #[test]
    fn a_demoted_admin_loses_the_admin_access_of_the_document() {
        let admin = doc(ADMIN, true, CONFIRMED);
        let demoted = reconcile(
            &admin,
            &row(
                SpaceRole::Member,
                CustomPermissions::NONE,
                MemberState::Confirmed,
            ),
        );
        assert_eq!(demoted.atype, USER);
        assert!(!demoted.access_all);
        assert!(!demoted.full_access());
        assert!(demoted.confirmed(), "the state is the row's, and it agrees");
    }

    #[test]
    fn a_custom_member_keeps_every_collection_only_while_the_row_has_the_permission() {
        let custom = doc(MANAGER, true, CONFIRMED);
        let without = reconcile(
            &custom,
            &row(
                SpaceRole::Custom,
                CustomPermissions::MANAGE_USERS,
                MemberState::Confirmed,
            ),
        );
        assert_eq!(without.atype, MANAGER);
        assert!(!without.access_all);
        let promoted = reconcile(
            &doc(USER, false, CONFIRMED),
            &row(
                SpaceRole::Admin,
                CustomPermissions::NONE,
                MemberState::Confirmed,
            ),
        );
        assert_eq!(promoted.atype, ADMIN);
        assert!(promoted.full_access());
    }

    #[test]
    fn a_revoked_row_revokes_the_document_and_a_restored_one_waits_to_be_confirmed() {
        let confirmed = doc(ADMIN, true, CONFIRMED);
        let revoked = reconcile(
            &confirmed,
            &row(
                SpaceRole::Admin,
                CustomPermissions::NONE,
                MemberState::Revoked,
            ),
        );
        assert!(revoked.revoked());
        assert_eq!(revoked.unrevoked_status(), CONFIRMED);
        assert_eq!(
            revoked.akey, "4.wrapped",
            "a Bitwarden restore may bring it back"
        );
        // Revoking twice is the same revocation.
        assert_eq!(
            reconcile(
                &revoked,
                &row(
                    SpaceRole::Admin,
                    CustomPermissions::NONE,
                    MemberState::Revoked
                )
            ),
            revoked
        );

        // The Kemlock API restores a member as an accepted one.
        let restored = reconcile(
            &revoked,
            &row(
                SpaceRole::Admin,
                CustomPermissions::NONE,
                MemberState::Accepted,
            ),
        );
        assert_eq!(restored.status, ACCEPTED);
        assert!(!restored.full_access());
        assert!(restored.akey.is_empty());
    }

    #[test]
    fn an_invitation_accepted_through_the_kemlock_api_is_accepted_here() {
        let invited = doc(USER, false, INVITED);
        let accepted = reconcile(
            &invited,
            &row(
                SpaceRole::Member,
                CustomPermissions::NONE,
                MemberState::Accepted,
            ),
        );
        assert_eq!(accepted.status, ACCEPTED);
        // A row that confirmed them does not make them accepted: they have not accepted here.
        let confirmed = reconcile(
            &invited,
            &row(
                SpaceRole::Member,
                CustomPermissions::NONE,
                MemberState::Confirmed,
            ),
        );
        assert_eq!(confirmed.status, INVITED);
        assert!(confirmed.akey.is_empty());
        // A row invited again after a removal is not the old confirmed membership.
        let again = reconcile(
            &doc(USER, false, CONFIRMED),
            &row(
                SpaceRole::Member,
                CustomPermissions::NONE,
                MemberState::Invited,
            ),
        );
        assert_eq!(again.status, INVITED);
        assert!(again.akey.is_empty());
    }
}
