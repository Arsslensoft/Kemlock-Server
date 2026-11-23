//! Reading and writing an organization: the space tables through `SpaceRepo`, the side documents
//! through `BwOrgStore`.

use super::json::UserInfo;
use super::model::{
    ACCEPTED, ADMIN, CONFIRMED, CollectionDoc, GroupDoc, KIND_COLLECTION, KIND_GROUP, KIND_MEMBER,
    KIND_ORG, KIND_PENDING, KIND_POLICY, MANAGER, MemberDoc, OWNER, Org, OrgDoc, PendingDoc,
    PolicyDoc,
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
    row.state = if doc.revoked() {
        MemberState::Revoked
    } else {
        match doc.status {
            CONFIRMED => MemberState::Confirmed,
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
            if let Some(uuid) = uuid_of(&key) {
                members.insert(UserId(uuid), member);
            }
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
            // Mail is off, so an invited account that registers has accepted: an admin confirms it.
            let mut member = MemberDoc::new(pending.atype, pending.access_all, ACCEPTED);
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
