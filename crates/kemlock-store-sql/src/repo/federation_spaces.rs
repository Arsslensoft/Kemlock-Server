//! `SpaceMirror` on `SqlStore`: a space's home-only state as home records carry it.
//!
//! At the home the snapshot reads the space the way `SpaceRepo::load` does, keeps only the
//! confirmed members (the ones whose accounts a replica holds), and adds the collection keys sealed
//! to each of them and the policies. At a replica each record becomes one `SpaceChanges`, applied
//! in one transaction: an upsert of its entity, with the grants of a collection and the key copies
//! of a member replaced as a set, or the removal of an entity that is gone.

use crate::store::SqlStore;
use kemlock_app::policies::PolicyRepo;
use kemlock_app::ports::StoreError;
use kemlock_app::spaces::{SpaceChanges, SpaceRepo};
use kemlock_domain::spaces::{Grantee, MemberState};
use kemlock_domain::{SpaceId, UserId};
use kemlock_federation::spaces::{PolicyState, SpaceMirror, SpaceRecord, SpaceSnapshot};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use uuid::Uuid;

impl SpaceMirror for SqlStore {
    async fn space_snapshot(&self, space: SpaceId) -> Result<Option<SpaceSnapshot>, StoreError> {
        let Some(mut state) = SpaceRepo::load(self, space).await? else {
            return Ok(None);
        };
        state.members.retain(|m| m.state == MemberState::Confirmed);
        let confirmed: BTreeSet<UserId> = state.members.iter().map(|m| m.user).collect();
        for group in &mut state.groups {
            group.members.retain(|u| confirmed.contains(u));
        }
        state.grants.retain(|g| match g.grantee {
            Grantee::Member(user) => confirmed.contains(&user),
            Grantee::Group(_) => true,
        });
        let mut key_copies = Vec::new();
        for member in &state.members {
            let copies = SpaceRepo::key_copies(self, space, member.user).await?;
            if !copies.is_empty() {
                key_copies.push((member.user, copies));
            }
        }
        let stored = PolicyRepo::space_policies(self, space).await?;
        let policies = stored.updated_at.map(|at| PolicyState {
            policies: stored.policies.clone(),
            updated_by: stored.updated_by,
            updated_at: Some(at),
        });
        let held = self.read_held(space).await?;
        Ok(Some(SpaceSnapshot {
            state,
            key_copies,
            policies,
            held,
        }))
    }

    async fn chain_records_after(
        &self,
        space: SpaceId,
        after: Option<u64>,
    ) -> Result<Vec<kemlock_federation::chain::ChainWire>, StoreError> {
        self.chain_wire_after(space, after).await
    }

    async fn apply_chain_record(
        &self,
        space: SpaceId,
        record: &kemlock_federation::chain::ChainWire,
    ) -> Result<(), StoreError> {
        self.keep_chain_wire(space, record).await
    }

    async fn apply_space_record(
        &self,
        space: SpaceId,
        record: &SpaceRecord,
    ) -> Result<(), StoreError> {
        let mut changes = SpaceChanges::new(space);
        match record {
            SpaceRecord::Space(row) => {
                changes.space = Some(row.clone());
                return if SpaceRepo::load(self, space).await?.is_some() {
                    self.write_changes(changes, false).await
                } else {
                    SpaceRepo::create(self, changes).await
                };
            }
            SpaceRecord::Held(items) => return self.replace_held(space, items).await,
            SpaceRecord::Policies(p) => {
                let by = p.updated_by.unwrap_or(UserId(Uuid::nil()));
                let at = p.updated_at.unwrap_or(OffsetDateTime::UNIX_EPOCH);
                return PolicyRepo::put_space_policies(self, space, &p.policies, by, at).await;
            }
            _ => {}
        }
        let Some(state) = SpaceRepo::load(self, space).await? else {
            tracing::warn!(%space, "a space record arrived before its space: ignored");
            return Ok(());
        };
        match record {
            SpaceRecord::Member(m) => changes.members.push(m.clone()),
            SpaceRecord::MemberGone(user) => changes.members_removed.push(*user),
            SpaceRecord::Group(g) => changes.groups.push(g.clone()),
            SpaceRecord::GroupGone(g) => changes.groups_removed.push(*g),
            SpaceRecord::Collection { collection, grants } => {
                for old in state
                    .grants
                    .iter()
                    .filter(|g| g.collection == collection.id)
                {
                    if !grants.iter().any(|g| g.grantee == old.grantee) {
                        changes.grants_removed.push((collection.id, old.grantee));
                    }
                }
                changes.collections.push(collection.clone());
                changes.grants.extend(grants.iter().copied());
            }
            SpaceRecord::CollectionGone(c) => changes.collections_removed.push(*c),
            SpaceRecord::Keys { user, copies } => {
                for old in SpaceRepo::key_copies(self, space, *user).await? {
                    if !copies.iter().any(|c| c.collection == old.collection) {
                        changes.key_copies_removed.push((old.collection, *user));
                    }
                }
                changes.key_copies.extend(copies.iter().cloned());
            }
            SpaceRecord::KeysGone(user) => {
                for old in SpaceRepo::key_copies(self, space, *user).await? {
                    changes.key_copies_removed.push((old.collection, *user));
                }
            }
            SpaceRecord::Space(_) | SpaceRecord::Policies(_) | SpaceRecord::Held(_) => {}
        }
        self.write_changes(changes, false).await
    }
}
