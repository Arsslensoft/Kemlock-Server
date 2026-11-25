//! An in-memory implementation of the federation ports, for tests and as the reference for what
//! the SQL adapter must do. It writes local items the way `SqlStore` does (next sequence number,
//! an HLC time not before the last one, a log entry) and keeps the replication state beside them.

use crate::change::{ChangeRecord, MAX_LINEAGE};
use crate::conflict::{Version, merge};
use crate::eventsync::{EventSync, LogEntry, PeerEvent};
use crate::extra::{ErasureOutbox, PendingErasure, VaultErased, VaultErasure};
use crate::hashtree::{Leaf, leaf_digest};
use crate::home::VaultFederation;
use crate::insight::{MismatchRecord, PeerSecurityRecord, VaultInfo};
use crate::keyrecs::{KeyStore, StoredKeyRecord};
use crate::ports::{
    ApplyOutcome, ExportPage, Exported, HomeStatus, LogSwitches, Peer, PeerRepo, PeerState,
    ReplicaStore, StoredHomeRecord, VaultRepo,
};
use crate::relay::{LearnedKey, OriginKeys};
use crate::spaces::{SpaceMirror, SpaceRecord, SpaceSnapshot};
use crate::outbox::{Withheld, Withholding};
use crate::sendsync::{SendApply, SendSync};
use crate::tagsync::{ItemTags, TagSync};
use crate::wire::ChangeKey;
use kemlock_app::ports::StoreError;
use kemlock_domain::sends::{SendId, SendRecord};
use kemlock_domain::BlobId;
use kemlock_domain::{
    ChangeId, Hlc, Item, ItemDraft, ItemId, Owner, Revision, ServerId, SpaceId, VersionVector,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
struct LogRow {
    key: ChangeKey,
    item: ItemId,
    hlc: Hlc,
}

#[derive(Clone, Debug)]
struct Meta {
    lineage: Vec<ChangeKey>,
    signature: Option<Vec<u8>>,
}

#[derive(Debug)]
struct State {
    server: ServerId,
    next_seq: u64,
    last_hlc: Hlc,
    heads: HashMap<ItemId, Item>,
    siblings: HashMap<ItemId, Vec<Item>>,
    log: Vec<LogRow>,
    meta: HashMap<ChangeKey, Meta>,
    peers: BTreeMap<ServerId, Peer>,
    switches: HashMap<ServerId, LogSwitches>,
    cursors: HashMap<(ServerId, Owner), VersionVector>,
    vaults: HashMap<Owner, VaultFederation>,
    home_records: Vec<StoredHomeRecord>,
}

fn millis(time: OffsetDateTime) -> u64 {
    u64::try_from(time.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

impl State {
    /// The head and then the siblings of an item.
    fn versions_of(&self, id: ItemId) -> Vec<Item> {
        let mut out = Vec::new();
        if let Some(head) = self.heads.get(&id) {
            out.push(head.clone());
        }
        if let Some(siblings) = self.siblings.get(&id) {
            out.extend(siblings.iter().cloned());
        }
        out
    }

    /// The lineage of a change this server accepted: every earlier change of the item in the log
    /// except the versions currently held as siblings (an edit of the head didn't see those),
    /// nearest first.
    fn derive_lineage(&self, id: ItemId, change: &ChangeId) -> Vec<ChangeKey> {
        let own = ChangeKey::of(change);
        let siblings: HashSet<ChangeKey> = self
            .siblings
            .get(&id)
            .map(|s| s.iter().map(|i| ChangeKey::of(&i.change)).collect())
            .unwrap_or_default();
        let mut entries: Vec<&LogRow> = self
            .log
            .iter()
            .filter(|e| {
                e.item == id && e.hlc < change.hlc && e.key != own && !siblings.contains(&e.key)
            })
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse((e.hlc, e.key)));
        entries
            .into_iter()
            .take(MAX_LINEAGE)
            .map(|e| e.key)
            .collect()
    }

    /// Fixes the lineage of a change this server accepted, once, before anything that could
    /// change the answer joins the log.
    fn ensure_meta(&mut self, item: &Item) {
        let key = ChangeKey::of(&item.change);
        if item.change.origin == self.server && !self.meta.contains_key(&key) {
            let lineage = self.derive_lineage(item.id, &item.change);
            self.meta.insert(
                key,
                Meta {
                    lineage,
                    signature: None,
                },
            );
        }
    }

    fn lineage_of(&self, item: &Item) -> Vec<ChangeKey> {
        self.meta
            .get(&ChangeKey::of(&item.change))
            .map(|m| m.lineage.clone())
            .unwrap_or_default()
    }

    fn exported(&mut self, item: Item) -> Exported {
        self.ensure_meta(&item);
        let meta = self.meta.get(&ChangeKey::of(&item.change));
        Exported {
            lineage: meta.map(|m| m.lineage.clone()).unwrap_or_default(),
            signature: meta.and_then(|m| m.signature.clone()),
            item,
        }
    }
}

/// The in-memory store. Cloning shares the state.
#[derive(Clone, Debug)]
pub struct MemoryStore {
    state: Arc<Mutex<State>>,
    /// Named leases: holder and expiry (Unix seconds).
    leases: Arc<Mutex<HashMap<String, (String, u64)>>>,
    /// The erasures this server, as a home, still has to tell its replicas.
    erasures: Arc<Mutex<Vec<PendingErasure>>>,
    /// What the later parts of federation keep: spaces, event logs, key records.
    extras: Arc<Mutex<Extras>>,
}

/// What the in-memory store keeps beside the items and the peers.
#[derive(Debug, Default)]
struct Extras {
    snapshots: HashMap<SpaceId, SpaceSnapshot>,
    space_applied: Vec<SpaceRecord>,
    vault_events: HashMap<Owner, Vec<LogEntry>>,
    peer_events: Vec<PeerEvent>,
    key_records: Vec<StoredKeyRecord>,
    learned: Vec<LearnedKey>,
    matching: HashSet<Owner>,
    tags: HashMap<(Owner, ItemId), ItemTags>,
    peer_security: HashMap<ServerId, PeerSecurityRecord>,
    mismatches: HashMap<ServerId, MismatchRecord>,
    sends: BTreeMap<SendId, SendRecord>,
    send_marks: HashMap<SendId, ServerId>,
    withheld: HashMap<(ServerId, Owner), Withheld>,
}

impl MemoryStore {
    pub fn new(server: ServerId) -> MemoryStore {
        MemoryStore {
            leases: Arc::new(Mutex::new(HashMap::new())),
            erasures: Arc::new(Mutex::new(Vec::new())),
            extras: Arc::new(Mutex::new(Extras::default())),
            state: Arc::new(Mutex::new(State {
                server,
                next_seq: 1,
                last_hlc: Hlc::default(),
                heads: HashMap::new(),
                siblings: HashMap::new(),
                log: Vec::new(),
                meta: HashMap::new(),
                peers: BTreeMap::new(),
                switches: HashMap::new(),
                cursors: HashMap::new(),
                vaults: HashMap::new(),
                home_records: Vec::new(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes an item as this server's own change, as `ItemStore::put` does.
    pub fn put(&self, draft: ItemDraft) -> Result<Item, StoreError> {
        let mut st = self.lock();
        let stored = st.heads.get(&draft.id);
        if stored.is_some_and(|s| s.owner != draft.owner) {
            return Err(StoreError::Duplicate);
        }
        let current = stored.map(|s| s.revision);
        if current != draft.expected {
            return Err(StoreError::Conflict {
                item: draft.id,
                current,
            });
        }
        let hlc = st.last_hlc.tick(millis(draft.updated_at));
        let change = ChangeId {
            origin: st.server,
            seq: st.next_seq,
            hlc,
        };
        st.next_seq += 1;
        st.last_hlc = hlc;
        let item = draft.into_item(change);
        st.heads.insert(item.id, item.clone());
        st.log.push(LogRow {
            key: ChangeKey::of(&change),
            item: item.id,
            hlc,
        });
        Ok(item)
    }

    /// Queues the erasure of `vault` for `peer`, as the SQL store does for each replica when its
    /// home deletes a vault. `at` is Unix seconds.
    pub fn queue_erasure(&self, peer: ServerId, vault: Owner, at: u64) {
        self.erasures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(PendingErasure {
                peer,
                vault,
                queued_at: at,
            });
    }

    /// The head of an item.
    pub fn get(&self, id: ItemId) -> Option<Item> {
        self.lock().heads.get(&id).cloned()
    }

    /// How many items have a head.
    pub fn len(&self) -> usize {
        self.lock().heads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn extras(&self) -> MutexGuard<'_, Extras> {
        self.extras.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets what the home's store would read of a space, for publishing.
    pub fn set_space_snapshot(&self, snapshot: SpaceSnapshot) {
        let space = snapshot.state.space.id;
        self.extras().snapshots.insert(space, snapshot);
    }

    /// The space records applied at this replica, in order.
    pub fn applied_space_records(&self) -> Vec<SpaceRecord> {
        self.extras().space_applied.clone()
    }

    /// Turns server matching on or off for `owner`.
    pub fn set_matching(&self, owner: Owner, on: bool) {
        let mut extras = self.extras();
        if on {
            extras.matching.insert(owner);
        } else {
            extras.matching.remove(&owner);
        }
    }

    /// Stores tags as a device's upload would have, without checking the revision.
    pub fn set_tags(&self, owner: Owner, tags: ItemTags) {
        self.extras().tags.insert((owner, tags.item), tags);
    }

    /// The tags held for `owner`'s items.
    pub fn tags_held(&self, owner: Owner) -> Vec<ItemTags> {
        self.extras()
            .tags
            .iter()
            .filter(|((o, _), _)| *o == owner)
            .map(|(_, t)| t.clone())
            .collect()
    }

    /// Sets the events the home's log holds for the members of `vault`, oldest first.
    pub fn set_vault_events(&self, vault: Owner, events: Vec<LogEntry>) {
        self.extras().vault_events.insert(vault, events);
    }
}

impl PeerRepo for MemoryStore {
    async fn insert_peer(&self, peer: &Peer) -> Result<(), StoreError> {
        let mut st = self.lock();
        if st.peers.contains_key(&peer.id) {
            return Err(StoreError::Duplicate);
        }
        st.peers.insert(peer.id, peer.clone());
        Ok(())
    }

    async fn get_peer(&self, id: ServerId) -> Result<Option<Peer>, StoreError> {
        Ok(self.lock().peers.get(&id).cloned())
    }

    async fn list_peers(&self) -> Result<Vec<Peer>, StoreError> {
        Ok(self.lock().peers.values().cloned().collect())
    }

    async fn set_peer_state(&self, id: ServerId, state: PeerState) -> Result<(), StoreError> {
        match self.lock().peers.get_mut(&id) {
            Some(peer) => {
                peer.state = state;
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn touch_peer(&self, id: ServerId, at: u64) -> Result<(), StoreError> {
        match self.lock().peers.get_mut(&id) {
            Some(peer) => {
                peer.last_seen = Some(at);
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn remove_peer(&self, id: ServerId) -> Result<bool, StoreError> {
        let mut st = self.lock();
        st.switches.remove(&id);
        st.cursors.retain(|(peer, _), _| *peer != id);
        Ok(st.peers.remove(&id).is_some())
    }

    async fn log_switches(&self, id: ServerId) -> Result<LogSwitches, StoreError> {
        Ok(self.lock().switches.get(&id).copied().unwrap_or_default())
    }

    async fn set_log_switches(
        &self,
        id: ServerId,
        switches: LogSwitches,
    ) -> Result<(), StoreError> {
        self.lock().switches.insert(id, switches);
        Ok(())
    }
}

impl VaultRepo for MemoryStore {
    async fn get_vault(&self, owner: Owner) -> Result<Option<VaultFederation>, StoreError> {
        Ok(self.lock().vaults.get(&owner).cloned())
    }

    async fn put_vault(&self, vault: &VaultFederation) -> Result<(), StoreError> {
        self.lock().vaults.insert(vault.owner, vault.clone());
        Ok(())
    }

    async fn list_vaults(&self) -> Result<Vec<VaultFederation>, StoreError> {
        Ok(self.lock().vaults.values().cloned().collect())
    }

    async fn peer_cursor(&self, peer: ServerId, vault: Owner) -> Result<VersionVector, StoreError> {
        Ok(self
            .lock()
            .cursors
            .get(&(peer, vault))
            .cloned()
            .unwrap_or_default())
    }

    async fn set_peer_cursor(
        &self,
        peer: ServerId,
        vault: Owner,
        cursor: &VersionVector,
    ) -> Result<(), StoreError> {
        self.lock().cursors.insert((peer, vault), cursor.clone());
        Ok(())
    }

    async fn put_home_record(&self, stored: &StoredHomeRecord) -> Result<bool, StoreError> {
        let mut st = self.lock();
        let held = st.home_records.iter().any(|r| {
            r.record.vault == stored.record.vault && r.record.index == stored.record.index
        });
        if held {
            return Ok(false);
        }
        st.home_records.push(stored.clone());
        Ok(true)
    }

    async fn home_records(
        &self,
        vault: Owner,
        after: u64,
        limit: u32,
    ) -> Result<Vec<StoredHomeRecord>, StoreError> {
        let st = self.lock();
        let mut out: Vec<StoredHomeRecord> = st
            .home_records
            .iter()
            .filter(|r| r.record.vault == vault && r.record.index > after)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.record.index);
        out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(out)
    }

    async fn quarantined(&self, vault: Owner) -> Result<Vec<StoredHomeRecord>, StoreError> {
        let st = self.lock();
        let mut out: Vec<StoredHomeRecord> = st
            .home_records
            .iter()
            .filter(|r| r.record.vault == vault && r.status == HomeStatus::Quarantined)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.record.index);
        Ok(out)
    }
}

impl ReplicaStore for MemoryStore {
    fn server_id(&self) -> ServerId {
        self.lock().server
    }

    async fn export_since(
        &self,
        owner: Owner,
        since: &VersionVector,
        limit: u32,
    ) -> Result<ExportPage, StoreError> {
        let mut st = self.lock();
        let ids: Vec<ItemId> = st
            .heads
            .values()
            .filter(|i| i.owner == owner)
            .map(|i| i.id)
            .collect();
        let mut versions: Vec<Item> = Vec::new();
        for id in ids {
            versions.extend(st.versions_of(id));
        }
        versions.retain(|i| !since.covers(&i.change));
        versions.sort_by_key(|i| ChangeKey::of(&i.change));
        let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
        let more = versions.len() > limit;
        versions.truncate(limit);

        let mut next = since.clone();
        let mut entries = Vec::with_capacity(versions.len());
        for item in versions {
            next.observe(&item.change);
            entries.push(st.exported(item));
        }
        Ok(ExportPage {
            entries,
            next,
            more,
        })
    }

    async fn export_items(
        &self,
        owner: Owner,
        items: &[ItemId],
    ) -> Result<Vec<Exported>, StoreError> {
        let mut st = self.lock();
        let mut out = Vec::new();
        for id in items {
            for item in st.versions_of(*id) {
                if item.owner == owner {
                    out.push(st.exported(item));
                }
            }
        }
        Ok(out)
    }

    async fn store_signature(
        &self,
        key: ChangeKey,
        lineage: &[ChangeKey],
        signature: &[u8],
    ) -> Result<(), StoreError> {
        let mut st = self.lock();
        let meta = st.meta.entry(key).or_insert_with(|| Meta {
            lineage: lineage.to_vec(),
            signature: None,
        });
        if meta.signature.is_none() {
            meta.signature = Some(signature.to_vec());
        }
        Ok(())
    }

    async fn apply(
        &self,
        record: &ChangeRecord,
        signature: &[u8],
    ) -> Result<ApplyOutcome, StoreError> {
        let incoming_item = record
            .to_item()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut st = self.lock();
        let key = record.key();
        // Every change is applied once: one that is in the log, held or since replaced, is done.
        if st.log.iter().any(|e| e.key == key) {
            return Ok(ApplyOutcome::Duplicate);
        }
        if st
            .heads
            .get(&record.item)
            .is_some_and(|h| h.owner != record.owner)
        {
            return Err(StoreError::Duplicate);
        }

        let held_items = st.versions_of(record.item);
        for item in &held_items {
            st.ensure_meta(item);
        }
        let held: Vec<Version> = held_items
            .iter()
            .map(|item| Version {
                key: ChangeKey::of(&item.change),
                hlc: item.change.hlc,
                revision: item.revision,
                lineage: st.lineage_of(item),
            })
            .collect();
        let held_head = st.heads.get(&record.item).map(|h| ChangeKey::of(&h.change));
        let m = merge(&held, held_head, &Version::of(record));
        if !m.kept {
            return Ok(ApplyOutcome::Duplicate);
        }

        let mut by_key: HashMap<ChangeKey, Item> = held_items
            .into_iter()
            .map(|item| (ChangeKey::of(&item.change), item))
            .collect();
        by_key.insert(key, incoming_item);
        let head = by_key.remove(&m.head).ok_or_else(|| {
            StoreError::Backend("a merge named a version it was not given".to_owned())
        })?;
        let siblings: Vec<Item> = m.siblings.iter().filter_map(|k| by_key.remove(k)).collect();
        st.heads.insert(record.item, head);
        if siblings.is_empty() {
            st.siblings.remove(&record.item);
        } else {
            st.siblings.insert(record.item, siblings);
        }
        st.log.push(LogRow {
            key,
            item: record.item,
            hlc: record.change.hlc,
        });
        st.meta.insert(
            key,
            Meta {
                lineage: record.lineage.clone(),
                signature: Some(signature.to_vec()),
            },
        );
        st.last_hlc = st.last_hlc.max(record.change.hlc);
        Ok(if m.head == key {
            ApplyOutcome::Applied
        } else {
            ApplyOutcome::Sibling
        })
    }

    async fn leaves(&self, owner: Owner) -> Result<Vec<Leaf>, StoreError> {
        let st = self.lock();
        let mut out: Vec<Leaf> = st
            .heads
            .values()
            .filter(|i| i.owner == owner)
            .map(|i| {
                let versions: Vec<(ChangeKey, Revision)> = st
                    .versions_of(i.id)
                    .iter()
                    .map(|v| (ChangeKey::of(&v.change), v.revision))
                    .collect();
                Leaf {
                    item: i.id,
                    digest: leaf_digest(i.id, &versions),
                }
            })
            .collect();
        out.sort_by_key(|l| l.item);
        Ok(out)
    }

    async fn latest(&self, owner: Owner) -> Result<VersionVector, StoreError> {
        let st = self.lock();
        let mut vector = VersionVector::new();
        for head in st.heads.values().filter(|i| i.owner == owner) {
            for version in st.versions_of(head.id) {
                vector.observe(&version.change);
            }
        }
        Ok(vector)
    }

    async fn siblings(&self, owner: Owner, item: ItemId) -> Result<Vec<Item>, StoreError> {
        let st = self.lock();
        Ok(st
            .siblings
            .get(&item)
            .map(|s| s.iter().filter(|i| i.owner == owner).cloned().collect())
            .unwrap_or_default())
    }

    async fn resolve_siblings(&self, owner: Owner, item: ItemId) -> Result<u64, StoreError> {
        let mut st = self.lock();
        let Some(head) = st.heads.get(&item).cloned() else {
            return Ok(0);
        };
        if head.owner != owner {
            return Ok(0);
        }
        let Some(siblings) = st.siblings.get(&item).cloned() else {
            return Ok(0);
        };
        st.ensure_meta(&head);
        let head_key = ChangeKey::of(&head.change);
        let signed = st
            .meta
            .get(&head_key)
            .is_some_and(|m| m.signature.is_some());
        if signed {
            return Err(StoreError::Backend(
                "the head was already sent to a peer, so it can no longer replace its siblings"
                    .to_owned(),
            ));
        }
        if let Some(meta) = st.meta.get_mut(&head_key) {
            for sibling in &siblings {
                let key = ChangeKey::of(&sibling.change);
                if !meta.lineage.contains(&key) {
                    meta.lineage.insert(0, key);
                }
            }
            meta.lineage.truncate(MAX_LINEAGE);
        }
        st.siblings.remove(&item);
        Ok(siblings.len() as u64)
    }
}

// The in-memory store keeps no consent, member accounts or files: the defaults answer "nothing".
impl MemoryStore {
    /// The vaults with a live item here, as the console lists them: sized by their ciphertext, one
    /// member each, no email (this store has no accounts).
    fn vault_infos(&self) -> Vec<VaultInfo> {
        let st = self.lock();
        let mut by_owner: BTreeMap<String, VaultInfo> = BTreeMap::new();
        for item in st.heads.values().filter(|i| i.deleted_at.is_none()) {
            let entry = by_owner
                .entry(item.owner.to_string())
                .or_insert_with(|| VaultInfo {
                    vault: item.owner,
                    owner_email: None,
                    members: 1,
                    size_bytes: 0,
                });
            let size = item.ciphertext.as_ref().map_or(0, Vec::len) as u64;
            entry.size_bytes = entry.size_bytes.saturating_add(size);
        }
        by_owner.into_values().collect()
    }
}

impl crate::extra::FedAdminRepo for MemoryStore {
    async fn local_vaults(&self) -> Result<Vec<VaultInfo>, StoreError> {
        Ok(self.vault_infos())
    }

    async fn vault_info(&self, vault: Owner) -> Result<Option<VaultInfo>, StoreError> {
        Ok(self.vault_infos().into_iter().find(|v| v.vault == vault))
    }

    async fn newest_change_from(
        &self,
        vault: Owner,
        origin: ServerId,
    ) -> Result<Option<u64>, StoreError> {
        let st = self.lock();
        Ok(st
            .heads
            .values()
            .filter(|i| i.owner == vault && i.change.origin == origin)
            .map(|i| i.updated_at.unix_timestamp())
            .max()
            .and_then(|t| u64::try_from(t).ok()))
    }

    async fn put_peer_security(&self, record: &PeerSecurityRecord) -> Result<(), StoreError> {
        self.extras()
            .peer_security
            .insert(record.peer, record.clone());
        Ok(())
    }

    async fn peer_security(
        &self,
        peer: ServerId,
    ) -> Result<Option<PeerSecurityRecord>, StoreError> {
        Ok(self.extras().peer_security.get(&peer).cloned())
    }

    async fn put_mismatch(&self, record: &MismatchRecord) -> Result<(), StoreError> {
        self.extras().mismatches.insert(record.peer, record.clone());
        Ok(())
    }

    async fn mismatch(&self, peer: ServerId) -> Result<Option<MismatchRecord>, StoreError> {
        Ok(self.extras().mismatches.get(&peer).cloned())
    }
}
impl crate::extra::MemberStore for MemoryStore {}
impl crate::extra::BlobSync for MemoryStore {}

impl ErasureOutbox for MemoryStore {
    async fn pending_erasures(&self, peer: ServerId) -> Result<Vec<PendingErasure>, StoreError> {
        Ok(self
            .erasures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|e| e.peer == peer)
            .copied()
            .collect())
    }

    async fn complete_erasure(&self, peer: ServerId, vault: Owner) -> Result<(), StoreError> {
        self.erasures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|e| !(e.peer == peer && e.vault == vault));
        Ok(())
    }
}

impl VaultErasure for MemoryStore {
    async fn erase_vault(&self, vault: Owner) -> Result<VaultErased, StoreError> {
        // What federation keeps beside the vault's items goes too: its event log copies, its
        // duplicate tags and its matching switch.
        {
            let mut extras = self.extras();
            extras.vault_events.remove(&vault);
            extras.matching.remove(&vault);
            extras.tags.retain(|(owner, _), _| *owner != vault);
        }
        let mut st = self.lock();
        let ids: Vec<ItemId> = st
            .heads
            .values()
            .filter(|i| i.owner == vault)
            .map(|i| i.id)
            .collect();
        for id in &ids {
            st.heads.remove(id);
            st.siblings.remove(id);
        }
        let gone: Vec<ChangeKey> = st
            .log
            .iter()
            .filter(|e| ids.contains(&e.item))
            .map(|e| e.key)
            .collect();
        st.log.retain(|e| !ids.contains(&e.item));
        for key in &gone {
            st.meta.remove(key);
        }
        st.cursors.retain(|(_, owner), _| *owner != vault);
        st.vaults.remove(&vault);
        st.home_records.retain(|r| r.record.vault != vault);
        Ok(VaultErased {
            items: ids.len() as u64,
            ..VaultErased::default()
        })
    }
}

impl SpaceMirror for MemoryStore {
    async fn space_snapshot(&self, space: SpaceId) -> Result<Option<SpaceSnapshot>, StoreError> {
        Ok(self.extras().snapshots.get(&space).cloned())
    }

    async fn apply_space_record(
        &self,
        _space: SpaceId,
        record: &SpaceRecord,
    ) -> Result<(), StoreError> {
        self.extras().space_applied.push(record.clone());
        Ok(())
    }
}

impl crate::extra::Leases for MemoryStore {
    async fn acquire_lease(
        &self,
        name: &str,
        holder: &str,
        ttl_secs: u64,
    ) -> Result<bool, StoreError> {
        let now = crate::session::unix_now();
        let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((current, expires)) = leases.get(name)
            && *expires > now
            && current != holder
        {
            return Ok(false);
        }
        leases.insert(name.to_owned(), (holder.to_owned(), now + ttl_secs));
        Ok(true)
    }

    async fn drop_lease(&self, name: &str, holder: &str) -> Result<(), StoreError> {
        let mut leases = self.leases.lock().unwrap_or_else(PoisonError::into_inner);
        if leases
            .get(name)
            .is_some_and(|(current, _)| current == holder)
        {
            leases.remove(name);
        }
        Ok(())
    }
}

impl crate::forget::Forgetting for MemoryStore {}

impl KeyStore for MemoryStore {
    async fn put_key_record(&self, record: &StoredKeyRecord) -> Result<bool, StoreError> {
        let mut extras = self.extras();
        if let Some(held) = extras
            .key_records
            .iter_mut()
            .find(|r| r.server == record.server && r.kind == record.kind)
        {
            if held.issued_at >= record.issued_at {
                return Ok(false);
            }
            *held = record.clone();
            return Ok(true);
        }
        extras.key_records.push(record.clone());
        Ok(true)
    }

    async fn key_records(&self) -> Result<Vec<StoredKeyRecord>, StoreError> {
        Ok(self.extras().key_records.clone())
    }

    async fn set_peer_identity(&self, peer: ServerId, key: &[u8]) -> Result<(), StoreError> {
        match self.lock().peers.get_mut(&peer) {
            Some(held) => {
                held.identity_key = key.to_vec();
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }
}

impl OriginKeys for MemoryStore {
    async fn put_learned_key(&self, key: &LearnedKey) -> Result<(), StoreError> {
        let mut extras = self.extras();
        extras.learned.retain(|l| l.server != key.server);
        extras.learned.push(key.clone());
        Ok(())
    }

    async fn learned_keys(&self) -> Result<Vec<LearnedKey>, StoreError> {
        Ok(self.extras().learned.clone())
    }

    async fn remove_learned_key(&self, server: ServerId) -> Result<(), StoreError> {
        self.extras().learned.retain(|l| l.server != server);
        Ok(())
    }
}

impl TagSync for MemoryStore {
    async fn matching_on(&self, owner: Owner) -> Result<bool, StoreError> {
        Ok(self.extras().matching.contains(&owner))
    }

    async fn tags_of(&self, owner: Owner, items: &[ItemId]) -> Result<Vec<ItemTags>, StoreError> {
        let revisions: HashMap<ItemId, u64> = {
            let st = self.lock();
            items
                .iter()
                .filter_map(|id| st.heads.get(id).map(|h| (*id, h.revision.0)))
                .collect()
        };
        let extras = self.extras();
        Ok(items
            .iter()
            .filter_map(|id| extras.tags.get(&(owner, *id)))
            .filter(|t| revisions.get(&t.item) == Some(&t.revision))
            .cloned()
            .collect())
    }

    async fn untagged(&self, owner: Owner, limit: u32) -> Result<Vec<ItemId>, StoreError> {
        let live: Vec<(ItemId, u64)> = {
            let st = self.lock();
            st.heads
                .values()
                .filter(|h| h.owner == owner && !h.is_tombstone())
                .map(|h| (h.id, h.revision.0))
                .collect()
        };
        let extras = self.extras();
        let mut out: Vec<ItemId> = live
            .into_iter()
            .filter(|(id, revision)| {
                extras
                    .tags
                    .get(&(owner, *id))
                    .is_none_or(|t| t.revision != *revision)
            })
            .map(|(id, _)| id)
            .collect();
        out.sort();
        out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(out)
    }

    async fn apply_tags(&self, owner: Owner, tags: &ItemTags) -> Result<bool, StoreError> {
        let fits = self.lock().heads.get(&tags.item).is_some_and(|h| {
            h.owner == owner && !h.is_tombstone() && h.revision.0 == tags.revision
        });
        if fits {
            self.extras().tags.insert((owner, tags.item), tags.clone());
        }
        Ok(fits)
    }
}

impl EventSync for MemoryStore {
    async fn vault_events(
        &self,
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    ) -> Result<Vec<LogEntry>, StoreError> {
        let extras = self.extras();
        let mut out: Vec<LogEntry> = extras
            .vault_events
            .get(&vault)
            .map(|all| all.iter().filter(|e| e.id > after).cloned().collect())
            .unwrap_or_default();
        out.sort_by_key(|e| e.id);
        out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(out)
    }

    async fn store_peer_events(
        &self,
        peer: ServerId,
        vault: Owner,
        events: &[LogEntry],
    ) -> Result<usize, StoreError> {
        let mut extras = self.extras();
        let mut new = 0;
        for entry in events {
            let held = extras
                .peer_events
                .iter()
                .any(|e| e.from == peer && e.vault == vault && e.entry.id == entry.id);
            if !held {
                extras.peer_events.push(PeerEvent {
                    from: peer,
                    vault,
                    entry: entry.clone(),
                });
                new += 1;
            }
        }
        Ok(new)
    }

    async fn peer_events_cursor(
        &self,
        peer: ServerId,
        vault: Owner,
    ) -> Result<[u8; 16], StoreError> {
        Ok(self
            .extras()
            .peer_events
            .iter()
            .filter(|e| e.from == peer && e.vault == vault)
            .map(|e| e.entry.id)
            .max()
            .unwrap_or([0; 16]))
    }

    async fn peer_events(&self, vault: Owner, limit: u32) -> Result<Vec<PeerEvent>, StoreError> {
        let mut out: Vec<PeerEvent> = self
            .extras()
            .peer_events
            .iter()
            .filter(|e| e.vault == vault)
            .cloned()
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.entry.id));
        out.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(out)
    }

    async fn forget_peer_events(&self, peer: ServerId) -> Result<u64, StoreError> {
        let mut extras = self.extras();
        let before = extras.peer_events.len();
        extras.peer_events.retain(|e| e.from != peer);
        Ok((before - extras.peer_events.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::draft;
    use kemlock_domain::UserId;

    fn store() -> MemoryStore {
        MemoryStore::new(ServerId::random())
    }

    #[tokio::test]
    async fn local_writes_take_sequence_numbers_and_check_revisions() {
        let s = store();
        let owner = Owner::User(UserId::random());
        let id = ItemId::random();
        let first = s.put(draft(id, owner, None, 1, 1_000)).expect("first");
        assert_eq!(first.change.seq, 1);
        let second = s.put(draft(id, owner, Some(1), 2, 1_000)).expect("second");
        assert_eq!(second.change.seq, 2);
        assert!(second.change.hlc > first.change.hlc);
        assert!(matches!(
            s.put(draft(id, owner, Some(1), 2, 1_000)),
            Err(StoreError::Conflict { .. })
        ));
        assert!(matches!(
            s.put(draft(id, Owner::User(UserId::random()), Some(2), 3, 1_000)),
            Err(StoreError::Duplicate)
        ));
        assert_eq!(s.len(), 1);
    }

    #[tokio::test]
    async fn export_pages_through_uncovered_versions_with_lineage() {
        let s = store();
        let owner = Owner::User(UserId::random());
        let id = ItemId::random();
        let one = s.put(draft(id, owner, None, 1, 1_000)).expect("one");
        let two = s.put(draft(id, owner, Some(1), 2, 2_000)).expect("two");
        let other = s
            .put(draft(ItemId::random(), owner, None, 1, 3_000))
            .expect("other");
        let page = s
            .export_since(owner, &VersionVector::new(), 10)
            .await
            .expect("export");
        assert!(!page.more);
        assert_eq!(page.entries.len(), 2, "each item once, at its head");
        let head = page
            .entries
            .iter()
            .find(|e| e.item.id == id)
            .expect("the edited item");
        assert_eq!(head.item.revision, Revision(2));
        assert_eq!(head.lineage, vec![ChangeKey::of(&one.change)]);
        assert!(head.signature.is_none());
        assert!(page.next.covers(&two.change) && page.next.covers(&other.change));

        let small = s
            .export_since(owner, &VersionVector::new(), 1)
            .await
            .expect("export");
        assert!(small.more);
        assert_eq!(small.entries.len(), 1);
        let rest = s
            .export_since(owner, &small.next, 10)
            .await
            .expect("export");
        assert_eq!(rest.entries.len(), 1);
        assert!(!rest.more);
    }

    #[tokio::test]
    async fn a_signature_is_stored_once() {
        let s = store();
        let owner = Owner::User(UserId::random());
        let item = s
            .put(draft(ItemId::random(), owner, None, 1, 1_000))
            .expect("put");
        let key = ChangeKey::of(&item.change);
        s.store_signature(key, &[], b"first").await.expect("store");
        s.store_signature(key, &[], b"second").await.expect("store");
        let page = s
            .export_since(owner, &VersionVector::new(), 10)
            .await
            .expect("export");
        assert_eq!(page.entries[0].signature.as_deref(), Some(&b"first"[..]));
    }

    #[tokio::test]
    async fn peers_vaults_and_cursors_are_kept() {
        let s = store();
        let peer = Peer {
            id: ServerId::random(),
            operator: "x".to_owned(),
            identity_key: vec![1],
            addresses: vec![],
            suites: vec![],
            state: PeerState::Paired,
            paired_at: 5,
            last_seen: None,
        };
        s.insert_peer(&peer).await.expect("insert");
        assert!(matches!(
            s.insert_peer(&peer).await,
            Err(StoreError::Duplicate)
        ));
        s.set_peer_state(peer.id, PeerState::Revoked)
            .await
            .expect("state");
        s.touch_peer(peer.id, 9).await.expect("touch");
        let got = s.get_peer(peer.id).await.expect("get").expect("there");
        assert_eq!(got.state, PeerState::Revoked);
        assert_eq!(got.last_seen, Some(9));
        assert!(matches!(
            s.set_peer_state(ServerId::random(), PeerState::Paired)
                .await,
            Err(StoreError::NotFound)
        ));

        assert_eq!(
            s.log_switches(peer.id).await.expect("switches"),
            LogSwitches::default()
        );
        let on = LogSwitches {
            send: true,
            pull: false,
        };
        s.set_log_switches(peer.id, on).await.expect("set");
        assert_eq!(s.log_switches(peer.id).await.expect("switches"), on);

        let vault = Owner::User(UserId::random());
        assert!(
            s.peer_cursor(peer.id, vault)
                .await
                .expect("cursor")
                .is_empty()
        );
        let mut cursor = VersionVector::new();
        cursor.observe(&ChangeId {
            origin: ServerId::random(),
            seq: 3,
            hlc: Hlc(1),
        });
        s.set_peer_cursor(peer.id, vault, &cursor)
            .await
            .expect("set");
        assert_eq!(s.peer_cursor(peer.id, vault).await.expect("cursor"), cursor);

        let fed = VaultFederation::federated(vault, s.server_id(), vec![peer.id]);
        s.put_vault(&fed).await.expect("put");
        assert_eq!(s.get_vault(vault).await.expect("get"), Some(fed));
        assert_eq!(s.list_vaults().await.expect("list").len(), 1);

        assert!(s.remove_peer(peer.id).await.expect("remove"));
        assert!(!s.remove_peer(peer.id).await.expect("remove"));
        assert!(
            s.peer_cursor(peer.id, vault)
                .await
                .expect("cursor")
                .is_empty()
        );
    }
}

impl MemoryStore {
    /// Adds a Send as the owner made it here.
    pub fn put_send(&self, send: SendRecord) {
        self.extras().sends.insert(send.id, send);
    }

    /// A Send held here, copied or made here.
    pub fn send(&self, id: SendId) -> Option<SendRecord> {
        self.extras().sends.get(&id).cloned()
    }

    /// The ids of the Sends held here.
    pub fn send_ids(&self) -> Vec<SendId> {
        self.extras().sends.keys().copied().collect()
    }
}

impl SendSync for MemoryStore {
    async fn sends_after(
        &self,
        owner: Owner,
        after: SendId,
        limit: u32,
        not_from: ServerId,
    ) -> Result<Vec<SendRecord>, StoreError> {
        let Owner::User(user) = owner else {
            return Ok(Vec::new());
        };
        let extras = self.extras();
        Ok(extras
            .sends
            .values()
            .filter(|s| s.owner == user && s.id > after && s.file.is_none_or(|f| f.ready))
            .filter(|s| extras.send_marks.get(&s.id) != Some(&not_from))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .cloned()
            .collect())
    }

    async fn send_of_blob(&self, blob: BlobId) -> Result<Option<SendRecord>, StoreError> {
        Ok(self
            .extras()
            .sends
            .values()
            .find(|s| s.file.is_some_and(|f| f.blob == blob))
            .cloned())
    }

    async fn send_row(&self, id: SendId) -> Result<Option<SendRecord>, StoreError> {
        Ok(self.send(id))
    }

    async fn apply_replicated_send(
        &self,
        from: ServerId,
        send: &SendRecord,
    ) -> Result<SendApply, StoreError> {
        let mut extras = self.extras();
        let Some(held) = extras.sends.get_mut(&send.id) else {
            extras.sends.insert(send.id, send.clone());
            extras.send_marks.insert(send.id, from);
            return Ok(SendApply::Added);
        };
        if held.owner != send.owner {
            return Ok(SendApply::Unchanged);
        }
        let newer = send.revised_at > held.revised_at;
        let more_views = send.access_count > held.access_count;
        if newer {
            let (file, count) = (held.file, held.access_count);
            *held = SendRecord {
                file,
                access_count: count,
                ..send.clone()
            };
        }
        if more_views {
            held.access_count = send.access_count;
        }
        Ok(if newer || more_views {
            SendApply::Updated
        } else {
            SendApply::Unchanged
        })
    }

    async fn replicated_send_ids(
        &self,
        owner: Owner,
        from: ServerId,
    ) -> Result<Vec<SendId>, StoreError> {
        let Owner::User(user) = owner else {
            return Ok(Vec::new());
        };
        let extras = self.extras();
        Ok(extras
            .send_marks
            .iter()
            .filter(|(id, origin)| {
                **origin == from && extras.sends.get(id).is_some_and(|s| s.owner == user)
            })
            .map(|(id, _)| *id)
            .collect())
    }

    async fn drop_replicated_send(&self, id: SendId) -> Result<Option<BlobId>, StoreError> {
        let mut extras = self.extras();
        if extras.send_marks.remove(&id).is_none() {
            return Ok(None);
        }
        Ok(extras
            .sends
            .remove(&id)
            .and_then(|s| s.file)
            .map(|f| f.blob))
    }
}

impl MemoryStore {
    /// Deletes a Send, as its owner did here.
    pub fn remove_send(&self, id: SendId) {
        self.extras().sends.remove(&id);
    }
}

impl Withholding for MemoryStore {
    async fn withheld(&self, peer: ServerId, vault: Owner) -> Result<Option<Withheld>, StoreError> {
        Ok(self.extras().withheld.get(&(peer, vault)).cloned())
    }

    async fn withhold(
        &self,
        peer: ServerId,
        vault: Owner,
        upto: &VersionVector,
        at: u64,
    ) -> Result<(), StoreError> {
        let mut extras = self.extras();
        let held = extras.withheld.entry((peer, vault)).or_default();
        held.upto.merge(upto);
        held.at = at;
        Ok(())
    }

    async fn release_withheld(&self, peer: ServerId, vault: Owner) -> Result<bool, StoreError> {
        Ok(self.extras().withheld.remove(&(peer, vault)).is_some())
    }

    async fn forget_withheld(&self, peer: ServerId) -> Result<(), StoreError> {
        self.extras().withheld.retain(|(p, _), _| *p != peer);
        Ok(())
    }
}
