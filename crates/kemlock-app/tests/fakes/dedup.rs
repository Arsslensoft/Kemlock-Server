//! Fakes for the duplicate cleaner's ports, kept beside `FakeStore` so one store value serves every
//! repository port. The state lives in `DedupState`, a field of `FakeStore`; item writes clear an
//! item's tags there, as the SQL store does in the write's own transaction.

use super::FakeStore;
use kemlock_app::dedup::{DismissalStore, TagStore};
use kemlock_app::ports::StoreError;
use kemlock_domain::dedup::group_pairs;
use kemlock_domain::{
    DedupTag, Dismissal, DismissalId, DuplicateGroup, ItemId, MatchingSettings, Owner, Revision,
    TagSet, UserId,
};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// One item's tags, as the store keeps them.
#[derive(Clone)]
struct Stored {
    owner: Owner,
    revision: Revision,
    version: u32,
    tags: Vec<DedupTag>,
}

#[derive(Default)]
struct DedupInner {
    settings: HashMap<Owner, MatchingSettings>,
    tags: HashMap<ItemId, Stored>,
    dismissals: Vec<Dismissal>,
}

/// The maps behind the two ports.
#[derive(Clone, Default)]
pub(crate) struct DedupState(Arc<Mutex<DedupInner>>);

impl DedupState {
    fn lock(&self) -> std::sync::MutexGuard<'_, DedupInner> {
        self.0.lock().expect("the dedup lock isn't poisoned")
    }

    /// An item was written: its tags are of an older revision.
    pub(crate) fn clear(&self, item: ItemId) {
        self.lock().tags.remove(&item);
    }
}

impl FakeStore {
    /// The live items of `owner` and their revisions.
    fn live_items(&self, owner: Owner) -> HashMap<ItemId, Revision> {
        self.lock()
            .items
            .values()
            .filter(|i| i.owner == owner && !i.is_tombstone())
            .map(|i| (i.id, i.revision))
            .collect()
    }

    /// The tags stored for an item, whatever their version.
    pub(crate) fn tags_of(&self, item: ItemId) -> Vec<DedupTag> {
        self.dedup
            .lock()
            .tags
            .get(&item)
            .map(|s| s.tags.clone())
            .unwrap_or_default()
    }

    /// How many items have tags.
    pub(crate) fn tagged_items(&self) -> usize {
        self.dedup.lock().tags.len()
    }

    fn valid_tags(&self, owner: Owner, version: u32) -> Vec<(ItemId, Vec<DedupTag>)> {
        let live = self.live_items(owner);
        self.dedup
            .lock()
            .tags
            .iter()
            .filter(|(id, s)| {
                s.owner == owner && s.version == version && live.get(*id) == Some(&s.revision)
            })
            .map(|(id, s)| (*id, s.tags.clone()))
            .collect()
    }
}

impl TagStore for FakeStore {
    async fn settings(&self, owner: Owner) -> Result<MatchingSettings, StoreError> {
        Ok(self
            .dedup
            .lock()
            .settings
            .get(&owner)
            .cloned()
            .unwrap_or_else(|| MatchingSettings::initial(owner)))
    }

    async fn set_matching(
        &self,
        owner: Owner,
        enabled: bool,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<MatchingSettings, StoreError> {
        let mut g = self.dedup.lock();
        let settings = g
            .settings
            .entry(owner)
            .or_insert_with(|| MatchingSettings::initial(owner));
        settings.enabled = enabled;
        settings.changed_by = Some(by);
        settings.changed_at = Some(at);
        let settings = settings.clone();
        if !enabled {
            g.tags.retain(|_, s| s.owner != owner);
        }
        Ok(settings)
    }

    async fn bump_version(&self, owner: Owner, _at: OffsetDateTime) -> Result<u32, StoreError> {
        let mut g = self.dedup.lock();
        let settings = g
            .settings
            .entry(owner)
            .or_insert_with(|| MatchingSettings::initial(owner));
        settings.version += 1;
        let version = settings.version;
        g.tags.retain(|_, s| s.owner != owner);
        Ok(version)
    }

    async fn put_tags(
        &self,
        owner: Owner,
        item: ItemId,
        revision: Revision,
        tags: &TagSet,
    ) -> Result<bool, StoreError> {
        let Some(stored) = self.item(item) else {
            return Ok(false);
        };
        if stored.owner != owner || stored.is_tombstone() || stored.revision != revision {
            return Ok(false);
        }
        let mut g = self.dedup.lock();
        g.tags.remove(&item);
        if !tags.tags.is_empty() {
            g.tags.insert(
                item,
                Stored {
                    owner,
                    revision,
                    version: tags.version,
                    tags: tags.tags.clone(),
                },
            );
        }
        Ok(true)
    }

    async fn matches(
        &self,
        owner: Owner,
        version: u32,
        item: ItemId,
    ) -> Result<Vec<ItemId>, StoreError> {
        let valid = self.valid_tags(owner, version);
        let Some((_, mine)) = valid.iter().find(|(id, _)| *id == item) else {
            return Ok(Vec::new());
        };
        let mine: BTreeSet<&DedupTag> = mine.iter().collect();
        let mut others: Vec<ItemId> = valid
            .iter()
            .filter(|(id, tags)| *id != item && tags.iter().any(|t| mine.contains(t)))
            .map(|(id, _)| *id)
            .collect();
        others.sort();
        Ok(others)
    }

    async fn groups(&self, owner: Owner, version: u32) -> Result<Vec<DuplicateGroup>, StoreError> {
        let pairs = self
            .valid_tags(owner, version)
            .into_iter()
            .flat_map(|(id, tags)| tags.into_iter().map(move |t| (t, id)));
        Ok(group_pairs(pairs))
    }

    async fn waiting(&self, owner: Owner, version: u32) -> Result<u64, StoreError> {
        let tagged: BTreeSet<ItemId> = self
            .valid_tags(owner, version)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let waiting = self
            .live_items(owner)
            .keys()
            .filter(|id| !tagged.contains(*id))
            .count();
        Ok(u64::try_from(waiting).unwrap_or(u64::MAX))
    }
}

impl DismissalStore for FakeStore {
    async fn add(&self, dismissal: &Dismissal) -> Result<(), StoreError> {
        self.dedup.lock().dismissals.push(dismissal.clone());
        Ok(())
    }

    async fn get(&self, id: DismissalId) -> Result<Option<Dismissal>, StoreError> {
        Ok(self
            .dedup
            .lock()
            .dismissals
            .iter()
            .find(|d| d.id == id)
            .cloned())
    }

    async fn list(&self, owner: Owner) -> Result<Vec<Dismissal>, StoreError> {
        Ok(self
            .dedup
            .lock()
            .dismissals
            .iter()
            .filter(|d| d.owner == owner)
            .cloned()
            .collect())
    }

    async fn remove(&self, id: DismissalId) -> Result<bool, StoreError> {
        let mut g = self.dedup.lock();
        let before = g.dismissals.len();
        g.dismissals.retain(|d| d.id != id);
        Ok(g.dismissals.len() != before)
    }
}
