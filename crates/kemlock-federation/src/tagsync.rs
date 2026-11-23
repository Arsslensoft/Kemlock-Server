//! Duplicate tags between servers, where server matching is on.
//!
//! A device that has server matching on uploads the duplicate tags of each item revision it writes
//! (`docs/crypto.md`, "Duplicate tags"); the server keeps them beside the revision and can tell
//! which items of an owner share a tag. A tag is valid only for the revision it was made for, so it
//! travels with that revision: after a replica pulls the revisions of a vault it asks the peer
//! ([`Request::Tags`]) for the tags of the items it holds without any, and applies the ones made
//! for the revision it holds. A replica where matching is off for the owner asks for nothing and a
//! server answers a vault with matching off with nothing, so a vault that never turned matching on
//! sends no tag anywhere.
//!
//! Tags are not part of the origin-signed change record: they are added to a revision after it is
//! written, and a signature is made once. They are hints (a tag only says two items might be equal,
//! and the device compares the values before it shows a group), received over an authenticated
//! session from a peer that holds the vault, and a tag that doesn't match the revision a replica
//! holds does nothing.

use crate::cbor::{Fields, Value};
use crate::error::{FedError, Result};
use crate::message::{Request, Response};
use crate::replicate::{Channel, FedStore, Replica};
use crate::wire::item_id;
use kemlock_app::ports::StoreError;
use kemlock_domain::dedup::{MAX_TAGS_PER_ITEM, TAG_LEN};
use kemlock_domain::{ItemId, Owner, ServerId};
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// How many items one request for tags names.
pub const CHUNK: u32 = 256;

/// The tags of one item revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemTags {
    pub item: ItemId,
    /// The revision the tags were made for.
    pub revision: u64,
    /// The owner's dedup key version they were made under.
    pub version: u32,
    /// Sorted, each once, at most 64.
    pub tags: Vec<[u8; TAG_LEN]>,
}

impl ItemTags {
    pub(crate) fn to_value(&self) -> Value {
        let mut packed = Vec::with_capacity(self.tags.len() * TAG_LEN);
        for tag in &self.tags {
            packed.extend_from_slice(tag);
        }
        Value::map(vec![
            (0, Value::bytes(self.item.as_bytes())),
            (1, Value::Uint(self.revision)),
            (2, Value::Uint(u64::from(self.version))),
            (3, Value::Bytes(packed)),
        ])
    }

    pub(crate) fn from_value(value: &Value) -> Result<ItemTags> {
        let f: Fields<'_> = value.as_fields()?;
        f.only(&[0, 1, 2, 3])?;
        let packed = f.bytes(3)?;
        if packed.len() % TAG_LEN != 0 || packed.len() / TAG_LEN > MAX_TAGS_PER_ITEM {
            return Err(FedError::Malformed("the tags are not a whole number"));
        }
        let tags: Vec<[u8; TAG_LEN]> = packed.as_chunks::<TAG_LEN>().0.to_vec();
        if !tags.windows(2).all(|w| w[0] < w[1]) {
            return Err(FedError::Malformed("the tags are not sorted and distinct"));
        }
        Ok(ItemTags {
            item: item_id(f.fixed::<16>(0)?),
            revision: f.uint(1)?,
            version: u32::try_from(f.uint(2)?)
                .map_err(|_| FedError::Malformed("a key version is out of range"))?,
            tags,
        })
    }
}

/// What federation needs from storage to move duplicate tags. The defaults say matching is off and
/// nothing is held.
pub trait TagSync: Send + Sync {
    /// Whether server matching is on for `owner`.
    fn matching_on(&self, _owner: Owner) -> impl Future<Output = R<bool>> + Send {
        ready(Ok(false))
    }

    /// The tags held for these live items at their current revision; items without are left out.
    fn tags_of(
        &self,
        _owner: Owner,
        _items: &[ItemId],
    ) -> impl Future<Output = R<Vec<ItemTags>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Live items of `owner` that have no tags at their current revision, at most `limit`.
    fn untagged(&self, _owner: Owner, _limit: u32) -> impl Future<Output = R<Vec<ItemId>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Keeps `tags` for the item if it is `owner`'s, live and at the revision they were made for;
    /// false when it isn't.
    fn apply_tags(&self, _owner: Owner, _tags: &ItemTags) -> impl Future<Output = R<bool>> + Send {
        ready(Ok(false))
    }
}

impl<S: FedStore> Replica<S> {
    /// Answers a request for the tags of some items, when matching is on for the vault.
    pub(crate) async fn serve_tags(
        &self,
        _peer: ServerId,
        vault: Owner,
        items: &[ItemId],
    ) -> Result<Response> {
        let entries = if self.store.matching_on(vault).await? {
            self.store.tags_of(vault, items).await?
        } else {
            Vec::new()
        };
        Ok(Response::Tags { vault, entries })
    }

    /// Asks `peer` for the tags of the items of `vault` this server holds without any, and keeps
    /// those made for the revision held. Does nothing when matching is off for the vault here.
    /// Returns how many items got tags.
    pub async fn pull_tags<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<usize> {
        self.authorize(peer, vault).await?;
        if !self.store.matching_on(vault).await? {
            return Ok(0);
        }
        let items = self.store.untagged(vault, CHUNK).await?;
        if items.is_empty() {
            return Ok(0);
        }
        let response = channel.call(&Request::Tags { vault, items }).await?;
        let entries = match response {
            Response::Tags { vault: v, entries } if v == vault => entries,
            Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
            _ => return Err(FedError::Malformed("an unexpected response to tags")),
        };
        let mut stored = 0;
        for entry in entries
            .iter()
            .filter(|e| !e.tags.is_empty() && e.version > 0)
        {
            if self.store.apply_tags(vault, entry).await? {
                stored += 1;
            }
        }
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::suite::Suite;
    use crate::testing::{draft, identity};
    use kemlock_domain::UserId;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    fn tags(item: ItemId, revision: u64, fill: &[u8]) -> ItemTags {
        ItemTags {
            item,
            revision,
            version: 1,
            tags: fill.iter().map(|b| [*b; TAG_LEN]).collect(),
        }
    }

    #[test]
    fn tags_round_trip_and_unsorted_or_odd_lengths_are_refused() {
        let t = tags(ItemId::random(), 3, &[1, 2, 3]);
        assert_eq!(ItemTags::from_value(&t.to_value()), Ok(t.clone()));
        let none = tags(ItemId::random(), 1, &[]);
        assert_eq!(ItemTags::from_value(&none.to_value()), Ok(none));
        let unsorted = tags(ItemId::random(), 1, &[2, 1]);
        assert!(ItemTags::from_value(&unsorted.to_value()).is_err());
        let repeated = tags(ItemId::random(), 1, &[1, 1]);
        assert!(ItemTags::from_value(&repeated.to_value()).is_err());
        let too_many = tags(ItemId::random(), 1, &(0..=64).collect::<Vec<u8>>());
        assert!(ItemTags::from_value(&too_many.to_value()).is_err());
        let mut value = t.to_value();
        if let Value::Map(entries) = &mut value {
            for (k, v) in entries.iter_mut() {
                if *k == 3 {
                    *v = Value::Bytes(vec![1; TAG_LEN + 1]);
                }
            }
        }
        assert!(ItemTags::from_value(&value).is_err());
    }

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
        calls: usize,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            self.calls += 1;
            Ok(self.remote.serve(self.caller, request, NOW).await.response)
        }
    }

    #[tokio::test]
    async fn tags_follow_their_revision_where_matching_is_on_at_both_ends() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        let (one, two) = (ItemId::random(), ItemId::random());
        a.store.put(draft(one, vault, None, 1, 1_000)).expect("put");
        a.store.put(draft(two, vault, None, 1, 1_001)).expect("put");
        a.store.set_matching(vault, true);
        a.store.set_tags(vault, tags(one, 1, &[1, 2]));
        a.store.set_tags(vault, tags(two, 1, &[2]));
        let mut channel = Direct {
            remote: &a,
            caller: ib.server,
            calls: 0,
        };
        b.pull(&mut channel, ia.server, vault).await.expect("pull");

        // Matching off at the replica: nothing is asked and nothing arrives.
        assert_eq!(b.pull_tags(&mut channel, ia.server, vault).await, Ok(0));
        assert_eq!(channel.calls, 1, "only the pull");
        assert!(b.store.tags_held(vault).is_empty());

        // On at the replica: the tags of both items arrive, once.
        b.store.set_matching(vault, true);
        assert_eq!(b.pull_tags(&mut channel, ia.server, vault).await, Ok(2));
        assert_eq!(b.store.tags_held(vault).len(), 2);
        assert_eq!(b.pull_tags(&mut channel, ia.server, vault).await, Ok(0));
        assert_eq!(
            channel.calls, 2,
            "the second time there was nothing to ask for"
        );

        // Off at the sender: it answers with nothing, even for an item the replica lacks tags of.
        let three = ItemId::random();
        a.store
            .put(draft(three, vault, None, 1, 1_002))
            .expect("put");
        a.store.set_tags(vault, tags(three, 1, &[9]));
        a.store.set_matching(vault, false);
        b.pull(&mut channel, ia.server, vault).await.expect("pull");
        assert_eq!(b.pull_tags(&mut channel, ia.server, vault).await, Ok(0));
        assert_eq!(b.store.tags_held(vault).len(), 2);
    }

    #[tokio::test]
    async fn tags_made_for_another_revision_are_not_kept() {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let vault = Owner::User(UserId::random());
        let item = ItemId::random();
        a.store
            .put(draft(item, vault, None, 1, 1_000))
            .expect("put");
        a.store.set_matching(vault, true);
        // The item is at revision 1; tags for revision 2 are not stored.
        assert_eq!(
            a.store.apply_tags(vault, &tags(item, 2, &[1])).await,
            Ok(false)
        );
        assert_eq!(
            a.store.apply_tags(vault, &tags(item, 1, &[1])).await,
            Ok(true)
        );
    }
}
