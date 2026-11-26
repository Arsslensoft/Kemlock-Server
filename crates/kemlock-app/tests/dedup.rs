//! The duplicate cleaner's use cases over the in-memory fakes: tags with a write and after it, the
//! groups, the "Not duplicates" answers, the on/off switch and the rules for spaces.

mod fakes;
mod space_fakes;

use fakes::{FakeEnv, FakeStore, actor, write};
use kemlock_app::dedup::{
    BackfillTags, DedupError, Dismiss, DuplicateReport, GetMatching, ListDuplicates,
    RotateDedupKey, SetMatching, StoreTags, Undismiss,
};
use kemlock_app::spaces::CreateCollectionInput;
use kemlock_domain::spaces::{CollectionId, CollectionPermission, SpaceRole};
use kemlock_domain::{DedupTag, Item, ItemId, Owner, Revision, TagSet, UserId};
use space_fakes::{SpaceWorld, Spaces, key_for, name};
use std::collections::HashMap;

fn tag(n: u8) -> DedupTag {
    DedupTag([n; 32])
}

fn set(version: u32, tags: &[u8]) -> TagSet {
    TagSet::new(version, tags.iter().copied().map(tag)).expect("a small set")
}

struct Scene {
    w: SpaceWorld,
}

impl Scene {
    fn new() -> Scene {
        Scene {
            w: SpaceWorld::new(),
        }
    }

    fn store(&self) -> FakeStore {
        self.w.world.store.clone()
    }

    fn store_tags(&self) -> StoreTags<FakeStore, Spaces> {
        StoreTags {
            tags: self.store(),
            spaces: self.w.spaces.clone(),
        }
    }

    fn backfill(&self) -> BackfillTags<FakeStore, FakeStore, Spaces> {
        BackfillTags {
            tags: self.store(),
            items: self.store(),
            spaces: self.w.spaces.clone(),
        }
    }

    fn list(&self) -> ListDuplicates<FakeStore, FakeStore, Spaces> {
        ListDuplicates {
            tags: self.store(),
            dismissals: self.store(),
            spaces: self.w.spaces.clone(),
        }
    }

    fn dismiss(&self) -> Dismiss<FakeStore, FakeStore, FakeStore, Spaces, FakeEnv> {
        Dismiss {
            tags: self.store(),
            dismissals: self.store(),
            items: self.store(),
            spaces: self.w.spaces.clone(),
            clock: self.w.world.env.clone(),
        }
    }

    fn undismiss(&self) -> Undismiss<FakeStore, Spaces> {
        Undismiss {
            dismissals: self.store(),
            spaces: self.w.spaces.clone(),
        }
    }

    fn set_matching(&self) -> SetMatching<FakeStore, Spaces, FakeStore, FakeEnv> {
        SetMatching {
            tags: self.store(),
            spaces: self.w.spaces.clone(),
            events: self.store(),
            clock: self.w.world.env.clone(),
        }
    }

    fn get_matching(&self) -> GetMatching<FakeStore, Spaces> {
        GetMatching {
            tags: self.store(),
            spaces: self.w.spaces.clone(),
        }
    }

    async fn user(&self, email: &str) -> UserId {
        self.w.user(email).await
    }

    /// Writes revision `revision` of a vault item (`expected` is the one before it).
    async fn put(&self, user: UserId, id: ItemId, revision: u64) -> Item {
        let expected = revision.checked_sub(1).filter(|r| *r > 0);
        self.w
            .world
            .put_item()
            .execute(&actor(user), write(user, id, expected, revision))
            .await
            .expect("the write is stored")
    }

    /// A new vault item with these tags, stored after the write.
    async fn put_tagged(&self, user: UserId, version: u32, tags: &[u8]) -> Item {
        let item = self.put(user, ItemId::random(), 1).await;
        let outcome = self
            .store_tags()
            .after_write(&actor(user), &item, set(version, tags))
            .await
            .expect("tags are stored");
        assert!(outcome.stored, "the tags were stored");
        item
    }

    async fn turn_on(&self, user: UserId) {
        self.set_matching()
            .execute(&actor(user), Owner::User(user), true)
            .await
            .expect("matching is turned on");
    }

    async fn report(&self, user: UserId) -> DuplicateReport {
        self.list()
            .execute(&actor(user), Owner::User(user))
            .await
            .expect("the groups are listed")
    }
}

#[tokio::test]
async fn matching_is_off_until_it_is_turned_on() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    let item = s.put(sam, ItemId::random(), 1).await;

    let settings = s
        .get_matching()
        .execute(&actor(sam), Owner::User(sam))
        .await
        .expect("settings");
    assert!(!settings.enabled);
    assert_eq!(settings.version, 1);

    let outcome = s
        .store_tags()
        .after_write(&actor(sam), &item, set(1, &[1]))
        .await
        .expect("a write's tags are ignored, not refused");
    assert!(!outcome.stored && outcome.matches.is_empty());
    assert_eq!(s.store().tagged_items(), 0);

    assert_eq!(
        s.backfill()
            .execute(&actor(sam), item.id, Revision(1), set(1, &[1]))
            .await,
        Err(DedupError::MatchingOff)
    );
    let report = s.report(sam).await;
    assert!(!report.enabled && report.groups.is_empty() && report.waiting == 0);
}

#[tokio::test]
async fn equal_tags_make_a_group_and_the_second_item_is_told_its_match() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;

    let a = s.put(sam, ItemId::random(), 1).await;
    let first = s
        .store_tags()
        .after_write(&actor(sam), &a, set(1, &[1, 2]))
        .await;
    assert_eq!(first.expect("stored").matches, Vec::<ItemId>::new());
    let b = s.put(sam, ItemId::random(), 1).await;
    let second = s
        .store_tags()
        .after_write(&actor(sam), &b, set(1, &[2, 3]))
        .await
        .expect("stored");
    assert!(second.stored);
    assert_eq!(second.matches, vec![a.id]);
    s.put_tagged(sam, 1, &[9]).await;
    // An item written without tags waits for them.
    s.put(sam, ItemId::random(), 1).await;

    let report = s.report(sam).await;
    assert!(report.enabled);
    assert_eq!(report.version, 1);
    assert_eq!(report.groups.len(), 1);
    let mut expected = vec![a.id, b.id];
    expected.sort();
    assert_eq!(report.groups[0].items, expected);
    assert_eq!(report.waiting, 1);
}

#[tokio::test]
async fn a_write_clears_the_tags_and_the_deleted_item_leaves_its_group() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    let a = s.put_tagged(sam, 1, &[1]).await;
    let b = s.put_tagged(sam, 1, &[1]).await;
    assert_eq!(s.report(sam).await.groups.len(), 1);

    // A new revision, with no tags: they are of the old one.
    s.put(sam, a.id, 2).await;
    assert!(s.store().tags_of(a.id).is_empty());
    let report = s.report(sam).await;
    assert!(report.groups.is_empty());
    assert_eq!(report.waiting, 1);

    // Tag it again, then delete the other one: no group, and no tags kept for it.
    let outcome = s
        .backfill()
        .execute(&actor(sam), a.id, Revision(2), set(1, &[1]))
        .await
        .expect("backfilled");
    assert_eq!(outcome, vec![b.id]);
    s.w.world
        .put_item()
        .execute(&actor(sam), fakes::delete(sam, b.id, 1, 2))
        .await
        .expect("deleted");
    assert!(s.store().tags_of(b.id).is_empty());
    assert!(s.report(sam).await.groups.is_empty());
}

#[tokio::test]
async fn a_backfill_needs_the_current_revision_and_key_version() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    let item = s.put(sam, ItemId::random(), 1).await;

    assert_eq!(
        s.backfill()
            .execute(&actor(sam), item.id, Revision(7), set(1, &[1]))
            .await,
        Err(DedupError::StaleItem {
            item: item.id,
            current: Some(Revision(1))
        })
    );
    assert_eq!(
        s.backfill()
            .execute(&actor(sam), item.id, Revision(1), set(5, &[1]))
            .await,
        Err(DedupError::StaleVersion { current: 1 })
    );
    assert_eq!(
        s.backfill()
            .execute(&actor(sam), ItemId::random(), Revision(1), set(1, &[1]))
            .await,
        Err(DedupError::NotFound)
    );
    s.backfill()
        .execute(&actor(sam), item.id, Revision(1), set(1, &[1]))
        .await
        .expect("backfilled");
    assert_eq!(s.store().tags_of(item.id), vec![tag(1)]);
    // An empty set clears them.
    s.backfill()
        .execute(&actor(sam), item.id, Revision(1), set(1, &[]))
        .await
        .expect("cleared");
    assert!(s.store().tags_of(item.id).is_empty());
}

#[tokio::test]
async fn tags_of_another_key_version_are_ignored_with_a_write() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    let item = s.put(sam, ItemId::random(), 1).await;
    let outcome = s
        .store_tags()
        .after_write(&actor(sam), &item, set(3, &[1]))
        .await
        .expect("ignored");
    assert!(!outcome.stored);
    assert_eq!(s.store().tagged_items(), 0);
}

#[tokio::test]
async fn a_batch_stores_the_tags_of_the_items_that_carried_them() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    let a = s.put(sam, ItemId::random(), 1).await;
    let b = s.put(sam, ItemId::random(), 1).await;
    let c = s.put(sam, ItemId::random(), 1).await;
    let mut tags = HashMap::new();
    tags.insert(a.id, set(1, &[4]));
    tags.insert(c.id, set(1, &[4]));
    let outcomes = s
        .store_tags()
        .after_batch(&actor(sam), &[a.clone(), b.clone(), c.clone()], tags)
        .await
        .expect("stored");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].0, a.id);
    assert_eq!(outcomes[1].0, c.id);
    assert_eq!(outcomes[1].1.matches, vec![a.id]);
    assert!(s.store().tags_of(b.id).is_empty());
}

#[tokio::test]
async fn turning_matching_off_deletes_every_tag() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    s.put_tagged(sam, 1, &[1]).await;
    s.put_tagged(sam, 1, &[1]).await;
    assert_eq!(s.store().tagged_items(), 2);

    let off = s
        .set_matching()
        .execute(&actor(sam), Owner::User(sam), false)
        .await
        .expect("off");
    assert!(!off.enabled);
    assert_eq!(off.changed_by, Some(sam));
    assert_eq!(s.store().tagged_items(), 0);
    assert!(!s.report(sam).await.enabled);
    let events = s.store().events();
    assert!(events.iter().any(|e| e.action == "dedup.matching-on"));
    assert!(events.iter().any(|e| e.action == "dedup.matching-off"));
}

#[tokio::test]
async fn a_rotation_deletes_the_tags_and_moves_the_version() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    let item = s.put_tagged(sam, 1, &[1]).await;
    let rotate = RotateDedupKey {
        tags: s.store(),
        clock: s.w.world.env.clone(),
    };
    assert_eq!(rotate.execute(Owner::User(sam)).await, Ok(2));
    assert!(s.store().tags_of(item.id).is_empty());
    assert_eq!(s.report(sam).await.version, 2);
    assert_eq!(
        s.backfill()
            .execute(&actor(sam), item.id, Revision(1), set(1, &[1]))
            .await,
        Err(DedupError::StaleVersion { current: 2 })
    );
    s.backfill()
        .execute(&actor(sam), item.id, Revision(1), set(2, &[1]))
        .await
        .expect("tags under the new version");
}

#[tokio::test]
async fn a_not_duplicates_answer_hides_the_group_until_a_new_item_joins() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    s.turn_on(sam).await;
    let a = s.put_tagged(sam, 1, &[1]).await;
    let b = s.put_tagged(sam, 1, &[1]).await;

    let answer = s
        .dismiss()
        .execute(&actor(sam), Owner::User(sam), vec![a.id, b.id])
        .await
        .expect("saved");
    assert_eq!(answer.by, sam);
    assert!(s.report(sam).await.groups.is_empty());

    let c = s.put_tagged(sam, 1, &[1]).await;
    let groups = s.report(sam).await.groups;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].items.len(), 3);
    assert!(groups[0].items.contains(&c.id));

    s.undismiss()
        .execute(&actor(sam), answer.id)
        .await
        .expect("taken back");
    assert_eq!(
        s.undismiss().execute(&actor(sam), answer.id).await,
        Err(DedupError::NotFound)
    );
}

#[tokio::test]
async fn an_answer_needs_matching_on_and_two_items_of_the_owner() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    let kim = s.user("kim@example.org").await;
    let a = s.put(sam, ItemId::random(), 1).await;
    let b = s.put(sam, ItemId::random(), 1).await;
    let theirs = s.put(kim, ItemId::random(), 1).await;

    assert_eq!(
        s.dismiss()
            .execute(&actor(sam), Owner::User(sam), vec![a.id, b.id])
            .await,
        Err(DedupError::MatchingOff)
    );
    s.turn_on(sam).await;
    assert!(matches!(
        s.dismiss()
            .execute(&actor(sam), Owner::User(sam), vec![a.id])
            .await,
        Err(DedupError::Invalid(_))
    ));
    assert_eq!(
        s.dismiss()
            .execute(&actor(sam), Owner::User(sam), vec![a.id, theirs.id])
            .await,
        Err(DedupError::NotFound)
    );
    assert_eq!(
        s.dismiss()
            .execute(&actor(sam), Owner::User(sam), vec![a.id, ItemId::random()])
            .await,
        Err(DedupError::NotFound)
    );
}

#[tokio::test]
async fn nobody_else_reads_or_changes_a_vaults_duplicates() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    let kim = s.user("kim@example.org").await;
    s.turn_on(sam).await;
    let item = s.put_tagged(sam, 1, &[1]).await;
    let answer = {
        let other = s.put_tagged(sam, 1, &[1]).await;
        s.dismiss()
            .execute(&actor(sam), Owner::User(sam), vec![item.id, other.id])
            .await
            .expect("saved")
    };

    let me = Owner::User(sam);
    assert_eq!(
        s.list().execute(&actor(kim), me).await,
        Err(DedupError::NotFound)
    );
    assert_eq!(
        s.get_matching().execute(&actor(kim), me).await,
        Err(DedupError::NotFound)
    );
    assert_eq!(
        s.set_matching().execute(&actor(kim), me, false).await,
        Err(DedupError::NotFound)
    );
    assert_eq!(
        s.backfill()
            .execute(&actor(kim), item.id, Revision(1), set(1, &[2]))
            .await,
        Err(DedupError::NotFound)
    );
    assert_eq!(
        s.undismiss().execute(&actor(kim), answer.id).await,
        Err(DedupError::NotFound)
    );
    assert_eq!(s.store().tags_of(item.id), vec![tag(1)]);
}

/// A space with sam as owner, kim as a member who may view its one collection, and lee as a member
/// with no grant at all; two items in the collection, tagged alike.
struct SpaceScene {
    s: Scene,
    space: kemlock_domain::SpaceId,
    sam: UserId,
    kim: UserId,
    lee: UserId,
    items: Vec<Item>,
}

async fn space_scene() -> SpaceScene {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    let kim = s.user("kim@example.org").await;
    let lee = s.user("lee@example.org").await;
    let (space, everyone) = s.w.make_space(sam).await;
    s.w.join(
        space,
        sam,
        sam,
        kim,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::View)],
    )
    .await;
    s.w.join(space, sam, sam, lee, SpaceRole::Member, Vec::new())
        .await;
    s.set_matching()
        .execute(&actor(sam), Owner::Space(space), true)
        .await
        .expect("an owner turns it on");
    let mut items = Vec::new();
    for _ in 0..2 {
        let item =
            s.w.put_space_item()
                .execute(
                    &actor(sam),
                    everyone,
                    s.w.item_write(space, ItemId::random(), None, 1, 1),
                )
                .await
                .expect("a space item");
        let outcome = s
            .store_tags()
            .after_write(&actor(sam), &item, set(1, &[1]))
            .await
            .expect("tags");
        assert!(outcome.stored);
        items.push(item);
    }
    SpaceScene {
        s,
        space,
        sam,
        kim,
        lee,
        items,
    }
}

#[tokio::test]
async fn a_member_sees_the_groups_of_the_collections_they_hold() {
    let sc = space_scene().await;
    let owner = Owner::Space(sc.space);
    let sam =
        sc.s.list()
            .execute(&actor(sc.sam), owner)
            .await
            .expect("sam");
    assert_eq!(sam.groups.len(), 1);
    let kim =
        sc.s.list()
            .execute(&actor(sc.kim), owner)
            .await
            .expect("kim");
    assert_eq!(kim.groups.len(), 1);
    assert_eq!(kim.groups[0].items.len(), 2);
    // Lee is in the space but holds no collection: the group is theirs to know nothing about.
    let lee =
        sc.s.list()
            .execute(&actor(sc.lee), owner)
            .await
            .expect("lee");
    assert!(lee.groups.is_empty());
    assert!(lee.enabled);
}

#[tokio::test]
async fn only_owners_and_admins_turn_a_spaces_matching_on_or_off() {
    let sc = space_scene().await;
    let owner = Owner::Space(sc.space);
    let denied =
        sc.s.set_matching()
            .execute(&actor(sc.kim), owner, false)
            .await;
    assert!(matches!(denied, Err(DedupError::Forbidden(_))));
    let outsider = sc.s.user("zed@example.org").await;
    assert_eq!(
        sc.s.set_matching()
            .execute(&actor(outsider), owner, false)
            .await,
        Err(DedupError::NotFound)
    );
    // Every member can read who turned it on.
    let seen =
        sc.s.get_matching()
            .execute(&actor(sc.lee), owner)
            .await
            .expect("a member reads");
    assert!(seen.enabled);
    assert_eq!(seen.changed_by, Some(sc.sam));
    assert!(seen.changed_at.is_some());

    sc.s.set_matching()
        .execute(&actor(sc.sam), owner, false)
        .await
        .expect("an owner turns it off");
    assert_eq!(sc.s.store().tagged_items(), 0);
}

#[tokio::test]
async fn a_backfill_in_a_space_takes_edit_on_the_items_collection() {
    let sc = space_scene().await;
    let item = &sc.items[0];
    // Kim may view the collection, not edit it.
    let refused =
        sc.s.backfill()
            .execute(&actor(sc.kim), item.id, Revision(1), set(1, &[2]))
            .await;
    assert!(matches!(refused, Err(DedupError::Forbidden(_))));
    let ok =
        sc.s.backfill()
            .execute(&actor(sc.sam), item.id, Revision(1), set(1, &[1]))
            .await
            .expect("an editor backfills");
    assert_eq!(ok, vec![sc.items[1].id]);
}

#[tokio::test]
async fn an_answer_in_a_space_is_seen_by_every_member() {
    let sc = space_scene().await;
    let owner = Owner::Space(sc.space);
    let ids: Vec<ItemId> = sc.items.iter().map(|i| i.id).collect();
    // Lee can't see these items, so can't answer about them.
    assert_eq!(
        sc.s.dismiss()
            .execute(&actor(sc.lee), owner, ids.clone())
            .await,
        Err(DedupError::NotFound)
    );
    let answer =
        sc.s.dismiss()
            .execute(&actor(sc.kim), owner, ids)
            .await
            .expect("a viewer answers");
    assert!(
        sc.s.list()
            .execute(&actor(sc.sam), owner)
            .await
            .expect("sam")
            .groups
            .is_empty()
    );
    sc.s.undismiss()
        .execute(&actor(sc.sam), answer.id)
        .await
        .expect("another member takes it back");
    assert_eq!(
        sc.s.list()
            .execute(&actor(sc.sam), owner)
            .await
            .expect("sam")
            .groups
            .len(),
        1
    );
}

#[tokio::test]
async fn a_tag_write_names_only_the_matches_the_writer_may_see() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    let kim = s.user("kim@example.org").await;
    let (space, everyone) = s.w.make_space(sam).await;
    s.w.join(
        space,
        sam,
        sam,
        kim,
        SpaceRole::Member,
        vec![(everyone, CollectionPermission::Edit)],
    )
    .await;
    // Finance holds an item only Sam may see.
    let finance = CollectionId::random();
    s.w.create_collection()
        .execute(
            &actor(sam),
            space,
            CreateCollectionInput {
                id: finance,
                parent: None,
                name: name(8),
                grants: Vec::new(),
                keys: vec![key_for(finance, sam, 6)],
            },
        )
        .await
        .expect("a collection only Sam holds");
    s.set_matching()
        .execute(&actor(sam), Owner::Space(space), true)
        .await
        .expect("an owner turns it on");
    let secret =
        s.w.put_space_item()
            .execute(
                &actor(sam),
                finance,
                s.w.item_write(space, ItemId::random(), None, 1, 1),
            )
            .await
            .expect("Sam's item");
    let stored = s
        .store_tags()
        .after_write(&actor(sam), &secret, set(1, &[7]))
        .await
        .expect("tags");
    assert!(stored.stored);

    // Kim, with edit on Everyone alone, writes an item and guesses the tag: the answer doesn't
    // say that Finance's item has it.
    let mine =
        s.w.put_space_item()
            .execute(
                &actor(kim),
                everyone,
                s.w.item_write(space, ItemId::random(), None, 1, 1),
            )
            .await
            .expect("Kim's item");
    let guessed = s
        .store_tags()
        .after_write(&actor(kim), &mine, set(1, &[7]))
        .await
        .expect("tags");
    assert!(guessed.stored);
    assert!(guessed.matches.is_empty(), "{:?}", guessed.matches);

    // The same for a batch and for a backfill.
    let mut tags = HashMap::new();
    tags.insert(mine.id, set(1, &[7]));
    let batch = s
        .store_tags()
        .after_batch(&actor(kim), std::slice::from_ref(&mine), tags)
        .await
        .expect("tags");
    assert!(batch[0].1.matches.is_empty());
    let backfilled = s
        .backfill()
        .execute(&actor(kim), mine.id, mine.revision, set(1, &[7]))
        .await
        .expect("backfilled");
    assert!(backfilled.is_empty(), "{backfilled:?}");

    // Sam holds both collections, so for him the tag does match Kim's item.
    let seen = s
        .backfill()
        .execute(&actor(sam), secret.id, secret.revision, set(1, &[7]))
        .await
        .expect("backfilled");
    assert_eq!(seen, vec![mine.id]);
}

#[tokio::test]
async fn tags_are_not_stored_when_the_writer_cannot_be_checked_against_the_space() {
    let s = Scene::new();
    let sam = s.user("sam@example.org").await;
    let zed = s.user("zed@example.org").await;
    let (space, everyone) = s.w.make_space(sam).await;
    s.set_matching()
        .execute(&actor(sam), Owner::Space(space), true)
        .await
        .expect("an owner turns it on");
    let item =
        s.w.put_space_item()
            .execute(
                &actor(sam),
                everyone,
                s.w.item_write(space, ItemId::random(), None, 1, 1),
            )
            .await
            .expect("Sam's item");

    // Zed isn't in the space. The refusal comes before the tags are stored, so the answer can't
    // say "not stored" about tags that were.
    let refused = s
        .store_tags()
        .after_write(&actor(zed), &item, set(1, &[1]))
        .await;
    assert_eq!(refused.map(|_| ()), Err(DedupError::NotFound));
    assert!(s.store().tags_of(item.id).is_empty());
}
