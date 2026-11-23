//! The duplicate cleaner's data (design, "Duplicate cleaner"): the tags a device may upload, the
//! groups the server makes of equal ones, and the "Not duplicates" answers.
//!
//! A tag is 32 bytes of HMAC-SHA-256 under a dedup key the server never holds (docs/crypto.md,
//! "Duplicate tags"), so the server can only see which tags are equal. It never makes one. Server
//! matching is off by default, per owner: a person turns it on for their vault, a space's admins for
//! their space.

use crate::ids::{ItemId, UserId};
use crate::owner::Owner;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

/// The length of a tag.
pub const TAG_LEN: usize = 32;
/// The most tags one item may carry. A login makes one `cred` tag per website.
pub const MAX_TAGS_PER_ITEM: usize = 64;
/// The most items one "Not duplicates" answer may name.
pub const MAX_DISMISSED_ITEMS: usize = 500;
/// The first dedup key version of an owner.
pub const FIRST_VERSION: u32 = 1;

/// A duplicate tag: HMAC-SHA-256 of a normalised input under the owner's dedup key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DedupTag(pub [u8; TAG_LEN]);

impl DedupTag {
    /// The tag in these bytes; `None` unless there are exactly 32.
    pub fn from_slice(bytes: &[u8]) -> Option<DedupTag> {
        <[u8; TAG_LEN]>::try_from(bytes).ok().map(DedupTag)
    }

    pub fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }
}

impl fmt::Debug for DedupTag {
    /// Never the bytes: a log line has no use for a tag.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DedupTag(..)")
    }
}

/// The tags of one item revision, made under one key version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagSet {
    /// The owner's dedup key version the tags were made under.
    pub version: u32,
    /// Sorted, each once.
    pub tags: Vec<DedupTag>,
}

/// Why tags or a dismissal were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    #[error("an item carries at most 64 tags")]
    TooMany,
    #[error("a dismissal names at least two and at most 500 items")]
    BadDismissal,
}

impl TagSet {
    /// A set from `tags`: sorted, duplicates dropped, at most [`MAX_TAGS_PER_ITEM`] of them.
    pub fn new(version: u32, tags: impl IntoIterator<Item = DedupTag>) -> Result<TagSet, TagError> {
        let tags: BTreeSet<DedupTag> = tags.into_iter().collect();
        if tags.len() > MAX_TAGS_PER_ITEM {
            return Err(TagError::TooMany);
        }
        Ok(TagSet {
            version,
            tags: tags.into_iter().collect(),
        })
    }
}

/// Items of one owner that share a tag: what the server says is a probable duplicate. The device
/// opens each group and compares the values before it shows it, so a group is a hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// The smallest tag the items share.
    pub tag: DedupTag,
    /// Two or more items, sorted.
    pub items: Vec<ItemId>,
}

/// Groups from `(tag, item)` pairs: items per tag, two or more of them, groups with the same items
/// counted once (a login with two websites would otherwise appear twice), in order of tag.
pub fn group_pairs(pairs: impl IntoIterator<Item = (DedupTag, ItemId)>) -> Vec<DuplicateGroup> {
    let mut by_tag: std::collections::BTreeMap<DedupTag, BTreeSet<ItemId>> =
        std::collections::BTreeMap::new();
    for (tag, item) in pairs {
        by_tag.entry(tag).or_default().insert(item);
    }
    let mut seen: BTreeSet<Vec<ItemId>> = BTreeSet::new();
    let mut groups = Vec::new();
    for (tag, items) in by_tag {
        if items.len() < 2 {
            continue;
        }
        let items: Vec<ItemId> = items.into_iter().collect();
        if seen.insert(items.clone()) {
            groups.push(DuplicateGroup { tag, items });
        }
    }
    groups
}

/// A saved "Not duplicates" answer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DismissalId(pub Uuid);

impl DismissalId {
    /// A new random id (UUID v4).
    pub fn random() -> DismissalId {
        DismissalId(Uuid::new_v4())
    }
}

impl fmt::Debug for DismissalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DismissalId({})", self.0)
    }
}

impl fmt::Display for DismissalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for DismissalId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(DismissalId)
    }
}

/// "These items are not duplicates", seen by every member of the owner. The group comes back only
/// if an item that isn't among these joins it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dismissal {
    pub id: DismissalId,
    pub owner: Owner,
    /// The group's items, sorted.
    pub items: Vec<ItemId>,
    /// Who answered.
    pub by: UserId,
    pub at: OffsetDateTime,
}

impl Dismissal {
    /// A dismissal of `items`: sorted, duplicates dropped, two to [`MAX_DISMISSED_ITEMS`] of them.
    pub fn new(
        owner: Owner,
        items: impl IntoIterator<Item = ItemId>,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<Dismissal, TagError> {
        let items: BTreeSet<ItemId> = items.into_iter().collect();
        if items.len() < 2 || items.len() > MAX_DISMISSED_ITEMS {
            return Err(TagError::BadDismissal);
        }
        Ok(Dismissal {
            id: DismissalId::random(),
            owner,
            items: items.into_iter().collect(),
            by,
            at,
        })
    }

    /// Whether the answer covers `group`: every item of the group was in the dismissed set.
    pub fn covers(&self, group: &DuplicateGroup) -> bool {
        group
            .items
            .iter()
            .all(|item| self.items.binary_search(item).is_ok())
    }
}

/// The groups that no dismissal covers.
pub fn without_dismissed(
    groups: Vec<DuplicateGroup>,
    dismissals: &[Dismissal],
) -> Vec<DuplicateGroup> {
    groups
        .into_iter()
        .filter(|group| !dismissals.iter().any(|d| d.covers(group)))
        .collect()
}

/// Whether the server may group an owner's tags, and which key version they must have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchingSettings {
    pub owner: Owner,
    /// Off until the person (or the space's admins) turn it on.
    pub enabled: bool,
    /// The dedup key version tags are grouped under; a new user key or space key bumps it.
    pub version: u32,
    /// Who last turned it on or off, and when.
    pub changed_by: Option<UserId>,
    pub changed_at: Option<OffsetDateTime>,
}

impl MatchingSettings {
    /// What an owner has before anyone has chosen: off, at the first version.
    pub fn initial(owner: Owner) -> MatchingSettings {
        MatchingSettings {
            owner,
            enabled: false,
            version: FIRST_VERSION,
            changed_by: None,
            changed_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn tag(n: u8) -> DedupTag {
        DedupTag([n; TAG_LEN])
    }

    fn ids(n: usize) -> Vec<ItemId> {
        let mut ids: Vec<ItemId> = (0..n).map(|_| ItemId::random()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn tags_are_exactly_32_bytes_and_never_printed() {
        assert!(DedupTag::from_slice(&[0; 31]).is_none());
        assert!(DedupTag::from_slice(&[0; 33]).is_none());
        let t = DedupTag::from_slice(&[7; 32]).expect("32 bytes");
        assert_eq!(t.as_bytes(), &[7; 32]);
        assert_eq!(format!("{t:?}"), "DedupTag(..)");
    }

    #[test]
    fn a_tag_set_is_sorted_unique_and_bounded() {
        let set = TagSet::new(2, [tag(3), tag(1), tag(3)]).expect("small");
        assert_eq!(set.version, 2);
        assert_eq!(set.tags, vec![tag(1), tag(3)]);
        let many = (0..=u8::try_from(MAX_TAGS_PER_ITEM).expect("fits")).map(tag);
        assert_eq!(TagSet::new(1, many), Err(TagError::TooMany));
        assert!(
            TagSet::new(1, std::iter::empty())
                .expect("empty is fine")
                .tags
                .is_empty()
        );
    }

    #[test]
    fn groups_need_two_items_and_count_one_item_set_once() {
        let items = ids(3);
        let groups = group_pairs([
            (tag(1), items[0]),
            (tag(1), items[1]),
            (tag(1), items[1]),
            (tag(2), items[0]),
            (tag(2), items[1]),
            (tag(3), items[2]),
            (tag(4), items[1]),
            (tag(4), items[2]),
        ]);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].tag, tag(1));
        assert_eq!(groups[0].items, vec![items[0], items[1]]);
        assert_eq!(groups[1].items, vec![items[1], items[2]]);
        assert!(group_pairs([(tag(1), items[0])]).is_empty());
    }

    #[test]
    fn a_dismissal_names_two_or_more_items_once_each() {
        let owner = Owner::User(UserId::random());
        let by = UserId::random();
        let at = OffsetDateTime::UNIX_EPOCH;
        let items = ids(2);
        let d = Dismissal::new(owner, [items[1], items[0], items[0]], by, at).expect("two");
        assert_eq!(d.items, items);
        assert_eq!(
            Dismissal::new(owner, [items[0], items[0]], by, at),
            Err(TagError::BadDismissal)
        );
        assert_eq!(
            Dismissal::new(owner, ids(MAX_DISMISSED_ITEMS + 1), by, at),
            Err(TagError::BadDismissal)
        );
    }

    #[test]
    fn a_group_comes_back_only_when_a_new_item_joins_it() {
        let owner = Owner::User(UserId::random());
        let items = ids(3);
        let d = Dismissal::new(
            owner,
            [items[0], items[1]],
            UserId::random(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("two");
        let same = DuplicateGroup {
            tag: tag(1),
            items: vec![items[0], items[1]],
        };
        let grown = DuplicateGroup {
            tag: tag(1),
            items: items.clone(),
        };
        assert!(d.covers(&same));
        assert!(!d.covers(&grown));
        let left = without_dismissed(vec![same, grown.clone()], &[d]);
        assert_eq!(left, vec![grown]);
    }

    #[test]
    fn matching_starts_off_at_the_first_version() {
        let s = MatchingSettings::initial(Owner::User(UserId::random()));
        assert!(!s.enabled);
        assert_eq!(s.version, 1);
        assert!(s.changed_by.is_none());
    }

    #[test]
    fn dismissal_ids_round_trip_through_text() {
        let id = DismissalId::random();
        assert_eq!(id.to_string().parse::<DismissalId>().expect("uuid"), id);
        assert!("nope".parse::<DismissalId>().is_err());
    }
}
