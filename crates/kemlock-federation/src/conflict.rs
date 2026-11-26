//! Merging versions of one item that two servers accepted while apart.
//!
//! Servers can't read items, so they can't merge them. What they can do is keep every version
//! that no other version replaced. A version replaces another when the other is in its lineage.
//! Of the versions nobody replaced, the one with the latest HLC time (then the higher origin id,
//! then the higher sequence number) is the **head**, the one devices sync and Bitwarden apps
//! see; the others are **siblings**, kept until a write supersedes them. The rule depends only on
//! the set of versions, so every server that holds the same set picks the same head, whatever
//! order the versions arrived in.

use crate::change::ChangeRecord;
use crate::wire::ChangeKey;
use kemlock_domain::{Hlc, Revision};

/// What a merge needs to know about a stored version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub key: ChangeKey,
    pub hlc: Hlc,
    pub revision: Revision,
    /// The versions this one replaced.
    pub lineage: Vec<ChangeKey>,
}

impl Version {
    pub fn of(record: &ChangeRecord) -> Version {
        Version {
            key: record.key(),
            hlc: record.change.hlc,
            revision: record.revision,
            lineage: record.lineage.clone(),
        }
    }

    /// Later versions sort higher: HLC time, then origin id, then sequence number; with
    /// [`Rank::Revision`], the revision first.
    ///
    /// The revision comes first so that a version below another unreplaced version's revision never
    /// takes the head from it, however late its clock: a replica that re-signs an old ciphertext as a
    /// new change that leaves the head out of its lineage can't roll the item back that way
    /// (docs/federation.md, "Rollback"). Concurrent edits of one revision are still ordered by clock.
    fn rank(&self, by: Rank) -> (Revision, Hlc, ChangeKey) {
        let revision = match by {
            Rank::Clock => Revision(0),
            Rank::Revision => self.revision,
        };
        (revision, self.hlc, self.key)
    }
}

/// How the head is chosen among the versions nothing replaced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rank {
    /// By clock alone: what servers did before writer signatures. Used while a server of the vault
    /// doesn't say it ranks by revision (`x-kemlock-signed-writes1`), so all of them agree.
    #[default]
    Clock,
    /// By revision first.
    Revision,
}

/// The result of adding a version to what a server holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merge {
    /// Whether the new version is held after the merge. False for a duplicate, for a version
    /// an held version already replaced, and for a rollback.
    pub kept: bool,
    /// The new version names the head in its lineage but has a revision no higher than the
    /// head's: a record that would roll the item back. It is not kept.
    pub regressed: bool,
    /// The head after the merge.
    pub head: ChangeKey,
    /// The siblings after the merge, latest first.
    pub siblings: Vec<ChangeKey>,
    /// Held versions the new one replaced: to be deleted.
    pub dropped: Vec<ChangeKey>,
    /// Whether the head is another version than before.
    pub head_changed: bool,
}

/// Adds `incoming` to the versions `held` (the head and the siblings; at least the head), the head
/// chosen by clock.
pub fn merge(held: &[Version], held_head: Option<ChangeKey>, incoming: &Version) -> Merge {
    merge_ranked(held, held_head, incoming, Rank::Clock)
}

/// [`merge`], choosing the head as `rank` says.
pub fn merge_ranked(
    held: &[Version],
    held_head: Option<ChangeKey>,
    incoming: &Version,
    rank: Rank,
) -> Merge {
    // A version replaces the head only at a higher revision (docs/federation.md, "Rollback"): a
    // replica that re-signs an old ciphertext as a new change naming the head can't roll it back.
    let regressed = held_head.is_some_and(|head| {
        incoming.lineage.contains(&head)
            && held
                .iter()
                .any(|v| v.key == head && v.revision >= incoming.revision)
    });
    let known = regressed
        || held
            .iter()
            .any(|v| v.key == incoming.key || v.lineage.contains(&incoming.key));

    let mut all: Vec<&Version> = held.iter().collect();
    if !known {
        all.push(incoming);
    }
    // Versions no other version replaced, latest first.
    let mut maximal: Vec<&Version> = all
        .iter()
        .copied()
        .filter(|v| {
            !all.iter()
                .any(|w| w.key != v.key && w.lineage.contains(&v.key))
        })
        .collect();
    maximal.sort_by_key(|v| std::cmp::Reverse(v.rank(rank)));

    let dropped: Vec<ChangeKey> = held
        .iter()
        .filter(|v| !maximal.iter().any(|m| m.key == v.key))
        .map(|v| v.key)
        .collect();
    let head = maximal.first().map_or(incoming.key, |v| v.key);
    let siblings: Vec<ChangeKey> = maximal.iter().skip(1).map(|v| v.key).collect();
    Merge {
        kept: !known,
        regressed,
        head,
        siblings,
        dropped,
        head_changed: held_head != Some(head),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::ServerId;

    fn id(n: u8) -> ServerId {
        ServerId(uuid::Uuid::from_bytes([n; 16]))
    }

    fn key(origin: u8, seq: u64) -> ChangeKey {
        ChangeKey {
            origin: id(origin),
            seq,
        }
    }

    fn v(origin: u8, seq: u64, hlc: u64, revision: u64, lineage: &[ChangeKey]) -> Version {
        Version {
            key: key(origin, seq),
            hlc: Hlc(hlc),
            revision: Revision(revision),
            lineage: lineage.to_vec(),
        }
    }

    #[test]
    fn a_successor_replaces_the_head() {
        let base = v(1, 1, 10, 1, &[]);
        let next = v(2, 7, 20, 2, &[base.key]);
        let m = merge(std::slice::from_ref(&base), Some(base.key), &next);
        assert!(m.kept);
        assert_eq!(m.head, next.key);
        assert!(m.siblings.is_empty());
        assert_eq!(m.dropped, vec![base.key]);
        assert!(m.head_changed);
    }

    #[test]
    fn a_duplicate_or_an_ancestor_changes_nothing() {
        let base = v(1, 1, 10, 1, &[]);
        let next = v(2, 7, 20, 2, &[base.key]);
        let held = [next.clone()];
        for old in [next.clone(), base.clone()] {
            let m = merge(&held, Some(next.key), &old);
            assert!(!m.kept);
            assert_eq!(m.head, next.key);
            assert!(m.dropped.is_empty());
            assert!(!m.head_changed);
        }
    }

    #[test]
    fn concurrent_versions_are_both_kept_and_the_later_clock_is_the_head() {
        let base = v(1, 1, 10, 1, &[]);
        let a = v(1, 2, 20, 2, &[base.key]);
        let b = v(2, 5, 30, 2, &[base.key]);
        // A is held; B arrives.
        let m = merge(std::slice::from_ref(&a), Some(a.key), &b);
        assert!(m.kept);
        assert_eq!(m.head, b.key);
        assert_eq!(m.siblings, vec![a.key]);
        assert!(m.dropped.is_empty());
        assert!(m.head_changed);
        // B is held; A arrives: the same result, and the head didn't change.
        let m = merge(std::slice::from_ref(&b), Some(b.key), &a);
        assert!(m.kept);
        assert_eq!(m.head, b.key);
        assert_eq!(m.siblings, vec![a.key]);
        assert!(!m.head_changed);
    }

    #[test]
    fn the_result_does_not_depend_on_arrival_order() {
        let base = v(1, 1, 10, 1, &[]);
        let a = v(1, 2, 20, 2, &[base.key]);
        let b = v(2, 5, 30, 2, &[base.key]);
        let c = v(3, 9, 25, 2, &[base.key]);
        let orders: [[&Version; 3]; 6] = [
            [&a, &b, &c],
            [&a, &c, &b],
            [&b, &a, &c],
            [&b, &c, &a],
            [&c, &a, &b],
            [&c, &b, &a],
        ];
        let mut results = Vec::new();
        for order in orders {
            let mut held = vec![base.clone()];
            let mut head = Some(base.key);
            for incoming in order {
                let m = merge(&held, head, incoming);
                if m.kept {
                    held.push(incoming.clone());
                }
                held.retain(|h| !m.dropped.contains(&h.key));
                head = Some(m.head);
            }
            let mut siblings: Vec<ChangeKey> = held
                .iter()
                .map(|h| h.key)
                .filter(|k| Some(*k) != head)
                .collect();
            siblings.sort();
            results.push((head, siblings));
        }
        assert!(results.windows(2).all(|w| w[0] == w[1]), "{results:?}");
        assert_eq!(results[0].0, Some(b.key));
        assert_eq!(results[0].1.len(), 2);
    }

    #[test]
    fn a_version_that_replaced_both_resolves_the_conflict() {
        let base = v(1, 1, 10, 1, &[]);
        let a = v(1, 2, 20, 2, &[base.key]);
        let b = v(2, 5, 30, 2, &[base.key]);
        let merged = v(1, 3, 40, 3, &[b.key, a.key, base.key]);
        let m = merge(&[b.clone(), a.clone()], Some(b.key), &merged);
        assert!(m.kept);
        assert_eq!(m.head, merged.key);
        assert!(m.siblings.is_empty());
        assert_eq!(m.dropped.len(), 2);
    }

    #[test]
    fn a_version_that_replaced_only_the_head_leaves_the_sibling() {
        let base = v(1, 1, 10, 1, &[]);
        let a = v(1, 2, 20, 2, &[base.key]);
        let b = v(2, 5, 30, 2, &[base.key]);
        // Someone edited B without seeing A.
        let edit = v(2, 6, 40, 3, &[b.key, base.key]);
        let m = merge(&[b.clone(), a.clone()], Some(b.key), &edit);
        assert_eq!(m.head, edit.key);
        assert_eq!(m.siblings, vec![a.key]);
        assert_eq!(m.dropped, vec![b.key]);
    }

    #[test]
    fn a_first_version_is_the_head() {
        let first = v(1, 1, 10, 1, &[]);
        let m = merge(&[], None, &first);
        assert!(m.kept);
        assert_eq!(m.head, first.key);
        assert!(m.head_changed);
    }

    #[test]
    fn a_replay_with_a_late_clock_that_leaves_the_head_out_of_its_lineage_stays_a_sibling() {
        // The head is revision 5. A replica re-signs revision 3 with a clock far ahead and a
        // lineage that names only the base: nothing replaces the head, and the replay is not it.
        let base = v(1, 1, 10, 1, &[]);
        let head = v(1, 9, 20, 5, &[base.key]);
        let replay = v(2, 4, 99, 3, &[base.key]);
        let m = merge_ranked(std::slice::from_ref(&head), Some(head.key), &replay, Rank::Revision);
        assert!(m.kept);
        assert!(!m.regressed);
        assert_eq!(m.head, head.key);
        assert_eq!(m.siblings, vec![replay.key]);
        assert!(!m.head_changed);
        // Whatever order they arrive in, the head is the same.
        let m = merge_ranked(
            std::slice::from_ref(&replay),
            Some(replay.key),
            &head,
            Rank::Revision,
        );
        assert_eq!(m.head, head.key);
        // By clock alone, as servers that don't rank by revision do, the replay takes the head.
        let m = merge(std::slice::from_ref(&head), Some(head.key), &replay);
        assert_eq!(m.head, replay.key);
    }

    #[test]
    fn equal_clocks_break_by_origin_then_sequence() {
        let base = v(1, 1, 10, 1, &[]);
        let a = v(1, 2, 20, 2, &[base.key]);
        let b = v(2, 2, 20, 2, &[base.key]);
        let m = merge(std::slice::from_ref(&a), Some(a.key), &b);
        assert_eq!(m.head, b.key);
    }

    #[test]
    fn a_version_that_names_the_head_at_a_lower_revision_is_a_rollback() {
        // The head is revision 5. A replica re-signs an old ciphertext as a new change at
        // revision 3, with a late clock and a lineage that names the head.
        let base = v(1, 1, 10, 1, &[]);
        let head = v(1, 9, 20, 5, &[base.key]);
        let replay = v(2, 4, 99, 3, &[head.key, base.key]);
        let m = merge(std::slice::from_ref(&head), Some(head.key), &replay);
        assert!(!m.kept);
        assert!(m.regressed);
        assert_eq!(m.head, head.key);
        assert!(m.dropped.is_empty());
        assert!(!m.head_changed);
        // The same revision doesn't replace it either.
        let same = v(2, 5, 99, 5, &[head.key]);
        assert!(merge(std::slice::from_ref(&head), Some(head.key), &same).regressed);
    }

    #[test]
    fn a_resolution_may_name_a_sibling_of_a_higher_revision() {
        // A device merged the head (revision 3) with a sibling that is further along (4): the
        // server makes the merge revision 4, the head's plus one. Only the head's revision counts.
        let base = v(1, 1, 10, 1, &[]);
        let head = v(1, 2, 30, 3, &[base.key]);
        let sibling = v(2, 5, 20, 4, &[base.key]);
        let merged = v(1, 3, 40, 4, &[head.key, sibling.key, base.key]);
        let m = merge(&[head.clone(), sibling], Some(head.key), &merged);
        assert!(m.kept);
        assert!(!m.regressed);
        assert_eq!(m.head, merged.key);
    }
}
