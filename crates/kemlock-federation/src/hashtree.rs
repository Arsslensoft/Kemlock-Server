//! Hash-tree summaries of a vault's item revisions.
//!
//! Every hour, and whenever a peer comes back, two servers compare a summary of each federated
//! vault and fetch what differs. The tree has three levels: a **leaf** per item (a hash of the
//! item id and every version held, with its revision), 256 **buckets** (the leaves whose item id
//! starts with that byte) and a **root**. Equal roots mean the vault is in step; otherwise the
//! buckets that differ narrow the search to a few leaves, and the items behind them are fetched
//! as change records. See `docs/federation.md`.

use crate::crypto;
use crate::wire::ChangeKey;
use kemlock_domain::{ItemId, Revision};

/// How many buckets the tree has.
pub const BUCKETS: usize = 256;

const LEAF_LABEL: &[u8] = b"kemlock/v1/fed/leaf";
const BUCKET_LABEL: &[u8] = b"kemlock/v1/fed/bucket";
const ROOT_LABEL: &[u8] = b"kemlock/v1/fed/root";

/// One item's digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub item: ItemId,
    pub digest: [u8; 32],
}

/// `SHA-256("kemlock/v1/fed/leaf" ‖ item id ‖ n × (origin (16) ‖ u64be(seq) ‖ u64be(revision)))`
/// over the versions held (the head and the siblings), sorted by change key.
pub fn leaf_digest(item: ItemId, versions: &[(ChangeKey, Revision)]) -> [u8; 32] {
    let mut sorted = versions.to_vec();
    sorted.sort_by_key(|(key, _)| *key);
    let mut input = LEAF_LABEL.to_vec();
    input.extend_from_slice(item.as_bytes());
    for (key, revision) in sorted {
        input.extend_from_slice(&key.to_bytes());
        input.extend_from_slice(&revision.0.to_be_bytes());
    }
    crypto::sha256(&input)
}

/// The bucket an item belongs to: the first byte of its id.
pub fn bucket_of(item: ItemId) -> u8 {
    item.as_bytes()[0]
}

/// The buckets and the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    pub root: [u8; 32],
    /// [`BUCKETS`] digests, indexed by bucket.
    pub buckets: Vec<[u8; 32]>,
}

impl Tree {
    /// Builds the tree over `leaves`, in any order.
    pub fn build(leaves: &[Leaf]) -> Tree {
        let mut by_bucket: Vec<Vec<&Leaf>> = vec![Vec::new(); BUCKETS];
        for leaf in leaves {
            by_bucket[usize::from(bucket_of(leaf.item))].push(leaf);
        }
        let mut buckets = Vec::with_capacity(BUCKETS);
        for (index, mut members) in by_bucket.into_iter().enumerate() {
            members.sort_by_key(|l| *l.item.as_bytes());
            let mut input = BUCKET_LABEL.to_vec();
            input.push(u8::try_from(index).unwrap_or(u8::MAX));
            for leaf in members {
                input.extend_from_slice(leaf.item.as_bytes());
                input.extend_from_slice(&leaf.digest);
            }
            buckets.push(crypto::sha256(&input));
        }
        let mut root_input = ROOT_LABEL.to_vec();
        for bucket in &buckets {
            root_input.extend_from_slice(bucket);
        }
        Tree {
            root: crypto::sha256(&root_input),
            buckets,
        }
    }
}

/// The buckets where two bucket lists differ. A list of the wrong length differs everywhere.
pub fn differing_buckets(a: &[[u8; 32]], b: &[[u8; 32]]) -> Vec<u8> {
    if a.len() != BUCKETS || b.len() != BUCKETS {
        return (0..=u8::MAX).collect();
    }
    (0..=u8::MAX)
        .filter(|i| a[usize::from(*i)] != b[usize::from(*i)])
        .collect()
}

/// What two lists of leaves say about each other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    /// Items the remote holds that we lack or hold differently: to fetch.
    pub fetch: Vec<ItemId>,
    /// Items we hold that the remote lacks or holds differently: the remote should fetch them.
    pub push: Vec<ItemId>,
}

/// Compares our leaves with the remote's, for the buckets that differ. Which side is newer isn't
/// known from a digest; each side fetches what differs and the merge decides.
pub fn diff(local: &[Leaf], remote: &[Leaf]) -> Diff {
    let mut out = Diff::default();
    for r in remote {
        match local.iter().find(|l| l.item == r.item) {
            Some(l) if l.digest == r.digest => {}
            _ => out.fetch.push(r.item),
        }
    }
    for l in local {
        match remote.iter().find(|r| r.item == l.item) {
            Some(r) if r.digest == l.digest => {}
            _ => out.push.push(l.item),
        }
    }
    out.fetch.sort();
    out.push.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::ServerId;

    fn item(first: u8, rest: u8) -> ItemId {
        let mut b = [rest; 16];
        b[0] = first;
        ItemId(uuid::Uuid::from_bytes(b))
    }

    fn key(n: u8, seq: u64) -> ChangeKey {
        ChangeKey {
            origin: ServerId(uuid::Uuid::from_bytes([n; 16])),
            seq,
        }
    }

    fn leaf(id: ItemId, versions: &[(ChangeKey, u64)]) -> Leaf {
        let versions: Vec<(ChangeKey, Revision)> =
            versions.iter().map(|(k, r)| (*k, Revision(*r))).collect();
        Leaf {
            item: id,
            digest: leaf_digest(id, &versions),
        }
    }

    #[test]
    fn a_leaf_depends_on_every_version_but_not_on_their_order() {
        let id = item(1, 1);
        let a = (key(1, 1), Revision(1));
        let b = (key(2, 7), Revision(2));
        assert_eq!(leaf_digest(id, &[a, b]), leaf_digest(id, &[b, a]));
        assert_ne!(leaf_digest(id, &[a]), leaf_digest(id, &[a, b]));
        assert_ne!(
            leaf_digest(id, &[a]),
            leaf_digest(id, &[(a.0, Revision(2))])
        );
        assert_ne!(leaf_digest(id, &[a]), leaf_digest(item(1, 2), &[a]));
    }

    #[test]
    fn the_tree_does_not_depend_on_the_order_of_leaves() {
        let leaves = vec![
            leaf(item(0, 1), &[(key(1, 1), 1)]),
            leaf(item(0, 2), &[(key(1, 2), 1)]),
            leaf(item(200, 3), &[(key(1, 3), 4)]),
        ];
        let mut reversed = leaves.clone();
        reversed.reverse();
        assert_eq!(Tree::build(&leaves), Tree::build(&reversed));
        assert_eq!(Tree::build(&leaves).buckets.len(), BUCKETS);
    }

    #[test]
    fn a_changed_leaf_moves_its_bucket_and_the_root_only() {
        let a = leaf(item(0, 1), &[(key(1, 1), 1)]);
        let b = leaf(item(200, 3), &[(key(1, 3), 4)]);
        let before = Tree::build(&[a, b]);
        let b2 = leaf(item(200, 3), &[(key(1, 9), 5)]);
        let after = Tree::build(&[a, b2]);
        assert_ne!(before.root, after.root);
        assert_eq!(
            differing_buckets(&before.buckets, &after.buckets),
            vec![200]
        );
        assert!(differing_buckets(&before.buckets, &before.buckets).is_empty());
        assert_eq!(differing_buckets(&before.buckets, &[]).len(), 256);
    }

    #[test]
    fn an_empty_vault_has_a_stable_root() {
        assert_eq!(Tree::build(&[]), Tree::build(&[]));
        assert_ne!(
            Tree::build(&[]).root,
            Tree::build(&[leaf(item(1, 1), &[(key(1, 1), 1)])]).root
        );
    }

    #[test]
    fn the_diff_lists_missing_and_differing_items() {
        let same = leaf(item(1, 1), &[(key(1, 1), 1)]);
        let mine = leaf(item(2, 2), &[(key(1, 2), 1)]);
        let theirs = leaf(item(3, 3), &[(key(2, 3), 1)]);
        let local_edit = leaf(item(4, 4), &[(key(1, 5), 2)]);
        let remote_edit = leaf(item(4, 4), &[(key(2, 6), 2)]);
        let d = diff(&[same, mine, local_edit], &[same, theirs, remote_edit]);
        assert_eq!(d.fetch, vec![theirs.item, remote_edit.item]);
        assert_eq!(d.push, vec![mine.item, local_edit.item]);
        assert_eq!(diff(&[same], &[same]), Diff::default());
    }
}
