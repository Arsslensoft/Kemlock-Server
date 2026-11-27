// Which spaces have a chain, as a fact the server can't take back (docs/crypto.md, "Chained spaces
// the account has met"). The account's own signed manifest lists them, in its own format: each is an
// entry that is a **tombstone at revision 0** whose id is the space's id. A real tombstone is a
// revision of an item, and revisions start at 1, so a revision 0 tombstone is never an item's; and
// an id that is no item's is the one entry a reader of the manifest has nothing to compare it with,
// so an app that knows nothing of it shows no warning for it.
//
// A server can't make one (the manifest is signed by the account's own key) and can't remove one
// from a manifest a browser has seen (the counter only goes up). It can serve an older manifest to a
// browser that has seen none: that browser meets the space as it would meet any, with the second
// rule (keys taken unsigned on first sight wait for a person to compare them) as its guard.
import type { ManifestEntry } from './format';
import { TOMBSTONE_HASH } from './format';

/** The revision of the tombstone entry that marks a space as chained. */
export const CHAINED_MARK_REVISION = 0;

/** Whether an entry is a chained-space mark: a tombstone at revision 0. */
export function isChainedMark(entry: ManifestEntry): boolean {
  return entry.deleted && entry.revision === CHAINED_MARK_REVISION && entry.hash === TOMBSTONE_HASH;
}

/** The ids of the spaces a manifest's marks name. */
export function chainedMarks(entries: readonly ManifestEntry[]): Set<string> {
  return new Set(entries.filter(isChainedMark).map((entry) => entry.id));
}

/** `entries` with a mark for each of `spaces` it does not have one for yet. */
export function withMarks(entries: ManifestEntry[], spaces: ReadonlySet<string>): ManifestEntry[] {
  const have = new Set(entries.map((entry) => entry.id));
  const added = [...spaces]
    .filter((id) => !have.has(id))
    .map((id) => ({ id, revision: CHAINED_MARK_REVISION, hash: TOMBSTONE_HASH, deleted: true }));
  return added.length === 0 ? entries : [...entries, ...added];
}
