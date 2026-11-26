// How a device sorts what the server serves against the signed manifest, after kemlock-core's
// `manifest_compare.dart` (one item at a time). The manifest is a floor, not a full list: items a
// device other than this one wrote after the manifest was signed (the Kemlock app, a Bitwarden
// client) are newer than their entry or unlisted, and that is fine. What is not fine:
//
//   rolled-back  the item has a lower revision than its entry;
//   missing      the entry is live and the server serves the item not at all, not even a tombstone;
//   resurrected  an id this device saw deleted comes back at or below the tombstone's revision, or
//                is served live where the manifest lists it deleted.
//
// Items at their entry's revision with another hash (a sibling written by two devices at once) and
// items newer than or absent from the manifest are accepted; the next signed manifest lists them.
import { TOMBSTONE_HASH, type Manifest, type ManifestEntry } from './format';

/** What the server served of one item: its revision and the hash of its ciphertext (hex). */
export interface Served {
  revision: number;
  hash: string;
  deleted: boolean;
}

/** Every item of one owner the server has served, by item id. */
export type Ledger = Map<string, Served>;

/** An id seen deleted, with the tombstone's revision and when this device first saw it (ms). */
export interface SeenDeleted {
  revision: number;
  seenAt: number;
}

export type DeletedRecord = Record<string, SeenDeleted>;

/** How long a device remembers an id it saw deleted: as long as the server keeps tombstones. */
export const DELETED_RETENTION_MS = 180 * 24 * 3600 * 1000;

export type FlaggedVerdict = 'rolled-back' | 'missing' | 'resurrected';

export interface Finding {
  id: string;
  verdict: FlaggedVerdict;
  /** The revision the server served; absent for a missing item. */
  revision?: number;
  /** The revision the manifest lists. */
  manifestRevision?: number;
}

type Verdict = FlaggedVerdict | 'expected' | 'unlisted' | 'sibling';

function classify(item: Served, entry: ManifestEntry | undefined, seenDeletedAt: number | undefined): Verdict {
  if (!item.deleted) {
    if (seenDeletedAt !== undefined) {
      // An id this device saw deleted is back. A later live entry the manifest lists (an undelete
      // its writer signed) is the one way through.
      const listedLaterAndLive = entry !== undefined && !entry.deleted && entry.revision > seenDeletedAt;
      if (item.revision <= seenDeletedAt || !listedLaterAndLive) return 'resurrected';
    }
    // A tombstone is a revision of its own: a live copy at or below it is not the item's.
    if (entry?.deleted && item.revision <= entry.revision) return 'resurrected';
  }
  if (!entry) return 'unlisted';
  if (item.revision < entry.revision) return 'rolled-back';
  if (item.revision > entry.revision) return 'unlisted';
  return item.deleted === entry.deleted && item.hash === entry.hash ? 'expected' : 'sibling';
}

/**
 * The findings that are a warning, in item id order. `deleted` is what this device saw before
 * this answer (record the answer's own tombstones after, with `recordDeleted`). `checkMissing` is
 * false for a space, whose members each see only the collections they may read: an entry for an
 * item this member was never served is no evidence of anything.
 */
export function compareLedger(
  manifest: Manifest,
  deleted: DeletedRecord,
  ledger: Ledger,
  checkMissing: boolean,
): Finding[] {
  const entries = new Map(manifest.entries.map((entry) => [entry.id, entry]));
  const findings: Finding[] = [];
  for (const [id, item] of ledger) {
    const entry = entries.get(id);
    const verdict = classify(item, entry, deleted[id]?.revision);
    if (verdict === 'rolled-back' || verdict === 'resurrected') {
      findings.push({
        id,
        verdict,
        revision: item.revision,
        ...(entry ? { manifestRevision: entry.revision } : {}),
      });
    }
  }
  if (checkMissing) {
    for (const entry of manifest.entries) {
      if (!entry.deleted && !ledger.has(entry.id)) {
        findings.push({ id: entry.id, verdict: 'missing', manifestRevision: entry.revision });
      }
    }
  }
  return findings.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * The deleted ids after seeing `manifest` and `ledger`: every tombstone in either, at its highest
 * revision, with the time it was first seen. Ids seen more than the retention ago are dropped.
 */
export function recordDeleted(
  before: DeletedRecord,
  manifest: Manifest | undefined,
  ledger: Ledger,
  now: number,
): DeletedRecord {
  const out: DeletedRecord = { ...before };
  const see = (id: string, revision: number) => {
    const existing = out[id];
    if (!existing || existing.revision < revision) {
      out[id] = { revision, seenAt: existing?.seenAt ?? now };
    }
  };
  for (const entry of manifest?.entries ?? []) if (entry.deleted) see(entry.id, entry.revision);
  for (const [id, item] of ledger) if (item.deleted) see(id, item.revision);
  for (const [id, seen] of Object.entries(out)) {
    if (seen.seenAt < now - DELETED_RETENTION_MS) delete out[id];
  }
  return out;
}

/**
 * The entries of the next manifest: what the last signed one lists, with each item this device was
 * served at a higher revision taken in. Nothing is taken from a lower revision (a rollback), no
 * entry is dropped for being unserved (a hidden item), and a deleted entry stays deleted (a
 * resurrection), so signing never makes what the server did permanent.
 */
export function mergeEntries(base: ManifestEntry[], ledger: Ledger): ManifestEntry[] {
  const byId = new Map(base.map((entry) => [entry.id, entry]));
  for (const [id, item] of ledger) {
    const listed = byId.get(id);
    const entry: ManifestEntry = {
      id,
      revision: item.revision,
      hash: item.deleted ? TOMBSTONE_HASH : item.hash,
      deleted: item.deleted,
    };
    if (!listed) byId.set(id, entry);
    else if (item.revision > listed.revision && !(listed.deleted && !item.deleted)) {
      byId.set(id, entry);
    }
  }
  return [...byId.values()];
}

/** Whether two entry lists say the same, whatever their order. */
export function sameEntries(a: ManifestEntry[], b: ManifestEntry[]): boolean {
  if (a.length !== b.length) return false;
  const other = new Map(b.map((entry) => [entry.id, entry]));
  return a.every((entry) => {
    const match = other.get(entry.id);
    return (
      match !== undefined &&
      match.revision === entry.revision &&
      match.hash === entry.hash &&
      match.deleted === entry.deleted
    );
  });
}
