import { describe, expect, it } from 'vitest';
import {
  DELETED_RETENTION_MS,
  type DeletedRecord,
  type Ledger,
  compareLedger,
  mergeEntries,
  recordDeleted,
  sameEntries,
} from './compare';
import { type Manifest, TOMBSTONE_HASH } from './format';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const H1 = '01'.repeat(32);
const H2 = '02'.repeat(32);
const OWNER = 'user:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const live = (revision: number, hash = H1, own = false, opened = true) => ({ revision, hash, deleted: false, opened, own });
const gone = (revision: number, own = false) => ({ revision, hash: TOMBSTONE_HASH, deleted: true, opened: false, own });
const entry = (id: string, revision: number, hash = H1) => ({ id, revision, hash, deleted: false });
const tomb = (id: string, revision: number) => ({ id, revision, hash: TOMBSTONE_HASH, deleted: true });
const manifest = (entries: Manifest['entries']): Manifest => ({ owner: OWNER, counter: 4, entries });
const ledger = (items: Record<string, ReturnType<typeof live>>): Ledger => new Map(Object.entries(items));
const NONE = new Set<string>();

describe('compareLedger', () => {
  it('has nothing to say about items that match, are newer than their entry, or are not listed', () => {
    const found = compareLedger(
      manifest([entry(A, 2), entry(B, 1)]),
      {},
      ledger({ [A]: live(2), [B]: live(4, H2), [C]: live(1) }),
    );
    expect(found).toEqual([]);
  });

  it('does not take a sibling at the same revision for a problem', () => {
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: live(2, H2) }))).toEqual([]);
  });

  it('flags an item served at a lower revision than its entry', () => {
    expect(compareLedger(manifest([entry(A, 3)]), {}, ledger({ [A]: live(2) }))).toEqual([
      { id: A, verdict: 'rolled-back', revision: 2, manifestRevision: 3 },
    ]);
  });

  it("flags a live entry the server does not serve at all, in a space as in an account's own vault", () => {
    const listed = manifest([entry(A, 3), tomb(B, 2)]);
    expect(compareLedger(listed, {}, ledger({}))).toEqual([{ id: A, verdict: 'missing', manifestRevision: 3 }]);
    // A tombstone served, or listed as deleted, is not missing.
    expect(compareLedger(listed, {}, ledger({ [A]: gone(4) }))).toEqual([]);
  });

  it('flags a deleted item served live again, whichever way it is known to be deleted', () => {
    // By the manifest, at or below the tombstone.
    expect(compareLedger(manifest([tomb(A, 5)]), {}, ledger({ [A]: live(5) }))).toEqual([
      { id: A, verdict: 'resurrected', revision: 5, manifestRevision: 5 },
    ]);
    expect(compareLedger(manifest([tomb(A, 5)]), {}, ledger({ [A]: live(3) }))[0]?.verdict).toBe(
      'resurrected',
    );
    // By what this browser saw, with the manifest silent about it.
    const seen: DeletedRecord = { [A]: { revision: 5, seenAt: 1 } };
    expect(compareLedger(manifest([]), seen, ledger({ [A]: live(7) }))[0]?.verdict).toBe('resurrected');
    expect(compareLedger(manifest([entry(A, 4)]), seen, ledger({ [A]: live(4) }))[0]?.verdict).toBe(
      'resurrected',
    );
  });

  it('lets a signed undelete through: a live entry above the tombstone this browser saw', () => {
    const seen: DeletedRecord = { [A]: { revision: 5, seenAt: 1 } };
    expect(compareLedger(manifest([entry(A, 7)]), seen, ledger({ [A]: live(7) }))).toEqual([]);
  });

  it('puts the findings in item id order', () => {
    const found = compareLedger(
      manifest([entry(C, 3), entry(A, 3)]),
      {},
      ledger({ [C]: live(1) }),
    );
    expect(found.map((finding) => finding.id)).toEqual([A, C]);
  });
});

describe('compareLedger, for what the server could be making up', () => {
  it('flags a tombstone this browser did not write for an item the manifest lists live', () => {
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: gone(3) }))).toEqual([
      { id: A, verdict: 'deleted', revision: 3, manifestRevision: 2 },
    ]);
    // Its own deletion is no warning, and neither is a tombstone for an entry already deleted.
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: gone(3) }))).toEqual([]);
    expect(compareLedger(manifest([tomb(A, 2)]), {}, ledger({ [A]: gone(3) }))).toEqual([]);
  });

  it("flags a revision more than 2^32 above the entry's, but not one of this browser's own", () => {
    const far = 2 + 2 ** 32 + 1;
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: live(far) }))[0]?.verdict).toBe('implausible');
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: gone(far) }))[0]?.verdict).toBe('implausible');
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: live(far, H1) }))).toEqual([]);
    expect(compareLedger(manifest([entry(A, 2)]), {}, ledger({ [A]: live(2 + 2 ** 32) }))).toEqual([]);
  });
});

describe('recordDeleted', () => {
  it('records the tombstones of the manifest and of what was served, at the highest revision, first seen once', () => {
    const first = recordDeleted({}, manifest([tomb(A, 3), entry(B, 1)]), ledger({ [C]: gone(2) }), 100);
    expect(first).toEqual({ [A]: { revision: 3, seenAt: 100 }, [C]: { revision: 2, seenAt: 100 } });
    const later = recordDeleted(first, manifest([tomb(A, 4)]), ledger({}), 500);
    expect(later[A]).toEqual({ revision: 4, seenAt: 100 });
    expect(recordDeleted(later, undefined, ledger({ [A]: gone(2) }), 900)[A]).toEqual({
      revision: 4,
      seenAt: 100,
    });
  });

  it('forgets an id after the time the server keeps tombstones', () => {
    const before: DeletedRecord = { [A]: { revision: 3, seenAt: 0 }, [B]: { revision: 1, seenAt: 10 } };
    const after = recordDeleted(before, undefined, ledger({}), DELETED_RETENTION_MS + 5);
    expect(Object.keys(after)).toEqual([B]);
  });
});

describe('mergeEntries, for what must not be signed', () => {
  it('takes in only live items that opened, or that this browser wrote', () => {
    const merged = mergeEntries(
      [entry(A, 1)],
      ledger({ [A]: live(2, H2, false, false), [B]: live(1, H2, false, false), [C]: live(1, H2, true, false) }),
      {},
      NONE,
    );
    expect(merged).toEqual(expect.arrayContaining([entry(A, 1), entry(C, 1, H2)]));
    expect(merged).toHaveLength(2);
  });

  it("takes in a tombstone only for this browser's own deletion or an entry already deleted", () => {
    const base = [entry(A, 2), tomb(B, 2)];
    const merged = mergeEntries(base, ledger({ [A]: gone(3), [B]: gone(4), [C]: gone(5) }), {}, NONE);
    expect(merged).toEqual(expect.arrayContaining([entry(A, 2), tomb(B, 4)]));
    expect(merged).toHaveLength(2);
    expect(mergeEntries(base, ledger({ [A]: gone(3, true) }), {}, NONE)).toEqual(
      expect.arrayContaining([tomb(A, 3)]),
    );
  });

  it('skips what was flagged and what this device saw deleted, even when its own write is the newest', () => {
    const base = [entry(A, 2)];
    const served = ledger({ [A]: live(3, H2, true), [B]: live(4, H2, true), [C]: live(1, H2, true) });
    const merged = mergeEntries(base, served, { [B]: { revision: 3, seenAt: 1 } }, new Set([A]));
    expect(merged).toEqual([entry(A, 2), entry(C, 1, H2)]);
    // A signed undelete above the tombstone this device saw is the one way through.
    expect(mergeEntries([entry(B, 5)], ledger({ [B]: live(6, H2, true) }), { [B]: { revision: 3, seenAt: 1 } }, NONE)).toEqual([
      entry(B, 6, H2),
    ]);
  });

  it("refuses a revision more than 2^32 above the entry's that is not its own", () => {
    expect(mergeEntries([entry(A, 2)], ledger({ [A]: live(3 + 2 ** 32, H2) }), {}, NONE)).toEqual([entry(A, 2)]);
  });

  it('drops a tombstone that is no longer served and no longer remembered, and keeps the others', () => {
    const base = [tomb(A, 2), tomb(B, 2), tomb(C, 2)];
    const merged = mergeEntries(base, ledger({ [B]: gone(2) }), { [C]: { revision: 2, seenAt: 1 } }, NONE);
    expect(merged.map((e) => e.id).sort()).toEqual([B, C]);
  });
});

describe('mergeEntries', () => {
  it('takes in what was served at a higher revision and what the manifest does not list', () => {
    const merged = mergeEntries([entry(A, 1), tomb(B, 2)], ledger({ [A]: live(2, H2), [C]: gone(3, true) }), { [B]: { revision: 2, seenAt: 1 } }, NONE);
    expect(merged).toEqual(
      expect.arrayContaining([entry(A, 2, H2), tomb(B, 2), tomb(C, 3)]),
    );
    expect(merged).toHaveLength(3);
  });

  it('never signs in a rollback, a hidden item or a resurrection', () => {
    const base = [entry(A, 3), entry(B, 2), tomb(C, 4)];
    // A is served lower, B is not served, C is served live above its tombstone.
    const merged = mergeEntries(base, ledger({ [A]: live(1, H2), [C]: live(6, H2) }), {}, NONE);
    expect(sameEntries(merged, base)).toBe(true);
  });

  it('is the same list when nothing changed, in any order', () => {
    const base = [entry(A, 3), entry(B, 2)];
    expect(sameEntries(mergeEntries(base, ledger({ [A]: live(3), [B]: live(2) }), {}, NONE), [...base].reverse())).toBe(true);
    expect(sameEntries(base, [entry(A, 3), entry(B, 2, H2)])).toBe(false);
    expect(sameEntries(base, [entry(A, 3)])).toBe(false);
  });
});
