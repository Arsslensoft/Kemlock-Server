import { describe, expect, it } from 'vitest';
import { CHAINED_MARK_REVISION, chainedMarks, isChainedMark, withMarks } from './chained';
import { mergeEntries } from './compare';
import { decodeManifest, encodeManifest, TOMBSTONE_HASH, type ManifestEntry } from './format';

const SPACE_A = '00000000-0000-4000-8000-0000000000a1';
const SPACE_B = '00000000-0000-4000-8000-0000000000a2';
const ITEM = '00000000-0000-4000-8000-0000000000b1';

const mark = (id: string): ManifestEntry => ({
  id,
  revision: CHAINED_MARK_REVISION,
  hash: TOMBSTONE_HASH,
  deleted: true,
});

describe('the marks of chained spaces in the account’s own manifest', () => {
  it('are tombstones at revision 0, which no item’s tombstone is', () => {
    expect(isChainedMark(mark(SPACE_A))).toBe(true);
    expect(isChainedMark({ id: ITEM, revision: 1, hash: TOMBSTONE_HASH, deleted: true })).toBe(false);
    expect(isChainedMark({ id: ITEM, revision: 0, hash: 'a'.repeat(64), deleted: false })).toBe(false);
  });

  it('are read from a manifest and written to one, and survive the format', () => {
    const entries = withMarks([], new Set([SPACE_A, SPACE_B]));
    const bytes = encodeManifest({ owner: `user:${ITEM}`, counter: 3, entries });
    const back = decodeManifest(bytes);
    expect(back).not.toBeNull();
    expect([...chainedMarks(back?.entries ?? [])].sort()).toEqual([SPACE_A, SPACE_B]);
  });

  it('are added once, and only for spaces without one', () => {
    const have = [mark(SPACE_A)];
    expect(withMarks(have, new Set([SPACE_A]))).toBe(have);
    expect(withMarks(have, new Set([SPACE_A, SPACE_B])).map((e) => e.id)).toEqual([SPACE_A, SPACE_B]);
  });

  it('are kept by the next manifest an item write makes', () => {
    const next = mergeEntries([mark(SPACE_A)], new Map(), {}, new Set());
    expect(chainedMarks(next)).toEqual(new Set([SPACE_A]));
  });
});

describe('what the rest of the manifest code makes of a mark', () => {
  it('is no id seen deleted, and no finding', async () => {
    const { recordDeleted, compareLedger } = await import('./compare');
    const manifest = { owner: `user:${ITEM}`, counter: 1, entries: [mark(SPACE_A)] };
    expect(recordDeleted({}, manifest, new Map(), 0)).toEqual({});
    expect(compareLedger(manifest, {}, new Map())).toEqual([]);
  });
});
