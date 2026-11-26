// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { defaultAnchorStore, memoryAnchorStore } from './anchors';

const A = '10000000-0000-4000-8000-000000000001';
const B = '10000000-0000-4000-8000-000000000002';
const SPACE = '20000000-0000-4000-8000-000000000001';

const at = (seq: number) => ({
  seq,
  epoch: 1,
  links: Array.from({ length: seq + 1 }, (_, i) => `l${i}`),
});

describe('the anchors this browser keeps', () => {
  it('keeps one per account and space', async () => {
    const store = memoryAnchorStore();
    expect(await store.load(A, SPACE)).toBeUndefined();
    await store.save(A, SPACE, at(3));
    expect(await store.load(A, SPACE)).toEqual(at(3));
    // Another account on the same browser has none.
    expect(await store.load(B, SPACE)).toBeUndefined();
  });

  it('never goes back, except after a fence', async () => {
    const store = memoryAnchorStore();
    await store.save(A, SPACE, at(5));
    await store.save(A, SPACE, at(2));
    expect((await store.load(A, SPACE))?.seq).toBe(5);
    await store.save(A, SPACE, at(7));
    expect((await store.load(A, SPACE))?.seq).toBe(7);
    // A fence parts the chain from the anchor: the new chain may be shorter.
    await store.save(A, SPACE, at(4), true);
    expect((await store.load(A, SPACE))?.seq).toBe(4);
  });

  it('falls back on memory where there is no IndexedDB', async () => {
    const store = defaultAnchorStore();
    await store.save(A, SPACE, at(1));
    expect((await store.load(A, SPACE))?.seq).toBe(1);
  });
});
