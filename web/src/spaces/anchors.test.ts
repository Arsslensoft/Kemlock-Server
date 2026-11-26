// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { defaultStores, memoryAnchorStore, memoryFloorStore, memoryPinStore, parseAnchor, parseFloor } from './anchors';

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
    const seal = {
      sealLocal: async (_label: string, text: string) => text,
      openLocal: async (_label: string, sealed: string) => sealed,
    };
    const { anchors, pins } = defaultStores(seal);
    await anchors.save(A, SPACE, at(1));
    expect((await anchors.load(A, SPACE))?.seq).toBe(1);
    await pins.save(A, B, '12345 67890');
    expect(await pins.load(A, B)).toBe('12345 67890');
  });

  it('keeps a pin per account and member', async () => {
    const pins = memoryPinStore();
    expect(await pins.load(A, B)).toBeUndefined();
    await pins.save(A, B, '12345 67890');
    expect(await pins.load(A, B)).toBe('12345 67890');
    expect(await pins.load(B, A)).toBeUndefined();
  });

  it('reads a kept anchor strictly: a damaged one is an error, never "none"', () => {
    expect(parseAnchor(JSON.stringify(at(2)))).toEqual(at(2));
    for (const bad of ['', 'null', '[]', '{"seq":1}', '{"seq":"1","epoch":1,"links":[]}', '{"seq":1,"epoch":1,"links":[1]}']) {
      expect(() => parseAnchor(bad), bad).toThrow();
    }
  });
});

describe('the signed floors this browser keeps', () => {
  it('keeps one per account and owner, empty when none', async () => {
    const store = memoryFloorStore();
    expect(await store.load(A, 'user:x')).toEqual({});
    await store.save(A, 'user:x', { i1: 3, i2: 7 });
    expect(await store.load(A, 'user:x')).toEqual({ i1: 3, i2: 7 });
    expect(await store.load(B, 'user:x')).toEqual({});
    expect(await store.load(A, 'user:y')).toEqual({});
  });

  it('goes through the sealed store where there is one, and reads a kept floor strictly', async () => {
    const { floors } = defaultStores({
      sealLocal: async (_label: string, text: string) => text,
      openLocal: async (_label: string, sealed: string) => sealed,
    });
    await floors.save(A, 'space:s', { i: 2 });
    expect(await floors.load(A, 'space:s')).toEqual({ i: 2 });
    expect(parseFloor('{"a":1}')).toEqual({ a: 1 });
    for (const bad of ['', 'null', '[]', '{"a":0}', '{"a":"1"}', '{"a":1.5}']) {
      expect(() => parseFloor(bad), bad).toThrow();
    }
  });
});
