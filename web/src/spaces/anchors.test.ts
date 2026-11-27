// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
  defaultStores,
  indexedDbStores,
  memoryAnchorStore,
  memoryFloorStore,
  memoryPinStore,
  parseAnchor,
  parseFloor,
  resealIndexedDb,
} from './anchors';

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

  it('reads an anchor kept before owners and promotions existed, and one that has them', () => {
    // An old anchor has neither, and is still an anchor.
    expect(parseAnchor('{"seq":2,"epoch":1,"links":["a","b","c"]}')).toEqual({ seq: 2, epoch: 1, links: ['a', 'b', 'c'] });
    const full = {
      ...at(1),
      owners: [
        { id: A, bundle: 'aGFzaDE' },
        { id: B, bundle: 'aGFzaDI' },
      ],
      promotions: [{ home: A, promotion: 'aGFzaA' }],
    };
    expect(parseAnchor(JSON.stringify(full))).toEqual(full);
    // The shapes an earlier page kept (a record of owners, pairs of promotions) are read into these.
    expect(
      parseAnchor(
        JSON.stringify({ ...at(1), owners: { [A]: 'aGFzaDE' }, promotions: [[A, 'aGFzaA']] }),
      ),
    ).toEqual({ ...at(1), owners: [{ id: A, bundle: 'aGFzaDE' }], promotions: [{ home: A, promotion: 'aGFzaA' }] });
    for (const bad of [
      '{"seq":1,"epoch":1,"links":[],"owners":"x"}',
      '{"seq":1,"epoch":1,"links":[],"owners":["a"]}',
      '{"seq":1,"epoch":1,"links":[],"owners":[{"id":"a"}]}',
      '{"seq":1,"epoch":1,"links":[],"owners":null}',
      '{"seq":1,"epoch":1,"links":[],"owners":{"a":1}}',
      '{"seq":1,"epoch":1,"links":[],"promotions":[["a"]]}',
      '{"seq":1,"epoch":1,"links":[],"promotions":[["a",1]]}',
      '{"seq":1,"epoch":1,"links":[],"promotions":"x"}',
    ]) {
      expect(() => parseAnchor(bad), bad).toThrow();
    }
  });

  it('keeps the owners and promotions with the anchor, through the sealed store too', async () => {
    const full = { ...at(2), owners: [{ id: A, bundle: 'aGFzaDE' }], promotions: [{ home: B, promotion: 'aGFzaA' }] };
    const store = memoryAnchorStore();
    await store.save(A, SPACE, full);
    expect(await store.load(A, SPACE)).toEqual(full);
    const { anchors } = defaultStores({
      sealLocal: async (_label: string, text: string) => text,
      openLocal: async (_label: string, sealed: string) => sealed,
    });
    await anchors.save(A, SPACE, full);
    expect(await anchors.load(A, SPACE)).toEqual(full);
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

/** Just enough of IndexedDB for the anchors: two object stores and requests that answer later. */
type FakeStores = { anchors: Map<string, unknown>; pins: Map<string, unknown> } & Record<string, Map<string, unknown>>;

function fakeIndexedDb(): { factory: IDBFactory; stores: FakeStores } {
  const stores: FakeStores = { anchors: new Map(), pins: new Map() };
  const factory = {
    open() {
      const req: { result?: unknown; onsuccess?: () => void; onupgradeneeded?: () => void } = {};
      setTimeout(() => {
        req.result = {
          createObjectStore: () => undefined,
          close: () => undefined,
          transaction(name: string) {
            const data = stores[name] as Map<string, unknown>;
            const tx: { oncomplete?: () => void; objectStore: () => unknown } = { objectStore: () => store };
            let outstanding = 0;
            const run = (work: () => unknown) => {
              const request: { result?: unknown; onsuccess?: () => void } = {};
              outstanding += 1;
              setTimeout(() => {
                request.result = work();
                request.onsuccess?.();
                outstanding -= 1;
                if (outstanding === 0) setTimeout(() => tx.oncomplete?.(), 0);
              }, 0);
              return request;
            };
            const store = {
              get: (key: string) => run(() => data.get(key)),
              put: (value: unknown, key: string) =>
                run(() => {
                  data.set(key, value);
                  return key;
                }),
              delete: (key: string) =>
                run(() => {
                  data.delete(key);
                }),
              getAllKeys: () => run(() => [...data.keys()]),
              getAll: () => run(() => [...data.values()]),
            };
            return tx;
          },
        };
        req.onupgradeneeded?.();
        req.onsuccess?.();
      }, 0);
      return req;
    },
  } as unknown as IDBFactory;
  return { factory, stores };
}

/** A worker whose key can change: a value opens only under the epoch and label it was sealed with. */
function keyed() {
  const worker = {
    epoch: 1,
    sealLocal: async (label: string, text: string) => `${worker.epoch}|${label}|${text}`,
    openLocal: async (label: string, sealed: string) => {
      const [epoch, kept, ...text] = sealed.split('|');
      if (Number(epoch) !== worker.epoch || kept !== label) throw new Error('invalid');
      return text.join('|');
    },
  };
  return worker;
}

describe('what this browser keeps across a rotation of the root key', () => {
  it('is sealed again for the account while both keys are held, and only for that account', async () => {
    const { factory, stores } = fakeIndexedDb();
    const worker = keyed();
    const { anchors, pins } = indexedDbStores(worker, factory);
    await anchors.save(A, SPACE, at(3));
    await pins.save(A, B, '12345 67890');
    await anchors.save(B, SPACE, at(9));
    const others = stores.anchors.get(`anchor/${B}/${SPACE}`);

    // The rotation: values open under the old key (epoch 1) and are sealed under the new (epoch 2).
    await resealIndexedDb(factory, A, async (label, sealed) => {
      const text = await worker.openLocal(label, sealed);
      return `2|${label}|${text}`;
    });
    // Another account's value is not touched.
    expect(stores.anchors.get(`anchor/${B}/${SPACE}`)).toBe(others);

    worker.epoch = 2;
    expect(await anchors.load(A, SPACE)).toEqual(at(3));
    expect(await pins.load(A, B)).toBe('12345 67890');
  });

  it('is met again, not unreadable, on a browser that did not rotate', async () => {
    const { factory, stores } = fakeIndexedDb();
    const worker = keyed();
    const { anchors, pins } = indexedDbStores(worker, factory);
    await anchors.save(A, SPACE, at(3));
    await anchors.markSeen(A, SPACE);
    await pins.save(A, B, '12345 67890');
    await anchors.save(B, SPACE, at(9));

    // Another device rotated the account's keys: nothing here opens any more.
    worker.epoch = 2;
    expect(await anchors.load(A, SPACE)).toBeUndefined();
    expect(await anchors.seen(A, SPACE)).toBe(false);
    expect(await pins.load(A, B)).toBeUndefined();
    // What was kept for the account is gone but its new canary, and another account's is not.
    expect([...stores.anchors.keys()].filter((key) => key.includes(`/${A}`))).toEqual([`canary/${A}`]);
    expect(stores.anchors.has(`anchor/${B}/${SPACE}`)).toBe(true);

    // It works again under the new keys.
    await anchors.save(A, SPACE, at(1));
    expect((await anchors.load(A, SPACE))?.seq).toBe(1);
  });

  it('still refuses a damaged value while the keys have not changed', async () => {
    const { factory, stores } = fakeIndexedDb();
    const worker = keyed();
    const { anchors } = indexedDbStores(worker, factory);
    await anchors.save(A, SPACE, at(3));
    stores.anchors.set(`anchor/${A}/${SPACE}`, '1|anchor/other|{}');
    await expect(anchors.load(A, SPACE)).rejects.toThrow();
    stores.anchors.set(`anchor/${A}/${SPACE}`, 'not sealed at all');
    await expect(anchors.load(A, SPACE)).rejects.toThrow();
    // Nothing was dropped: the canary opens.
    expect(stores.anchors.has(`canary/${A}`)).toBe(true);
  });

  it('makes the canary for a store from before canaries, the first time it reads one', async () => {
    const { factory, stores } = fakeIndexedDb();
    const worker = keyed();
    stores.anchors.set(`anchor/${A}/${SPACE}`, `1|anchor/${A}/${SPACE}|${JSON.stringify(at(2))}`);
    const { anchors } = indexedDbStores(worker, factory);
    expect((await anchors.load(A, SPACE))?.seq).toBe(2);
    expect(stores.anchors.has(`canary/${A}`)).toBe(true);
    // And once it has one, a rotation elsewhere is met again.
    worker.epoch = 2;
    expect(await anchors.load(A, SPACE)).toBeUndefined();
  });
});
