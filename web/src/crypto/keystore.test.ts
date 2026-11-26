// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { indexedDbTabKeyStore, purgeTabKeys, tabKeyFresh, touchTabKey } from './keystore';

interface Req {
  result?: unknown;
  error?: unknown;
  onsuccess?: () => void;
  onerror?: () => void;
  onupgradeneeded?: () => void;
  onblocked?: () => void;
}

interface Tx {
  error?: unknown;
  oncomplete?: () => void;
  onerror?: () => void;
  onabort?: () => void;
  objectStore(name: string): unknown;
}

/** Just enough of IndexedDB for the key stores: one object store, requests that answer later. */
function fakeIndexedDb(): { factory: IDBFactory; data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  const factory = {
    open(): Req {
      const req: Req = {};
      setTimeout(() => {
        req.result = {
          createObjectStore: () => undefined,
          close: () => undefined,
          transaction(): Tx {
            let outstanding = 0;
            let failed = false;
            const tx: Tx = {
              objectStore: () => store,
            };
            const settle = () =>
              setTimeout(() => {
                if (outstanding === 0 && !failed) tx.oncomplete?.();
              }, 0);
            const run = (work: () => unknown): Req => {
              const request: Req = {};
              outstanding += 1;
              setTimeout(() => {
                try {
                  request.result = work();
                  request.onsuccess?.();
                } catch (error) {
                  failed = true;
                  request.error = error;
                  request.onerror?.();
                  tx.error = error;
                  tx.onerror?.();
                }
                outstanding -= 1;
                settle();
              }, 0);
              return request;
            };
            const store = {
              get: (key: string) => run(() => data.get(key)),
              getAllKeys: () => run(() => [...data.keys()]),
              add: (value: unknown, key: string) =>
                run(() => {
                  if (data.has(key)) throw Object.assign(new Error('exists'), { name: 'ConstraintError' });
                  data.set(key, value);
                  return key;
                }),
              put: (value: unknown, key: string) =>
                run(() => {
                  data.set(key, value);
                  return key;
                }),
              delete: (key: string) =>
                run(() => {
                  data.delete(key);
                  return undefined;
                }),
            };
            return tx;
          },
        };
        req.onupgradeneeded?.();
        req.onsuccess?.();
      }, 0);
      return req;
    },
  };
  return { factory: factory as unknown as IDBFactory, data };
}

const NOW = 1_700_000_000_000;
const MAX = 14_000;

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

describe('a page is fresh while it was heard from within the limit', () => {
  it('counts the limit and the clock running backwards as silent', () => {
    expect(tabKeyFresh(NOW - 1, NOW, MAX)).toBe(true);
    expect(tabKeyFresh(NOW - MAX + 1, NOW, MAX)).toBe(true);
    expect(tabKeyFresh(NOW - MAX, NOW, MAX)).toBe(false);
    expect(tabKeyFresh(NOW + 1, NOW, MAX)).toBe(false);
  });
});

describe('a tab key store', () => {
  it('keeps one non-extractable key per tab, and the first one added wins', async () => {
    const { factory } = fakeIndexedDb();
    const store = indexedDbTabKeyStore('tab-one', factory, () => NOW);
    expect(await store.load()).toBeUndefined();
    const first = await aesKey();
    expect(await store.add(first)).toBe(true);
    expect(await store.add(await aesKey())).toBe(false);
    expect(await store.load()).toBe(first);
    expect(await indexedDbTabKeyStore('tab-two', factory, () => NOW).load()).toBeUndefined();
    await store.clear();
    expect(await store.load()).toBeUndefined();
  });
});

describe('deleting the keys of closed tabs at the start of a page load', () => {
  async function withTabs() {
    const { factory, data } = fakeIndexedDb();
    // The trusted-device key and the DPoP pair are not tab keys and are never touched.
    data.set('device-wrap', await aesKey());
    data.set('dpop', { privateKey: 'x' });
    await indexedDbTabKeyStore('closed', factory, () => NOW - 60_000).add(await aesKey());
    await indexedDbTabKeyStore('reloading', factory, () => NOW - 3_000).add(await aesKey());
    await indexedDbTabKeyStore('quiet-but-open', factory, () => NOW - 120_000).add(await aesKey());
    return { factory, data };
  }

  it('deletes a key whose page has been silent past the reload window, so what it sealed cannot open', async () => {
    const { factory, data } = await withTabs();
    await purgeTabKeys({ now: NOW, maxAgeMs: MAX, factory, isOpen: async (id) => id === 'quiet-but-open' });
    expect([...data.keys()].sort()).toEqual(['device-wrap', 'dpop', 'tab-wrap:quiet-but-open', 'tab-wrap:reloading']);
  });

  it('keeps a key that was stamped again, which is what an open page does every few seconds', async () => {
    const { factory, data } = await withTabs();
    await touchTabKey('closed', NOW - 1_000, factory);
    await purgeTabKeys({ now: NOW, maxAgeMs: MAX, factory, isOpen: async () => false });
    expect(data.has('tab-wrap:closed')).toBe(true);
    expect(data.has('tab-wrap:quiet-but-open')).toBe(false);
  });

  it('does not make a key that is not there, and deletes a record it cannot read', async () => {
    const { factory, data } = fakeIndexedDb();
    await touchTabKey('nobody', NOW, factory);
    expect(data.size).toBe(0);
    data.set('tab-wrap:damaged', 'not a record');
    await purgeTabKeys({ now: NOW, maxAgeMs: MAX, factory });
    expect(data.size).toBe(0);
  });
});
