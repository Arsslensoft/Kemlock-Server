// What the vault takes in of what the server serves, by write signature (docs/crypto.md, "Signed
// item writes"): a signature that fails is never taken in; an unsigned newer revision of an item of
// an owner whose writes are signed is not either; before that, unsigned items are taken as ever.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SyncResult } from '@/api/client';
import type { ItemDto } from '@/api/types';
import { signedItem } from '@/api/signedWrites';
import { createWriteChecker } from '@/manifest/writes';
import { encodeB64, utf8 } from '@/lib/b64url';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { type VaultDeps, VaultStore, syncVault } from './vault';

const ACCOUNT = '99999999-9999-4999-8999-999999999999';
const OWN = `user:${ACCOUNT}`;
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';

/** An item as a device seals it, then as the server serves it. */
async function sealed(id: string, revision: number): Promise<ItemDto> {
  const s = await crypto.sealItem({
    id,
    owner: OWN,
    kind: 'login',
    revision,
    json: JSON.stringify({ id, name: `${id}-${revision}` }),
  });
  return {
    id,
    owner: OWN,
    kind: 'login',
    format: 'kem1',
    revision,
    keyVersion: s.keyVersion,
    ciphertext: encodeB64(s.ciphertext),
    itemKey: encodeB64(s.itemKey),
    deleted: false,
  };
}

const tombstone = (id: string, revision: number): ItemDto => ({
  id,
  owner: OWN,
  kind: 'login',
  format: 'kem1',
  revision,
  keyVersion: 1,
  deleted: true,
});

function setup() {
  const store = new VaultStore();
  const pages: ItemDto[][] = [];
  const rejected = vi.fn();
  const served = vi.fn();
  const deps: VaultDeps = {
    api: {
      putItem: vi.fn(),
      putBatch: vi.fn(),
      async sync(): Promise<SyncResult> {
        const items = pages.shift() ?? [];
        return { notModified: false, page: { items, cursor: `c${pages.length}`, more: false } };
      },
    },
    crypto,
    writes: createWriteChecker({
      crypto,
      accountId: () => ACCOUNT,
      spaceSigner: async () => null,
    }),
    rejected,
    served,
  };
  const sync = async (...next: ItemDto[]) => {
    pages.push(next);
    await syncVault(deps, store);
  };
  return { store, sync, rejected, served };
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
});

describe('syncing with write signatures', () => {
  it('takes in unsigned items until the owner has been seen signing', async () => {
    const { store, sync, rejected } = setup();
    await sync(await sealed(A, 1), await sealed(B, 1));
    expect([...store.items.keys()].sort()).toEqual([A, B]);
    expect(store.signedOwners.has(OWN)).toBe(false);
    // A newer unsigned revision is still taken in: nothing says this owner's writes are signed.
    await sync(await sealed(A, 2));
    expect(store.items.get(A)?.revision).toBe(2);
    expect(rejected).not.toHaveBeenCalled();
  });

  it('takes in a signed revision and then refuses an unsigned newer one of the same item', async () => {
    const { store, sync, rejected, served } = setup();
    await sync(await signedItem(crypto, await sealed(A, 1)));
    expect(store.signedOwners.has(OWN)).toBe(true);
    await sync(await sealed(A, 2));
    expect(store.items.get(A)?.revision).toBe(1);
    expect(rejected).toHaveBeenCalledWith(expect.objectContaining({ id: A, revision: 2 }), 'unsigned');
    // The keeper is still told what the server served, so a rollback is still seen.
    expect(served).toHaveBeenLastCalledWith(expect.objectContaining({ id: A, revision: 2 }), false, 'unsigned');
    // A signed one goes through.
    await sync(await signedItem(crypto, await sealed(A, 3)));
    expect(store.items.get(A)?.revision).toBe(3);
  });

  it('still takes in an unsigned item it never held, as the first sync of a new browser must', async () => {
    const { store, sync } = setup();
    await sync(await signedItem(crypto, await sealed(A, 1)), await sealed(B, 1));
    expect(store.items.get(B)?.revision).toBe(1);
  });

  it('never takes in a signature that fails', async () => {
    const { store, sync, rejected } = setup();
    const signed = await signedItem(crypto, await sealed(A, 1));
    // The same signature over another revision, as a server re-sending an old write would.
    await sync({ ...(await sealed(A, 2)), writer: signed.writer, writerKeyVersion: 1, writeSignature: signed.writeSignature });
    expect(store.items.has(A)).toBe(false);
    expect(rejected).toHaveBeenCalledWith(expect.objectContaining({ id: A, revision: 2 }), 'invalid');
  });

  it('removes an item for a signed deletion and keeps it for an unsigned one', async () => {
    const { store, sync, rejected, served } = setup();
    await sync(await signedItem(crypto, await sealed(A, 1)), await signedItem(crypto, await sealed(B, 1)));
    await sync(tombstone(A, 2));
    expect(store.items.has(A)).toBe(true);
    expect(rejected).toHaveBeenCalledWith(expect.objectContaining({ id: A, revision: 2 }), 'unsigned');

    await sync(await signedItem(crypto, tombstone(B, 2)));
    expect(store.items.has(B)).toBe(false);
    expect(served).toHaveBeenLastCalledWith(expect.objectContaining({ id: B, deleted: true }), false, 'signed');
  });

  it('does not check anything when it has no checker', async () => {
    const store = new VaultStore();
    const served = vi.fn();
    const deps: VaultDeps = {
      api: {
        putItem: vi.fn(),
        putBatch: vi.fn(),
        sync: async () => ({ notModified: false, page: { items: [await sealed(A, 1)], cursor: 'c', more: false } }),
      },
      crypto,
      served,
    };
    await syncVault(deps, store);
    expect(store.items.get(A)?.revision).toBe(1);
    expect(served).toHaveBeenCalledWith(expect.anything(), true, undefined);
  });
});
