import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PutResult } from '@/api/client';
import type { ItemDto } from '@/api/types';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { type VaultDeps, VaultStore, deleteForGood, openDto, saveItem, spaceOf, syncVault, trashItem } from './vault';
import { saveBatch } from './batch';

const SPACE = '00000000-0000-4000-8000-0000000000bb';
const COLLECTION = '00000000-0000-4000-8000-0000000000cc';
const OTHER_COLLECTION = '00000000-0000-4000-8000-0000000000dd';
const SPACE_OWNER = `space:${SPACE}`;
const USER_OWNER = 'user:00000000-0000-4000-8000-0000000000aa';
const NOW = new Date('2026-11-25T12:00:00Z');

function setup(over: Partial<VaultDeps> = {}) {
  const rows = new Map<string, ItemDto>();
  const puts: ItemDto[] = [];
  const batches: ItemDto[][] = [];
  const api: VaultDeps['api'] = {
    async putItem(dto): Promise<PutResult> {
      puts.push(dto);
      rows.set(dto.id, dto);
      return { item: dto, etag: null };
    },
    async putBatch(request) {
      batches.push(request.writes.map((w) => w.item));
      for (const write of request.writes) rows.set(write.item.id, write.item);
      return request.writes.map((w) => w.item);
    },
    async sync() {
      return { notModified: false, page: { items: [...rows.values()], cursor: 'c', more: false } };
    },
  };
  const store = new VaultStore();
  let n = 0;
  const deps: VaultDeps = {
    api,
    crypto,
    now: () => NOW,
    newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
    ...over,
  };
  return { rows, puts, batches, store, deps };
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('items of a space', () => {
  it('knows a space owner from a user owner', () => {
    expect(spaceOf(SPACE_OWNER)).toBe(SPACE);
    expect(spaceOf(USER_OWNER)).toBeNull();
  });

  it('seals a new item under the collection key and writes it with its collectionId', async () => {
    const { puts, store, deps } = setup();
    const saved = await saveItem(deps, store, {
      kind: 'login',
      owner: SPACE_OWNER,
      collectionId: COLLECTION,
      fields: { name: 'VPN', username: 'ops', password: 'pw' },
    });
    expect(puts[0]).toMatchObject({
      owner: SPACE_OWNER,
      collectionId: COLLECTION,
      revision: 1,
      format: 'kem1',
      // The key version is the collection key's, which the worker answers, not the account's.
      keyVersion: 2,
    });
    expect(saved.collectionId).toBe(COLLECTION);
    expect(store.items.get(saved.id)?.data?.name).toBe('VPN');
    // It went through the space operation, never the vault's own seal.
    const sealed = puts[0]?.ciphertext ?? '';
    expect(sealed).not.toBe('');
  });

  it('leaves collectionId off an item of the account\'s own vault', async () => {
    const { puts, store, deps } = setup();
    await saveItem(deps, store, {
      kind: 'note',
      owner: USER_OWNER,
      // A stray collection is not sent for a vault item: the server refuses one.
      collectionId: COLLECTION,
      fields: { name: 'n', text: 't' },
    });
    expect(puts[0]).not.toHaveProperty('collectionId');
    expect(puts[0]?.keyVersion).toBe(1);
  });

  it('refuses to seal an item of a space without a collection', async () => {
    const { store, deps } = setup();
    await expect(
      saveItem(deps, store, { kind: 'note', owner: SPACE_OWNER, fields: { name: 'n' } }),
    ).rejects.toThrow('needs a collection');
  });

  it('edits in the same collection, as the next revision, and trashes and deletes there too', async () => {
    const { puts, store, deps } = setup();
    const made = await saveItem(deps, store, {
      kind: 'login',
      owner: SPACE_OWNER,
      collectionId: COLLECTION,
      fields: { name: 'VPN' },
    });
    // The form offers no other collection to an existing item: its own stays, whatever is passed.
    const edited = await saveItem(deps, store, {
      existing: made,
      kind: 'login',
      owner: SPACE_OWNER,
      collectionId: OTHER_COLLECTION,
      fields: { name: 'VPN 2' },
    });
    expect(edited.revision).toBe(2);
    expect(edited.collectionId).toBe(COLLECTION);
    expect(puts[1]).toMatchObject({ revision: 2, collectionId: COLLECTION });

    const trashed = await trashItem(deps, store, edited);
    expect(puts[2]).toMatchObject({ revision: 3, collectionId: COLLECTION });
    await deleteForGood(deps, store, trashed);
    expect(puts[3]).toMatchObject({ deleted: true, revision: 4, collectionId: COLLECTION });
    expect(store.items.has(made.id)).toBe(false);
  });

  it('batches space items with their collection', async () => {
    const { batches, store, deps } = setup();
    await saveBatch(deps, store, [
      { kind: 'note', owner: SPACE_OWNER, collectionId: COLLECTION, fields: { name: 'a' } },
      { kind: 'note', owner: USER_OWNER, fields: { name: 'b' } },
    ]);
    expect(batches[0]?.[0]).toMatchObject({ owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(batches[0]?.[1]).not.toHaveProperty('collectionId');
  });

  it('opens a synced item of a space, asking for the space keys when it does not open yet', async () => {
    const { rows, store, deps } = setup();
    const made = await saveItem(deps, store, {
      kind: 'login',
      owner: SPACE_OWNER,
      collectionId: COLLECTION,
      fields: { name: 'VPN' },
    });
    expect(rows.get(made.id)?.collectionId).toBe(COLLECTION);

    // A fresh browser: the worker holds no key for the space until it is told to.
    let keysOpen = false;
    const ensureSpaceKeys = vi.fn(async (space: string) => {
      expect(space).toBe(SPACE);
      keysOpen = true;
    });
    const gated: VaultDeps['crypto'] = {
      ...crypto,
      openSpaceItem: async (input) => {
        if (!keysOpen) throw new Error('no key');
        return crypto.openSpaceItem(input);
      },
    };
    const fresh = new VaultStore();
    const items = await syncVault({ ...deps, crypto: gated, ensureSpaceKeys }, fresh);
    expect(ensureSpaceKeys).toHaveBeenCalledTimes(1);
    expect(items[0]).toMatchObject({ id: made.id, collectionId: COLLECTION, data: { name: 'VPN' } });
  });

  it('keeps an item it cannot open as unreadable instead of failing the sync', async () => {
    const { rows, store, deps } = setup();
    const made = await saveItem(deps, store, {
      kind: 'login',
      owner: SPACE_OWNER,
      collectionId: COLLECTION,
      fields: { name: 'VPN' },
    });
    const dto = rows.get(made.id) as ItemDto;
    const refused = vi.fn(async () => {
      throw new Error('still no key');
    });
    const noKey: VaultDeps['crypto'] = {
      ...crypto,
      openSpaceItem: async () => {
        throw new Error('no key');
      },
    };
    const opened = await openDto(noKey, dto, refused);
    expect(refused).toHaveBeenCalledTimes(1);
    expect(opened).toMatchObject({ id: made.id, owner: SPACE_OWNER, data: null });
    // Without a collection on the item there is no key to ask for.
    const lost = await openDto(crypto, { ...dto, collectionId: null });
    expect(lost?.data).toBeNull();
  });
});
