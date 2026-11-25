import { beforeEach, describe, expect, it } from 'vitest';
import type { ItemDto } from '@/api/types';
import { decodeB64, fromUtf8 } from '@/lib/b64url';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { fakeFiles } from '@/test/fake-files';
import { canCopy, copyData, copyDraft, copyFields, saveCopy } from './copy';
import { cardDefaults, cardFields } from './forms/card';
import { type VaultDeps, type VaultItem, VaultStore, saveItem } from './vault';

const OWNER = 'user:00000000-0000-4000-8000-0000000000aa';

function item(kind: string, data: Record<string, unknown> | null): VaultItem {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    owner: OWNER,
    kind,
    revision: 14,
    keyVersion: 3,
    collectionId: '00000000-0000-4000-8000-0000000000cc',
    data,
    sizes: { ciphertext: 1214, itemKey: 1648 },
  };
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('what a copy keeps', () => {
  it('keeps what the person typed and the item held, and drops what names the old item', () => {
    const original = {
      id: '00000000-0000-4000-8000-000000000001',
      name: 'GitHub',
      username: 'sam@example.org',
      password: 'pw',
      urls: ['https://github.com'],
      uris: [{ uri: 'https://github.com' }],
      fields: [{ name: 'Recovery email', value: 'x', kind: 'text', adminField: 'f1' }],
      tags: ['work'],
      secret: 'JBSWY3DPEHPK3PXP',
      someKeyAnotherAppWrote: { nested: [1, 2] },
      attachments: [{ id: 'a1', name: 'a.txt', size: 3, key: 'k', kemlockFile: 'f-1' }],
      notes: 'Personal account.',
      favorite: true,
      links: [{ id: '00000000-0000-4000-8000-000000000002' }],
      linkedLoginId: '00000000-0000-4000-8000-000000000002',
      passkeys: [{ credentialId: 'c' }],
      passwordHistory: [{ password: 'old' }],
      file: { name: 'a.txt' },
      trashedAt: '2026-11-01T00:00:00.000Z',
      updatedAt: 1,
      createdAt: 2,
      addedAt: 3,
    };
    expect(copyData(original)).toEqual({
      name: 'GitHub',
      username: 'sam@example.org',
      password: 'pw',
      urls: ['https://github.com'],
      uris: [{ uri: 'https://github.com' }],
      fields: [{ name: 'Recovery email', value: 'x', kind: 'text', adminField: 'f1' }],
      tags: ['work'],
      secret: 'JBSWY3DPEHPK3PXP',
      someKeyAnotherAppWrote: { nested: [1, 2] },
      attachments: [{ id: 'a1', name: 'a.txt', size: 3, key: 'k', kemlockFile: 'f-1' }],
      notes: 'Personal account.',
      favorite: true,
    });
    // The item it was made from is untouched.
    expect(original.links).toHaveLength(1);
  });

  it('makes a stand-in with no id, no revision and no collection', () => {
    const draft = copyDraft(item('login', { id: 'x', name: 'GitHub', links: [{ id: 'y' }] }));
    expect(draft).toMatchObject({ id: '', revision: 0, kind: 'login', data: { name: 'GitHub' } });
    expect(draft.data).not.toHaveProperty('id');
    expect(draft.data).not.toHaveProperty('links');
    expect(draft).not.toHaveProperty('collectionId');
  });

  it('is offered for what can be filled in again, not for a passkey, a file or an item that cannot be read', () => {
    expect(canCopy(item('login', {}))).toBe(true);
    expect(canCopy(item('contact', {}))).toBe(true);
    expect(canCopy(item('passkey', {}))).toBe(false);
    expect(canCopy(item('file', {}))).toBe(false);
    expect(canCopy(item('login', null))).toBe(false);
    expect(copyDraft(item('login', null)).data).toBeNull();
  });
});

describe('what a copy saves', () => {
  it('is the draft with the form\'s values on top: what the form owns wins, the rest comes through', () => {
    const draft = copyDraft(item('login', { name: 'GitHub', notes: 'old', fields: [{ name: 'a', value: 'b', kind: 'text' }], tags: ['t'] }));
    // A cleared field is undefined, which saving drops.
    expect(copyFields(draft, { name: 'GitHub 2', notes: undefined })).toEqual({
      name: 'GitHub 2',
      notes: undefined,
      fields: [{ name: 'a', value: 'b', kind: 'text' }],
      tags: ['t'],
    });
  });

  describe('sealed', () => {
    function setup() {
      const rows = new Map<string, ItemDto>();
      const puts: ItemDto[] = [];
      const store = new VaultStore();
      let n = 0;
      const deps: VaultDeps = {
        api: {
          async putItem(dto) {
            puts.push(dto);
            rows.set(dto.id, dto);
            return { item: dto, etag: null };
          },
          async putBatch(request) {
            return request.writes.map((w) => w.item);
          },
          async sync() {
            return { notModified: true } as never;
          },
        },
        crypto,
        now: () => new Date('2026-11-25T12:00:00Z'),
        newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
      };
      return { rows, puts, store, deps };
    }
    const bodyOf = (dto: ItemDto | undefined): Record<string, unknown> => {
      const sealed = JSON.parse(fromUtf8(decodeB64(dto?.ciphertext ?? ''))) as unknown[];
      return JSON.parse(String(sealed[sealed.length - 1])) as Record<string, unknown>;
    };
    const extras = {
      fields: [{ name: 'Employee ID', value: '42', kind: 'text', adminField: 'f1' }],
      tags: ['work'],
      someKeyAnotherAppWrote: { nested: true },
    };

    it('keeps the custom fields, tags and an unknown key of a card', async () => {
      const { puts, store, deps } = setup();
      const source = item('card', { name: 'Visa', number: '4111111111111111', brand: 'Visa', expMonth: 5, expYear: 2029, ...extras });
      const draft = copyDraft(source);
      // The card form hands back only the fields it owns.
      const formFields = cardFields({ ...cardDefaults(draft), name: 'Visa copy' }, draft);
      await saveItem(deps, store, { kind: 'card', owner: OWNER, fields: copyFields(draft, formFields), entry: true });
      expect(bodyOf(puts[0])).toMatchObject({ name: 'Visa copy', number: '4111111111111111', ...extras });
      expect(bodyOf(puts[0])['id']).toBe(puts[0]?.id);
    });

    it('keeps them for a login, whose form owns even fewer fields', async () => {
      const { puts, store, deps } = setup();
      const source = item('login', { name: 'GitHub', username: 'sam', password: 'pw', urls: ['https://github.com'], ...extras });
      const draft = copyDraft(source);
      const saved = await saveItem(deps, store, {
        kind: 'login',
        owner: OWNER,
        fields: copyFields(draft, { name: 'GitHub copy', username: 'sam', password: 'pw', urls: ['https://github.com'], notes: undefined }),
      });
      expect(bodyOf(puts[0])).toMatchObject({ name: 'GitHub copy', ...extras });
      expect(saved.data).toMatchObject(extras);
    });

    it('saves a copy with no files as one write', async () => {
      const { puts, store, deps } = setup();
      const files = fakeFiles();
      const saved = await saveCopy(deps, store, files, { kind: 'note', owner: OWNER, fields: { name: 'N', text: 't' } }, 'source');
      expect(puts).toHaveLength(1);
      expect(saved.revision).toBe(1);
      expect(files.calls).toEqual([]);
    });

    it('sends a note\'s files again under the copy, naming the new files, and leaves an entry never uploaded without one', async () => {
      const { rows, puts, store, deps } = setup();
      const files = fakeFiles({ knowsItem: (id) => rows.has(id) });
      files.held.set('source', new Map([['old-1', new Uint8Array([1, 2, 3])]]));
      const source = item('note', {
        name: 'Wi-Fi',
        text: 'hunter2',
        ...extras,
        attachments: [
          { id: 'a1', name: 'map.png', size: 3, key: 'k1', addedAt: 1, kemlockFile: 'old-1' },
          { id: 'a2', name: 'pending.txt', size: 9, key: 'k2', addedAt: 2 },
        ],
      });
      const draft = copyDraft(source);
      const saved = await saveCopy(
        deps,
        store,
        files,
        { kind: 'note', owner: OWNER, fields: copyFields(draft, { name: 'Wi-Fi copy', text: 'hunter2' }) },
        'source',
      );
      // The stub first, with no file named; then the file; then the item naming it.
      expect(puts.map((dto) => dto.revision)).toEqual([1, 2]);
      expect(bodyOf(puts[0])['attachments']).toEqual([
        expect.not.objectContaining({ kemlockFile: expect.anything() }),
        expect.objectContaining({ name: 'pending.txt' }),
      ]);
      const entries = saved.data?.['attachments'] as Array<Record<string, unknown>>;
      expect(entries[0]).toMatchObject({ name: 'map.png', key: 'k1', kemlockFile: 'new-file-1' });
      expect(entries[1]).not.toHaveProperty('kemlockFile');
      expect(files.held.get(saved.id)?.get('new-file-1')).toEqual(new Uint8Array([1, 2, 3]));
      expect(saved.data).toMatchObject({ name: 'Wi-Fi copy', ...extras });
      // The source keeps its own file.
      expect(files.held.get('source')?.has('old-1')).toBe(true);
    });

    it('leaves no copy behind when the quota refuses the files', async () => {
      const { rows, puts, store, deps } = setup();
      const files = fakeFiles({ knowsItem: (id) => rows.has(id), refuseStart: 1 });
      files.held.set('source', new Map([['old-1', new Uint8Array([1])]]));
      const attachments = [{ id: 'a1', name: 'map.png', size: 1, key: 'k1', addedAt: 1, kemlockFile: 'old-1' }];
      await expect(
        saveCopy(deps, store, files, { kind: 'note', owner: OWNER, fields: { name: 'N', text: 't', attachments } }, 'source'),
      ).rejects.toMatchObject({ status: 413 });
      expect(puts.map((dto) => [dto.revision, dto.deleted])).toEqual([
        [1, false],
        [2, true],
      ]);
      expect([...store.items.keys()]).toEqual([]);
    });
  });
});
