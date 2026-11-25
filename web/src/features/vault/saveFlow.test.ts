import { describe, expect, it, vi } from 'vitest';
import { fileKeyText, kma1Length } from '@/lib/kma1';
import { type AttachmentEntry, entryBody } from './attachments';
import { type FormResult, UploadError, saveWithExtras } from './saveFlow';
import type { ItemData, SaveInput, VaultItem } from './vault';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

function item(id: string, kind: string, data: ItemData, extra: Partial<VaultItem> = {}): VaultItem {
  return { id, owner: 'user:u', kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 }, ...extra };
}

/** A vault of one process: saves put items in it, as `saveItem` does. */
function world(initial: VaultItem[] = []) {
  const items = new Map(initial.map((entry) => [entry.id, entry]));
  const inputs: SaveInput[] = [];
  let made = 0;
  const failOn = new Set<string>();
  const save = vi.fn(async (input: SaveInput): Promise<VaultItem> => {
    inputs.push(input);
    if (input.existing && failOn.has(input.existing.id)) throw new Error('refused');
    made += 1;
    const id = input.existing?.id ?? `99999999-9999-4999-8999-99999999999${made}`;
    const data: ItemData = { ...(input.existing?.data ?? {}), ...input.fields };
    for (const key of Object.keys(data)) if (data[key] === undefined) delete data[key];
    const saved = item(id, input.kind, data, {
      owner: input.existing?.owner ?? input.owner,
      revision: (input.existing?.revision ?? 0) + 1,
    });
    items.set(id, saved);
    return saved;
  });
  const files = {
    start: vi.fn(async (itemId: string, size: number) => ({
      fileId: `file-${itemId.slice(-1)}`,
      itemId,
      size,
      maxSize: 1_000_000,
      uploadUrl: '',
      presigned: false,
    })),
    upload: vi.fn(async (itemId: string, fileId: string) => ({ fileId, itemId, size: 0, status: 'ready' as const })),
    remove: vi.fn(async () => undefined),
  };
  const removeItem = vi.fn(async (gone: VaultItem) => {
    items.delete(gone.id);
  });
  const read = vi.fn(async () => new TextEncoder().encode('abc'));
  return { items, inputs, failOn, save, files, removeItem, read, deps: { save, lookup: (id: string) => items.get(id), files, removeItem, read } };
}

function result(over: Partial<FormResult> = {}): FormResult {
  return {
    fields: { name: 'GitHub' },
    entry: false,
    links: [],
    uploads: [],
    removedFiles: [],
    withUploaded: () => ({}),
    rollbackOnFailure: false,
    ...over,
  };
}

const request = (over: { result: FormResult; existing?: VaultItem; linksBefore?: string[] }) => ({
  kind: 'login',
  owner: 'user:u',
  linksBefore: [],
  ...over,
});

describe('saving an item', () => {
  it('saves it once, as an entry of the app when it is one, in the collection chosen', async () => {
    const w = world();
    const outcome = await saveWithExtras(w.deps, {
      ...request({ result: result({ entry: true }) }),
      owner: 'space:s',
      collectionId: 'col-1',
    });
    expect(w.save).toHaveBeenCalledOnce();
    expect(w.inputs[0]).toMatchObject({ kind: 'login', owner: 'space:s', collectionId: 'col-1', entry: true, fields: { name: 'GitHub' } });
    expect(outcome).toMatchObject({ linkFailures: [] });
    expect(w.files.start).not.toHaveBeenCalled();
  });

  it('edits the item it is given', async () => {
    const existing = item(A, 'login', { name: 'Old' });
    const w = world([existing]);
    const outcome = await saveWithExtras(w.deps, request({ result: result(), existing }));
    expect(w.inputs[0]?.existing).toBe(existing);
    expect(outcome.item.id).toBe(A);
  });
});

describe('links are written on both items', () => {
  it('names the new item in each item it links to', async () => {
    const other = item(B, 'otp', { issuer: 'GitHub' });
    const w = world([other]);
    const outcome = await saveWithExtras(w.deps, request({ result: result({ links: [B] }) }));
    const saved = w.items.get(B);
    expect(saved?.data?.['links']).toEqual([{ id: outcome.item.id }]);
    expect(saved?.revision).toBe(2);
    expect(outcome.linkFailures).toEqual([]);
  });

  it('removes the item from the ones it no longer links to, and leaves the others\' links alone', async () => {
    const mine = item(A, 'login', { name: 'GitHub', links: [{ id: B }] });
    const other = item(B, 'otp', { links: [{ id: A }, { id: C }] });
    const w = world([mine, other]);
    await saveWithExtras(w.deps, request({ result: result({ fields: { links: undefined } }), existing: mine, linksBefore: [B] }));
    expect(w.items.get(B)?.data?.['links']).toEqual([{ id: C }]);
    expect(w.items.get(A)?.data?.['links']).toBeUndefined();
  });

  it('does not write an item whose end is right already', async () => {
    const mine = item(A, 'login', { links: [{ id: B }] });
    const other = item(B, 'otp', { links: [{ id: A }] });
    const w = world([mine, other]);
    await saveWithExtras(w.deps, request({ result: result({ links: [B] }), existing: mine, linksBefore: [B] }));
    expect(w.save).toHaveBeenCalledOnce();
  });

  it('keeps the item saved and names the ones whose link could not be written', async () => {
    const other = item(B, 'otp', { issuer: 'GitHub code' });
    const w = world([other]);
    w.failOn.add(B);
    const outcome = await saveWithExtras(w.deps, request({ result: result({ links: [B] }) }));
    expect(outcome.item.data?.['name']).toBe('GitHub');
    expect(outcome.linkFailures).toEqual(['GitHub code']);
  });

  it('skips a linked item that is not in the vault any more', async () => {
    const w = world();
    const outcome = await saveWithExtras(w.deps, request({ result: result({ links: [B] }) }));
    expect(outcome.linkFailures).toEqual([]);
    expect(w.save).toHaveBeenCalledOnce();
  });
});

describe('files are sent after the item is saved', () => {
  const key = fileKeyText(new Uint8Array(32).fill(7));
  const chosen = (): AttachmentEntry => ({
    id: 'attachment-1',
    name: 'notes.txt',
    size: 3,
    type: 'text/plain',
    key,
    addedAt: 5,
    file: new Blob(['abc']),
  });

  function note(uploads: AttachmentEntry[], over: Partial<FormResult> = {}): FormResult {
    return result({
      fields: { name: 'Plan', attachments: undefined },
      uploads,
      withUploaded: (uploaded) => ({ attachments: uploaded.map(entryBody) }),
      ...over,
    });
  }

  it('saves the item, announces the length of the KMA1 file, sends sealed bytes and saves the item again naming the file', async () => {
    const w = world();
    const outcome = await saveWithExtras(w.deps, request({ result: note([chosen()]) }));
    expect(w.save).toHaveBeenCalledTimes(2);
    // The first save names no file: the server takes a file only for an item that exists.
    expect(w.inputs[0]?.fields['attachments']).toBeUndefined();
    expect(w.files.start).toHaveBeenCalledWith(outcome.item.id, kma1Length(3));
    const [, , sealed] = w.files.upload.mock.calls[0] as unknown as [string, string, Uint8Array];
    expect(sealed).toHaveLength(kma1Length(3));
    expect(new TextDecoder().decode(sealed.subarray(0, 4))).toBe('KMA1');
    const attachments = outcome.item.data?.['attachments'] as Array<Record<string, unknown>>;
    expect(attachments).toHaveLength(1);
    expect(attachments[0]).toMatchObject({ id: 'attachment-1', name: 'notes.txt', size: 3, key, kemlockFile: expect.stringMatching(/^file-/) });
    expect('file' in (attachments[0] ?? {})).toBe(false);
  });

  it('keeps the SHA-256 of the plaintext bytes, in lower-case hex, in the body', async () => {
    const w = world();
    const outcome = await saveWithExtras(w.deps, request({ result: note([chosen()]) }));
    const [attachment] = outcome.item.data?.['attachments'] as Array<Record<string, unknown>>;
    // The hash of "abc", taken before the bytes were sealed.
    expect(attachment?.['sha256']).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('writes a File item\'s one file as file, with its hash', async () => {
    const w = world();
    const outcome = await saveWithExtras(
      w.deps,
      request({
        result: result({
          fields: { name: 'Lease' },
          uploads: [chosen()],
          withUploaded: (uploaded) => ({ file: entryBody(uploaded[0] as AttachmentEntry) }),
          rollbackOnFailure: true,
        }),
      }),
    );
    expect(w.inputs[0]?.fields['file']).toBeUndefined();
    expect(outcome.item.data?.['file']).toMatchObject({
      name: 'notes.txt',
      sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      kemlockFile: expect.stringMatching(/^file-/),
    });
  });

  it('removes the upload it started when the bytes could not be sent, keeps the item and does not save it again', async () => {
    const w = world();
    w.files.upload.mockRejectedValueOnce(new Error('network'));
    const failure = await saveWithExtras(w.deps, request({ result: note([chosen()]) })).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(UploadError);
    expect((failure as UploadError).saved?.data?.['name']).toBe('Plan');
    expect(w.files.remove).toHaveBeenCalledOnce();
    expect(w.save).toHaveBeenCalledOnce();
    expect(w.removeItem).not.toHaveBeenCalled();
  });

  it('does not write the links of an item whose file failed, so Save tries them again', async () => {
    const other = item(B, 'otp', {});
    const w = world([other]);
    w.files.start.mockRejectedValueOnce(new Error('too large'));
    await expect(saveWithExtras(w.deps, request({ result: note([chosen()], { links: [B] }) }))).rejects.toBeInstanceOf(UploadError);
    expect(w.items.get(B)?.data?.['links']).toBeUndefined();
  });

  it('does not keep a new item that has nothing without its file', async () => {
    const w = world();
    w.files.upload.mockRejectedValueOnce(new Error('network'));
    const failure = await saveWithExtras(
      w.deps,
      request({ result: note([chosen()], { rollbackOnFailure: true }) }),
    ).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(UploadError);
    expect((failure as UploadError).saved).toBeUndefined();
    expect(w.removeItem).toHaveBeenCalledOnce();
    expect(w.items.size).toBe(0);
  });

  it('deletes from the server the files the person removed, once the item no longer names them', async () => {
    const existing = item(A, 'note', { name: 'Plan', attachments: [{ id: 'old', name: 'old.txt', size: 1, key, addedAt: 1, kemlockFile: 'server-9' }] });
    const w = world([existing]);
    await saveWithExtras(
      w.deps,
      request({ result: result({ fields: { name: 'Plan', attachments: undefined }, removedFiles: ['server-9'] }), existing }),
    );
    expect(w.files.remove).toHaveBeenCalledWith(A, 'server-9');
    const order = [w.save.mock.invocationCallOrder[0] ?? 0, w.files.remove.mock.invocationCallOrder[0] ?? 0];
    expect(order[0]).toBeLessThan(order[1] ?? 0);
  });

  it('carries on when a file to delete cannot be', async () => {
    const w = world();
    w.files.remove.mockRejectedValueOnce(new Error('gone'));
    const outcome = await saveWithExtras(w.deps, request({ result: result({ removedFiles: ['server-9'] }) }));
    expect(outcome.item.data?.['name']).toBe('GitHub');
  });
});
