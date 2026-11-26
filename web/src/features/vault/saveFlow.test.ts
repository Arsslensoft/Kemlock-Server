import { describe, expect, it, vi } from 'vitest';
import { fileKeyText, kma1Length } from '@/lib/kma1';
import { type AttachmentEntry, copiedEntries, entryBody, readAttachments, storedEntries } from './attachments';
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
  let calls = 0;
  const failOn = new Set<string>();
  const failCall = new Set<number>();
  const save = vi.fn(async (input: SaveInput): Promise<VaultItem> => {
    inputs.push(input);
    calls += 1;
    if (failCall.has(calls)) throw new Error('refused');
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
  let sentFiles = 0;
  const files = {
    start: vi.fn(async (itemId: string, size: number) => {
      sentFiles += 1;
      return {
        fileId: `file-${sentFiles}`,
        itemId,
        size,
        maxSize: 1_000_000,
        uploadUrl: '',
        presigned: false,
      };
    }),
    upload: vi.fn(async (itemId: string, fileId: string) => ({ fileId, itemId, size: 0, status: 'ready' as const })),
    remove: vi.fn(async () => undefined),
  };
  const removeItem = vi.fn(async (gone: VaultItem) => {
    items.delete(gone.id);
  });
  const read = vi.fn(async () => new TextEncoder().encode('abc'));
  return {
    items,
    inputs,
    failOn,
    failCall,
    save,
    files,
    removeItem,
    read,
    deps: { save, lookup: (id: string) => items.get(id), files, removeItem, read },
  };
}

function result(over: Partial<FormResult> = {}): FormResult {
  return {
    fields: { name: 'GitHub' },
    entry: false,
    links: [],
    files: [],
    uploads: [],
    withUploaded: () => ({}),
    rollbackOnFailure: false,
    ...over,
  };
}

const request = (over: {
  result: FormResult;
  existing?: VaultItem;
  linksBefore?: string[];
  filesBefore?: string[];
  uploaded?: AttachmentEntry[];
}) => ({
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

  it('clears linkedLoginId on a code whose login is unlinked', async () => {
    const mine = item(A, 'login', { name: 'GitHub' });
    const code = item(B, 'otp', { issuer: 'GitHub', linkedLoginId: A });
    const w = world([mine, code]);
    await saveWithExtras(w.deps, request({ result: result(), existing: mine, linksBefore: [B] }));
    expect('linkedLoginId' in (w.items.get(B)?.data ?? {})).toBe(false);
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
  const chosen = (id = 'attachment-1', name = 'notes.txt'): AttachmentEntry => ({
    id,
    name,
    size: 3,
    type: 'text/plain',
    key,
    addedAt: 5,
    file: new Blob(['abc']),
  });

  /** A note's result: the entries are the form's, in order, and the sent ones come back named. */
  function note(entries: AttachmentEntry[], over: Partial<FormResult> = {}): FormResult {
    const body = (list: AttachmentEntry[]) => list.filter((e) => e.file === undefined).map(entryBody);
    return result({
      fields: { name: 'Plan', attachments: undefined },
      files: entries,
      uploads: entries.filter((entry) => entry.file !== undefined),
      withUploaded: (uploaded) => {
        const sent = new Map(uploaded.map((entry) => [entry.id, entry]));
        const list = body(entries.map((entry) => sent.get(entry.id) ?? entry));
        return { attachments: list.length > 0 ? list : undefined };
      },
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
    const entry = chosen();
    const outcome = await saveWithExtras(
      w.deps,
      request({
        result: result({
          fields: { name: 'Lease' },
          files: [entry],
          uploads: [entry],
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
    expect((failure as UploadError).uploaded).toEqual([]);
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
      request({ result: result({ fields: { name: 'Plan', attachments: undefined } }), existing, filesBefore: ['server-9'] }),
    );
    expect(w.files.remove).toHaveBeenCalledWith(A, 'server-9');
    const order = [w.save.mock.invocationCallOrder[0] ?? 0, w.files.remove.mock.invocationCallOrder[0] ?? 0];
    expect(order[0]).toBeLessThan(order[1] ?? 0);
  });

  it('keeps a file the form still holds, even one the item named when it opened', async () => {
    const kept: AttachmentEntry = { id: 'old', name: 'old.txt', size: 1, key, addedAt: 1, kemlockFile: 'server-9' };
    const existing = item(A, 'note', { name: 'Plan' });
    const w = world([existing]);
    await saveWithExtras(
      w.deps,
      request({ result: result({ files: [kept] }), existing, filesBefore: ['server-9', 'server-8'] }),
    );
    expect(w.files.remove).toHaveBeenCalledOnce();
    expect(w.files.remove).toHaveBeenCalledWith(A, 'server-8');
  });

  it('carries on when a file to delete cannot be', async () => {
    const w = world();
    w.files.remove.mockRejectedValueOnce(new Error('gone'));
    const outcome = await saveWithExtras(w.deps, request({ result: result(), filesBefore: ['server-9'] }));
    expect(outcome.item.data?.['name']).toBe('GitHub');
  });

  describe('when the second of two files cannot be sent', () => {
    it('names the file that went up in the item, and carries it, so a retry sends only the other', async () => {
      const w = world();
      w.files.start.mockImplementationOnce(async (itemId: string, size: number) => ({
        fileId: 'file-first',
        itemId,
        size,
        maxSize: 1,
        uploadUrl: '',
        presigned: false,
      }));
      w.files.start.mockRejectedValueOnce(new Error('too large'));
      const entries = [chosen('first', 'first.txt'), chosen('second', 'second.txt')];
      const failure = (await saveWithExtras(w.deps, request({ result: note(entries) })).catch((e: unknown) => e)) as UploadError;
      expect(failure).toBeInstanceOf(UploadError);
      // Saved twice: the item, then the item naming the first file.
      expect(w.save).toHaveBeenCalledTimes(2);
      const named = failure.saved?.data?.['attachments'] as Array<Record<string, unknown>>;
      expect(named.map((entry) => entry['id'])).toEqual(['first']);
      expect(named[0]?.['kemlockFile']).toBe('file-first');
      expect(failure.uploaded.map((entry) => entry.id)).toEqual(['first']);
      expect(w.files.remove).not.toHaveBeenCalled();

      // The retry is given what the error carried: it updates that item and sends the other file.
      w.files.start.mockClear();
      const outcome = await saveWithExtras(
        w.deps,
        request({ result: note(entries), existing: failure.saved, uploaded: failure.uploaded }),
      );
      expect(w.files.start).toHaveBeenCalledOnce();
      const finished = outcome.item.data?.['attachments'] as Array<Record<string, unknown>>;
      expect(finished.map((entry) => entry['id'])).toEqual(['first', 'second']);
      expect(finished[0]?.['kemlockFile']).toBe('file-first');
      expect(outcome.item.id).toBe(failure.saved?.id);
    });

    it('takes the file back off the server when the item cannot name it', async () => {
      const w = world();
      w.files.start.mockImplementationOnce(async (itemId: string, size: number) => ({
        fileId: 'file-first',
        itemId,
        size,
        maxSize: 1,
        uploadUrl: '',
        presigned: false,
      }));
      w.files.start.mockRejectedValueOnce(new Error('too large'));
      w.failCall.add(2);
      const entries = [chosen('first', 'first.txt'), chosen('second', 'second.txt')];
      const failure = (await saveWithExtras(w.deps, request({ result: note(entries) })).catch((e: unknown) => e)) as UploadError;
      expect(failure.uploaded).toEqual([]);
      expect(w.files.remove).toHaveBeenCalledWith(failure.saved?.id, 'file-first');
    });

    it('takes every file back and does not keep a new item that is nothing without them', async () => {
      const w = world();
      w.files.start.mockImplementationOnce(async (itemId: string, size: number) => ({
        fileId: 'file-first',
        itemId,
        size,
        maxSize: 1,
        uploadUrl: '',
        presigned: false,
      }));
      w.files.start.mockRejectedValueOnce(new Error('too large'));
      const entries = [chosen('first', 'first.txt'), chosen('second', 'second.txt')];
      const failure = (await saveWithExtras(w.deps, request({ result: note(entries, { rollbackOnFailure: true }) })).catch(
        (e: unknown) => e,
      )) as UploadError;
      expect(failure.saved).toBeUndefined();
      expect(w.files.remove).toHaveBeenCalledWith(expect.any(String), 'file-first');
      expect(w.removeItem).toHaveBeenCalledOnce();
    });
  });

  describe('a retry', () => {
    const named = (id: string, serverId: string) => ({
      id,
      name: `${id}.txt`,
      size: 3,
      key,
      addedAt: 5,
      sha256: 'ab'.repeat(32),
      kemlockFile: serverId,
    });

    it('does not send a file the saved body already names, matched by its attachment id', async () => {
      const existing = item(A, 'note', { name: 'Plan', attachments: [named('first', 'file-9')] });
      const w = world([existing]);
      const outcome = await saveWithExtras(
        w.deps,
        request({ result: note([chosen('first'), chosen('second')]), existing }),
      );
      expect(w.files.start).toHaveBeenCalledOnce();
      // The first save already names the file that was up, so a failure after it loses nothing.
      expect((w.inputs[0]?.fields['attachments'] as Array<Record<string, unknown>>).map((entry) => entry['id'])).toEqual(['first']);
      const finished = outcome.item.data?.['attachments'] as Array<Record<string, unknown>>;
      expect(finished.map((entry) => entry['id'])).toEqual(['first', 'second']);
      expect(finished[0]).toEqual(named('first', 'file-9'));
    });

    it('sends nothing, and saves once, when every file is on the server already', async () => {
      const existing = item(A, 'note', { name: 'Plan', attachments: [named('first', 'file-9')] });
      const w = world([existing]);
      await saveWithExtras(w.deps, request({ result: note([chosen('first')]), existing }));
      expect(w.files.start).not.toHaveBeenCalled();
      expect(w.save).toHaveBeenCalledOnce();
    });

    it('does not send a file an earlier try carried', async () => {
      const existing = item(A, 'note', { name: 'Plan' });
      const w = world([existing]);
      const sent = { ...named('first', 'file-9') } as AttachmentEntry;
      const outcome = await saveWithExtras(
        w.deps,
        request({ result: note([chosen('first')]), existing, uploaded: [sent] }),
      );
      expect(w.files.start).not.toHaveBeenCalled();
      expect((outcome.item.data?.['attachments'] as Array<Record<string, unknown>>)[0]?.['kemlockFile']).toBe('file-9');
    });
  });

  describe('when the second save fails', () => {
    it('carries the item and the files that went up, so the next Save updates the item and sends nothing', async () => {
      const w = world();
      w.failCall.add(2);
      const entries = [chosen('first')];
      const failure = (await saveWithExtras(w.deps, request({ result: note(entries) })).catch((e: unknown) => e)) as UploadError;
      expect(failure).toBeInstanceOf(UploadError);
      expect(failure.saved?.data?.['name']).toBe('Plan');
      expect(failure.uploaded.map((entry) => entry.id)).toEqual(['first']);
      expect(failure.uploaded[0]?.kemlockFile).toMatch(/^file-/);
      expect(w.files.remove).not.toHaveBeenCalled();

      w.files.start.mockClear();
      w.inputs.length = 0;
      const outcome = await saveWithExtras(
        w.deps,
        request({ result: note(entries), existing: failure.saved, uploaded: failure.uploaded }),
      );
      // It updates the item that was saved, rather than making another, and sends no file again.
      expect(w.inputs[0]?.existing?.id).toBe(failure.saved?.id);
      expect(w.files.start).not.toHaveBeenCalled();
      expect(outcome.item.id).toBe(failure.saved?.id);
      expect((outcome.item.data?.['attachments'] as unknown[]).length).toBe(1);
    });

    it('does not keep a new item that is nothing without its file', async () => {
      const w = world();
      w.failCall.add(2);
      const entry = chosen();
      const failure = (await saveWithExtras(
        w.deps,
        request({
          result: result({
            fields: { name: 'Lease' },
            files: [entry],
            uploads: [entry],
            withUploaded: (uploaded) => ({ file: entryBody(uploaded[0] as AttachmentEntry) }),
            rollbackOnFailure: true,
          }),
        }),
      ).catch((e: unknown) => e)) as UploadError;
      expect(failure.saved).toBeUndefined();
      expect(w.removeItem).toHaveBeenCalledOnce();
      expect(w.files.remove).toHaveBeenCalledOnce();
    });
  });
});

describe("a copy of a note sends the original's files again", () => {
  const key = fileKeyText(new Uint8Array(32).fill(3));
  const SOURCE = 'source-item';
  const sha256 = 'ab'.repeat(32);
  const stored = {
    id: 'a1',
    name: 'map.png',
    size: 3,
    key,
    addedAt: 5,
    sha256,
    kemlockFile: 'old-1',
    vendor: 'kept',
  };
  // What the copy's form holds: the original's entry, waiting to have its file sent again.
  const waiting = (): AttachmentEntry[] => copiedEntries(readAttachments({ attachments: [stored] }), SOURCE);

  function note(entries: AttachmentEntry[]): FormResult {
    return result({
      fields: { name: 'Plan', attachments: undefined },
      files: entries,
      uploads: entries.filter((entry) => entry.file !== undefined || entry.copyOf !== undefined),
      withUploaded: (uploaded) => {
        const sent = new Map(uploaded.map((entry) => [entry.id, entry]));
        const list = storedEntries(entries.map((entry) => sent.get(entry.id) ?? entry)).map(entryBody);
        return { attachments: list.length > 0 ? list : undefined };
      },
    });
  }

  it('waits to name any file: the entry names none until its bytes are under the copy', () => {
    const [entry] = waiting();
    expect(entry).toMatchObject({ id: 'a1', name: 'map.png', sha256, copyOf: { itemId: SOURCE, fileId: 'old-1' } });
    expect(entry?.kemlockFile).toBeUndefined();
    expect(storedEntries(waiting())).toEqual([]);
  });

  it('saves the copy, sends the sealed bytes as they are and saves it again naming the new file', async () => {
    const w = world();
    const download = vi.fn(async () => new Uint8Array([9, 9, 9]));
    const outcome = await saveWithExtras({ ...w.deps, files: { ...w.files, download } }, request({ result: note(waiting()) }));
    expect(w.save).toHaveBeenCalledTimes(2);
    // The first save names no file.
    expect(w.inputs[0]?.fields['attachments']).toBeUndefined();
    expect(download).toHaveBeenCalledWith(SOURCE, 'old-1');
    // The bytes are sent as the server holds them: nothing is read from a file or sealed again.
    expect(w.files.start).toHaveBeenCalledWith(outcome.item.id, 3);
    expect(w.files.upload).toHaveBeenCalledWith(outcome.item.id, 'file-1', new Uint8Array([9, 9, 9]));
    expect(w.read).not.toHaveBeenCalled();
    const [entry] = outcome.item.data?.['attachments'] as Array<Record<string, unknown>>;
    expect(entry).toMatchObject({ id: 'a1', name: 'map.png', key, sha256, vendor: 'kept', kemlockFile: 'file-1' });
    expect(entry).not.toHaveProperty('copyOf');
    // The original keeps its file.
    expect(w.files.remove).not.toHaveBeenCalled();
  });

  it('keeps the copy and carries nothing when the original cannot be read, so Save tries again', async () => {
    const w = world();
    const failure = (await saveWithExtras(w.deps, request({ result: note(waiting()) })).catch((e: unknown) => e)) as UploadError;
    expect(failure).toBeInstanceOf(UploadError);
    expect(failure.saved).toBeDefined();
    expect(failure.uploaded).toEqual([]);
    expect(w.files.start).not.toHaveBeenCalled();
  });

  it('takes back the upload it started when the bytes could not be sent', async () => {
    const w = world();
    w.files.upload.mockRejectedValueOnce(new Error('cut off'));
    const download = vi.fn(async () => new Uint8Array([1]));
    const failure = (await saveWithExtras({ ...w.deps, files: { ...w.files, download } }, request({ result: note(waiting()) })).catch(
      (e: unknown) => e,
    )) as UploadError;
    expect(failure).toBeInstanceOf(UploadError);
    expect(w.files.remove).toHaveBeenCalledWith(failure.saved?.id, 'file-1');
    expect(w.save).toHaveBeenCalledOnce();
  });

  it('does not send a file again on a retry that finds it on the copy already', async () => {
    const w = world();
    const download = vi.fn(async () => new Uint8Array([1]));
    const first = await saveWithExtras({ ...w.deps, files: { ...w.files, download } }, request({ result: note(waiting()) }));
    w.files.start.mockClear();
    download.mockClear();
    await saveWithExtras(
      { ...w.deps, files: { ...w.files, download } },
      request({ result: note(waiting()), existing: first.item, filesBefore: [] }),
    );
    expect(download).not.toHaveBeenCalled();
    expect(w.files.start).not.toHaveBeenCalled();
  });
});
