import { describe, expect, it } from 'vitest';
import { fakeFiles } from '@/test/fake-files';
import { copyFiles, removeFiles, serverFileIds, withServerFiles, withoutServerFiles } from './fileCopy';

const fileEntry = (over: Record<string, unknown> = {}) => ({
  id: 'a1',
  name: 'lease.pdf',
  size: 3,
  type: 'application/pdf',
  key: 'k1',
  addedAt: 1,
  kemlockFile: 'old-1',
  ...over,
});

describe('which files a body names', () => {
  it('lists the uploaded ones of a File item and of a note, each once', () => {
    expect(serverFileIds({ file: fileEntry() })).toEqual(['old-1']);
    expect(
      serverFileIds({
        attachments: [fileEntry({ kemlockFile: 'old-1' }), fileEntry({ kemlockFile: undefined, name: 'never.txt' }), fileEntry({ kemlockFile: undefined, fileId: 'old-2' }), fileEntry({ kemlockFile: 'old-1' })],
      }),
    ).toEqual(['old-1', 'old-2']);
  });

  it('is empty for a body with no files, a body that could not be read, and entries it cannot read', () => {
    expect(serverFileIds({ name: 'x' })).toEqual([]);
    expect(serverFileIds(null)).toEqual([]);
    expect(serverFileIds({ file: 'junk', attachments: ['junk', null, [1]] })).toEqual([]);
  });
});

describe('rewriting the file ids of a body', () => {
  const body = {
    name: 'Notes',
    attachments: [fileEntry(), fileEntry({ id: 'a2', name: 'never.txt', kemlockFile: undefined })],
    file: fileEntry({ id: 'a3', kemlockFile: undefined, fileId: 'old-2' }),
  };

  it('strips the server ids and keeps every entry with its name, size and key', () => {
    const stripped = withoutServerFiles(body);
    expect(stripped['attachments']).toEqual([
      expect.not.objectContaining({ kemlockFile: expect.anything() }),
      expect.objectContaining({ name: 'never.txt' }),
    ]);
    expect((stripped['attachments'] as Array<Record<string, unknown>>)[0]).toMatchObject({ name: 'lease.pdf', key: 'k1', size: 3 });
    expect(stripped['file']).not.toHaveProperty('fileId');
    expect(serverFileIds(stripped)).toEqual([]);
    // The body it was given is not changed.
    expect(serverFileIds(body)).toEqual(['old-2', 'old-1']);
  });

  it('names the new files, and leaves an entry that was never uploaded without one', () => {
    const next = withServerFiles(body, new Map([['old-1', 'new-1'], ['old-2', 'new-2']]));
    const entries = next['attachments'] as Array<Record<string, unknown>>;
    expect(entries[0]).toMatchObject({ kemlockFile: 'new-1' });
    expect(entries[1]).not.toHaveProperty('kemlockFile');
    expect(next['file']).toMatchObject({ fileId: 'new-2' });
  });

  it('drops an id it has no new one for, so a body never names a file the server lacks', () => {
    const next = withServerFiles(body, new Map([['old-1', 'new-1']]));
    expect(next['file']).not.toHaveProperty('fileId');
  });
});

describe('sending files again', () => {
  function setup() {
    const files = fakeFiles({ knowsItem: (id) => id === 'new-item' });
    files.held.set('old-item', new Map([['old-1', new Uint8Array([1, 2, 3])], ['old-2', new Uint8Array([4, 5])]]));
    return files;
  }
  const body = { attachments: [fileEntry({ kemlockFile: 'old-1' }), fileEntry({ id: 'a2', kemlockFile: 'old-2' })] };

  it('reads each file from the old item and sends its sealed bytes as they are to the new one', async () => {
    const files = setup();
    const copied = await copyFiles(files, 'old-item', 'new-item', body);
    expect(copied.uploaded).toEqual(['new-file-1', 'new-file-2']);
    expect(files.held.get('new-item')?.get('new-file-1')).toEqual(new Uint8Array([1, 2, 3]));
    expect(files.held.get('new-item')?.get('new-file-2')).toEqual(new Uint8Array([4, 5]));
    expect((copied.data['attachments'] as Array<Record<string, unknown>>).map((e) => e['kemlockFile'])).toEqual([
      'new-file-1',
      'new-file-2',
    ]);
  });

  it('removes the files already sent when one is refused, and throws the refusal', async () => {
    const files = fakeFiles({ knowsItem: (id) => id === 'new-item', refuseStart: 2 });
    files.held.set('old-item', new Map([['old-1', new Uint8Array([1])], ['old-2', new Uint8Array([2])]]));
    await expect(copyFiles(files, 'old-item', 'new-item', body)).rejects.toMatchObject({ status: 413, slug: 'storage-limit-exceeded' });
    expect(files.held.get('new-item')?.size ?? 0).toBe(0);
    expect(files.calls).toContain('remove:new-item/new-file-1');
  });

  it('does nothing for a body with no uploaded file', async () => {
    const files = setup();
    const copied = await copyFiles(files, 'old-item', 'new-item', { name: 'x' });
    expect(copied).toEqual({ data: { name: 'x' }, uploaded: [] });
    expect(files.calls).toEqual([]);
  });

  it('removes files and does not mind one already gone', async () => {
    const files = setup();
    await removeFiles({ remove: (item, id) => (id === 'old-1' ? Promise.reject(new Error('gone')) : files.remove(item, id)) }, 'old-item', ['old-1', 'old-2']);
    expect(files.held.get('old-item')?.has('old-2')).toBe(false);
  });
});
