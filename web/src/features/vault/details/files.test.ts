import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { ItemFiles } from '@/api/itemFiles';
import { fetchFile, downloadFile, NoServerFileError, saveBytes } from './fileDownload';
import { type AttachedFile, fileOf, filesOf, formatSize } from './files';

// Read from the working directory (web/): under jsdom import.meta.url is not a file: URL.
const dir = resolve(process.cwd(), '..', 'crates', 'kemlock-blob', 'tests', 'fixtures');
const KEY = JSON.parse(readFileSync(resolve(dir, 'kma1.json'), 'utf8')).key as string;
const twoChunks = new Uint8Array(readFileSync(resolve(dir, 'two-chunks.kma1')));

describe('the files an item holds', () => {
  it('reads a File item from `file`, the way the app writes an attachment', () => {
    const file = fileOf({
      file: { id: 'a1', name: 'Lease agreement.pdf', size: 2_400_000, type: 'application/pdf', key: KEY, addedAt: 1, kemlockFile: 'f-1' },
    });
    expect(file).toEqual({
      id: 'a1',
      name: 'Lease agreement.pdf',
      size: 2_400_000,
      type: 'application/pdf',
      key: KEY,
      serverId: 'f-1',
    });
  });

  it('falls back to the first attachment, and reads every attachment of a note', () => {
    const data = {
      attachments: [
        { name: 'a.txt', size: 3, key: KEY, kemlockFile: 'f-1' },
        { name: 'b.txt', size: 4, key: KEY },
        'junk',
        { size: 9 },
      ],
    };
    expect(fileOf(data)?.name).toBe('a.txt');
    expect(filesOf(data).map((f) => f.name)).toEqual(['a.txt', 'b.txt']);
    expect(filesOf(data)[1]?.serverId).toBe('');
    expect(fileOf({})).toBeUndefined();
    expect(filesOf(null)).toEqual([]);
  });

  it('writes sizes in decimal units', () => {
    const size = (bytes: number) => formatSize(bytes, 'en', (unit, value) => `${value} ${unit.toUpperCase()}`);
    expect(size(0)).toBe('0 B');
    expect(size(999)).toBe('999 B');
    expect(size(1500)).toBe('2 KB');
    expect(size(2_400_000)).toBe('2.4 MB');
    expect(size(150_000_000)).toBe('150 MB');
  });

  it('writes the number as the language does and lets the message place the unit', () => {
    const german = (bytes: number) => formatSize(bytes, 'de', (unit, value) => `${value} ${unit === 'mb' ? 'Mio. Byte' : unit}`);
    expect(german(2_400_000)).toBe('2,4 Mio. Byte');
    expect(formatSize(2_400_000, 'en', (unit, value) => `${unit}:${value}`)).toBe('mb:2.4');
  });
});

describe('downloading a file', () => {
  const file: AttachedFile = { id: 'a1', name: 'pattern.bin', size: 65636, type: 'application/octet-stream', key: KEY, serverId: 'f/1' };

  function apiAnswering(bytes: Uint8Array) {
    const download = vi.fn(async () => bytes);
    return { api: { download } as Pick<ItemFiles, 'download'>, download };
  }

  it('fetches the ciphertext of the file and opens it with the file key', async () => {
    const { api, download } = apiAnswering(twoChunks);
    const plain = await fetchFile(api, 'item 1', file);
    expect(download).toHaveBeenCalledWith('item 1', 'f/1');
    expect(plain).toHaveLength(65636);
  });

  it('hands the plaintext to the browser under the file name', async () => {
    const { api } = apiAnswering(twoChunks);
    const save = vi.fn();
    await downloadFile(api, 'i', file, save);
    expect(save).toHaveBeenCalledOnce();
    expect(save.mock.calls[0]?.[0]).toBe('pattern.bin');
    expect(save.mock.calls[0]?.[1]).toBe('application/octet-stream');
    expect(save.mock.calls[0]?.[2]).toHaveLength(65636);
  });

  it('saves nothing when the file does not open', async () => {
    const { api } = apiAnswering(twoChunks.slice(0, 100));
    const save = vi.fn();
    await expect(downloadFile(api, 'i', file, save)).rejects.toThrow();
    expect(save).not.toHaveBeenCalled();
  });

  it('says so when the file was never uploaded', async () => {
    const { api, download } = apiAnswering(twoChunks);
    await expect(fetchFile(api, 'i', { ...file, serverId: '' })).rejects.toBeInstanceOf(NoServerFileError);
    expect(download).not.toHaveBeenCalled();
  });

  it('downloads through an anchor with the name, and lets go of the blob URL', () => {
    const created = vi.fn(() => 'blob:x');
    const revoked = vi.fn();
    // jsdom has no object URLs: stand in for the two calls, and take them away afterwards.
    const urls = URL as unknown as Record<string, unknown>;
    urls['createObjectURL'] = created;
    urls['revokeObjectURL'] = revoked;
    vi.useFakeTimers();
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    try {
      saveBytes('lease.pdf', 'application/pdf', new Uint8Array([1, 2, 3]));
      expect(created).toHaveBeenCalledOnce();
      expect(click).toHaveBeenCalledOnce();
      expect(document.querySelector('a[download]')).toBeNull();
      vi.advanceTimersByTime(10_000);
      expect(revoked).toHaveBeenCalledWith('blob:x');
    } finally {
      vi.useRealTimers();
      click.mockRestore();
      delete urls['createObjectURL'];
      delete urls['revokeObjectURL'];
    }
  });
});
