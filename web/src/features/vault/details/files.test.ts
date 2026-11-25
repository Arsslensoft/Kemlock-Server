import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import type { Api } from '@/api/client';
import { fetchFile, downloadFile, NoServerFileError, saveBytes } from './fileDownload';
import { type AttachedFile, fileOf, filesOf, formatSize, typeLabel } from './files';

const dir = new URL('../../../../../crates/kemlock-blob/tests/fixtures/', import.meta.url);
const KEY = JSON.parse(readFileSync(fileURLToPath(new URL('kma1.json', dir)), 'utf8')).key as string;
const twoChunks = new Uint8Array(readFileSync(fileURLToPath(new URL('two-chunks.kma1', dir))));

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
    expect(formatSize(0)).toBe('0 B');
    expect(formatSize(999)).toBe('999 B');
    expect(formatSize(1500)).toBe('2 KB');
    expect(formatSize(2_400_000)).toBe('2.4 MB');
    expect(formatSize(150_000_000)).toBe('150 MB');
  });

  it('names a type by the extension, or by the media type', () => {
    expect(typeLabel({ name: 'Lease agreement.pdf', type: 'application/pdf' })).toBe('PDF');
    expect(typeLabel({ name: 'photo', type: 'image/png' })).toBe('PNG');
    expect(typeLabel({ name: 'archive.tar.gz', type: '' })).toBe('GZ');
    expect(typeLabel({ name: 'README', type: '' })).toBe('');
  });
});

describe('downloading a file', () => {
  const file: AttachedFile = { id: 'a1', name: 'pattern.bin', size: 65636, type: 'application/octet-stream', key: KEY, serverId: 'f/1' };

  function apiAnswering(bytes: Uint8Array) {
    const raw = vi.fn(async () => new Response(bytes as BodyInit));
    return { api: { raw } as unknown as Pick<Api, 'raw'>, raw };
  }

  it('fetches the ciphertext from the item files route and opens it with the file key', async () => {
    const { api, raw } = apiAnswering(twoChunks);
    const plain = await fetchFile(api, 'item 1', file);
    expect(raw).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/items/item%201/files/f%2F1' });
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
    const { api, raw } = apiAnswering(twoChunks);
    await expect(fetchFile(api, 'i', { ...file, serverId: '' })).rejects.toBeInstanceOf(NoServerFileError);
    expect(raw).not.toHaveBeenCalled();
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
