// A stand-in for the server's item files routes (api/itemFiles.ts): files held per item, an upload
// that must match the length announced and may only start for an item the server knows, and an
// optional refusal on the Nth start, as the attachment quota gives (413 storage-limit-exceeded).
import { ApiError } from '@/api/errors';
import type { ItemFiles } from '@/api/itemFiles';

export interface FakeFiles extends ItemFiles {
  /** item id -> file id -> the sealed bytes held. */
  held: Map<string, Map<string, Uint8Array>>;
  /** What was asked, in order: `start:<item>`, `upload:<item>/<file>`, `remove:<item>/<file>`. */
  calls: string[];
}

export function quotaError(slug = 'storage-limit-exceeded', status = 413): ApiError {
  return new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: 'No room for the file', status });
}

export function fakeFiles(
  options: {
    /** Whether the server holds the item: a file can only start for one that exists. */
    knowsItem?: (itemId: string) => boolean;
    /** The 1-based start that is refused by the quota. */
    refuseStart?: number;
  } = {},
): FakeFiles {
  const held = new Map<string, Map<string, Uint8Array>>();
  const calls: string[] = [];
  const announced = new Map<string, number>();
  let starts = 0;
  const filesOf = (itemId: string) => {
    let files = held.get(itemId);
    if (!files) {
      files = new Map();
      held.set(itemId, files);
    }
    return files;
  };
  return {
    held,
    calls,
    async download(itemId, fileId) {
      const bytes = held.get(itemId)?.get(fileId);
      if (!bytes) throw new ApiError(404, { type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 });
      return bytes;
    },
    async start(itemId, size) {
      calls.push(`start:${itemId}`);
      starts += 1;
      if (options.knowsItem && !options.knowsItem(itemId)) {
        throw new ApiError(404, { type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 });
      }
      if (options.refuseStart === starts) throw quotaError();
      const fileId = `new-file-${starts}`;
      announced.set(`${itemId}/${fileId}`, size);
      return { fileId, itemId, size, maxSize: 1_000_000, uploadUrl: '', presigned: false };
    },
    async upload(itemId, fileId, bytes) {
      calls.push(`upload:${itemId}/${fileId}`);
      if (announced.get(`${itemId}/${fileId}`) !== bytes.length) throw new Error('the upload is not the length announced');
      filesOf(itemId).set(fileId, bytes);
      return { fileId, itemId, size: bytes.length, status: 'ready' };
    },
    async remove(itemId, fileId) {
      calls.push(`remove:${itemId}/${fileId}`);
      held.get(itemId)?.delete(fileId);
    },
  };
}
