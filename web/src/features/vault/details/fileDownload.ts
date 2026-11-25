// Downloads a file an item holds: the `KMA1` bytes from the item files route, opened in the
// browser with the file's own key from the body, then handed to the browser as a download. The
// server only ever sends ciphertext; nothing is kept once the download is handed over.
import type { Api } from '@/api/client';
import type { AttachedFile } from './files';
import { openKma1 } from './kma1';

export class NoServerFileError extends Error {
  constructor() {
    super('the file was never uploaded');
    this.name = 'NoServerFileError';
  }
}

/** The plaintext of `file`, fetched through `api` and opened. */
export async function fetchFile(api: Pick<Api, 'raw'>, itemId: string, file: AttachedFile): Promise<Uint8Array> {
  if (!file.serverId) throw new NoServerFileError();
  const response = await api.raw({
    method: 'GET',
    path: `/kem/v1/items/${encodeURIComponent(itemId)}/files/${encodeURIComponent(file.serverId)}`,
  });
  return openKma1(file.key, new Uint8Array(await response.arrayBuffer()));
}

/** Hands bytes to the browser as a download. */
export function saveBytes(name: string, type: string, bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: type || 'application/octet-stream' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name || 'file';
  anchor.rel = 'noopener';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Fetches, opens and saves one file. */
export async function downloadFile(
  api: Pick<Api, 'raw'>,
  itemId: string,
  file: AttachedFile,
  save: typeof saveBytes = saveBytes,
): Promise<void> {
  save(file.name, file.type, await fetchFile(api, itemId, file));
}
