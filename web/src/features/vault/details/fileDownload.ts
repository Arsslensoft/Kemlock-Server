// Downloads a file an item holds: the `KMA1` bytes from the item files route, opened in the
// browser with the file's own key from the body, then handed to the browser as a download. The
// server only ever sends ciphertext; nothing is kept once the download is handed over.
import type { ItemFiles } from '@/api/itemFiles';
import { openKma1 } from '@/lib/kma1';
import type { AttachedFile } from './files';

export class NoServerFileError extends Error {
  constructor() {
    super('the file was never uploaded');
    this.name = 'NoServerFileError';
  }
}

/** The plaintext of `file`: its sealed bytes from the item files route, opened with the file's key. */
export async function fetchFile(
  files: Pick<ItemFiles, 'download'>,
  itemId: string,
  file: AttachedFile,
): Promise<Uint8Array> {
  if (!file.serverId) throw new NoServerFileError();
  return openKma1(file.key, await files.download(itemId, file.serverId));
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
  files: Pick<ItemFiles, 'download'>,
  itemId: string,
  file: AttachedFile,
  save: typeof saveBytes = saveBytes,
): Promise<void> {
  save(file.name, file.type, await fetchFile(files, itemId, file));
}
