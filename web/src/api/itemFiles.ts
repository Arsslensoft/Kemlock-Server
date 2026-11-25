// The files of an item as the item page uses them: start, upload and remove (api/files.ts), and the
// sealed bytes read back. `download` returns the `KMA1` file exactly as the server holds it, which
// is what a move or a copy sends again under another item: the file's chunks are not bound to the
// item (docs/crypto.md, "Files"), so they open with the same key wherever they sit.
import type { Api } from './client';
import { type FilesApi, createFilesApi } from './files';

export interface ItemFiles extends FilesApi {
  /** `GET /kem/v1/items/{id}/files/{fileId}`: the `KMA1` bytes, still sealed. */
  download(itemId: string, fileId: string): Promise<Uint8Array>;
}

export function createItemFilesApi(api: Pick<Api, 'request' | 'send' | 'raw'>): ItemFiles {
  return {
    ...createFilesApi(api),
    download: async (itemId, fileId) => {
      const response = await api.raw({
        method: 'GET',
        path: `/kem/v1/items/${encodeURIComponent(itemId)}/files/${encodeURIComponent(fileId)}`,
      });
      return new Uint8Array(await response.arrayBuffer());
    },
  };
}
