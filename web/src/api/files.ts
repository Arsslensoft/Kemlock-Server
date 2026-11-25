// The files of an item (crates/kemlock-api-kem/src/routes/files.rs): `POST /kem/v1/items/{id}/files`
// starts an upload with the exact length of the `KMA1` file, `PUT …/files/{fileId}` sends its
// bytes, `DELETE …/files/{fileId}` removes it. The item must exist on the server first.
//
// The bytes always go to this server's own route, even when the server also offers a pre-signed
// bucket address: the page's content security policy lets it talk to its own origin only, and the
// server takes the bytes of any file whose upload it started.
import type { Api } from './client';

/** `POST /kem/v1/items/{id}/files` answers this (201). */
export interface StartFileResponse {
  fileId: string;
  itemId: string;
  size: number;
  /** The most bytes this server takes for one file. */
  maxSize: number;
  uploadUrl: string;
  presigned: boolean;
  expiresIn?: number | null;
}

export interface FileDto {
  fileId: string;
  itemId: string;
  size: number;
  status: 'pending' | 'ready';
}

export interface FilesApi {
  /** Starts the upload of a file whose `KMA1` form is `size` bytes long. */
  start(itemId: string, size: number): Promise<StartFileResponse>;
  /** Sends the `KMA1` bytes, whose length must be the size announced. */
  upload(itemId: string, fileId: string, bytes: Uint8Array): Promise<FileDto>;
  /** Removes the file's bytes and row. */
  remove(itemId: string, fileId: string): Promise<void>;
}

export function createFilesApi(api: Pick<Api, 'request' | 'send'>): FilesApi {
  const base = (itemId: string) => `/kem/v1/items/${encodeURIComponent(itemId)}/files`;
  const one = (itemId: string, fileId: string) => `${base(itemId)}/${encodeURIComponent(fileId)}`;
  return {
    start: (itemId, size) =>
      api.request<StartFileResponse>({ method: 'POST', path: base(itemId), body: { size } }),
    upload: (itemId, fileId, bytes) =>
      api.request<FileDto>({
        method: 'PUT',
        path: one(itemId, fileId),
        body: bytes,
        headers: { 'Content-Type': 'application/octet-stream' },
      }),
    remove: (itemId, fileId) => api.send({ method: 'DELETE', path: one(itemId, fileId) }),
  };
}
