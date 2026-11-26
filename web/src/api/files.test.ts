import { describe, expect, it, vi } from 'vitest';
import { createFilesApi } from './files';

describe('the files client', () => {
  it('starts an upload with the announced size, sends the bytes to the server\'s own route and deletes', async () => {
    const request = vi.fn(async () => ({}));
    const send = vi.fn(async () => undefined);
    const files = createFilesApi({ request, send } as never);
    const bytes = new Uint8Array([1, 2, 3]);
    await files.start('i-1', 3);
    await files.upload('i-1', 'f/2', bytes);
    await files.remove('i-1', 'f/2');
    expect(request).toHaveBeenNthCalledWith(1, { method: 'POST', path: '/kem/v1/items/i-1/files', body: { size: 3 } });
    expect(request).toHaveBeenNthCalledWith(2, {
      method: 'PUT',
      path: '/kem/v1/items/i-1/files/f%2F2',
      body: bytes,
      headers: { 'Content-Type': 'application/octet-stream' },
    });
    expect(send).toHaveBeenCalledWith({ method: 'DELETE', path: '/kem/v1/items/i-1/files/f%2F2' });
  });
});
