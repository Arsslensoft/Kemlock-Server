import { describe, expect, it, vi } from 'vitest';
import { createItemFilesApi } from './itemFiles';

function client() {
  const raw = vi.fn(async () => new Response(new Uint8Array([1, 2, 3]) as BodyInit));
  const request = vi.fn(async () => ({ fileId: 'f1' }));
  const send = vi.fn(async () => undefined);
  return { raw, request, send, files: createItemFilesApi({ raw, request, send } as never) };
}

describe('the files of an item', () => {
  it('reads the sealed bytes back from the item files route', async () => {
    const { files, raw } = client();
    expect(await files.download('item 1', 'f/1')).toEqual(new Uint8Array([1, 2, 3]));
    expect(raw).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/items/item%201/files/f%2F1' });
  });

  it('starts, uploads and removes through the same routes the forms use', async () => {
    const { files, request, send } = client();
    await files.start('i1', 28);
    expect(request).toHaveBeenCalledWith({ method: 'POST', path: '/kem/v1/items/i1/files', body: { size: 28 } });
    await files.upload('i1', 'f1', new Uint8Array([9]));
    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'PUT', path: '/kem/v1/items/i1/files/f1', body: new Uint8Array([9]) }),
    );
    await files.remove('i1', 'f1');
    expect(send).toHaveBeenCalledWith({ method: 'DELETE', path: '/kem/v1/items/i1/files/f1' });
  });
});
