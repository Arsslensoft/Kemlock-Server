import { describe, expect, it, vi } from 'vitest';
import { ApiError } from './errors';
import { createManifestsApi, currentCounter } from './manifests';

const DTO = {
  owner: 'user:99999999-9999-4999-8999-999999999999',
  counter: 3,
  manifest: 'bWFuaWZlc3Q',
  signature: 'c2ln',
  signer: '99999999-9999-4999-8999-999999999999',
  storedAt: '2026-11-26T10:00:00Z',
};

describe('the manifests client', () => {
  it('reads an owner’s manifest, and takes a 404 for none', async () => {
    const request = vi.fn(async () => DTO);
    const api = createManifestsApi({ request } as never);
    expect(await api.get(DTO.owner)).toEqual(DTO);
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: `/kem/v1/manifests/${DTO.owner}` });

    request.mockRejectedValueOnce(new ApiError(404, { type: 'urn:kemlock:problem:not-found', title: 'x', status: 404 }));
    expect(await api.get(DTO.owner)).toBeNull();

    // Anything else is a failure to read, not "none".
    request.mockRejectedValueOnce(new ApiError(500, undefined));
    await expect(api.get(DTO.owner)).rejects.toBeInstanceOf(ApiError);
    request.mockRejectedValueOnce(new Error('offline'));
    await expect(api.get(DTO.owner)).rejects.toThrow('offline');
  });

  it('stores a manifest with the signed bytes and the signature as they are', async () => {
    const request = vi.fn(async () => DTO);
    const api = createManifestsApi({ request } as never);
    await api.put(DTO.owner, { manifest: 'bWFuaWZlc3Q', signature: 'c2ln' });
    expect(request).toHaveBeenCalledWith({
      method: 'PUT',
      path: `/kem/v1/manifests/${DTO.owner}`,
      body: { manifest: 'bWFuaWZlc3Q', signature: 'c2ln' },
    });
  });

  it('reads the counter a 409 says the server holds', () => {
    const stale = new ApiError(409, {
      type: 'urn:kemlock:problem:stale-manifest',
      title: 'stale',
      status: 409,
      currentCounter: 8,
    });
    expect(currentCounter(stale)).toBe(8);
    expect(currentCounter(new ApiError(409, undefined))).toBeUndefined();
    expect(currentCounter(new Error('x'))).toBeUndefined();
  });
});
