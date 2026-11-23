import { describe, expect, it, vi } from 'vitest';
import { ApiError } from './errors';
import { PLACEMENT } from '@/test/placement-fixture';
import { createPlacementApi, offlineHomes } from './placement';

describe('createPlacementApi', () => {
  it('reads the placement', async () => {
    const request = vi.fn().mockResolvedValue(PLACEMENT);
    const api = createPlacementApi({ request, send: vi.fn() });
    expect(await api.placement()).toEqual(PLACEMENT);
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/placement' });
  });

  it('treats a 404 as a single server', async () => {
    const request = vi.fn().mockRejectedValue(new ApiError(404, undefined));
    expect(await createPlacementApi({ request, send: vi.fn() }).placement()).toBeNull();
  });

  it('passes other failures on', async () => {
    const request = vi.fn().mockRejectedValue(new ApiError(500, undefined));
    await expect(createPlacementApi({ request, send: vi.fn() }).placement()).rejects.toBeInstanceOf(ApiError);
  });

  it('cancels a waiting change', async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    await createPlacementApi({ request: vi.fn(), send }).cancelPending('me', 'c 1');
    expect(send).toHaveBeenCalledWith({ method: 'DELETE', path: '/kem/v1/placement/me/pending/c%201' });
  });
});

describe('offlineHomes', () => {
  it('finds the vaults whose home is down, with the replica in use', () => {
    const down = offlineHomes(PLACEMENT);
    expect(down).toHaveLength(1);
    expect(down[0]?.vault.id).toBe('me');
    expect(down[0]?.home.name).toBe('Home server');
    expect(down[0]?.replica?.name).toBe('VPS');
  });

  it('finds nothing when every home is up, or there is no placement', () => {
    expect(offlineHomes(null)).toEqual([]);
    expect(offlineHomes(undefined)).toEqual([]);
    expect(offlineHomes({ ...PLACEMENT, vaults: PLACEMENT.vaults.slice(1) })).toEqual([]);
  });
});
