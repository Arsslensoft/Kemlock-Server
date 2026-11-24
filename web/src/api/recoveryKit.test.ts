import { describe, expect, it, vi } from 'vitest';
import { createRecoveryKitApi } from './recoveryKit';
import { ApiError } from './errors';

const kit = {
  kitId: 'ABCDEFGH',
  threshold: 2,
  shares: 3,
  keyVersion: 1,
  createdAt: '2026-11-28T10:00:00Z',
  current: true,
  wrappedKey: 'AAAA',
};

describe('the Recovery Kit API', () => {
  it('reads the kit, and null when the account has none', async () => {
    const request = vi.fn().mockResolvedValueOnce(kit).mockRejectedValueOnce(new ApiError(404, undefined));
    const kits = createRecoveryKitApi({ request, send: vi.fn() } as never);
    expect(await kits.show()).toEqual(kit);
    expect(await kits.show()).toBeNull();
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/account/recovery-kit' });
  });

  it('does not hide other failures as no kit', async () => {
    const request = vi.fn().mockRejectedValue(new ApiError(500, undefined));
    await expect(createRecoveryKitApi({ request, send: vi.fn() } as never).show()).rejects.toThrow();
  });

  it('makes the first kit without a proof and replaces or removes one with it', async () => {
    const request = vi.fn(async () => kit);
    const send = vi.fn(async () => undefined);
    const kits = createRecoveryKitApi({ request, send } as never);
    const record = { kitId: 'ABCDEFGH', keyVersion: 1, wrappedKey: 'AAAA' };
    await kits.create(record);
    expect(request).toHaveBeenLastCalledWith({ method: 'POST', path: '/kem/v1/account/recovery-kit', body: record });
    await kits.replace(record, '123456');
    expect(request).toHaveBeenLastCalledWith({
      method: 'PUT',
      path: '/kem/v1/account/recovery-kit',
      body: { ...record, proof: '123456' },
    });
    await kits.remove('654321');
    expect(send).toHaveBeenLastCalledWith({
      method: 'DELETE',
      path: '/kem/v1/account/recovery-kit',
      body: { proof: '654321' },
    });
    await kits.proofRequest();
    expect(send).toHaveBeenLastCalledWith({ method: 'POST', path: '/kem/v1/account/two-factor/proof' });
  });
});
