import { describe, expect, it, vi } from 'vitest';
import { NO_POLICIES, createPoliciesApi } from './policies';

describe('the policies client', () => {
  it('reads and replaces a space\'s policies, and reads what binds the caller', async () => {
    const request = vi.fn(async () => ({ policies: NO_POLICIES }));
    const api = createPoliciesApi({ request } as never);
    await api.forSpace('s1');
    await api.setForSpace('s1', { ...NO_POLICIES, disableSend: true, sessionTimeoutMinutes: 30, sessionTimeoutAction: 'logOut' });
    await api.mine();
    expect(request).toHaveBeenNthCalledWith(1, { method: 'GET', path: '/kem/v1/spaces/s1/policies' });
    expect(request).toHaveBeenNthCalledWith(2, {
      method: 'PUT',
      path: '/kem/v1/spaces/s1/policies',
      body: expect.objectContaining({ disableSend: true, sessionTimeoutMinutes: 30, sessionTimeoutAction: 'logOut', requireSso: false }),
    });
    expect(request).toHaveBeenNthCalledWith(3, { method: 'GET', path: '/kem/v1/policies' });
  });

  it('starts with every policy off', () => {
    expect(Object.values(NO_POLICIES).filter((value) => value === true)).toEqual([]);
  });
});
