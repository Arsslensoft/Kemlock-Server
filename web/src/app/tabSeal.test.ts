import { describe, expect, it } from 'vitest';
import { crypto as fake, fakeTabKeys } from '@/test/fake-crypto';
import { createTabSealer } from './tabSeal';

const USER = '11111111-1111-4111-8111-111111111111';
const DEVICE = '22222222-2222-4222-8222-222222222222';

describe('sealing for a tab', () => {
  it('opens only for its own tab, account and device, and not at all once the tab key is reset', async () => {
    const sealer = createTabSealer(fake);
    const sealed = await sealer.seal('tab-one-0001', USER, DEVICE, '{"refresh":"r"}');
    expect(sealed).not.toContain('refresh');
    expect(await sealer.open('tab-one-0001', USER, DEVICE, sealed)).toBe('{"refresh":"r"}');
    await expect(sealer.open('tab-one-0001', DEVICE, DEVICE, sealed)).rejects.toThrow();
    fakeTabKeys.add('tab-two-0002');
    await expect(sealer.open('tab-two-0002', USER, DEVICE, sealed)).rejects.toThrow();
    await sealer.reset('tab-one-0001');
    await expect(sealer.open('tab-one-0001', USER, DEVICE, sealed)).rejects.toThrow();
  });
});
