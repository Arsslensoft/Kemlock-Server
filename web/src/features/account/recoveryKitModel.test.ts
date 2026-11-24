import { beforeEach, describe, expect, it, vi } from 'vitest';
import { utf8 } from '@/lib/b64url';
import { crypto as fake, fakeCalls, resetFakeCrypto } from '@/test/fake-crypto';
import { confirmsPiece, keepKit, makeKit } from './recoveryKitModel';

const ACCOUNT = '11111111-1111-4111-8111-111111111111';

beforeEach(() => resetFakeCrypto());

describe('making a Recovery Kit', () => {
  it('needs an open vault: the key worker will not make a kit from a locked one', async () => {
    await expect(makeKit(fake)).rejects.toThrow();
  });

  it('takes the 3 pieces and the wrap from the key worker, and never a key', async () => {
    await fake.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), utf8('mk'), utf8('ek'));
    const kit = await makeKit(fake);
    expect(fakeCalls).toContain('kitMake');
    expect(kit.pieces).toHaveLength(3);
    expect(kit.kitId).toBe('FAKEKIT2');
    expect(kit.keyVersion).toBe(1);
    expect(typeof kit.wrappedKey).toBe('string');
  });

  it('checks the piece typed back against the ones shown, in any case and spacing', () => {
    const kit = {
      kitId: 'K',
      keyVersion: 1,
      wrappedKey: 'AAAA',
      pieces: ['BMCKIT1-AAAAAAAA-231-AAAA-ABCD', 'BMCKIT1-AAAAAAAA-232-BBBB-ABCD'],
    };
    expect(confirmsPiece(kit, 'bmckit1-aaaaaaaa-232-bbbb-abcd')).toBe(true);
    expect(confirmsPiece(kit, 'BMCKIT1 AAAAAAAA 232')).toBe(false);
    expect(confirmsPiece(kit, '')).toBe(false);
  });

  it('keeps the first kit without a proof and a new one in place of the old with it', async () => {
    const api = { create: vi.fn(async () => ({}) as never), replace: vi.fn(async () => ({}) as never) };
    const kit = { kitId: 'FAKEKIT2', keyVersion: 1, wrappedKey: 'AAAA', pieces: [] };
    const record = { kitId: 'FAKEKIT2', keyVersion: 1, wrappedKey: 'AAAA' };
    await keepKit(api, kit);
    expect(api.create).toHaveBeenCalledWith(record);
    expect(api.replace).not.toHaveBeenCalled();
    await keepKit(api, kit, '123456');
    expect(api.replace).toHaveBeenCalledWith(record, '123456');
  });
});
