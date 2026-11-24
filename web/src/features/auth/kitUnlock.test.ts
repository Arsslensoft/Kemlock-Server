import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createSession } from '@/app/session';
import { encodeB64, utf8 } from '@/lib/b64url';
import { crypto as fake, fakeCalls, resetFakeCrypto } from '@/test/fake-crypto';
import { checkPieces, newestOnly, unlockWithKit } from './kitUnlock';

const USER = '11111111-1111-4111-8111-111111111111';
const piece = (n: number, id = 'FAKEKIT2', check = 'ABCD') => `BMCKIT1-${id}-23${n}-${'A'.repeat(52)}-${check}`;

beforeEach(() => resetFakeCrypto());

function setup(kit: object | null) {
  const session = createSession();
  session.signedIn({ email: 'sam@example.co', userId: USER, deviceId: 'dev', admin: false });
  const deps = {
    kit: { show: vi.fn(async () => kit as never) },
    api: { accountKeys: vi.fn(async () => ({ keyVersion: 1, sealedPrivateKeys: 'c2s' })) } as never,
    crypto: fake,
    session,
  };
  return { deps, session };
}

const KIT = {
  kitId: 'FAKEKIT2',
  keyVersion: 1,
  current: true,
  wrappedKey: encodeB64(utf8(JSON.stringify(['kit', 'FAKEKIT2']))),
};

describe('checkPieces', () => {
  it('reads each piece and says a typo, from its checksum, at once', async () => {
    const { each, together } = await checkPieces(fake, [piece(1), piece(2, 'FAKEKIT2', 'ZZZZ'), '']);
    expect(each.map((c) => c.status)).toEqual(['ok', 'bad', 'empty']);
    expect(each[1]).toEqual({ status: 'bad', problem: 'checksum' });
    expect(together).toBeUndefined();
  });

  it('says text that is not a piece is not one', async () => {
    const { each } = await checkPieces(fake, ['hello world']);
    expect(each[0]).toEqual({ status: 'bad', problem: 'format' });
  });

  it('refuses pieces of two kits and the same piece twice', async () => {
    expect((await checkPieces(fake, [piece(1), piece(2, 'OTHERKIT')])).together).toBe('other-kit');
    expect((await checkPieces(fake, [piece(1), piece(1)])).together).toBe('duplicate');
    expect((await checkPieces(fake, [piece(1), piece(2)])).together).toBeUndefined();
  });
});

describe('unlockWithKit', () => {
  it('opens the vault with 2 pieces and the server wrap, with no master password', async () => {
    const { deps, session } = setup(KIT);
    const result = await unlockWithKit(deps, USER, [piece(1), piece(3)]);
    expect(result).toEqual({ status: 'unlocked' });
    expect(fakeCalls).toEqual(expect.arrayContaining(['kitOpenRoot', 'unlockWithRoot']));
    expect(session.getState().status).toBe('unlocked');
  });

  it('says so when the account has no kit, or its kit is for an older key', async () => {
    expect(await unlockWithKit(setup(null).deps, USER, [piece(1), piece(2)])).toEqual({ status: 'no-kit' });
    const stale = setup({ ...KIT, current: false });
    expect(await unlockWithKit(stale.deps, USER, [piece(1), piece(2)])).toEqual({ status: 'stale' });
    expect(fakeCalls).not.toContain('kitOpenRoot');
  });

  it('stays shut when the pieces do not open the kit', async () => {
    const { deps, session } = setup({ ...KIT, kitId: 'ANOTHER2' });
    const result = await unlockWithKit(deps, USER, [piece(1), piece(2)]);
    expect(result).toEqual({ status: 'wrong' });
    expect(fakeCalls).not.toContain('unlockWithRoot');
    expect(session.getState().status).not.toBe('unlocked');
  });
});

describe('newestOnly', () => {
  it('drops the answer of a check that a newer one overtook', async () => {
    const run = newestOnly();
    let release: (value: string) => void = () => undefined;
    const slow = run(() => new Promise<string>((resolve) => (release = resolve)));
    const fast = run(async () => 'new');
    expect(await fast).toBe('new');
    release('old');
    expect(await slow).toBeUndefined();
  });

  it('keeps the answer when nothing newer started', async () => {
    const run = newestOnly();
    expect(await run(async () => 'only')).toBe('only');
    expect(await run(async () => 'next')).toBe('next');
  });
});
