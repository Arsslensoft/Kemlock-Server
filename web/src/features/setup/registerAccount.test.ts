import { beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeB64 } from '@/lib/b64url';
import { crypto, fakeCalls, resetFakeCrypto } from '@/test/fake-crypto';
import { NEW_ACCOUNT_KDF, registerAccount } from './registerAccount';

beforeEach(() => resetFakeCrypto());

function setup() {
  const api = {
    registerStart: vi.fn(async () => ({ response: 'cmVzcG9uc2U' })),
    registerFinish: vi.fn(async (body: { userId: string }) => ({ userId: body.userId, admin: true })),
  };
  return {
    api,
    deps: {
      api,
      crypto,
      randomBytes: (n: number) => new Uint8Array(n).fill(7),
      newId: () => '11111111-1111-4111-8111-111111111111',
    },
  };
}

describe('registerAccount', () => {
  it('makes the keys in the browser and stores them in one finish call', async () => {
    const { api, deps } = setup();
    const out = await registerAccount(deps, {
      email: 'sam@example.co',
      name: 'Sam',
      password: 'correct horse battery',
      setupGrant: 'grant-1',
    });
    expect(fakeCalls).toEqual([
      'masterKey',
      'opaqueRegisterStart',
      'opaqueRegisterFinish',
      'newAccount',
    ]);
    expect(api.registerStart).toHaveBeenCalledWith({
      email: 'sam@example.co',
      request: expect.any(String),
      setupGrant: 'grant-1',
    });
    const finish = api.registerFinish.mock.calls[0]?.[0] as unknown as Record<string, unknown>;
    expect(finish).toMatchObject({
      userId: '11111111-1111-4111-8111-111111111111',
      email: 'sam@example.co',
      name: 'Sam',
      setupGrant: 'grant-1',
      kdf: { ...NEW_ACCOUNT_KDF },
    });
    expect(decodeB64((finish['kdf'] as { salt: string }).salt)).toEqual(new Uint8Array(16).fill(7));
    expect(new TextDecoder().decode(decodeB64(finish['wrappedRootKey'] as string))).toBe(
      'wrapped:11111111-1111-4111-8111-111111111111',
    );
    expect(out.admin).toBe(true);
    expect(new TextDecoder().decode(out.wrappedRootKey)).toBe('wrapped:11111111-1111-4111-8111-111111111111');
  });

  it('never sends the password or the master key', async () => {
    const { api, deps } = setup();
    await registerAccount(deps, { email: 'a@b.co', name: 'A', password: 'hunter2hunter2' });
    const sent = JSON.stringify([api.registerStart.mock.calls, api.registerFinish.mock.calls]);
    expect(sent).not.toContain('hunter2hunter2');
  });

  it('uses the account KDF from docs/crypto.md', () => {
    expect(NEW_ACCOUNT_KDF).toEqual({ memoryKib: 65536, iterations: 3, parallelism: 4 });
  });

  it('leaves no master key behind when the server refuses', async () => {
    const { api, deps } = setup();
    api.registerStart.mockRejectedValueOnce(new Error('refused'));
    let key: Uint8Array | undefined;
    const spy = vi.spyOn(crypto, 'masterKey').mockImplementation(async (pw, kdf) => {
      key = new Uint8Array([1, 2, 3]);
      return key ?? new Uint8Array([pw.length, kdf.iterations]);
    });
    await expect(registerAccount(deps, { email: 'a@b.co', name: 'A', password: 'x'.repeat(12) })).rejects.toThrow('refused');
    expect(key).toEqual(new Uint8Array([0, 0, 0]));
    spy.mockRestore();
  });
});
