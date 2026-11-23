import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { CredentialsError, describeError } from '@/lib/errors';
import type { AccountKeysResponse, SignInResponse, TokenResponse } from '@/api/types';
import { createSession } from '@/app/session';
import { encodeB64 } from '@/lib/b64url';
import { crypto, fakeCalls, isFakeLocked, resetFakeCrypto } from '@/test/fake-crypto';
import { type SignInDeps, createSignIn } from './signIn';

const tokens: TokenResponse = {
  tokenType: 'DPoP',
  accessToken: 'access',
  expiresIn: 600,
  refreshToken: 'refresh',
  refreshExpiresIn: 86400,
  userId: 'user-1',
  deviceId: 'device-1',
  admin: false,
};

function setup(finish: SignInResponse) {
  const session = createSession();
  const api = {
    prelogin: vi.fn(async () => ({
      memoryKib: 65536,
      iterations: 3,
      parallelism: 4,
      salt: encodeB64(new Uint8Array(16)),
    })),
    opaqueStart: vi.fn(async () => ({
      response: encodeB64(new TextEncoder().encode('server-response')),
      loginState: 'state-blob',
    })),
    opaqueFinish: vi.fn(async () => finish),
    twoFactor: vi.fn(async () => tokens),
    accountKeys: vi.fn(
      async (): Promise<AccountKeysResponse> => ({
        keyVersion: 1,
        kdf: { memoryKib: 1, iterations: 1, parallelism: 1, salt: encodeB64(new Uint8Array(16)) },
        wrappedRootKey: encodeB64(new TextEncoder().encode('wrapped:user-1')),
        publicBundle: '',
        bundleSignature: '',
        sealedPrivateKeys: '',
      }),
    ),
  };
  const deps: SignInDeps = {
    api,
    crypto,
    session,
    device: () => ({ id: null, name: 'Web', kind: 'kemlock-web' }),
    now: () => 1_000,
  };
  return { api, session, signIn: createSignIn(deps) };
}

beforeEach(() => resetFakeCrypto());

describe('password sign-in', () => {
  it('runs prelogin, OPAQUE, token, key fetch and unlock in order', async () => {
    const { api, session, signIn } = setup({ status: 'signed_in', tokens });
    const result = await signIn.password('sam@example.co', 'correct horse battery');
    expect(result).toEqual({ status: 'signed-in', admin: false });
    expect(fakeCalls.filter((c) => c !== 'dpopProof')).toEqual([
      'masterKey',
      'opaqueLoginStart',
      'opaqueLoginFinish',
      'unlock',
    ]);
    expect(api.opaqueStart).toHaveBeenCalledWith({
      email: 'sam@example.co',
      request: expect.any(String),
    });
    expect(api.opaqueFinish).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'sam@example.co', loginState: 'state-blob' }),
    );
    expect(session.getState()).toMatchObject({ status: 'unlocked', userId: 'user-1', email: 'sam@example.co' });
    expect(session.tokenStore.get()).toMatchObject({ access: 'access', refresh: 'refresh' });
    expect(isFakeLocked()).toBe(false);
  });

  it('opens the private keys with the account keys the server returns', async () => {
    const { api, signIn } = setup({ status: 'signed_in', tokens });
    api.accountKeys.mockResolvedValueOnce({
      wrappedRootKey: encodeB64(new TextEncoder().encode('wrapped:user-1')),
      keyVersion: 2,
      sealedPrivateKeys: encodeB64(new TextEncoder().encode('sealed-keys')),
    } as never);
    const spy = vi.spyOn(crypto, 'unlock');
    await signIn.password('sam@example.co', 'pw');
    expect(spy).toHaveBeenCalledTimes(1);
    const [account, wrapped, , , keys] = spy.mock.calls[0] ?? [];
    expect(account).toBe('user-1');
    expect(Array.from(wrapped ?? [])).toEqual(Array.from(new TextEncoder().encode('wrapped:user-1')));
    // Compared as plain numbers: under jsdom, TextEncoder's Uint8Array and the one decodeB64 makes
    // may come from different realms, and toEqual treats those as different types.
    expect(keys?.keyVersion).toBe(2);
    expect(Array.from(keys?.sealedPrivateKeys ?? [])).toEqual(
      Array.from(new TextEncoder().encode('sealed-keys')),
    );
    spy.mockRestore();
  });

  it('opens the keys a caller has just made without asking the server for them', async () => {
    const { api, signIn } = setup({ status: 'signed_in', tokens });
    const spy = vi.spyOn(crypto, 'unlock');
    const enc = new TextEncoder();
    await signIn.start(
      'sam@example.co',
      enc.encode('master'),
      enc.encode('wrapped:user-1'),
      enc.encode('sealed-keys'),
    );
    expect(api.accountKeys).not.toHaveBeenCalled();
    expect(spy).toHaveBeenCalledWith('user-1', enc.encode('wrapped:user-1'), expect.anything(), expect.anything(), {
      sealedPrivateKeys: enc.encode('sealed-keys'),
    });
    spy.mockRestore();
  });

  it('sends the master password in NFC form', async () => {
    const { signIn } = setup({ status: 'signed_in', tokens });
    const spy = vi.spyOn(crypto, 'masterKey');
    await signIn.password('a@b.co', 'é'); // "e" + combining acute
    expect(spy.mock.calls[0]?.[0]).toBe('é');
    spy.mockRestore();
  });

  it('stops for a second step and finishes with the code', async () => {
    const { api, session, signIn } = setup({
      status: 'two_factor_required',
      challenge: 'chal',
      methods: ['totp'],
    });
    const first = await signIn.password('sam@example.co', 'pw');
    expect(first).toEqual({ status: 'second-step', methods: ['totp'] });
    expect(session.getState().status).toBe('signed-out');
    const second = await signIn.secondStep('123456');
    expect(second.status).toBe('signed-in');
    expect(api.twoFactor).toHaveBeenCalledWith({ challenge: 'chal', method: 'totp', code: '123456' });
    expect(session.getState().status).toBe('unlocked');
  });

  it('lets a wrong code be retried, but not a lost challenge', async () => {
    const { api, signIn } = setup({ status: 'two_factor_required', challenge: 'chal', methods: ['totp'] });
    await signIn.password('sam@example.co', 'pw');
    api.twoFactor.mockRejectedValueOnce(
      new ApiError(401, { type: 'urn:kemlock:problem:unauthorized', title: 'no', status: 401 }),
    );
    await expect(signIn.secondStep('000000')).rejects.toBeInstanceOf(ApiError);
    await expect(signIn.secondStep('123456')).resolves.toMatchObject({ status: 'signed-in' });
    await expect(signIn.secondStep('123456')).rejects.toThrow('no sign-in waiting');
  });

  it('reports a wrong password as wrong credentials, not as a crash', async () => {
    const { signIn, session } = setup({ status: 'signed_in', tokens });
    const spy = vi.spyOn(crypto, 'opaqueLoginFinish').mockRejectedValueOnce(new Error('InvalidLogin'));
    const error = await signIn.password('sam@example.co', 'wrong').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CredentialsError);
    expect(describeError(error).id).toBe('error.credentials');
    expect(session.getState().status).toBe('signed-out');
    spy.mockRestore();
  });

  it('refuses a sign-in the server answers oddly', async () => {
    const { signIn, session } = setup({ status: 'signed_in', tokens: null });
    await expect(signIn.password('a@b.co', 'pw')).rejects.toThrow('unexpected');
    expect(session.getState().status).toBe('signed-out');
  });

  it('ends the session if the vault will not open', async () => {
    const { api, session, signIn } = setup({ status: 'signed_in', tokens });
    api.accountKeys.mockResolvedValueOnce({
      keyVersion: 1,
      kdf: { memoryKib: 1, iterations: 1, parallelism: 1, salt: encodeB64(new Uint8Array(16)) },
      wrappedRootKey: encodeB64(new TextEncoder().encode('garbage')),
      publicBundle: '',
      bundleSignature: '',
      sealedPrivateKeys: '',
    });
    await expect(signIn.password('a@b.co', 'pw')).rejects.toThrow('wrong wrapped key');
    expect(session.getState().status).toBe('signed-out');
    expect(session.tokenStore.get()).toBeUndefined();
  });

  it('uses a known wrapped key instead of asking the server', async () => {
    const { api, signIn } = setup({ status: 'signed_in', tokens });
    const key = await crypto.masterKey('pw', { memoryKib: 1, iterations: 1, parallelism: 1, salt: new Uint8Array(16) });
    await signIn.start('a@b.co', key, new TextEncoder().encode('wrapped:user-1'));
    expect(api.accountKeys).not.toHaveBeenCalled();
    // The master key is overwritten once the vault is open. Compared as plain numbers: the bytes
    // come from a different realm than the test's own Uint8Array under jsdom.
    expect([...key].every((byte) => byte === 0)).toBe(true);
  });
});
