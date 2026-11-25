// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { createSession } from '@/app/session';
import { PasskeyError } from '@/lib/passkey';
import { SSO_RETURN_PATH, beginSso, completeSso, secondSsoKeyStep, secondSsoStep } from './ssoFlow';

const TOKENS = {
  tokenType: 'DPoP' as const,
  accessToken: 'a',
  expiresIn: 60,
  refreshToken: 'r',
  refreshExpiresIn: 600,
  userId: '11111111-1111-4111-8111-111111111111',
  deviceId: '22222222-2222-4222-8222-222222222222',
  admin: false,
};

interface Started {
  state: string;
  challenge: string;
  redirect: string;
}

function memory() {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  };
}

function setup(finish: Record<string, unknown>) {
  const session = createSession();
  const sso = {
    start: vi.fn(async (_body: Started) => ({
      authorizationUrl: 'http://idp/auth?x=1',
      providerName: 'Keycloak',
    })),
    finish: vi.fn(async (_body: { code: string; verifier: string }) => ({
      status: 'signed_in',
      tokens: TOKENS,
      challenge: null,
      methods: null,
      newAccount: false,
      mfaViaSso: false,
      ...finish,
    })),
  };
  const api = { twoFactor: vi.fn(async () => TOKENS) };
  const securityKey = {
    options: vi.fn(async (_challenge: string) => ({ challenge: 'key-challenge' }) as Record<string, unknown>),
    verify: vi.fn(async (_body: { challenge: string; credential: Record<string, unknown> }) => TOKENS),
  };
  const assert = vi.fn(async (_options: Record<string, unknown>) => ({ id: 'cred' }) as Record<string, unknown>);
  const deps = {
    sso: sso as never,
    api,
    securityKey,
    assert,
    session,
    device: () => ({ id: null, name: 'Web vault', kind: 'kemlock-web' as const }),
    origin: 'https://vault.example.org',
    storage: memory(),
  };
  return { deps, sso, api, securityKey, assert, session };
}

async function begin(env: ReturnType<typeof setup>): Promise<Started> {
  await beginSso(env.deps, 'sam@example.co', '/vault');
  const body = env.sso.start.mock.calls[0]?.[0];
  if (!body) throw new Error('start was not called');
  return body;
}

describe('single sign-on', () => {
  it('starts with a PKCE challenge, a state of its own and a redirect to a path of this server', async () => {
    const env = setup({});
    expect(await beginSso(env.deps, 'sam@example.co')).toBe('http://idp/auth?x=1');
    const body = env.sso.start.mock.calls[0]?.[0];
    expect(body?.redirect).toBe(`https://vault.example.org${SSO_RETURN_PATH}`);
    expect(body?.state.length).toBeGreaterThanOrEqual(16);
    expect(body?.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('trades the code for tokens with the verifier it kept, and leaves the vault shut', async () => {
    const env = setup({});
    const started = await begin(env);
    const outcome = await completeSso(env.deps, { code: 'one-time', state: started.state });
    expect(outcome).toEqual({ status: 'signed-in', email: 'sam@example.co', admin: false, next: '/vault' });
    const finish = env.sso.finish.mock.calls[0]?.[0];
    expect(finish?.code).toBe('one-time');
    expect(finish?.verifier).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(env.session.getState().status).toBe('locked');
  });

  it('refuses a return whose state is not the one it sent, and a return it never started', async () => {
    const env = setup({});
    await begin(env);
    expect(await completeSso(env.deps, { code: 'c', state: 'another-state' })).toEqual({ status: 'lost' });
    expect(await completeSso(env.deps, { code: 'c', state: 'x' })).toEqual({ status: 'lost' });
    expect(env.sso.finish).not.toHaveBeenCalled();
    expect(env.session.getState().status).toBe('signed-out');
  });

  it('signs in an account SSO has just made, which has no keys, and says so', async () => {
    const env = setup({ newAccount: true });
    const started = await begin(env);
    expect(await completeSso(env.deps, { code: 'c', state: started.state })).toEqual({
      status: 'new-account',
      email: 'sam@example.co',
      admin: false,
      next: '/vault',
    });
    expect(env.session.getState().status).toBe('locked');
  });

  it('asks for the second step the provider did not do, then signs in', async () => {
    const env = setup({
      status: 'two_factor_required',
      tokens: null,
      challenge: 'sealed',
      methods: ['totp'],
    });
    const started = await begin(env);
    expect(await completeSso(env.deps, { code: 'c', state: started.state })).toEqual({
      status: 'second-step',
      email: 'sam@example.co',
      methods: ['totp'],
    });
    expect(env.session.getState().status).toBe('signed-out');
    const done = await secondSsoStep(env.deps, 'sam@example.co', '123456');
    expect(done.status).toBe('signed-in');
    expect(env.api.twoFactor).toHaveBeenCalledWith({ challenge: 'sealed', method: 'totp', code: '123456' });
    expect(env.session.getState().status).toBe('locked');
  });

  it('keeps a security key among the methods and signs in with it: options, the key, then the tokens', async () => {
    const env = setup({
      status: 'two_factor_required',
      tokens: null,
      challenge: 'sealed-key',
      methods: ['webauthn'],
    });
    const started = await begin(env);
    expect(await completeSso(env.deps, { code: 'c', state: started.state })).toEqual({
      status: 'second-step',
      email: 'sam@example.co',
      methods: ['webauthn'],
    });
    const done = await secondSsoKeyStep(env.deps, 'sam@example.co');
    expect(done).toEqual({ status: 'signed-in', email: 'sam@example.co', admin: false, next: '/vault' });
    expect(env.securityKey.options).toHaveBeenCalledWith('sealed-key');
    expect(env.assert).toHaveBeenCalledWith({ challenge: 'key-challenge' });
    expect(env.securityKey.verify).toHaveBeenCalledWith({
      challenge: 'sealed-key',
      credential: { id: 'cred' },
    });
    expect(env.api.twoFactor).not.toHaveBeenCalled();
    expect(env.session.getState().status).toBe('locked');
  });

  it('lets a key that was not touched be tried again', async () => {
    const env = setup({
      status: 'two_factor_required',
      tokens: null,
      challenge: 'sealed-key',
      methods: ['webauthn', 'totp'],
    });
    const started = await begin(env);
    await completeSso(env.deps, { code: 'c', state: started.state });
    env.assert.mockRejectedValueOnce(new PasskeyError('cancelled'));
    await expect(secondSsoKeyStep(env.deps, 'sam@example.co')).rejects.toBeInstanceOf(PasskeyError);
    expect(env.session.getState().status).toBe('signed-out');
    await expect(secondSsoKeyStep(env.deps, 'sam@example.co')).resolves.toMatchObject({ status: 'signed-in' });
  });
});
