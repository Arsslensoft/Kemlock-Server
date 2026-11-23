import { describe, expect, it, vi } from 'vitest';
import { createSession } from '@/app/session';
import { encodeB64, utf8 } from '@/lib/b64url';
import { crypto as fake, fakeCalls } from '@/test/fake-crypto';
import { signInWithPasskey } from './passkeySignIn';

const USER = '11111111-1111-4111-8111-111111111111';

function tokens() {
  return {
    tokenType: 'DPoP' as const,
    accessToken: 'a',
    expiresIn: 60,
    refreshToken: 'r',
    refreshExpiresIn: 600,
    userId: USER,
    deviceId: '22222222-2222-4222-8222-222222222222',
    admin: false,
  };
}

function setup(prf: boolean, answerPrf: boolean) {
  const session = createSession();
  const passkeys = {
    options: vi.fn(async () => ({ options: { challenge: 'x' }, challenge: 'sealed' })),
    verify: vi.fn(async () => ({
      tokens: tokens(),
      passkeyId: '33333333-3333-4333-8333-333333333333',
      prf: prf
        ? { wrappedKey: encodeB64(utf8(JSON.stringify(['prf', 'out', 'cred']))), keyVersion: 1 }
        : null,
      keyVersion: 1,
    })),
  };
  const api = { accountKeys: vi.fn(async () => ({ keyVersion: 1, sealedPrivateKeys: 'c2s' })) };
  const assert = vi.fn(async () => ({
    credential: { id: 'cred' },
    credentialId: utf8('cred'),
    ...(answerPrf ? { prfOutput: utf8('out') } : {}),
  }));
  const deps = {
    passkeys,
    api: api as never,
    crypto: fake,
    session,
    device: () => ({ id: null, name: 'Web vault', kind: 'kemlock-web' as const }),
    assert,
  };
  return { deps, session, passkeys, api, assert };
}

describe('signInWithPasskey', () => {
  it('opens the vault with the PRF wrap, with no master password', async () => {
    const { deps, session, passkeys } = setup(true, true);
    fakeCalls.length = 0;
    const result = await signInWithPasskey(deps, 'sam@example.co');
    expect(result).toEqual({ status: 'unlocked', admin: false });
    expect(session.getState().status).toBe('unlocked');
    expect(session.getState().email).toBe('sam@example.co');
    expect(passkeys.verify).toHaveBeenCalledWith(
      expect.objectContaining({ challenge: 'sealed', credential: { id: 'cred' } }),
    );
    expect(fakeCalls).toEqual(expect.arrayContaining(['prfOpenRoot', 'unlockWithRoot']));
  });

  it('signs in with the vault shut when the passkey has no PRF wrap', async () => {
    const { deps, session } = setup(false, true);
    expect(await signInWithPasskey(deps, 'sam@example.co')).toEqual({
      status: 'needs-password',
      admin: false,
    });
    expect(session.getState().status).toBe('locked');
  });

  it('signs in with the vault shut when the authenticator gave no PRF output', async () => {
    const { deps, session } = setup(true, false);
    expect((await signInWithPasskey(deps, 'sam@example.co')).status).toBe('needs-password');
    expect(session.getState().status).toBe('locked');
  });

  it('signs in with the vault shut when the wrap does not open', async () => {
    const { deps, session } = setup(true, true);
    deps.assert.mockResolvedValueOnce({
      credential: { id: 'cred' },
      credentialId: utf8('other'),
      prfOutput: utf8('out'),
    });
    expect((await signInWithPasskey(deps, 'sam@example.co')).status).toBe('needs-password');
    expect(session.getState().status).toBe('locked');
  });

  it('signs nobody in when the authenticator is refused', async () => {
    const { deps, session, passkeys } = setup(true, true);
    deps.assert.mockRejectedValueOnce(new Error('cancelled'));
    await expect(signInWithPasskey(deps, 'sam@example.co')).rejects.toThrow('cancelled');
    expect(passkeys.verify).not.toHaveBeenCalled();
    expect(session.getState().status).toBe('signed-out');
  });
});
