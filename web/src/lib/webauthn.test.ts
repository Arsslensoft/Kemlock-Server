import { describe, expect, it, vi } from 'vitest';
import { proveWithKey, registerPasskey, registerSecurityKey } from './webauthn';

function deps(prfOutput?: Uint8Array) {
  const passkeys = {
    creationOptions: vi.fn(async () => ({ challenge: 'AAAA' })),
    register: vi.fn(async (name: string) => ({
      id: 'p1',
      name,
      prf: false,
      prfKeyVersion: null,
      createdAt: '',
      lastUsedAt: null,
    })),
  };
  const crypto = {
    prfWrapRoot: vi.fn(async () => ({ wrappedKey: new Uint8Array([1, 2, 3]), keyVersion: 4 })),
  };
  const create = vi.fn(async () => ({
    credential: { id: 'c' },
    credentialId: new Uint8Array([9]),
    ...(prfOutput ? { prfOutput } : {}),
  }));
  return { passkeys, crypto, create };
}

describe('registerPasskey', () => {
  it('stores a wrap of the root key when the authenticator gave a PRF output', async () => {
    const prf = new Uint8Array([5, 5, 5]);
    const d = deps(prf);
    await registerPasskey(d, 'Key');
    expect(d.crypto.prfWrapRoot).toHaveBeenCalledOnce();
    expect(d.passkeys.register).toHaveBeenCalledWith('Key', { id: 'c' }, { wrappedKey: 'AQID', keyVersion: 4 });
    // The PRF output is wiped once used.
    expect([...prf]).toEqual([0, 0, 0]);
  });

  it('stores a passkey with no wrap when there is no PRF output', async () => {
    const d = deps();
    await registerPasskey(d, 'Key');
    expect(d.crypto.prfWrapRoot).not.toHaveBeenCalled();
    expect(d.passkeys.register).toHaveBeenCalledWith('Key', { id: 'c' }, undefined);
  });

  it('sends the fresh proof an account with a second step on has to give', async () => {
    const d = deps();
    await registerPasskey(d, 'Key', '123456');
    expect(d.passkeys.register).toHaveBeenCalledWith('Key', { id: 'c' }, undefined, '123456');
    await registerPasskey(d, 'Key', { webauthn: { id: 'k' } });
    expect(d.passkeys.register).toHaveBeenLastCalledWith('Key', { id: 'c' }, undefined, { webauthn: { id: 'k' } });
  });

  it('wipes the PRF output when the server refuses the passkey', async () => {
    const prf = new Uint8Array([5, 5, 5]);
    const d = deps(prf);
    d.passkeys.register.mockRejectedValueOnce(new Error('refused'));
    await expect(registerPasskey(d, 'Key')).rejects.toThrow('refused');
    expect([...prf]).toEqual([0, 0, 0]);
  });

  it('wipes the PRF output when wrapping the root key fails', async () => {
    const prf = new Uint8Array([5, 5, 5]);
    const d = deps(prf);
    d.crypto.prfWrapRoot.mockRejectedValueOnce(new Error('locked'));
    await expect(registerPasskey(d, 'Key')).rejects.toThrow('locked');
    expect([...prf]).toEqual([0, 0, 0]);
    expect(d.passkeys.register).not.toHaveBeenCalled();
  });
});

describe('registerSecurityKey', () => {
  it('turns the key on as a second step through the two-factor routes', async () => {
    const keys = {
      creationOptions: vi.fn(async () => ({ challenge: 'AAAA' })),
      confirm: vi.fn(async () => ({ enabled: true, keys: [] })),
    };
    const create = vi.fn(async () => ({ id: 'k' }));
    await registerSecurityKey({ keys, create }, 'Key');
    expect(create).toHaveBeenCalledWith({ challenge: 'AAAA' });
    expect(keys.confirm).toHaveBeenCalledWith('Key', { id: 'k' });
  });
});

describe('proveWithKey', () => {
  it('asks for options, has the key answer them, and returns the { webauthn } proof', async () => {
    const options = vi.fn(async () => ({ challenge: 'AAAA', allowCredentials: [] }));
    const assert = vi.fn(async () => ({ id: 'c', response: { signature: 's' } }));
    // jsdom has no WebAuthn: say this browser has it.
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    vi.stubGlobal('navigator', { credentials: { get: () => undefined } });
    try {
      const proof = await proveWithKey({ options, assert });
      expect(options).toHaveBeenCalledOnce();
      expect(assert).toHaveBeenCalledWith({ challenge: 'AAAA', allowCredentials: [] });
      expect(proof).toEqual({ webauthn: { id: 'c', response: { signature: 's' } } });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
