import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setupMemory } from './memory';
import { type TwoStepSetupDeps, confirmAuthenticatorApp, confirmSecurityKey } from './twoStepSetup';

function deps() {
  const order: string[] = [];
  const passkeys = {
    creationOptions: vi.fn(async () => {
      order.push('passkey');
      return { challenge: 'AAAA' };
    }),
    register: vi.fn(async (name: string) => ({
      id: 'p',
      name,
      prf: false,
      prfKeyVersion: null,
      createdAt: '',
      lastUsedAt: null,
    })),
  };
  const keys = {
    creationOptions: vi.fn(async () => ({ challenge: 'AAAA' })),
    confirm: vi.fn(async () => ({ enabled: true, keys: [] })),
  };
  const totpConfirm = vi.fn(async () => {
    order.push('totp');
  });
  const create = vi.fn(async () => ({ credential: { id: 'c' }, credentialId: new Uint8Array([1]) }));
  const value: TwoStepSetupDeps = {
    passkeys: { passkeys, crypto: { prfWrapRoot: vi.fn() }, create },
    keys: { keys, create: vi.fn(async () => ({ id: 'k' })) },
    totpConfirm,
    name: 'Passkey',
  };
  return { value, order, passkeys, keys, totpConfirm, create };
}

beforeEach(() => setupMemory.clear());

describe('confirmAuthenticatorApp', () => {
  it('makes the ticked passkey before it confirms the code, once', async () => {
    setupMemory.set({ wantPasskey: true });
    const d = deps();
    expect(await confirmAuthenticatorApp(d.value, '123456')).toEqual({ passkeyFailed: false });
    expect(d.order).toEqual(['passkey', 'totp']);
    expect(setupMemory.get()).toMatchObject({ passkeyMade: true, twoStep: 'totp' });
    await confirmAuthenticatorApp(d.value, '123456');
    expect(d.passkeys.register).toHaveBeenCalledOnce();
  });

  it('makes no passkey when none was ticked', async () => {
    const d = deps();
    await confirmAuthenticatorApp(d.value, '123456');
    expect(d.passkeys.creationOptions).not.toHaveBeenCalled();
    expect(d.totpConfirm).toHaveBeenCalledWith('123456');
  });

  it('still confirms the code when the passkey fails, and says so', async () => {
    setupMemory.set({ wantPasskey: true });
    const d = deps();
    d.create.mockRejectedValueOnce(new Error('cancelled'));
    expect(await confirmAuthenticatorApp(d.value, '123456')).toEqual({ passkeyFailed: true });
    expect(d.totpConfirm).toHaveBeenCalledOnce();
    expect(setupMemory.get().passkeyMade).toBeUndefined();
    expect(setupMemory.get().twoStep).toBe('totp');
  });

  it('does not swallow a wrong code', async () => {
    const d = deps();
    d.totpConfirm.mockRejectedValueOnce(new Error('wrong code'));
    await expect(confirmAuthenticatorApp(d.value, '000000')).rejects.toThrow('wrong code');
  });
});

describe('confirmSecurityKey', () => {
  it('uses the two-factor routes, not an account passkey', async () => {
    const d = deps();
    await confirmSecurityKey(d.value);
    expect(d.keys.creationOptions).toHaveBeenCalledOnce();
    expect(d.keys.confirm).toHaveBeenCalledWith('Passkey', { id: 'k' });
    expect(d.passkeys.register).not.toHaveBeenCalled();
    expect(setupMemory.get().twoStep).toBe('key');
  });
});

describe('confirmSecurityKey with a passkey ticked', () => {
  it('makes the key, then the passkey, once each', async () => {
    setupMemory.set({ wantPasskey: true });
    const d = deps();
    expect(await confirmSecurityKey({ ...d.value, keyName: 'Security key' })).toEqual({ passkeyFailed: false });
    expect(d.keys.confirm).toHaveBeenCalledWith('Security key', { id: 'k' });
    expect(d.passkeys.register).toHaveBeenCalledOnce();
    expect(setupMemory.get()).toMatchObject({ passkeyMade: true, twoStep: 'key' });
    await confirmSecurityKey(d.value);
    expect(d.keys.confirm).toHaveBeenCalledOnce();
    expect(d.passkeys.register).toHaveBeenCalledOnce();
  });

  it('keeps the key when the passkey fails, says so, and asks only for the passkey again', async () => {
    setupMemory.set({ wantPasskey: true });
    const d = deps();
    d.create.mockRejectedValueOnce(new Error('cancelled'));
    expect(await confirmSecurityKey(d.value)).toEqual({ passkeyFailed: true });
    expect(setupMemory.get().twoStep).toBe('key');
    expect(await confirmSecurityKey(d.value)).toEqual({ passkeyFailed: false });
    expect(d.keys.confirm).toHaveBeenCalledOnce();
  });
});
