import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { createProfileApi } from '@/api/profile';
import { decodeB64, encodeB64, utf8 } from '@/lib/b64url';
import { describeAccountError } from './errors';
import {
  type ProfileDeps,
  WrongPasswordError,
  changePassword,
  isEmail,
  makeCredential,
  passwordProblem,
  requestEmailChange,
  sameEmail,
} from './profileModel';

const EMAIL = 'sam@example.org';
const SALT = new Uint8Array(16).fill(7);

function deps(over: { crypto?: Record<string, unknown>; api?: Record<string, unknown> } = {}) {
  const order: string[] = [];
  const crypto = {
    masterKey: vi.fn(async (password: string) => {
      order.push(`masterKey:${password}`);
      return utf8(`mk:${password}`);
    }),
    opaqueRegisterStart: vi.fn(async () => {
      order.push('opaqueRegisterStart');
      return { request: utf8('reg-request'), state: 'reg-state' };
    }),
    opaqueRegisterFinish: vi.fn(async () => {
      order.push('opaqueRegisterFinish');
      return { upload: utf8('upload'), exportKey: utf8('export-new') };
    }),
    opaqueLoginStart: vi.fn(async () => {
      order.push('opaqueLoginStart');
      return { request: utf8('login-request'), state: 'login-state' };
    }),
    opaqueLoginFinish: vi.fn(async () => {
      order.push('opaqueLoginFinish');
      return { finalization: utf8('finalization'), exportKey: utf8('export-old') };
    }),
    rewrapRoot: vi.fn(async () => {
      order.push('rewrapRoot');
      return utf8('wrap');
    }),
    release: vi.fn(async () => undefined),
    ...over.crypto,
  };
  const api = {
    prelogin: vi.fn(async () => ({
      salt: encodeB64(new Uint8Array(16).fill(1)),
      memoryKib: 65536,
      iterations: 3,
      parallelism: 4,
    })),
    opaqueStart: vi.fn(async () => {
      order.push('opaqueStart');
      return { response: encodeB64(utf8('login-response')), loginState: 'login-state-token' };
    }),
    credentialsStart: vi.fn(async () => {
      order.push('credentialsStart');
      return { response: encodeB64(utf8('reg-response')) };
    }),
    changePassword: vi.fn(async () => {
      order.push('changePassword');
    }),
    requestEmailChange: vi.fn(async (body: { email: string }) => {
      order.push('requestEmailChange');
      return { pendingEmail: body.email, expiresAt: '2026-11-26T10:00:00Z' };
    }),
    ...over.api,
  };
  const wiring = { api, crypto, randomBytes: () => SALT } as unknown as ProfileDeps;
  return { wiring, api, crypto, order };
}

describe('what a new master password must be', () => {
  it('is at least 12 characters, typed twice, and not the current one', () => {
    expect(passwordProblem('old', 'short', 'short')).toBe('short');
    expect(passwordProblem('old', 'a long enough phrase', 'a long enough phrasX')).toBe('mismatch');
    expect(passwordProblem('a long enough phrase', 'a long enough phrase', 'a long enough phrase')).toBe('same');
    expect(passwordProblem('old password', 'a long enough phrase', 'a long enough phrase')).toBeUndefined();
  });

  it('wants 12 characters, and says so before it says the two differ', () => {
    expect(passwordProblem('x', '12345678901', '1')).toBe('short');
    expect(passwordProblem('x', '123456789012', '123456789012')).toBeUndefined();
  });
});

describe('addresses', () => {
  it('are told apart from slips of the keyboard', () => {
    expect(isEmail(' name@example.co ')).toBe(true);
    for (const bad of ['', 'name', 'name@', '@example.co', 'a b@example.co']) expect(isEmail(bad), bad).toBe(false);
  });

  it('are one address however they are cased and spaced', () => {
    expect(sameEmail(' Sam@Example.ORG', EMAIL)).toBe(true);
    expect(sameEmail('sam@example.com', EMAIL)).toBe(false);
  });
});

describe('making the new record', () => {
  it('makes a master key from the new password, registers OPAQUE, and wraps the root key under both', async () => {
    const { wiring, api, crypto, order } = deps();
    const made = await makeCredential(wiring, 'a new long password');
    expect(order).toEqual(['masterKey:a new long password', 'opaqueRegisterStart', 'credentialsStart', 'opaqueRegisterFinish', 'rewrapRoot']);
    expect(crypto.masterKey).toHaveBeenCalledWith('a new long password', {
      memoryKib: 65536,
      iterations: 3,
      parallelism: 4,
      salt: SALT,
    });
    expect(api.credentialsStart).toHaveBeenCalledWith(encodeB64(utf8('reg-request')), undefined);
    expect(crypto.rewrapRoot).toHaveBeenCalledWith(utf8('mk:a new long password'), utf8('export-new'));
    expect(made).toEqual({
      upload: encodeB64(utf8('upload')),
      kdf: { memoryKib: 65536, iterations: 3, parallelism: 4, salt: encodeB64(SALT) },
      wrappedRootKey: encodeB64(utf8('wrap')),
    });
    // The wrap spent both handles, so nothing is given back.
    expect(crypto.release).not.toHaveBeenCalled();
  });

  it('normalises the password the way every other master key is made', async () => {
    const { wiring, crypto } = deps();
    await makeCredential(wiring, 'café au lait');
    expect(crypto.masterKey).toHaveBeenCalledWith('café au lait', expect.anything());
  });

  it('registers under the new address when there is one', async () => {
    const { wiring, api } = deps();
    await makeCredential(wiring, 'a long enough password', 'new@example.org');
    expect(api.credentialsStart).toHaveBeenCalledWith(expect.any(String), 'new@example.org');
  });

  it('gives the handles back when the server refuses the registration', async () => {
    const refuse = new ApiError(409, undefined);
    const { wiring, crypto } = deps({ api: { credentialsStart: vi.fn().mockRejectedValue(refuse) } });
    await expect(makeCredential(wiring, 'a long enough password')).rejects.toBe(refuse);
    expect(crypto.release).toHaveBeenCalledWith(utf8('mk:a long enough password'));
    expect(crypto.rewrapRoot).not.toHaveBeenCalled();
  });

  it('gives both handles back when the wrap itself fails', async () => {
    const { wiring, crypto } = deps({ crypto: { rewrapRoot: vi.fn().mockRejectedValue(new Error('locked')) } });
    await expect(makeCredential(wiring, 'a long enough password')).rejects.toThrow('locked');
    expect(crypto.release).toHaveBeenCalledWith(utf8('mk:a long enough password'));
    expect(crypto.release).toHaveBeenCalledWith(utf8('export-new'));
  });
});

describe('changing the master password', () => {
  const input = { email: EMAIL, current: 'the current password', next: 'a brand new password', signOutOthers: true };

  it('proves the current password first, then sends the new record with the proof', async () => {
    const { wiring, api, order } = deps();
    await changePassword(wiring, input);
    expect(order.indexOf('opaqueLoginFinish')).toBeLessThan(order.indexOf('masterKey:a brand new password'));
    expect(order.at(-1)).toBe('changePassword');
    expect(api.prelogin).toHaveBeenCalledWith(EMAIL);
    expect(api.changePassword).toHaveBeenCalledWith({
      loginState: 'login-state-token',
      finalization: encodeB64(utf8('finalization')),
      upload: encodeB64(utf8('upload')),
      kdf: { memoryKib: 65536, iterations: 3, parallelism: 4, salt: encodeB64(SALT) },
      wrappedRootKey: encodeB64(utf8('wrap')),
      signOutOthers: true,
    });
    // The record is made for the address in force.
    expect(api.credentialsStart).toHaveBeenCalledWith(expect.any(String), undefined);
  });

  it('sends the choice of leaving the other devices signed in', async () => {
    const { wiring, api } = deps();
    await changePassword(wiring, { ...input, signOutOthers: false });
    expect(api.changePassword).toHaveBeenCalledWith(expect.objectContaining({ signOutOthers: false }));
  });

  it('never sends either password, only what is made from them', async () => {
    const { wiring, api } = deps();
    await changePassword(wiring, input);
    const sent = JSON.stringify([...api.changePassword.mock.calls, ...api.credentialsStart.mock.calls, ...api.opaqueStart.mock.calls]);
    expect(sent).not.toContain(input.current);
    expect(sent).not.toContain(input.next);
  });

  it('stops at a wrong current password, before anything is made or sent', async () => {
    const { wiring, api, crypto } = deps({ crypto: { opaqueLoginFinish: vi.fn().mockRejectedValue(new Error('bad')) } });
    await expect(changePassword(wiring, input)).rejects.toBeInstanceOf(WrongPasswordError);
    expect(crypto.rewrapRoot).not.toHaveBeenCalled();
    expect(api.credentialsStart).not.toHaveBeenCalled();
    expect(api.changePassword).not.toHaveBeenCalled();
  });

  it('says the same when the server refuses the proof', async () => {
    const { wiring } = deps({ api: { changePassword: vi.fn().mockRejectedValue(new ApiError(401, undefined)) } });
    await expect(changePassword(wiring, input)).rejects.toBeInstanceOf(WrongPasswordError);
  });

  it('lets the server\'s other refusals through', async () => {
    const refusal = new ApiError(403, { type: 'urn:kemlock:problem:compatible-account', title: 'x', status: 403 } as never);
    const { wiring } = deps({ api: { changePassword: vi.fn().mockRejectedValue(refusal) } });
    await expect(changePassword(wiring, input)).rejects.toBe(refusal);
  });
});

describe('changing the address', () => {
  const input = { email: EMAIL, newEmail: ' New@Example.org ', current: 'the current password' };

  it('registers the same password under the new address and asks for the link', async () => {
    const { wiring, api, crypto } = deps();
    const asked = await requestEmailChange(wiring, input);
    expect(crypto.masterKey).toHaveBeenLastCalledWith('the current password', expect.anything());
    expect(api.credentialsStart).toHaveBeenCalledWith(expect.any(String), 'new@example.org');
    expect(api.requestEmailChange).toHaveBeenCalledWith({
      email: 'new@example.org',
      loginState: 'login-state-token',
      finalization: encodeB64(utf8('finalization')),
      upload: encodeB64(utf8('upload')),
      kdf: { memoryKib: 65536, iterations: 3, parallelism: 4, salt: encodeB64(SALT) },
      wrappedRootKey: encodeB64(utf8('wrap')),
    });
    expect(asked.pendingEmail).toBe('new@example.org');
  });

  it('proves the password for the address in force, not the new one', async () => {
    const { wiring, api } = deps();
    await requestEmailChange(wiring, input);
    expect(api.prelogin).toHaveBeenCalledWith(EMAIL);
  });

  it('stops at a wrong current password', async () => {
    const { wiring, api } = deps({ crypto: { opaqueLoginFinish: vi.fn().mockRejectedValue(new Error('bad')) } });
    await expect(requestEmailChange(wiring, input)).rejects.toBeInstanceOf(WrongPasswordError);
    expect(api.requestEmailChange).not.toHaveBeenCalled();
  });
});

describe('the profile client', () => {
  const problem = (slug: string, status: number) =>
    new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: slug, status } as never);

  it('calls the routes the server has', async () => {
    const request = vi.fn(async () => ({}));
    const send = vi.fn(async () => undefined);
    const profile = createProfileApi({ request, send } as never);
    await profile.get();
    expect(request).toHaveBeenLastCalledWith({ method: 'GET', path: '/kem/v1/account/profile' });
    await profile.rename('Alex');
    expect(request).toHaveBeenLastCalledWith({ method: 'PATCH', path: '/kem/v1/account/profile', body: { name: 'Alex' } });
    await profile.credentialsStart('req');
    expect(request).toHaveBeenLastCalledWith({
      method: 'POST',
      path: '/kem/v1/account/credentials/start',
      body: { request: 'req' },
    });
    await profile.credentialsStart('req', 'new@example.org');
    expect(request).toHaveBeenLastCalledWith({
      method: 'POST',
      path: '/kem/v1/account/credentials/start',
      body: { request: 'req', email: 'new@example.org' },
    });
    await profile.cancelEmailChange();
    expect(send).toHaveBeenLastCalledWith({ method: 'DELETE', path: '/kem/v1/account/email' });
    await profile.confirmEmailChange('tok');
    expect(request).toHaveBeenLastCalledWith({
      method: 'POST',
      path: '/kem/v1/account/email/confirm',
      mode: 'public',
      body: { token: 'tok' },
    });
  });

  it('sends the password change and the address request as the server reads them', async () => {
    const request = vi.fn(async () => ({}));
    const send = vi.fn(async () => undefined);
    const profile = createProfileApi({ request, send } as never);
    const record = {
      loginState: 's',
      finalization: 'f',
      upload: 'u',
      kdf: { memoryKib: 65536, iterations: 3, parallelism: 4, salt: 'c2FsdA' },
      wrappedRootKey: 'w',
    };
    await profile.changePassword({ ...record, signOutOthers: true });
    expect(send).toHaveBeenLastCalledWith({
      method: 'PUT',
      path: '/kem/v1/account/password',
      body: { ...record, signOutOthers: true },
    });
    await profile.requestEmailChange({ ...record, email: 'new@example.org' });
    expect(request).toHaveBeenLastCalledWith({
      method: 'POST',
      path: '/kem/v1/account/email',
      body: { ...record, email: 'new@example.org' },
    });
  });

  it('keeps the wrap as base64url the server accepts', () => {
    expect(decodeB64(encodeB64(utf8('wrap')))).toEqual(utf8('wrap'));
  });

  it('words each refusal the server gives', () => {
    expect(describeAccountError(problem('sso-managed', 403)).id).toBe('profile.error.sso');
    expect(describeAccountError(problem('compatible-account', 403)).id).toBe('profile.error.compatible');
    expect(describeAccountError(problem('no-password', 403)).id).toBe('profile.error.noPassword');
    expect(describeAccountError(problem('email-taken', 409)).id).toBe('profile.error.taken');
    expect(describeAccountError(problem('mail-off', 409)).id).toBe('profile.error.mailOff');
    expect(describeAccountError(problem('mail-failed', 502)).id).toBe('profile.error.mailFailed');
    expect(describeAccountError(problem('invalid-request', 400)).id).toBe('profile.error.badRequest');
    expect(describeAccountError(new WrongPasswordError()).id).toBe('profile.error.wrong');
  });
});
