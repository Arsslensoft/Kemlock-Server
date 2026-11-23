import { describe, expect, it, vi } from 'vitest';
import { createSession } from '@/app/session';
import { decodeB64 } from '@/lib/b64url';
import type { KeyCopyRequest } from '@/api/devices';
import { crypto as fake, fakeCalls } from '@/test/fake-crypto';
import { enrolNewAccountKeys } from './enrolKeys';
import { trustThisBrowser, unlockWithTrustedDevice } from './trustedDevice';

const USER = '11111111-1111-4111-8111-111111111111';
const DEVICE = '22222222-2222-4222-8222-222222222222';

function signedInSession() {
  const session = createSession();
  session.signedIn({ email: 'sam@example.co', userId: USER, deviceId: DEVICE, admin: false });
  return session;
}

/** A server that keeps one copy, as PUT and GET /kem/v1/devices/key-copy do. */
function devices() {
  let held: string | null = null;
  return {
    keyCopy: vi.fn(async () =>
      held
        ? {
            deviceId: DEVICE,
            wrappedKey: held,
            protection: 'web-crypto' as const,
            createdAt: 'x',
            updatedAt: 'x',
          }
        : null,
    ),
    putKeyCopy: vi.fn(async (body: KeyCopyRequest) => {
      held = body.wrappedKey;
      return {
        deviceId: DEVICE,
        wrappedKey: body.wrappedKey,
        protection: body.protection,
        createdAt: 'x',
        updatedAt: 'x',
      };
    }),
  };
}

const api = { accountKeys: vi.fn(async () => ({ keyVersion: 1, sealedPrivateKeys: 'c2s' })) } as never;

describe('the trusted-device copy', () => {
  it('is kept by the server and opens the vault after a sign-in with no password', async () => {
    const server = devices();
    const first = signedInSession();
    await fake.newSsoAccount(USER); // the vault is open on this browser
    first.unlocked();
    await trustThisBrowser({ devices: server, api, crypto: fake, session: first }, 1);
    expect(server.putKeyCopy).toHaveBeenCalledWith(
      expect.objectContaining({ protection: 'web-crypto' }),
    );

    // Another visit: tokens in, vault shut.
    const next = signedInSession();
    fakeCalls.length = 0;
    expect(await unlockWithTrustedDevice({ devices: server, api, crypto: fake, session: next })).toBe(true);
    expect(next.getState().status).toBe('unlocked');
    expect(fakeCalls).toEqual(expect.arrayContaining(['deviceCopyOpen', 'unlockWithRoot']));
  });

  it('is false for a browser the server holds no copy for', async () => {
    const next = signedInSession();
    expect(
      await unlockWithTrustedDevice({ devices: devices(), api, crypto: fake, session: next }),
    ).toBe(false);
    expect(next.getState().status).toBe('locked');
  });

  it('is false when the copy does not open here, and leaves the vault shut', async () => {
    const server = devices();
    await server.putKeyCopy({ wrappedKey: 'bm90LW91cnM', protection: 'web-crypto' });
    const next = signedInSession();
    expect(await unlockWithTrustedDevice({ devices: server, api, crypto: fake, session: next })).toBe(false);
    expect(next.getState().status).toBe('locked');
  });

  it('is false for a session that has nobody in it', async () => {
    expect(
      await unlockWithTrustedDevice({ devices: devices(), api, crypto: fake, session: createSession() }),
    ).toBe(false);
  });
});

describe('the first keys of an SSO-made account', () => {
  function keysApi(refuse = false) {
    return {
      enrol: vi.fn(async (_body: unknown) => {
        if (refuse) throw new Error('409');
        return { keyVersion: 1 };
      }),
    };
  }

  it('are made by the worker, sent with this browser copy, and open the vault', async () => {
    const session = signedInSession();
    const keys = keysApi();
    fakeCalls.length = 0;
    await enrolNewAccountKeys({ keys, crypto: fake, session });
    expect(session.getState().status).toBe('unlocked');
    expect(fakeCalls).toEqual(expect.arrayContaining(['newSsoAccount', 'deviceCopySeal']));
    const body = keys.enrol.mock.calls[0]?.[0] as {
      publicBundle: string;
      deviceCopy: { wrappedKey: string; protection: string };
    };
    expect(decodeB64(body.publicBundle).length).toBeGreaterThan(0);
    expect(body.deviceCopy.protection).toBe('web-crypto');
  });

  it('end the session and shut the vault when the server refuses them', async () => {
    const session = signedInSession();
    await expect(enrolNewAccountKeys({ keys: keysApi(true), crypto: fake, session })).rejects.toThrow('409');
    expect(session.getState().status).toBe('signed-out');
  });
});
