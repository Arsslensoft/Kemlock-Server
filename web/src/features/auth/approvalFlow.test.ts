import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApprovalPollResponse, ApprovalRequestBody } from '@/api/devices';
import type { AccountKeysResponse, TokenResponse } from '@/api/types';
import { createSession } from '@/app/session';
import { CryptoError } from '@/crypto/types';
import { approvalPhrase } from '@/lib/approvalPhrase';
import { decodeB64, encodeB64, utf8 } from '@/lib/b64url';
import { crypto, fakeApprovalBox, fakeCalls, isFakeLocked, resetFakeCrypto } from '@/test/fake-crypto';
import {
  ApprovalRefused,
  type ApprovalProgress,
  type DeviceApprovalDeps,
  signInWithAnotherDevice,
} from './approvalFlow';

const ACCOUNT = '11111111-2222-4333-8444-555555555555';
const REQUEST = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

const tokens: TokenResponse = {
  tokenType: 'DPoP',
  accessToken: 'access',
  expiresIn: 600,
  refreshToken: 'refresh',
  refreshExpiresIn: 86400,
  userId: ACCOUNT,
  deviceId: 'device-9',
  admin: false,
};

interface Script {
  /** What each poll answers, in order; the last repeats. */
  polls: Array<(publicKey: Uint8Array) => ApprovalPollResponse>;
  /** Overrides the phrase the server reports. */
  serverPhrase?: string;
  userId?: string;
  /** The account's bundle as the server serves it; the fake's own is `bundle:<account>`. */
  publicBundle?: string;
  /** What the sealed private keys are, as served; empty for none. */
  sealedPrivateKeys?: string;
}

const pending = (): ApprovalPollResponse => ({ status: 'pending', expiresAt: 'later', sealedKey: null });
const approvedFor =
  (account = ACCOUNT, request = REQUEST) =>
  (publicKey: Uint8Array): ApprovalPollResponse => ({
    status: 'approved',
    expiresAt: null,
    sealedKey: encodeB64(fakeApprovalBox(publicKey, account, request)),
    accountId: account,
  });

function setup(script: Script) {
  const session = createSession();
  let publicKey: Uint8Array = new Uint8Array();
  let polled = 0;
  const approval = {
    request: vi.fn(async (body: ApprovalRequestBody) => {
      publicKey = decodeB64(body.publicKey);
      return {
        requestId: REQUEST,
        phrase: script.serverPhrase ?? (await approvalPhrase(publicKey)),
        expiresAt: '2026-11-25T10:05:00Z',
      };
    }),
    poll: vi.fn(async () => {
      const step = script.polls[Math.min(polled, script.polls.length - 1)];
      polled += 1;
      if (!step) throw new Error('no script');
      return step(publicKey);
    }),
    challenge: vi.fn(async () => ({ challenge: 'chal' })),
    verify: vi.fn(async () => ({ ...tokens, userId: script.userId ?? ACCOUNT })),
  };
  const api = {
    accountKeys: vi.fn(
      async (): Promise<AccountKeysResponse> => ({
        keyVersion: 3,
        kdf: { memoryKib: 1, iterations: 1, parallelism: 1, salt: '' },
        wrappedRootKey: '',
        publicBundle: script.publicBundle ?? encodeB64(utf8(`bundle:${ACCOUNT}`)),
        bundleSignature: '',
        sealedPrivateKeys: script.sealedPrivateKeys ?? encodeB64(utf8('sealed')),
      }),
    ),
  };
  const confirmFingerprint = vi.fn(async (_fingerprint: string, _signal: AbortSignal) => true);
  const deps: DeviceApprovalDeps = {
    approval,
    api,
    crypto,
    confirmFingerprint,
    session,
    device: () => ({ name: 'Web vault', kind: 'kemlock-web' }),
    wait: async () => undefined,
  };
  return { deps, approval, api, session, confirmFingerprint, publicKey: () => publicKey };
}

describe('signInWithAnotherDevice', () => {
  beforeEach(() => resetFakeCrypto());

  it('shows the phrase worked out from its own key, then opens the vault with the approved root key', async () => {
    const run = setup({ polls: [pending, pending, approvedFor()] });
    const seen: ApprovalProgress[] = [];
    const outcome = await signInWithAnotherDevice(
      run.deps,
      'sam@example.co',
      (progress) => seen.push(progress),
      new AbortController().signal,
    );
    expect(outcome).toEqual({ status: 'signed-in', admin: false });

    const waiting = seen.find((p) => p.step === 'waiting');
    expect(waiting).toEqual({
      step: 'waiting',
      phrase: await approvalPhrase(run.publicKey()),
      expiresAt: '2026-11-25T10:05:00Z',
    });
    expect(run.approval.request).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'sam@example.co' }),
    );
    expect(run.approval.poll).toHaveBeenCalledTimes(3);
    // The request carried a public key and nothing secret.
    expect(decodeB64(run.approval.request.mock.calls[0]?.[0].publicKey ?? '')).toHaveLength(1600);

    // The sequence: key, open the sealed key, trade the approval for tokens, unlock.
    expect(fakeCalls.filter((c) => ['newDeviceKey', 'openApprovedKey', 'unlockWithRoot'].includes(c))).toEqual([
      'newDeviceKey',
      'openApprovedKey',
      'unlockWithRoot',
    ]);
    // The person was asked to compare the fingerprint of the keys now in use before the vault counted as open.
    expect(seen).toContainEqual({ step: 'compare', fingerprint: await crypto.fingerprint(utf8(`bundle:${ACCOUNT}`)) });
    expect(run.confirmFingerprint).toHaveBeenCalledOnce();
    expect(run.approval.challenge).toHaveBeenCalledWith(REQUEST);
    expect(run.approval.verify).toHaveBeenCalledWith('chal');
    expect(run.session.getState()).toMatchObject({ status: 'unlocked', userId: ACCOUNT });
    expect(run.session.tokenStore.get()?.access).toBe('access');
    expect(isFakeLocked()).toBe(false);
  });

  it('keeps the vault shut while the person compares the fingerprints, and opens it on a match', async () => {
    const run = setup({ polls: [approvedFor()] });
    let statusWhileComparing = '';
    run.confirmFingerprint.mockImplementation(async () => {
      statusWhileComparing = run.session.getState().status;
      return true;
    });
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome.status).toBe('signed-in');
    expect(statusWhileComparing).toBe('locked');
    expect(run.session.getState().status).toBe('unlocked');
  });

  it('locks the worker and ends the session when the person says the fingerprints differ', async () => {
    const run = setup({ polls: [approvedFor()] });
    run.confirmFingerprint.mockResolvedValue(false);
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome).toMatchObject({ status: 'failed', error: expect.any(ApprovalRefused) });
    expect(outcome.status === 'failed' && (outcome.error as ApprovalRefused).reason).toBe('fingerprint');
    expect(isFakeLocked()).toBe(true);
    expect(fakeCalls).toContain('lock');
    expect(run.session.getState().status).toBe('signed-out');
    expect(run.session.tokenStore.get()).toBeUndefined();
  });

  it("refuses keys that are not the bundle's the server serves, and asks nobody to compare", async () => {
    // The root key opens (a server sealed its own), but its private keys are not the bundle's.
    const run = setup({ polls: [approvedFor()], publicBundle: encodeB64(utf8('bundle:somebody-else')) });
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    // The person is told the keys were not the account's, not handed a generic failure.
    expect(outcome).toMatchObject({ status: 'failed', error: expect.any(ApprovalRefused) });
    expect(outcome.status === 'failed' && (outcome.error as ApprovalRefused).reason).toBe('keys');
    expect(run.confirmFingerprint).not.toHaveBeenCalled();
    expect(isFakeLocked()).toBe(true);
    expect(run.session.getState().status).toBe('signed-out');
  });

  it("does not call a worker that is not there a forgery", async () => {
    const run = setup({ polls: [approvedFor()] });
    run.deps.crypto = {
      ...crypto,
      unlockWithRoot: async () => {
        throw new CryptoError('unavailable');
      },
    };
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome).toMatchObject({ status: 'failed', error: expect.any(CryptoError) });
    expect(run.session.getState().status).toBe('signed-out');
  });

  it.each([
    ['no bundle', { publicBundle: '' }],
    ['no sealed private keys', { sealedPrivateKeys: '' }],
  ])('refuses an account served with %s, since nothing then ties the root key to the account', async (_name, served) => {
    const run = setup({ polls: [approvedFor()], ...served });
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome).toMatchObject({ status: 'failed', error: expect.any(ApprovalRefused) });
    expect(fakeCalls).not.toContain('unlockWithRoot');
    expect(isFakeLocked()).toBe(true);
    expect(run.session.getState().status).toBe('signed-out');
  });

  it('seals to the account and request the approved poll names: another request is refused', async () => {
    const run = setup({ polls: [approvedFor(ACCOUNT, 'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee')] });
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome.status).toBe('failed');
    expect(run.approval.challenge).not.toHaveBeenCalled();
    expect(run.session.getState().status).toBe('signed-out');
    expect(isFakeLocked()).toBe(true);
  });

  it('does not sign in when the tokens are for another account than the key opened', async () => {
    const run = setup({ polls: [approvedFor()], userId: '99999999-2222-4333-8444-555555555555' });
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome).toMatchObject({ status: 'failed', error: expect.any(ApprovalRefused) });
    expect(run.session.getState().status).toBe('signed-out');
    expect(run.session.tokenStore.get()).toBeUndefined();
    expect(isFakeLocked()).toBe(true);
  });

  it('refuses a server whose phrase is not the one this key gives, and polls nothing', async () => {
    const run = setup({ polls: [approvedFor()], serverPhrase: 'abacus abacus abacus abacus abacus' });
    const outcome = await signInWithAnotherDevice(run.deps, 'sam@example.co', () => undefined, new AbortController().signal);
    expect(outcome).toMatchObject({ status: 'failed', error: expect.any(ApprovalRefused) });
    expect(run.approval.poll).not.toHaveBeenCalled();
    // The one-time key is let go, not left in the worker.
    expect(fakeCalls).toContain('release');
  });

  it('says when the other device refused, and when the request lapsed', async () => {
    const denied = setup({ polls: [pending, () => ({ status: 'denied', expiresAt: null, sealedKey: null })] });
    expect(
      await signInWithAnotherDevice(denied.deps, 'a@b.c', () => undefined, new AbortController().signal),
    ).toEqual({ status: 'denied' });
    const expired = setup({ polls: [() => ({ status: 'expired', expiresAt: null, sealedKey: null })] });
    expect(
      await signInWithAnotherDevice(expired.deps, 'a@b.c', () => undefined, new AbortController().signal),
    ).toEqual({ status: 'expired' });
  });

  it('gives up when cancelled and spends the one-time key', async () => {
    const run = setup({ polls: [pending] });
    const abort = new AbortController();
    run.deps.wait = async () => {
      abort.abort();
    };
    const outcome = await signInWithAnotherDevice(run.deps, 'a@b.c', () => undefined, abort.signal);
    expect(outcome).toEqual({ status: 'cancelled' });
    expect(fakeCalls).toContain('release');
    expect(run.session.getState().status).toBe('signed-out');
  });

  it('reports a server that cannot be reached as a failure, not a sign-in', async () => {
    const run = setup({ polls: [pending] });
    run.approval.request.mockRejectedValueOnce(new Error('offline'));
    const outcome = await signInWithAnotherDevice(run.deps, 'a@b.c', () => undefined, new AbortController().signal);
    expect(outcome.status).toBe('failed');
  });
});
