// "Sign in with another device", the new device's side (docs/crypto.md, sealed box context
// `device-approval` and "Device-approval phrase"). No React in here, so it is tested with fakes.
//
//   1. the worker makes a one-time kx1 key pair; its public half goes in the request;
//   2. the five-word phrase is worked out here from that public half, never taken from the server,
//      and shown for the person to match against the phrase on the approving device;
//   3. the request is polled until an open device approves it with the root key sealed to our key;
//   4. the worker opens the box with aad = account id ‖ request id, the account id coming from the
//      approved poll, so an answer can't be replayed onto another request;
//   5. a challenge, signed for by this device's DPoP key, trades the approval for tokens, and the
//      vault opens with the root key that never left the worker.
import type { Api } from '@/api/client';
import { tokensFromResponse } from '@/api/client';
import type { NewDeviceApi } from '@/api/devices';
import type { DeviceDto } from '@/api/types';
import type { Session } from '@/app/session';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { approvalPhrase } from '@/lib/approvalPhrase';
import { rememberDeviceId } from '@/lib/device';

export interface DeviceApprovalDeps {
  approval: NewDeviceApi;
  api: Pick<Api, 'accountKeys'>;
  crypto: Pick<
    CryptoPort,
    'newDeviceKey' | 'openApprovedKey' | 'unlockWithRoot' | 'release'
  >;
  session: Session;
  device: () => DeviceDto;
  now?: () => number;
  /** Resolves after `ms`, or at once when `signal` aborts. */
  wait?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** Milliseconds between polls. */
  pollEvery?: number;
}

export type ApprovalProgress =
  | { step: 'requesting' }
  /** The phrase to match against the approving device's, and when the request lapses. */
  | { step: 'waiting'; phrase: string; expiresAt: string }
  | { step: 'signing-in' };

export type ApprovalOutcome =
  | { status: 'signed-in'; admin: boolean }
  | { status: 'denied' }
  | { status: 'expired' }
  | { status: 'cancelled' }
  /** The request or the answer could not be used: a network error, an answer that did not open. */
  | { status: 'failed'; error: unknown };

/** A fixed message for what the server said that this side will not accept. */
export class ApprovalRefused extends Error {
  constructor(readonly reason: 'phrase' | 'account' | 'sealed') {
    super(`the approval was refused: ${reason}`);
    this.name = 'ApprovalRefused';
  }
}

const defaultWait = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener('abort', done);
  });

function samePhrase(ours: string, theirs: string): boolean {
  const normal = (text: string) => text.trim().toLowerCase().split(/\s+/).join(' ');
  return normal(ours) === normal(theirs);
}

/**
 * Asks for an approval and follows it to a signed-in session. `onProgress` is told the phrase as
 * soon as it is known. Aborting the signal gives up and spends the one-time key.
 */
export async function signInWithAnotherDevice(
  deps: DeviceApprovalDeps,
  email: string,
  onProgress: (progress: ApprovalProgress) => void,
  signal: AbortSignal,
): Promise<ApprovalOutcome> {
  const now = deps.now ?? (() => Date.now());
  const wait = deps.wait ?? defaultWait;
  const pollEvery = deps.pollEvery ?? 2000;
  let deviceKey: Uint8Array | undefined;
  let root: Uint8Array | undefined;

  async function dropKeys(): Promise<void> {
    for (const handle of [deviceKey, root]) {
      if (handle) await deps.crypto.release(handle).catch(() => undefined);
    }
    deviceKey = root = undefined;
  }

  try {
    onProgress({ step: 'requesting' });
    const made = await deps.crypto.newDeviceKey();
    deviceKey = made.handle;
    const requested = await deps.approval.request({
      email,
      publicKey: encodeB64(made.publicKey),
      device: deps.device(),
    });
    // The words come from our own key. The server's are a cross-check: a request it stored under
    // another key would show up as words that do not match, and nothing is sealed to that key.
    const phrase = await approvalPhrase(made.publicKey);
    if (!samePhrase(phrase, requested.phrase)) throw new ApprovalRefused('phrase');
    onProgress({ step: 'waiting', phrase, expiresAt: requested.expiresAt });

    for (;;) {
      if (signal.aborted) return { status: 'cancelled' };
      const poll = await deps.approval.poll(requested.requestId);
      if (poll.status === 'denied') return { status: 'denied' };
      if (poll.status === 'expired' || poll.status === 'used') return { status: 'expired' };
      if (poll.status === 'approved') {
        if (!poll.sealedKey || !poll.accountId) throw new ApprovalRefused('sealed');
        onProgress({ step: 'signing-in' });
        const handle = deviceKey;
        deviceKey = undefined; // the worker spends it, opened or not
        root = await deps.crypto.openApprovedKey(
          handle,
          poll.accountId,
          requested.requestId,
          decodeB64(poll.sealedKey),
        );
        const { challenge } = await deps.approval.challenge(requested.requestId);
        const tokens = await deps.approval.verify(challenge);
        if (tokens.userId !== poll.accountId) throw new ApprovalRefused('account');
        deps.session.tokenStore.set(tokensFromResponse(tokens, now()));
        rememberDeviceId(tokens.deviceId);
        deps.session.signedIn({
          email,
          userId: tokens.userId,
          deviceId: tokens.deviceId,
          admin: tokens.admin,
        });
        try {
          const keys = await deps.api.accountKeys();
          // The unlock consumes the root handle; releasing it afterwards (in `finally`) is harmless.
          await deps.crypto.unlockWithRoot(tokens.userId, root, {
            keyVersion: keys.keyVersion,
            ...(keys.sealedPrivateKeys
              ? { sealedPrivateKeys: decodeB64(keys.sealedPrivateKeys) }
              : {}),
          });
        } catch (error) {
          deps.session.end();
          throw error;
        }
        deps.session.unlocked();
        return { status: 'signed-in', admin: tokens.admin };
      }
      await wait(pollEvery, signal);
    }
  } catch (error) {
    return { status: 'failed', error };
  } finally {
    await dropKeys();
  }
}
