// Signing in with a passkey (docs/crypto.md, "The passkey PRF wrap of the root key"). No React in
// here, so it is tested with fakes.
//
//   1. the server's options (a discoverable credential, so no account is named) go to the
//      authenticator with the PRF extension asked for;
//   2. its answer, bound to this browser's DPoP key by the challenge, is traded for tokens;
//   3. with a PRF output and the passkey's wrap of the root key, the worker opens the root key and
//      the vault opens, with no master password;
//   4. without them (a passkey made with no PRF, or an authenticator that gave none) the person is
//      signed in with the vault shut, and the master password opens it.
import type { Api } from '@/api/client';
import { tokensFromResponse } from '@/api/client';
import type { PasskeySignInApi } from '@/api/passkeys';
import type { DeviceDto } from '@/api/types';
import type { Session } from '@/app/session';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, wipe } from '@/lib/b64url';
import { rememberDeviceId } from '@/lib/device';
import type { PasskeyAnswer } from '@/lib/passkey';

export interface PasskeySignInDeps {
  passkeys: PasskeySignInApi;
  api: Pick<Api, 'accountKeys'>;
  crypto: Pick<CryptoPort, 'prfOpenRoot' | 'unlockWithRoot' | 'release'>;
  session: Session;
  device: () => DeviceDto;
  /** Asks the authenticator, with the PRF extension. */
  assert: (options: Record<string, unknown>) => Promise<PasskeyAnswer>;
  now?: () => number;
}

export type PasskeySignInResult =
  /** The vault is open. */
  | { status: 'unlocked'; admin: boolean }
  /** Signed in, the vault shut: the master password opens it. */
  | { status: 'needs-password'; admin: boolean };

/** `email` is what the person typed; it is only shown, the passkey says who signs in. */
export async function signInWithPasskey(
  deps: PasskeySignInDeps,
  email: string,
): Promise<PasskeySignInResult> {
  const now = deps.now ?? (() => Date.now());
  const { options, challenge } = await deps.passkeys.options();
  const answer = await deps.assert(options);
  try {
    const signed = await deps.passkeys.verify({
      challenge,
      credential: answer.credential,
      device: deps.device(),
    });
    const { tokens } = signed;
    deps.session.tokenStore.set(tokensFromResponse(tokens, now()));
    rememberDeviceId(tokens.deviceId);
    deps.session.signedIn({
      email,
      userId: tokens.userId,
      deviceId: tokens.deviceId,
      admin: tokens.admin,
    });
    if (!signed.prf || !answer.prfOutput) {
      return { status: 'needs-password', admin: tokens.admin };
    }
    let root: Uint8Array | undefined;
    try {
      root = await deps.crypto.prfOpenRoot(
        answer.prfOutput,
        answer.credentialId,
        tokens.userId,
        signed.prf.keyVersion,
        decodeB64(signed.prf.wrappedKey),
      );
      const keys = await deps.api.accountKeys();
      await deps.crypto.unlockWithRoot(tokens.userId, root, {
        keyVersion: keys.keyVersion,
        ...(keys.sealedPrivateKeys ? { sealedPrivateKeys: decodeB64(keys.sealedPrivateKeys) } : {}),
      });
      root = undefined;
    } catch {
      if (root) await deps.crypto.release(root).catch(() => undefined);
      // The wrap did not open (a stale key version, say): signed in, vault shut.
      return { status: 'needs-password', admin: tokens.admin };
    }
    deps.session.unlocked();
    return { status: 'unlocked', admin: tokens.admin };
  } finally {
    wipe(answer.prfOutput);
  }
}
