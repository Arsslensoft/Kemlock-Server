// Deleting the account: what the person must type, and the calls that do it. No React in here, so
// it is tested with fakes.
import type { EraseAccountApi, PasswordProof } from '@/api/eraseAccount';
import type { Api } from '@/api/client';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64, wipe } from '@/lib/b64url';
import { CredentialsError } from '@/lib/errors';

/** Whether what was typed is the account's address: the check that this is no slip of a finger. */
export function confirmsEmail(typed: string, email: string): boolean {
  const wanted = email.trim().toLowerCase();
  return wanted !== '' && typed.trim().toLowerCase() === wanted;
}

export interface DeleteDeps {
  api: Pick<EraseAccountApi, 'erase'> & Pick<Api, 'prelogin' | 'opaqueStart'>;
  crypto: Pick<CryptoPort, 'masterKey' | 'opaqueLoginStart' | 'opaqueLoginFinish'>;
  signOut: () => Promise<void>;
}

/**
 * The password again, as sign-in asks it: the master key from the server's KDF settings, then the
 * OPAQUE exchange, whose last message the server checks. A wrong password fails here, in the
 * client, as at sign-in.
 */
export async function reauthenticate(
  deps: Pick<DeleteDeps, 'api' | 'crypto'>,
  email: string,
  password: string,
): Promise<PasswordProof> {
  const dto = await deps.api.prelogin(email);
  const key = await deps.crypto.masterKey(password.normalize('NFC'), {
    memoryKib: dto.memoryKib,
    iterations: dto.iterations,
    parallelism: dto.parallelism,
    salt: decodeB64(dto.salt),
  });
  try {
    const first = await deps.crypto.opaqueLoginStart(key);
    const started = await deps.api.opaqueStart({ email, request: encodeB64(first.request) });
    const last = await deps.crypto
      .opaqueLoginFinish(first.state, key, decodeB64(started.response))
      .catch(() => {
        throw new CredentialsError();
      });
    wipe(last.exportKey);
    return { loginState: started.loginState, finalization: encodeB64(last.finalization) };
  } finally {
    wipe(key);
  }
}

/**
 * Erases the account with the password and, when a second step is on, a fresh proof, once the
 * address was typed back. `signOut` runs only after the server said yes: its answer is 204, or 202
 * when the admin gave deleted accounts a grace period, and either way the sessions are over.
 */
export async function deleteAccount(
  deps: DeleteDeps,
  input: { email: string; typed: string; password: string; proof?: string | undefined; secondStep: boolean },
): Promise<boolean> {
  const proof = input.proof?.trim() ?? '';
  if (!confirmsEmail(input.typed, input.email) || input.password === '') return false;
  if (input.secondStep && proof === '') return false;
  const password = await reauthenticate(deps, input.email, input.password);
  await deps.api.erase(password, input.secondStep ? proof : undefined);
  await deps.signOut();
  return true;
}
