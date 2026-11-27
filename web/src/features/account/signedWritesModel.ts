// The signed-only flag of the account's own vault: turning it on, and turning it off with the
// password again. No React in here, so it is tested with fakes.
import type { OwnerSigningApi } from '@/api/ownerSigning';
import type { Api } from '@/api/client';
import { type ReauthDeps, reauthenticate } from './deleteAccountModel';

export interface SignedWritesDeps extends ReauthDeps {
  api: Pick<OwnerSigningApi, 'require' | 'clear'> & Pick<Api, 'prelogin' | 'opaqueStart'>;
}

/** The owner of the account's own vault, as the server names it. */
export const ownVault = (userId: string) => `user:${userId}`;

/** Asks that the vault take signed writes only. */
export function requireSignedWrites(deps: Pick<SignedWritesDeps, 'api'>, userId: string): Promise<unknown> {
  return deps.api.require(ownVault(userId));
}

/**
 * Takes the flag off: the password again and, with a second step on, a fresh proof. False, with
 * nothing sent, when the password is missing or a second step is on and the proof is.
 */
export async function clearSignedWrites(
  deps: SignedWritesDeps,
  input: { userId: string; email: string; password: string; proof?: string | undefined; secondStep: boolean },
): Promise<boolean> {
  const proof = input.proof?.trim() ?? '';
  if (input.password === '' || (input.secondStep && proof === '')) return false;
  const password = await reauthenticate(deps, input.email, input.password);
  await deps.api.clear(ownVault(input.userId), password, input.secondStep ? proof : undefined);
  return true;
}
