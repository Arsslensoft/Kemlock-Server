// Deleting the account: what the person must type, and the one call that does it. No React in
// here, so it is tested with fakes.
import type { EraseAccountApi } from '@/api/eraseAccount';

/** Whether what was typed is the account's address: the check that this is no slip of a finger. */
export function confirmsEmail(typed: string, email: string): boolean {
  const wanted = email.trim().toLowerCase();
  return wanted !== '' && typed.trim().toLowerCase() === wanted;
}

/**
 * Erases the account with a fresh proof, once the address was typed back. `signOut` runs only after
 * the server said yes: its answer is 204, or 202 when the admin gave deleted accounts a grace
 * period, and either way the sessions are over.
 */
export async function deleteAccount(
  deps: { api: Pick<EraseAccountApi, 'erase'>; signOut: () => Promise<void> },
  input: { email: string; typed: string; proof: string },
): Promise<boolean> {
  if (!confirmsEmail(input.typed, input.email) || input.proof.trim() === '') return false;
  await deps.api.erase(input.proof.trim());
  await deps.signOut();
  return true;
}
