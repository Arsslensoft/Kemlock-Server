import { clearVault } from '@/features/vault/hooks';
import { vaultCrypto } from '@/crypto-port';
import { queryClient, session } from './services';

/** Cached answers that hold no secret and that routing needs before anyone is signed in. */
const KEPT_QUERIES = new Set(['config', 'placement']);

/** Drops every cached answer that may hold decrypted data (items, spaces, Sends, settings). */
function forgetCachedData(): void {
  queryClient.removeQueries({
    predicate: (query) => !KEPT_QUERIES.has(String(query.queryKey[0])),
  });
}

/** Forgets the keys but keeps the tokens: the master password opens the vault again. */
export async function lockVault(): Promise<void> {
  // First, so that nothing syncs the vault while the keys go.
  session.locked();
  await vaultCrypto.lock();
  clearVault();
}

/**
 * The server ended the session (the refresh token was refused): the page still holds the last
 * user's decrypted items, and the next sign-in in this tab must not see them.
 */
export function forgetEndedSession(): void {
  clearVault();
  forgetCachedData();
}

/** Forgets the keys and the tokens. */
export async function signOut(): Promise<void> {
  await vaultCrypto.lock();
  clearVault();
  session.end();
  queryClient.clear();
}
