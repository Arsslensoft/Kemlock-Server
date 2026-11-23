import { clearVault } from '@/features/vault/hooks';
import { vaultCrypto } from '@/crypto-port';
import { queryClient, session } from './services';

/** Forgets the keys but keeps the tokens: the master password opens the vault again. */
export async function lockVault(): Promise<void> {
  // First, so that nothing syncs the vault while the keys go.
  session.locked();
  await vaultCrypto.lock();
  clearVault();
}

/** Forgets the keys and the tokens. */
export async function signOut(): Promise<void> {
  await vaultCrypto.lock();
  clearVault();
  session.end();
  queryClient.clear();
}
