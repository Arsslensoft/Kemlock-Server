// Keeping the vault open across a reload of the tab. No React in here, so it is tested with fakes.
//
//   keepRootSealed: whenever the vault opens, by any road (password, passkey, Recovery Kit, device
//                   approval, single sign-on, a new account), the worker seals the root key under
//                   this browser's non-extractable key and the sealed blob goes into the tab's
//                   storage. One subscription to the session covers every unlock path;
//   restoreSession: at start, before the router decides where a page may go, takes back the tokens
//                   and, if a sealed copy is there, opens it and opens the vault with it.
//
// The sealed blob opens only in this browser, for this account, device and key version, and only
// inside the worker. If it does not open (the browser's key was reset, the key version moved on,
// the blob is damaged, the server is out of reach) the copy is dropped and the vault stays shut:
// the master password opens it. A shut vault is the safe failure, never a signed-out one, unless
// the server itself says the session is over.
import type { Api } from '@/api/client';
import type { Session } from '@/app/session';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';

export interface PersistenceDeps {
  session: Session;
  /** Where the key version and the sealed private keys come from. */
  api: Pick<Api, 'accountKeys'>;
  crypto: Pick<CryptoPort, 'deviceCopySeal' | 'deviceCopyOpen' | 'unlockWithRoot' | 'release'>;
}

/** Seals the open vault's root key for this tab, unless it already is. Never throws. */
async function sealRoot({ session, api, crypto }: PersistenceDeps): Promise<void> {
  const { userId, deviceId } = session.getState();
  if (!userId || !deviceId) return;
  // A restore opened the vault from a copy that is still there: nothing to redo.
  if (session.sealedRoot.get()) return;
  try {
    const { keyVersion } = await api.accountKeys();
    const sealed = await crypto.deviceCopySeal(userId, deviceId, keyVersion);
    // The vault may have been shut, or another account opened, while this waited.
    const now = session.getState();
    if (now.status !== 'unlocked' || now.userId !== userId || now.deviceId !== deviceId) return;
    session.sealedRoot.set({ sealed: encodeB64(sealed), keyVersion });
  } catch {
    // No copy, so a reload asks for the master password. That is the cost, not a failure.
  }
}

/** Starts sealing a copy each time the vault opens. Returns the function that stops it. */
export function keepRootSealed(deps: PersistenceDeps): () => void {
  let previous = deps.session.getState().status;
  return deps.session.subscribe(() => {
    const { status } = deps.session.getState();
    const opened = status === 'unlocked' && previous !== 'unlocked';
    previous = status;
    if (opened) void sealRoot(deps);
  });
}

/**
 * Brings back this tab's session: the tokens with the vault shut, then, when a sealed copy of the
 * root key is there, the open vault. Settles before the first page is chosen.
 */
export async function restoreSession(deps: PersistenceDeps): Promise<void> {
  const { session, api, crypto } = deps;
  if (!session.restore()) return;
  const held = session.sealedRoot.get();
  if (!held) return;
  const { userId, deviceId } = session.getState();
  if (!userId || !deviceId) return;
  let root: Uint8Array | undefined;
  try {
    // Also where an expired access token is refreshed; a refresh the server refuses ends the session.
    const keys = await api.accountKeys();
    root = await crypto.deviceCopyOpen(userId, deviceId, keys.keyVersion, decodeB64(held.sealed));
    await crypto.unlockWithRoot(userId, root, {
      keyVersion: keys.keyVersion,
      ...(keys.sealedPrivateKeys ? { sealedPrivateKeys: decodeB64(keys.sealedPrivateKeys) } : {}),
    });
    root = undefined;
  } catch {
    if (root) await crypto.release(root).catch(() => undefined);
    session.sealedRoot.clear();
    return;
  }
  session.unlocked();
}
