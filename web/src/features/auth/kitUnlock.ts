// Opening the vault with a Recovery Kit (docs/crypto.md, "The Recovery Kit"). No React in here, so
// it is tested with fakes.
//
//   1. each piece typed or scanned is read in the key worker (`kitReadPiece`), so a typo is told
//      at once, with the checksum, and `kitCheckPieces` says when two are of different kits or the
//      same piece twice;
//   2. with the account's kit record from the server, the worker rebuilds the kit key from 2
//      pieces, opens the wrap of the root key and keeps the root key behind a handle;
//   3. `unlockWithRoot` opens the vault with that handle. The page never sees a key.
import type { Api } from '@/api/client';
import type { RecoveryKitApi } from '@/api/recoveryKit';
import type { Session } from '@/app/session';
import type { KitPieceRead, KitProblem } from '@/crypto/types';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64 } from '@/lib/b64url';

export interface KitUnlockDeps {
  kit: Pick<RecoveryKitApi, 'show'>;
  api: Pick<Api, 'accountKeys'>;
  crypto: Pick<CryptoPort, 'kitOpenRoot' | 'unlockWithRoot' | 'release'>;
  session: Session;
}

export type KitUnlockResult =
  | { status: 'unlocked' }
  /** The account has no kit on this server. */
  | { status: 'no-kit' }
  /** The kit is for an older key of the account: no piece opens it. */
  | { status: 'stale' }
  /** The pieces do not open this account's kit (another or an older kit). */
  | { status: 'wrong' };

/** What the screen says about one piece typed so far. */
export type PieceCheck =
  | { status: 'empty' }
  | { status: 'ok'; read: Extract<KitPieceRead, { kitId: string }> }
  | { status: 'bad'; problem: KitProblem };

/** Reads each piece, then says whether the readable ones are of one kit with none twice. */
export async function checkPieces(
  crypto: Pick<CryptoPort, 'kitReadPiece' | 'kitCheckPieces'>,
  texts: readonly string[],
): Promise<{ each: PieceCheck[]; together: KitProblem | undefined }> {
  const each: PieceCheck[] = [];
  for (const text of texts) {
    if (text.trim() === '') {
      each.push({ status: 'empty' });
      continue;
    }
    const read = await crypto.kitReadPiece(text);
    if (read.problem === undefined) each.push({ status: 'ok', read });
    else each.push({ status: 'bad', problem: read.problem });
  }
  const readable = texts.filter((_, i) => each[i]?.status === 'ok');
  const together = readable.length > 1 ? (await crypto.kitCheckPieces(readable)).problem : undefined;
  return { each, together };
}

export async function unlockWithKit(
  deps: KitUnlockDeps,
  accountId: string,
  pieces: string[],
): Promise<KitUnlockResult> {
  const kit = await deps.kit.show();
  if (!kit) return { status: 'no-kit' };
  if (!kit.current) return { status: 'stale' };
  let root: Uint8Array | undefined;
  try {
    root = await deps.crypto.kitOpenRoot(
      pieces,
      kit.kitId,
      accountId,
      kit.keyVersion,
      decodeB64(kit.wrappedKey),
    );
  } catch {
    return { status: 'wrong' };
  }
  try {
    const keys = await deps.api.accountKeys();
    await deps.crypto.unlockWithRoot(accountId, root, {
      keyVersion: keys.keyVersion,
      ...(keys.sealedPrivateKeys ? { sealedPrivateKeys: decodeB64(keys.sealedPrivateKeys) } : {}),
    });
    root = undefined;
  } finally {
    if (root) await deps.crypto.release(root).catch(() => undefined);
  }
  deps.session.unlocked();
  return { status: 'unlocked' };
}
