// Making and keeping a Recovery Kit (docs/crypto.md, "The Recovery Kit"). No React in here, so it
// is tested with fakes.
//
//   1. the key worker makes the kit: a 2-of-3 split of a new key, and the root key wrapped under
//      it. The pieces' text comes back to be shown once; the root key does not leave the worker;
//   2. the person confirms they kept one by typing it back;
//   3. only then is the record sent to the server (the wrap, the kit id, the key version), so a
//      kit that was never confirmed is never kept. Replacing it takes a fresh proof.
import type { RecoveryKitApi, RecoveryKitDto } from '@/api/recoveryKit';
import type { Proof } from '@/api/twoStep';
import type { CryptoPort } from '@/crypto-port';
import { encodeB64 } from '@/lib/b64url';
import { isOneOf } from '@/lib/kitPiece';

/** A kit the worker made and the server does not hold yet. */
export interface PendingKit {
  kitId: string;
  /** The text of each piece: shown once, never stored by the page. */
  pieces: string[];
  keyVersion: number;
  /** base64url. */
  wrappedKey: string;
}

export async function makeKit(crypto: Pick<CryptoPort, 'kitMake'>): Promise<PendingKit> {
  const made = await crypto.kitMake();
  return {
    kitId: made.kitId,
    pieces: made.pieces,
    keyVersion: made.keyVersion,
    wrappedKey: encodeB64(made.wrappedKey),
  };
}

/** Whether what was typed is one of the new kit's pieces. */
export function confirmsPiece(kit: PendingKit, typed: string): boolean {
  return isOneOf(typed, kit.pieces);
}

/**
 * Keeps the kit on the server: the first one, or, with a `proof`, in place of the old one (whose
 * pieces then stop working).
 */
export function keepKit(
  api: Pick<RecoveryKitApi, 'create' | 'replace'>,
  kit: PendingKit,
  proof?: Proof,
): Promise<RecoveryKitDto> {
  const record = { kitId: kit.kitId, keyVersion: kit.keyVersion, wrappedKey: kit.wrappedKey };
  return proof === undefined ? api.create(record) : api.replace(record, proof);
}
