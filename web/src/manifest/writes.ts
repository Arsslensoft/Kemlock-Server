// What the web vault makes of the write signature of an item the server serves (docs/crypto.md,
// "Signed item writes"). No React in here, so it is tested with fakes.
//
// Every `kem1` revision the server serves, a tombstone included, may carry the signature of the
// account that wrote it. The check says one of:
//
//   signed    the signature verifies and its writer is one this browser can vouch for: the account
//             itself (its own sig1 key, never a bundle the server served), or, in a space, a member
//             the space vouches for (`SpaceSigner`);
//   unsigned  none came;
//   invalid   one came and fails, or it names another account for the account's own vault;
//   unknown   it can't be checked now: the vault is locked, or the space doesn't vouch for the
//             writer (a member who has left, say), or the member list couldn't be reached.
//
// A `bw` item has no `kem1` envelope to sign: it has no verdict at all.
import type { ItemDto } from '@/api/types';
import { writeFields } from '@/api/signedWrites';
import type { CryptoPort } from '@/crypto-port';
import type { SpaceSigner } from './keeper';

export type WriteVerdict = 'signed' | 'unsigned' | 'invalid' | 'unknown';

export interface WriteCheckerDeps {
  crypto: Pick<CryptoPort, 'itemWriteVerifyOwn' | 'itemWriteVerify'>;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
  /** The bundle of a member the space vouches for, or null (see `SpaceSigner`). */
  spaceSigner: SpaceSigner;
}

export interface WriteChecker {
  /** The verdict for an item as served, or `undefined` for one that is not a `kem1` item. */
  verdict(dto: ItemDto): Promise<WriteVerdict | undefined>;
}

export function createWriteChecker(deps: WriteCheckerDeps): WriteChecker {
  return {
    async verdict(dto) {
      if (dto.format !== 'kem1') return undefined;
      const { writer, writerKeyVersion, writeSignature } = dto;
      if (!writer && writerKeyVersion == null && !writeSignature) return 'unsigned';
      if (!writer || writerKeyVersion == null || !writeSignature) return 'invalid';
      const fields = { ...writeFields(dto), writer, writerKeyVersion };
      try {
        if (dto.owner.startsWith('user:')) {
          // A person's own vault is written by that person only, and checked with their own key.
          if (dto.owner !== `user:${writer}`) return 'invalid';
          if (deps.accountId() !== writer) return 'unknown';
          return (await deps.crypto.itemWriteVerifyOwn(fields, writeSignature)) ? 'signed' : 'invalid';
        }
        const space = dto.owner.slice('space:'.length);
        const bundle = await deps.spaceSigner(space, writer);
        if (!bundle) return 'unknown';
        return (await deps.crypto.itemWriteVerify(bundle, fields, writeSignature)) ? 'signed' : 'invalid';
      } catch {
        // The worker is locked, or the member list could not be reached: no verdict.
        return 'unknown';
      }
    },
  };
}
