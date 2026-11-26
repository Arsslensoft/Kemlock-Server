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
//             writer (a member it never had, say; one taken out since still counts, for what they
//             signed before), or the member list couldn't be reached, or the
//             write names an older key version of the writer whose bundle this browser has no pin
//             for (bundleHistory.ts).
//
// A write names the key version it was signed under. At the writer's current version it is checked
// with the account's own key (its own vault) or the bundle the space vouches for; at an older one
// with that version's bundle from the server's history, taken only when it is the one this browser
// pinned when it was current. A version newer than the current one is unknown.
//
// A `bw` item has no `kem1` envelope to sign: it has no verdict at all.
import type { ItemDto } from '@/api/types';
import { writeFields } from '@/api/signedWrites';
import type { CryptoPort } from '@/crypto-port';
import { parseBundle } from '@/sharing/bundle';
import type { BundleHistory } from './bundleHistory';
import type { SpaceSigner } from './keeper';

export type WriteVerdict = 'signed' | 'unsigned' | 'invalid' | 'unknown';

export interface WriteCheckerDeps {
  crypto: Pick<CryptoPort, 'itemWriteVerifyOwn' | 'itemWriteVerify' | 'ownKeyVersion'>;
  /** The bundles before an account's current key version. Without it an older version is unknown. */
  history?: BundleHistory;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
  /** The bundle of a member the space vouches for, or null (see `SpaceSigner`). */
  spaceSigner: SpaceSigner;
  /** The time in ms; for tests. */
  now?: () => number;
}

export interface WriteChecker {
  /**
   * Starts a sync: what was looked up for the one before (a space's member list, a writer's past
   * bundle) is asked again. Within a sync each is asked once, however many items name it.
   */
  beginSync(): void;
  /** The verdict for an item as served, or `undefined` for one that is not a `kem1` item. */
  verdict(dto: ItemDto): Promise<WriteVerdict | undefined>;
}

/** How long what was looked up is kept when no sync says otherwise. */
const MEMO_MS = 30_000;

export function createWriteChecker(deps: WriteCheckerDeps): WriteChecker {
  /** The versions pinned this session: once each is enough. */
  const pinned = new Set<string>();
  // One sync names the same space and writer for many items, and each lookup asks the server
  // (the member list and the space, a past bundle), so the answers are kept for the sync. A failure
  // is not kept.
  const now = deps.now ?? Date.now;
  let memo = new Map<string, Promise<Uint8Array | null>>();
  let since = now();
  const memoized = (key: string, ask: () => Promise<Uint8Array | null>): Promise<Uint8Array | null> => {
    if (now() - since > MEMO_MS) {
      memo = new Map();
      since = now();
    }
    let answer = memo.get(key);
    if (!answer) {
      answer = ask();
      memo.set(key, answer);
      answer.catch(() => memo.delete(key));
    }
    return answer;
  };
  const spaceBundle = (space: string, writer: string) =>
    memoized(`space/${space}/${writer}`, () => deps.spaceSigner(space, writer, { former: true }));
  const pastBundle = (writer: string, version: number) =>
    memoized(`past/${writer}/${version}`, async () => (await deps.history?.past(writer, version)) ?? null);
  return {
    beginSync() {
      memo = new Map();
      since = now();
    },
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
          const current = await deps.crypto.ownKeyVersion();
          if (writerKeyVersion > current) return 'unknown';
          if (writerKeyVersion === current) {
            await deps.history?.pinOwn(current, pinned);
            return (await deps.crypto.itemWriteVerifyOwn(fields, writeSignature)) ? 'signed' : 'invalid';
          }
          const past = await pastBundle(writer, writerKeyVersion);
          if (!past) return 'unknown';
          return (await deps.crypto.itemWriteVerify(past, fields, writeSignature)) ? 'signed' : 'invalid';
        }
        const space = dto.owner.slice('space:'.length);
        const bundle = await spaceBundle(space, writer);
        const parsed = bundle ? parseBundle(bundle) : null;
        if (!bundle || !parsed) return 'unknown';
        if (writerKeyVersion > parsed.keyVersion) return 'unknown';
        let signer = bundle;
        if (writerKeyVersion === parsed.keyVersion) {
          // This account's own bundle is known for certain. Another member's is the server's word
          // until the space chain is verified here, and a pin of it would hold the server to a bundle
          // it made up, so nothing is pinned and an older version of theirs has no verdict.
          if (writer === deps.accountId() || deps.spaceSigner.vouched === true) {
            await deps.history?.pin(bundle, pinned);
          }
        } else {
          const past = await pastBundle(writer, writerKeyVersion);
          if (!past) return 'unknown';
          signer = past;
        }
        return (await deps.crypto.itemWriteVerify(signer, fields, writeSignature)) ? 'signed' : 'invalid';
      } catch {
        // The worker is locked, or the member list could not be reached: no verdict.
        return 'unknown';
      }
    },
  };
}
