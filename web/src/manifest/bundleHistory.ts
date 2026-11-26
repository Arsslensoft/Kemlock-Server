// The bundles an account had before its current key version, for checking a write it signed under
// one (docs/crypto.md, "Signed item writes", "Key versions"). No React in here, so it is tested
// with fakes.
//
// The server keeps every bundle an account has had and serves them by key version, and a server can
// also make one up: a bundle with its own signature under any key. So a bundle for an older version
// is taken only when this browser has already seen that version vouched:
//
//   - the account's own keys, or a member list the space vouches for, vouched the bundle when it
//     was the account's current one, and the browser pinned its fingerprint then (`pin`); and
//   - the bundle the server serves now parses as that account's at that version, carries a valid
//     signature of its own key, and has exactly the pinned fingerprint (`past`).
//
// A browser that never saw the version has nothing to hold the served bundle against, and so gets
// no verdict ("unknown"), which the vault treats as unsigned.
import type { BundlesApi } from '@/api/bundles';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64 } from '@/lib/b64url';
import { parseBundle } from '@/sharing/bundle';
import type { BundlePinStore } from '@/spaces/anchors';
import { uuidText } from './spaceSigner';

export interface BundleHistoryDeps {
  api: Pick<BundlesApi, 'at'>;
  crypto: Pick<CryptoPort, 'verifyBundle' | 'fingerprint' | 'ownFingerprint'>;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
  pins: BundlePinStore;
}

export interface BundleHistory {
  /**
   * Remembers `bundle` as the bundle `writer` has at the key version it carries, once something
   * this browser trusts vouched it as the account's current one. Never throws: a store that can't
   * be written only means a later version check has nothing to hold the server's bundle against.
   */
  pin(bundle: Uint8Array, done?: Set<string>): Promise<void>;
  /** [`pin`], for the account's own bundle at `version`, which only its own keys can name. */
  pinOwn(version: number, done?: Set<string>): Promise<void>;
  /**
   * The bundle of `writer` at `version`, as the server serves it, when it is the one pinned for
   * that version; null for anything else (no pin, no bundle, a bundle that isn't the account's at
   * that version or whose signature fails, or a fingerprint that isn't the pinned one).
   */
  past(writer: string, version: number): Promise<Uint8Array | null>;
}

export function createBundleHistory(deps: BundleHistoryDeps): BundleHistory {
  return {
    async pin(bundle, done) {
      try {
        const account = deps.accountId();
        const parsed = parseBundle(bundle);
        if (!account || !parsed) return;
        const writer = uuidText(parsed.accountId);
        const key = `${writer}/${parsed.keyVersion}`;
        if (done?.has(key)) return;
        await deps.pins.save(account, writer, parsed.keyVersion, await deps.crypto.fingerprint(bundle));
        done?.add(key);
      } catch {
        // Nothing is pinned; a version check for an older bundle has no pin and says unknown.
      }
    },

    async pinOwn(version, done) {
      try {
        const account = deps.accountId();
        const key = `${account}/${version}`;
        if (!account || done?.has(key)) return;
        await deps.pins.save(account, account, version, await deps.crypto.ownFingerprint());
        done?.add(key);
      } catch {
        // Nothing is pinned; see `pin`.
      }
    },

    async past(writer, version) {
      const account = deps.accountId();
      if (!account) return null;
      let pinned: string | undefined;
      try {
        pinned = await deps.pins.load(account, writer, version);
      } catch {
        return null;
      }
      if (pinned === undefined) return null;
      const served = await deps.api.at(writer, version);
      if (!served) return null;
      let bundle: Uint8Array;
      let signature: Uint8Array;
      try {
        bundle = decodeB64(served.publicBundle);
        signature = decodeB64(served.bundleSignature);
      } catch {
        return null;
      }
      const parsed = parseBundle(bundle);
      if (!parsed || uuidText(parsed.accountId) !== writer || parsed.keyVersion !== version) return null;
      if (!(await deps.crypto.verifyBundle(bundle, signature))) return null;
      return (await deps.crypto.fingerprint(bundle)) === pinned ? bundle : null;
    },
  };
}
