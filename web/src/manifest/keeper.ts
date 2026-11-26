// The web vault's use of the signed manifest (docs/crypto.md, "Signed manifest"). No React in here,
// so it is tested with fakes.
//
// What it does, for the account's own vault and for each space the account's items come from:
//
//   - keeps a ledger of what the server served of each item: its revision and the hash of its
//     ciphertext, tombstones included (`served`, from the vault as it takes in each sync page,
//     with whether the envelope opened; `wrote`, from this browser's own writes);
//   - after a sync (`verify`), fetches the owner's manifest, checks its signature (the account's
//     own sig1 key for its own vault; the signer's bundle for a space, through `spaceSigner`) and
//     its counter against the highest this browser has seen (`records`), and sorts the ledger
//     against it (compare.ts). A lower counter, a manifest that doesn't verify or one that has
//     gone missing, items older than their entry, missing items and deleted items that came back
//     are reported in `getWarning()`;
//   - after this browser's own writes (`wrote`), and only then, signs and `PUT`s the next manifest:
//     the last one accepted, with each opened item served at a higher revision taken in, at a
//     counter one above the highest known (compare.ts, `mergeEntries`, says what is never taken
//     in: a rollback, a hidden item, a tombstone the server made, a resurrection, anything flagged).
//
// The manifest is a floor, not a list the server must match exactly: other apps write items too,
// and what they write is newer than, or absent from, the last manifest, which is accepted.
import { isApiError } from '@/api/errors';
import { type ManifestDto, type ManifestsApi, currentCounter } from '@/api/manifests';
import type { ItemDto } from '@/api/types';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import {
  MAX_JUMP,
  type DeletedRecord,
  type Finding,
  type Ledger,
  type Served,
  compareLedger,
  mergeEntries,
  recordDeleted,
  sameEntries,
} from './compare';
import { type Manifest, TOMBSTONE_HASH, ciphertextHash, decodeManifest, encodeManifest } from './format';
import type { ManifestRecord, RecordStore } from './records';

/** What is wrong with a whole manifest. */
export type ManifestProblem =
  /** The server served a lower counter than this browser has seen, or another manifest at the same one. */
  | 'rolled-back'
  /** The one it served is not a manifest of this owner, or its signature does not verify. */
  | 'invalid'
  /** The server has none, though this browser has seen one. */
  | 'dropped';

/** What the page shows: nothing at all when everything matches. */
export interface ManifestWarning {
  manifests: Array<{ owner: string; problem: ManifestProblem }>;
  items: Array<Finding & { owner: string }>;
  /**
   * This browser could not store the signed list it made after a write (too big for the server,
   * a counter it would not go above, no network): until one is stored, a rollback or a hidden
   * item may go unseen.
   */
  publishFailed: boolean;
}

export const NO_WARNING: ManifestWarning = { manifests: [], items: [], publishFailed: false };

/** The most bytes a manifest may hold: the server refuses more (docs/crypto.md, "What the server checks"). */
export const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

/**
 * The bundle of the member who signed a space's manifest, or null when the space does not vouch
 * for that member. This is where the space chain's verified state plugs in: for a chained space
 * the answer must be the bundle the chain records for the signer, who must be `confirmed` with
 * `edit` on at least one collection (docs/crypto.md, "Using the state", Manifest). Until the
 * chain is verified in the web vault, `spaceSigner.ts` answers from the member list the server
 * serves, which is the server's word.
 */
export type SpaceSigner = (space: string, signer: string) => Promise<Uint8Array | null>;

export interface KeeperDeps {
  api: Pick<ManifestsApi, 'get' | 'put'>;
  crypto: Pick<CryptoPort, 'manifestSign' | 'manifestVerifyOwn' | 'manifestVerify'>;
  records: RecordStore;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
  spaceSigner: SpaceSigner;
  /**
   * The ids of the spaces the account is a confirmed member of now. Their manifests are checked
   * whether or not the sync served any item of them (a server that withholds all of a space's
   * items would otherwise go unseen), and a space not on the list is one the account has left: a
   * 404 for it is no manifest dropped. Without it, only spaces that served items are checked.
   */
  spaces?: () => Promise<string[]>;
  now?: () => number;
  /** The most bytes a manifest may hold; the server's limit when left out. */
  maxBytes?: number;
  /** Runs `run` after `ms` and returns what cancels it. */
  schedule?: (run: () => void, ms: number) => () => void;
}

/** How long without a change in the ledger before a sync is checked again anyway. */
export const VERIFY_EVERY_MS = 5 * 60_000;
/** How long after a write the next manifest is signed, so a burst of writes is one manifest. */
export const PUBLISH_AFTER_MS = 2_000;

function defaultSchedule(run: () => void, ms: number): () => void {
  const timer = setTimeout(run, ms);
  return () => clearTimeout(timer);
}

const isOwnVault = (owner: string): boolean => owner.startsWith('user:');

/** What the server served of an item, or null for one that is not a kem1 item this can vouch for. */
async function servedOf(dto: ItemDto, opened: boolean, own: boolean): Promise<Served | null> {
  if (dto.format !== 'kem1') return null;
  if (dto.deleted) {
    return { revision: dto.revision, hash: TOMBSTONE_HASH, deleted: true, opened: false, own };
  }
  if (!dto.ciphertext) return null;
  try {
    const hash = await ciphertextHash(decodeB64(dto.ciphertext));
    return { revision: dto.revision, hash, deleted: false, opened: opened || own, own };
  } catch {
    return null;
  }
}

/** The manifest this browser accepted last, from its record; null when it has none or can't read it. */
function recordedManifest(record: ManifestRecord | undefined): Manifest | null {
  if (!record) return null;
  try {
    return decodeManifest(decodeB64(record.manifest));
  } catch {
    return null;
  }
}

interface Checked {
  /** What to compare against and to build on: the newest manifest known to be good. */
  accepted: Manifest | undefined;
  /** The bytes of `accepted`, base64url. */
  acceptedBytes: string | undefined;
  /** Whether `accepted` is newer than the record: it must be stored. */
  fresh: boolean;
  /** The highest counter known, which the next manifest goes above. */
  floor: number;
  problem: ManifestProblem | undefined;
  record: ManifestRecord | undefined;
  key: string;
}

export function createManifestKeeper(deps: KeeperDeps) {
  const now = deps.now ?? (() => Date.now());
  const schedule = deps.schedule ?? defaultSchedule;
  let ledgers = new Map<string, Ledger>();
  /** Items the server served lower than it already had, this session: `owner|id`. */
  const anomalies = new Map<string, Finding & { owner: string }>();
  const results = new Map<string, { problem?: ManifestProblem; findings: Finding[] }>();
  const pending = new Set<string>();
  /** Owners the server refused our manifest for (not allowed to write); not asked again. */
  const refused = new Set<string>();
  /** Owners whose last manifest could not be stored. */
  const failed = new Set<string>();
  let complete = false;
  let dirty = false;
  let lastVerify = 0;
  /** Bumped by `reset`: work that began before it drops what it found. */
  let epoch = 0;
  let warning: ManifestWarning = NO_WARNING;
  let cancelTimer: (() => void) | undefined;
  let queue: Promise<void> = Promise.resolve();
  /** Ledger updates, in the order the server served them; hashing runs ahead of it, in parallel. */
  let ledgerTail: Promise<void> = Promise.resolve();
  const listeners = new Set<() => void>();

  function setWarning(next: ManifestWarning): void {
    warning = next;
    for (const listener of listeners) listener();
  }

  function publishWarning(): void {
    const manifests: ManifestWarning['manifests'] = [];
    const items: ManifestWarning['items'] = [];
    for (const [owner, result] of results) {
      if (result.problem) manifests.push({ owner, problem: result.problem });
      for (const finding of result.findings) items.push({ ...finding, owner });
    }
    const seen = new Set(items.map((item) => `${item.owner}|${item.id}`));
    for (const [key, finding] of anomalies) if (!seen.has(key)) items.push(finding);
    const publishFailed = failed.size > 0;
    setWarning(
      manifests.length === 0 && items.length === 0 && !publishFailed
        ? NO_WARNING
        : { manifests, items, publishFailed },
    );
  }

  /** Runs `task` after everything queued before it, whatever became of that. */
  function serially(task: () => Promise<void>): Promise<void> {
    const next = queue.then(task, task);
    queue = next.catch(() => undefined);
    return next;
  }

  function ledgerOf(owner: string): Ledger {
    let ledger = ledgers.get(owner);
    if (!ledger) {
      ledger = new Map();
      ledgers.set(owner, ledger);
    }
    return ledger;
  }

  /** A manifest the server served, if it is one of `owner`'s with a good signature; else null. */
  async function read(
    owner: string,
    dto: ManifestDto,
  ): Promise<{ manifest: Manifest; bytes: Uint8Array } | null> {
    let bytes: Uint8Array;
    let signature: Uint8Array;
    let manifest: Manifest | null;
    try {
      bytes = decodeB64(dto.manifest);
      signature = decodeB64(dto.signature);
      manifest = decodeManifest(bytes);
    } catch {
      return null;
    }
    if (!manifest || manifest.owner !== owner || manifest.counter !== dto.counter) return null;
    if (isOwnVault(owner)) {
      // The account's own key, never a bundle the server served.
      if (!(await deps.crypto.manifestVerifyOwn(bytes, signature))) return null;
    } else {
      // A failure to reach the member list is not a verdict: it propagates.
      const bundle = await deps.spaceSigner(owner.slice('space:'.length), dto.signer);
      if (!bundle || !(await deps.crypto.manifestVerify(bundle, bytes, signature))) return null;
    }
    return { manifest, bytes };
  }

  async function check(owner: string, account: string): Promise<Checked> {
    const key = `${account}|${owner}`;
    const record = await deps.records.get(key);
    const local = recordedManifest(record);
    const served = await deps.api.get(owner);
    const checked: Checked = {
      accepted: local ?? undefined,
      acceptedBytes: local ? record?.manifest : undefined,
      fresh: false,
      floor: Math.max(local?.counter ?? 0, record?.counter ?? 0),
      problem: undefined,
      record,
      key,
    };
    if (!served) {
      if (record) checked.problem = 'dropped';
      return checked;
    }
    const verified = await read(owner, served);
    if (!verified) {
      checked.problem = 'invalid';
      return checked;
    }
    // Counters go up by one a write: one far above any this browser has seen is a server trying to
    // use up the counter so that nothing can be signed above it.
    if (verified.manifest.counter > (record?.counter ?? 0) + MAX_JUMP) {
      checked.problem = 'invalid';
      return checked;
    }
    const encoded = encodeB64(verified.bytes);
    if (
      record &&
      (verified.manifest.counter < record.counter ||
        (verified.manifest.counter === record.counter && encoded !== record.manifest))
    ) {
      checked.problem = 'rolled-back';
      return checked;
    }
    checked.accepted = verified.manifest;
    checked.acceptedBytes = encoded;
    checked.fresh = !record || verified.manifest.counter > record.counter;
    checked.floor = Math.max(checked.floor, verified.manifest.counter);
    return checked;
  }

  async function verifyOwner(
    owner: string,
    account: string,
    mine: number,
    knownMember: boolean,
  ): Promise<void> {
    const checked = await check(owner, account);
    if (mine !== epoch) return;
    // Without the list of spaces, a space with no manifest may be one the account has just left.
    if (!knownMember && checked.problem === 'dropped') checked.problem = undefined;
    const ledger = ledgers.get(owner) ?? new Map<string, Served>();
    const deletedBefore: DeletedRecord = checked.record?.deleted ?? {};
    const findings = checked.accepted ? compareLedger(checked.accepted, deletedBefore, ledger) : [];
    if (checked.accepted && checked.acceptedBytes) {
      const deleted = recordDeleted(deletedBefore, checked.accepted, ledger, now());
      if (checked.fresh || JSON.stringify(deleted) !== JSON.stringify(deletedBefore)) {
        await deps.records.put(checked.key, {
          manifest: checked.acceptedBytes,
          counter: checked.accepted.counter,
          deleted,
        });
      }
    }
    if (mine !== epoch) return;
    results.set(owner, { ...(checked.problem ? { problem: checked.problem } : {}), findings });
  }

  async function runVerify(): Promise<void> {
    const account = deps.accountId();
    if (!account || !complete) return;
    const mine = epoch;
    // A change that lands while this runs makes the next sync check again.
    dirty = false;
    let member: Set<string> | null = null;
    try {
      const listed = await deps.spaces?.();
      if (listed) member = new Set(listed.map((id) => `space:${id}`));
    } catch {
      // No list: spaces that served items are checked, and a missing manifest says nothing.
    }
    const own = `user:${account}`;
    const owners = new Set([own, ...(member ?? [...ledgers.keys()])]);
    if (member) for (const owner of results.keys()) if (!owners.has(owner)) results.delete(owner);
    for (const owner of owners) {
      try {
        await verifyOwner(owner, account, mine, member !== null || owner === own);
      } catch {
        // The server or the member list could not be reached: what was found before stands.
      }
      if (mine !== epoch) return;
    }
    lastVerify = now();
    publishWarning();
  }

  async function publish(owner: string, account: string, mine: number): Promise<void> {
    let above = 0;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const checked = await check(owner, account);
      if (mine !== epoch) return;
      const ledger = ledgers.get(owner);
      if (!ledger) return;
      const base = checked.accepted;
      // What the check flags, and what this device saw deleted, is not signed in: a write of the
      // person's own must not make a rollback, a hidden item or a resurrection permanent.
      const deleted = recordDeleted(checked.record?.deleted ?? {}, base, ledger, now());
      const skip = new Set<string>(
        (base ? compareLedger(base, deleted, ledger) : []).map((finding) => finding.id),
      );
      for (const anomaly of anomalies.values()) if (anomaly.owner === owner) skip.add(anomaly.id);
      const entries = mergeEntries(base?.entries ?? [], ledger, deleted, skip);
      if (base ? sameEntries(entries, base.entries) : entries.length === 0) return;
      const counter = Math.max(checked.floor, above) + 1;
      const next: Manifest = { owner, counter, entries };
      const bytes = encodeManifest(next);
      if (bytes.length > (deps.maxBytes ?? MAX_MANIFEST_BYTES)) throw new Error('size');
      const signature = await deps.crypto.manifestSign(bytes);
      try {
        await deps.api.put(owner, { manifest: encodeB64(bytes), signature: encodeB64(signature) });
      } catch (error) {
        if (isApiError(error) && error.status === 409) {
          // Another device wrote first, or the server holds a counter this browser never saw:
          // go above whatever it says.
          const held = currentCounter(error) ?? counter;
          // A counter far above any known is not adopted: nothing could be signed above it.
          if (held > Math.max(checked.floor, above) + MAX_JUMP) throw new Error('counter');
          above = Math.max(above, held);
          continue;
        }
        if (isApiError(error) && (error.status === 403 || error.status === 404)) refused.add(owner);
        throw error;
      }
      await deps.records.put(checked.key, {
        manifest: encodeB64(bytes),
        counter,
        deleted: recordDeleted(deleted, next, ledger, now()),
      });
      return;
    }
  }

  function planPublish(): void {
    cancelTimer?.();
    cancelTimer = schedule(() => void flush(), PUBLISH_AFTER_MS);
  }

  /** Signs and stores the next manifest of every owner written to, now. */
  function flush(): Promise<void> {
    cancelTimer?.();
    cancelTimer = undefined;
    const owners = [...pending].filter((owner) => !refused.has(owner));
    pending.clear();
    const account = deps.accountId();
    if (!account || owners.length === 0) return Promise.resolve();
    const mine = epoch;
    return serially(async () => {
      for (const owner of owners) {
        try {
          await publish(owner, account, mine);
          failed.delete(owner);
        } catch (error) {
          // Not allowed to write a space's manifest is no failure. Anything else (too big, a
          // counter it would not go above, no network) is shown, and the next write tries again.
          if (!(isApiError(error) && (error.status === 403 || error.status === 404))) failed.add(owner);
        }
        if (mine !== epoch) return;
      }
      publishWarning();
    });
  }

  return {
    /** Forgets everything but what is stored: a sync starts from scratch, or the vault locks. */
    reset(): void {
      epoch += 1;
      ledgers = new Map();
      ledgerTail = Promise.resolve();
      anomalies.clear();
      results.clear();
      pending.clear();
      refused.clear();
      failed.clear();
      cancelTimer?.();
      cancelTimer = undefined;
      complete = false;
      dirty = false;
      lastVerify = 0;
      setWarning(NO_WARNING);
    },

    /**
     * Takes in an item the server served in a sync, as the vault takes it in (`opened`: its
     * envelope opened). Hashing starts at once and runs in parallel; the ledger is updated in the
     * order the items were served. Anything served lower than before is flagged. A tombstone is
     * recorded as served, but never signed in for an item this browser did not delete.
     */
    served(dto: ItemDto, opened: boolean): void {
      const mine = epoch;
      const hashing = servedOf(dto, opened, false);
      ledgerTail = ledgerTail.then(async () => {
        const served = await hashing;
        if (!served || mine !== epoch) return;
        const ledger = ledgerOf(dto.owner);
        const have = ledger.get(dto.id);
        if (have) {
          const lower = served.revision < have.revision;
          const back = served.revision <= have.revision && have.deleted && !served.deleted;
          if (lower || back) {
            anomalies.set(`${dto.owner}|${dto.id}`, {
              owner: dto.owner,
              id: dto.id,
              verdict: have.deleted && !served.deleted ? 'resurrected' : 'rolled-back',
              revision: served.revision,
              manifestRevision: have.revision,
            });
            publishWarning();
          }
          if (served.revision <= have.revision) return;
        }
        ledger.set(dto.id, served);
        dirty = true;
      });
    },

    /** Takes in what this browser just wrote, and plans the manifest that lists it. */
    wrote(items: ItemDto[]): Promise<void> {
      const mine = epoch;
      const hashing = items.map((dto) => servedOf(dto, true, true));
      ledgerTail = ledgerTail.then(async () => {
        const all = await Promise.all(hashing);
        items.forEach((dto, index) => {
          const served = all[index];
          if (!served || mine !== epoch) return;
          const ledger = ledgerOf(dto.owner);
          const have = ledger.get(dto.id);
          if (have && have.revision > served.revision) return;
          ledger.set(dto.id, served);
          pending.add(dto.owner);
          dirty = true;
        });
        if (pending.size > 0 && mine === epoch) planPublish();
      });
      return ledgerTail;
    },

    /**
     * The last manifest of `owner` that is good: the server's, fetched and checked as a sync's is
     * (its signature, its signer, its counter against the highest seen), or null when there is
     * none or something is wrong with it. What an item has to match to be taken as accepted.
     * Throws when the server or the member list can't be reached.
     */
    async acceptedManifest(owner: string): Promise<Manifest | null> {
      const account = deps.accountId();
      if (!account) return null;
      const checked = await check(owner, account);
      return checked.problem ? null : (checked.accepted ?? null);
    },

    /** Resolves once every item told to `served` and `wrote` so far is in the ledger. */
    settled: (): Promise<void> => ledgerTail,

    /** The ledger now holds everything the server serves: a check can say what is missing. */
    markComplete(): void {
      complete = true;
    },

    /**
     * Checks the ledger against the manifests, when something changed or it has been a while (or
     * `force`). Never throws: a server that can't be reached leaves the last answer standing.
     */
    verify(force = false): Promise<void> {
      if (!complete) return Promise.resolve();
      if (!force && !dirty && now() - lastVerify < VERIFY_EVERY_MS) return Promise.resolve();
      return serially(async () => {
        await ledgerTail;
        await runVerify();
      }).catch(() => undefined);
    },

    flush,

    getWarning: (): ManifestWarning => warning,
    subscribe(listener: () => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export type ManifestKeeper = ReturnType<typeof createManifestKeeper>;
