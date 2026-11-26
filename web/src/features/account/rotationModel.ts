// Rotating the account's root key, from the browser's side (docs/crypto.md, "Rotating the root key").
// No React in here, so it is tested with fakes.
//
// The key worker makes the new root key and key pair, moves every item and Send to them, and wraps
// the new root key for every way in the person keeps; this only carries what the server stores.
// The order matters:
//
//   1. read the plan, and refuse an account the web vault can't rotate safely;
//   2. start the rotation in the worker;
//   3. move every live item and stage it in batches, with progress; nothing a device can see changes;
//   4. move the Sends, make the new kit and this browser's copy;
//   5. prove the password again and wrap the new root key under it, then install, all at once
//      (the server checks everything in one transaction and writes it, or nothing);
//   6. on `rotation-incomplete` (another device wrote meanwhile) stage what changed and try again;
//   7. make the new keys the account's in the worker.
//
// What the web vault does not carry over, and the page says so before it starts: a passkey's PRF
// wrap (it needs the passkey touched), an emergency contact's box (it needs their current bundle)
// and a space recovery enrolment are removed, so the person sets each up again; and an account that
// is in a space is refused, because the space keys must move to the new keys too.
import { ApiError } from '@/api/errors';
import type { Api } from '@/api/client';
import type { Proof } from '@/api/twoStep';
import type { InstallRequest, RotationApi, RotationPlanDto, Rotated } from '@/api/rotation';
import type { SendsApi } from '@/api/sends';
import type { ItemDto } from '@/api/types';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { CredentialsError } from '@/lib/errors';

/** The page can't rotate this account. */
export class RotationBlockedError extends Error {
  readonly reason: 'spaces' | 'compatible' | 'unsupported-items';
  constructor(reason: 'spaces' | 'compatible' | 'unsupported-items') {
    super(`Keys can't be rotated here: ${reason}`);
    this.name = 'RotationBlockedError';
    this.reason = reason;
  }
}

/** The password was not it. */
export class RotationPasswordError extends Error {
  constructor() {
    super('The master password is wrong');
    this.name = 'RotationPasswordError';
  }
}

export type RotationPhase = 'plan' | 'items' | 'sends' | 'install' | 'done';

export interface RotationProgress {
  phase: RotationPhase;
  done: number;
  total: number;
}

export interface RotationDeps {
  api: RotationApi & Pick<Api, 'prelogin' | 'opaqueStart' | 'sync'>;
  sends: Pick<SendsApi, 'list'>;
  crypto: Pick<
    CryptoPort,
    | 'masterKey'
    | 'opaqueLoginStart'
    | 'opaqueLoginFinish'
    | 'release'
    | 'rotationStart'
    | 'rotationResealItem'
    | 'rotationResealSend'
    | 'rotationWrapPassword'
    | 'rotationKitMake'
    | 'rotationDeviceCopySeal'
    | 'rotationCommit'
    | 'rotationAbort'
  >;
  /** The signed-in account and device. */
  userId: string;
  deviceId: string;
  randomBytes?: (length: number) => Uint8Array;
}

export interface RotationInput {
  email: string;
  password: string;
  /** The second step's fresh proof, when one is on. */
  proof?: Proof;
  /** Makes a new Recovery Kit; one the account has is replaced either way, or dropped without it. */
  makeKit: boolean;
}

/** What a rotation leaves for the person: the new kit to save, and what it removed. */
export interface RotationResult {
  keyVersion: number;
  fingerprint: string;
  kit: { kitId: string; pieces: string[] } | null;
  /** The live items as they are now, re-encrypted: what the next signed manifest lists. */
  rewritten: ItemDto[];
  tokens: Rotated['tokens'];
  removed: { passkeys: number; emergency: number; recovery: number };
}

/** Items per staging request, and the most encoded bytes one request carries (the body limit is 2 MiB). */
const BATCH_ITEMS = 200;
const BATCH_BYTES = 1_200_000;
/** Rounds of "stage what changed, install again" before giving up. */
const MAX_ROUNDS = 5;

type Resealed = Awaited<ReturnType<RotationDeps['crypto']['rotationResealItem']>>;

/** Every live item of the account's own vault, as the server serves it now. */
export async function liveItems(deps: Pick<RotationDeps, 'api' | 'userId'>): Promise<ItemDto[]> {
  const owner = `user:${deps.userId}`;
  const items = new Map<string, ItemDto>();
  let since: string | undefined;
  for (;;) {
    const result = await deps.api.sync(since, 500);
    if (result.notModified) break;
    for (const item of result.page.items) {
      if (item.owner !== owner) continue;
      if (item.deleted) items.delete(item.id);
      else items.set(item.id, item);
    }
    since = result.page.cursor;
    if (!result.page.more) break;
  }
  return [...items.values()];
}

/** The proof of the password and the new root key's wrap under it, from one fresh login. */
async function proveAndWrap(deps: RotationDeps, email: string, password: string) {
  const dto = await deps.api.prelogin(email);
  const masterKey = await deps.crypto.masterKey(password.normalize('NFC'), {
    memoryKib: dto.memoryKib,
    iterations: dto.iterations,
    parallelism: dto.parallelism,
    salt: decodeB64(dto.salt),
  });
  let exportKey: Uint8Array | undefined;
  let wrapped = false;
  try {
    const first = await deps.crypto.opaqueLoginStart(masterKey);
    const started = await deps.api.opaqueStart({ email, request: encodeB64(first.request) });
    const last = await deps.crypto
      .opaqueLoginFinish(first.state, masterKey, decodeB64(started.response))
      .catch(() => {
        throw new RotationPasswordError();
      });
    exportKey = last.exportKey;
    const wrap = await deps.crypto.rotationWrapPassword(masterKey, exportKey);
    wrapped = true;
    return {
      loginState: started.loginState,
      finalization: encodeB64(last.finalization),
      wrappedRootKey: encodeB64(wrap),
    };
  } catch (error) {
    if (error instanceof CredentialsError) throw new RotationPasswordError();
    throw error;
  } finally {
    if (!wrapped) {
      await deps.crypto.release(masterKey).catch(() => undefined);
      if (exportKey) await deps.crypto.release(exportKey).catch(() => undefined);
    }
  }
}

/** Moves `items` to the new keys and stages them in batches. Returns the revision of each staged. */
async function stageItems(
  deps: RotationDeps,
  rotationId: string,
  toVersion: number,
  items: ItemDto[],
  staged: Map<string, number>,
  rewritten: Map<string, ItemDto>,
  report: (done: number, total: number) => void,
): Promise<void> {
  let batch: Array<{ id: string; baseRevision: number; ciphertext: string; itemKey: string }> = [];
  let bytes = 0;
  let done = 0;
  const flush = async () => {
    if (batch.length === 0) return;
    await deps.api.stage({ rotationId, toVersion, items: batch });
    for (const item of batch) staged.set(item.id, item.baseRevision);
    batch = [];
    bytes = 0;
  };
  for (const item of items) {
    if (!item.ciphertext || !item.itemKey) continue;
    const moved: Resealed = await deps.crypto.rotationResealItem({
      id: item.id,
      owner: item.owner,
      kind: item.kind,
      revision: item.revision,
      keyVersion: item.keyVersion,
      ciphertext: decodeB64(item.ciphertext),
      itemKey: decodeB64(item.itemKey),
    });
    const entry = {
      id: item.id,
      baseRevision: item.revision,
      ciphertext: encodeB64(moved.ciphertext),
      itemKey: encodeB64(moved.itemKey),
    };
    rewritten.set(item.id, {
      id: item.id,
      owner: item.owner,
      kind: item.kind,
      format: 'kem1',
      revision: moved.revision,
      keyVersion: moved.keyVersion,
      ciphertext: entry.ciphertext,
      itemKey: entry.itemKey,
    });
    batch.push(entry);
    bytes += entry.ciphertext.length + entry.itemKey.length + 120;
    done += 1;
    if (batch.length >= BATCH_ITEMS || bytes >= BATCH_BYTES) await flush();
    report(done, items.length);
  }
  await flush();
}

/** Whether the server said what changed since the plan was read. */
function isIncomplete(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409 && error.slug === 'rotation-incomplete';
}

/**
 * Rotates the account's root key. Throws {@link RotationBlockedError} for an account that is in a
 * space or whose items can't be moved, {@link RotationPasswordError} for a wrong password, and the
 * server's error otherwise; on any failure before the install the worker forgets the new keys and
 * the staged items are dropped, so the account is as it was.
 */
export async function rotateKeys(
  deps: RotationDeps,
  input: RotationInput,
  onProgress: (progress: RotationProgress) => void = () => undefined,
): Promise<RotationResult> {
  const random = deps.randomBytes ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  onProgress({ phase: 'plan', done: 0, total: 1 });
  let plan: RotationPlanDto = await deps.api.plan();
  if (plan.spaces > 0) throw new RotationBlockedError('spaces');

  const rotationId = encodeB64(random(16));
  const started = await deps.crypto.rotationStart();
  const toVersion = started.keyVersion;
  const staged = new Map<string, number>();
  const rewritten = new Map<string, ItemDto>();
  let installed = false;
  try {
    // The items.
    let items = await liveItems(deps);
    if (items.some((item) => item.format !== 'kem1')) throw new RotationBlockedError('unsupported-items');
    onProgress({ phase: 'items', done: 0, total: items.length });
    await stageItems(deps, rotationId, toVersion, items, staged, rewritten, (done, total) =>
      onProgress({ phase: 'items', done, total }),
    );

    // The Sends, the kit and this browser's copy do not change between rounds.
    const sends = await deps.sends.list();
    onProgress({ phase: 'sends', done: 0, total: sends.length });
    const movedSends: NonNullable<InstallRequest['sends']> = [];
    for (const send of sends) {
      const moved = await deps.crypto.rotationResealSend({
        id: send.id,
        kind: send.kind === 'file' ? 'file' : 'text',
        sealedKey: decodeB64(send.sealedKey),
        meta: decodeB64(send.meta),
      });
      movedSends.push({ id: send.id, sealedKey: encodeB64(moved.sealedKey), meta: encodeB64(moved.meta) });
      onProgress({ phase: 'sends', done: movedSends.length, total: sends.length });
    }
    const kit = input.makeKit ? await deps.crypto.rotationKitMake() : null;
    let deviceCopy: InstallRequest['deviceCopy'];
    if (plan.deviceCopies.some((copy) => copy.deviceId === deps.deviceId)) {
      const copy = await deps.crypto.rotationDeviceCopySeal(deps.userId, deps.deviceId, toVersion);
      deviceCopy = { wrappedKey: encodeB64(copy), protection: 'web-crypto' };
    }

    // The install, again as often as another device's write makes it incomplete.
    onProgress({ phase: 'install', done: 0, total: 1 });
    let rotated: Rotated | undefined;
    for (let round = 0; round < MAX_ROUNDS && !rotated; round++) {
      if (round > 0) {
        plan = await deps.api.plan();
        if (plan.spaces > 0) throw new RotationBlockedError('spaces');
        items = await liveItems(deps);
        const changed = items.filter((item) => staged.get(item.id) !== item.revision);
        await stageItems(deps, rotationId, toVersion, changed, staged, rewritten, () => undefined);
      }
      const proof = plan.hasPassword
        ? await proveAndWrap(deps, input.email, input.password)
        : undefined;
      const request: InstallRequest = {
        rotationId,
        fromVersion: plan.keyVersion,
        toVersion,
        publicBundle: encodeB64(started.publicBundle),
        bundleSignature: encodeB64(started.bundleSignature),
        sealedPrivateKeys: encodeB64(started.sealedPrivateKeys),
        sealedPreviousPrivateKeys: encodeB64(started.sealedPreviousPrivateKeys),
        ...(proof ? proof : {}),
        ...(input.proof !== undefined ? { proof: input.proof } : {}),
        ...(kit ? { kit: { kitId: kit.kitId, wrappedKey: encodeB64(kit.wrappedKey) } } : {}),
        dropKit: !kit && plan.kit !== null,
        ...(deviceCopy ? { deviceCopy } : {}),
        // What the page can't re-wrap now is removed, and the person sets it up again.
        dropPasskeys: plan.passkeys.map((passkey) => passkey.id),
        dropEmergency: plan.emergency.map((grant) => grant.id),
        dropRecovery: plan.recovery.map((enrolment) => enrolment.space),
        sends: movedSends,
        spacesHandled: false,
      };
      try {
        rotated = await deps.api.install(request);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) throw new RotationPasswordError();
        if (!isIncomplete(error) || round === MAX_ROUNDS - 1) throw error;
      }
    }
    if (!rotated) throw new Error('the rotation was not installed');
    installed = true;

    // The server has the new keys: make them the account's here.
    const committed = await deps.crypto.rotationCommit();
    onProgress({ phase: 'done', done: 1, total: 1 });
    return {
      keyVersion: committed.keyVersion,
      fingerprint: committed.fingerprint,
      kit: kit ? { kitId: kit.kitId, pieces: kit.pieces } : null,
      rewritten: items.flatMap((item) => rewritten.get(item.id) ?? []),
      tokens: rotated.tokens,
      removed: {
        passkeys: plan.passkeys.length,
        emergency: plan.emergency.length,
        recovery: plan.recovery.length,
      },
    };
  } finally {
    if (!installed) {
      await deps.crypto.rotationAbort().catch(() => undefined);
      await deps.api.abandon().catch(() => undefined);
    }
  }
}
