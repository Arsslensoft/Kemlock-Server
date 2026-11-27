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
// What the web vault re-wraps: an emergency contact's box, to the bundle the person compared with the
// contact's own screen (a contact not compared is removed and confirmed again later), and a space
// recovery enrolment, to the recovery key a verified chain gives (`recoveryKeys`). A passkey's PRF
// wrap needs the authenticator, so it is removed and the page offers to add it back after the install
// (`removed.passkeys` says which). An account that is in a space is refused, because the space keys
// must move to the new keys too.
import { ApiError } from '@/api/errors';
import type { Api } from '@/api/client';
import type { Proof } from '@/api/twoStep';
import type { InstallRequest, RotationApi, RotationPlanDto, Rotated, StagedItemDto } from '@/api/rotation';
import type { PasskeysApi } from '@/api/passkeys';
import type { SendsApi } from '@/api/sends';
import type { ItemDto } from '@/api/types';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { CredentialsError } from '@/lib/errors';
import { PasskeyError } from '@/lib/passkey';
import { resealLocalStores } from '@/local/registry';
import { parseBundle, uuidBytes } from '@/sharing/bundle';

/** The page can't rotate this account. */
export class RotationBlockedError extends Error {
  readonly reason: 'spaces' | 'compatible' | 'federated' | 'unsupported-items';
  constructor(reason: 'spaces' | 'compatible' | 'federated' | 'unsupported-items') {
    super(`Keys can't be rotated here: ${reason}`);
    this.name = 'RotationBlockedError';
    this.reason = reason;
  }
}

/**
 * The account changed while the keys were being rotated, after a one-time second-step proof had
 * been given, which the server may have spent. Nothing was changed; the person starts again with a
 * new proof.
 */
export class RotationProofSpentError extends Error {
  constructor() {
    super('The account changed meanwhile; a new proof is needed');
    this.name = 'RotationProofSpentError';
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
    | 'rotationSealRootKey'
    | 'rotationResealLocal'
    | 'rotationCommit'
    | 'rotationAbort'
  >;
  /** The signed-in account and device. */
  userId: string;
  deviceId: string;
  /**
   * The recovery key (kx1 public key) a verified chain gives for a space, for the `seq` of the record
   * that set it; undefined when it can't be said. The enrolment is then removed, not re-sealed.
   */
  recoveryKeys?: (space: string, keySeq: number) => Promise<Uint8Array | undefined>;
  randomBytes?: (length: number) => Uint8Array;
  /**
   * Called as soon as the server has the new keys, before they are made the account's here: the
   * page shows the new Recovery Kit from this, so that a failure after it does not lose the pieces.
   */
  onInstalled?: (installed: { kit: { kitId: string; pieces: string[] } | null }) => void;
}

export interface RotationInput {
  email: string;
  password: string;
  /** The second step's fresh proof, when one is on. */
  proof?: Proof;
  /** Makes a new Recovery Kit; one the account has is replaced either way, or dropped without it. */
  makeKit: boolean;
  /**
   * The emergency contacts the person compared: grant id to the bundle (base64url) whose fingerprint
   * they compared. A box is sealed only to exactly that bundle, and only if the server still names it.
   */
  emergencyKeep?: Record<string, string>;
}

/** What a rotation leaves for the person: the new kit to save, and what it removed. */
export interface RotationResult {
  keyVersion: number;
  fingerprint: string;
  kit: { kitId: string; pieces: string[] } | null;
  /** The live items as they are now, re-encrypted: what the next signed manifest lists. */
  rewritten: ItemDto[];
  tokens: Rotated['tokens'];
  /** What was removed and is to be set up again; the passkeys can be added back from here. */
  removed: {
    passkeys: Array<{ id: string; credentialId: string }>;
    emergency: number;
    recovery: number;
  };
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
  let batch: StagedItemDto[] = [];
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
    // The re-encrypted item is a write of the account, signed by the new keys: a vault that takes
    // signed writes only is installed with every item signed, and the signature is kept with it.
    const entry: StagedItemDto = {
      id: item.id,
      baseRevision: item.revision,
      ciphertext: encodeB64(moved.ciphertext),
      itemKey: encodeB64(moved.itemKey),
      writer: moved.writer,
      writerKeyVersion: moved.writerKeyVersion,
      writeSignature: moved.writeSignature,
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
      writer: moved.writer,
      writerKeyVersion: moved.writerKeyVersion,
      writeSignature: moved.writeSignature,
    });
    // Keep the request under the body limit: send what is held before this item would pass it.
    const size = entry.ciphertext.length + entry.itemKey.length + 120;
    if (batch.length > 0 && bytes + size > BATCH_BYTES) await flush();
    batch.push(entry);
    bytes += size;
    done += 1;
    if (batch.length >= BATCH_ITEMS) await flush();
    report(done, items.length);
  }
  await flush();
}

/** The 8 bytes of a number, big endian: a `keySeq` in the recovery box's aad. */
function u64be(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

/**
 * The new root key sealed to what the person verified: each emergency contact whose bundle they
 * compared (and the server still serves unchanged), each recovery enrolment whose key a verified
 * chain gives. What can't be sealed is named as dropped, for the server to remove.
 */
async function sealBoxes(deps: RotationDeps, input: RotationInput, plan: RotationPlanDto) {
  const emergency: NonNullable<InstallRequest['emergency']> = [];
  const dropEmergency: string[] = [];
  for (const grant of plan.emergency) {
    const verified = input.emergencyKeep?.[grant.id];
    const parsed =
      verified !== undefined && verified === grant.granteeBundle && grant.granteeId
        ? parseBundle(decodeB64(verified))
        : null;
    const grantee = grant.granteeId ? uuidBytes(grant.granteeId) : null;
    const same = parsed && grantee && parsed.accountId.every((byte, i) => byte === grantee[i]);
    if (!parsed || !grantee || !same) {
      dropEmergency.push(grant.id);
      continue;
    }
    const box = await deps.crypto.rotationSealRootKey(parsed.kx1, 'emergency-access', grantee);
    emergency.push({ id: grant.id, sealedKey: encodeB64(box) });
  }
  const recovery: NonNullable<InstallRequest['recovery']> = [];
  const dropRecovery: string[] = [];
  for (const enrolment of plan.recovery) {
    const key = await deps.recoveryKeys?.(enrolment.space, enrolment.keySeq);
    if (!key) {
      dropRecovery.push(enrolment.space);
      continue;
    }
    const aad = new Uint8Array(40);
    aad.set(uuidBytes(enrolment.space), 0);
    aad.set(uuidBytes(deps.userId), 16);
    aad.set(u64be(enrolment.keySeq), 32);
    const box = await deps.crypto.rotationSealRootKey(key, 'account-recovery', aad);
    recovery.push({ space: enrolment.space, keySeq: enrolment.keySeq, box: encodeB64(box) });
  }
  return { emergency, dropEmergency, recovery, dropRecovery };
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
  let plan: RotationPlanDto = await deps.api.plan().catch((error: unknown) => {
    if (error instanceof ApiError && error.slug === 'rotation-federated') {
      throw new RotationBlockedError('federated');
    }
    throw error;
  });
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

    // The Sends are read and moved each round: one made or edited while the items were moved is
    // one the server holds now, and the install must name every one it holds.
    const moveSends = async (report: (done: number, total: number) => void) => {
      const sends = await deps.sends.list();
      report(0, sends.length);
      const moved: NonNullable<InstallRequest['sends']> = [];
      for (const send of sends) {
        const again = await deps.crypto.rotationResealSend({
          id: send.id,
          kind: send.kind === 'file' ? 'file' : 'text',
          sealedKey: decodeB64(send.sealedKey),
          meta: decodeB64(send.meta),
        });
        moved.push({ id: send.id, sealedKey: encodeB64(again.sealedKey), meta: encodeB64(again.meta) });
        report(moved.length, sends.length);
      }
      return moved;
    };
    let sendsNow = await moveSends((done, total) => onProgress({ phase: 'sends', done, total }));
    // The kit and this browser's copy do not change between rounds.
    // An account with no password has the kit and its devices as its ways back in: it always gets
    // a new kit, since the old one's pieces open nothing after the rotation.
    const kit = input.makeKit || !plan.hasPassword ? await deps.crypto.rotationKitMake() : null;
    let deviceCopy: InstallRequest['deviceCopy'];
    if (plan.deviceCopies.some((copy) => copy.deviceId === deps.deviceId)) {
      const copy = await deps.crypto.rotationDeviceCopySeal(deps.userId, deps.deviceId, toVersion);
      deviceCopy = { wrappedKey: encodeB64(copy), protection: 'web-crypto' };
    }

    // The install, again as often as another device's write makes it incomplete.
    onProgress({ phase: 'install', done: 0, total: 1 });
    let rotated: Rotated | undefined;
    let dropped = { emergency: 0, recovery: 0 };
    for (let round = 0; round < MAX_ROUNDS && !rotated; round++) {
      if (round > 0) {
        plan = await deps.api.plan();
        if (plan.spaces > 0) throw new RotationBlockedError('spaces');
        items = await liveItems(deps);
        const changed = items.filter((item) => staged.get(item.id) !== item.revision);
        await stageItems(deps, rotationId, toVersion, changed, staged, rewritten, () => undefined);
        sendsNow = await moveSends(() => undefined);
      }
      const proof = plan.hasPassword
        ? await proveAndWrap(deps, input.email, input.password)
        : undefined;
      const boxes = await sealBoxes(deps, input, plan);
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
        // A passkey's wrap needs the authenticator: removed now, added back after the install.
        dropPasskeys: plan.passkeys.map((passkey) => passkey.id),
        emergency: boxes.emergency,
        dropEmergency: boxes.dropEmergency,
        recovery: boxes.recovery,
        dropRecovery: boxes.dropRecovery,
        sends: sendsNow,
        spacesHandled: false,
      };
      dropped = { emergency: boxes.dropEmergency.length, recovery: boxes.dropRecovery.length };
      try {
        rotated = await deps.api.install(request);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) throw new RotationPasswordError();
        // A one-time proof may be spent: ask for a new one, don't retry with it.
        if (isIncomplete(error) && input.proof !== undefined) throw new RotationProofSpentError();
        if (!isIncomplete(error) || round === MAX_ROUNDS - 1) throw error;
      }
    }
    if (!rotated) throw new Error('the rotation was not installed');
    installed = true;
    // The server has the new keys. The kit's pieces exist only here: hand them over before anything
    // that could fail.
    deps.onInstalled?.({ kit: kit ? { kitId: kit.kitId, pieces: kit.pieces } : null });

    // What this browser keeps sealed under the old keys (space anchors and pins, and whatever else
    // registers in `local/`) moves to the new ones now, while the worker holds both. A store that
    // fails keeps values the old keys sealed, which it reads as "ask again".
    await resealLocalStores(deps.userId, (label, sealed) => deps.crypto.rotationResealLocal(label, sealed));

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
        passkeys: plan.passkeys.map((passkey) => ({ id: passkey.id, credentialId: passkey.credentialId })),
        emergency: dropped.emergency,
        recovery: dropped.recovery,
      },
    };
  } finally {
    if (!installed) {
      await deps.crypto.rotationAbort().catch(() => undefined);
      await deps.api.abandon().catch(() => undefined);
    }
  }
}

export interface PasskeyUnlockDeps {
  api: Pick<PasskeysApi, 'putPrf'>;
  crypto: Pick<CryptoPort, 'prfWrapRoot'>;
  /** Asks the authenticator for its PRF output (`assertWithPasskeyAndPrf`). */
  assert: (options: Record<string, unknown>) => Promise<{ credentialId: Uint8Array; prfOutput?: Uint8Array }>;
  randomBytes?: (length: number) => Uint8Array;
}

/**
 * Adds a passkey's unlock back after a rotation removed it: the person touches that passkey, it
 * answers with its PRF output, the worker wraps the new root key under it and the server keeps the
 * wrap. Throws a `PasskeyError` when the authenticator gives no PRF output or is another passkey.
 */
export async function readdPasskeyUnlock(
  deps: PasskeyUnlockDeps,
  passkey: { id: string; credentialId: string },
): Promise<void> {
  const random = deps.randomBytes ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const answer = await deps.assert({
    challenge: encodeB64(random(32)),
    allowCredentials: [{ type: 'public-key', id: passkey.credentialId }],
    userVerification: 'preferred',
    timeout: 60_000,
  });
  const asked = decodeB64(passkey.credentialId);
  const same = answer.credentialId.length === asked.length && answer.credentialId.every((byte, i) => byte === asked[i]);
  if (!answer.prfOutput || !same) throw new PasskeyError('unavailable');
  try {
    const wrap = await deps.crypto.prfWrapRoot(answer.prfOutput, answer.credentialId);
    await deps.api.putPrf(passkey.id, { wrappedKey: encodeB64(wrap.wrappedKey), keyVersion: wrap.keyVersion });
  } finally {
    answer.prfOutput.fill(0);
  }
}
