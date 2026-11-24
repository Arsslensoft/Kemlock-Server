// What the worker does with a request: the dispatcher turns typed operations into calls on the
// WebAssembly `Vault` and the DPoP signer, and `attachWorker` wires it to a message port. Neither
// touches `self`, so tests run both with a mocked wasm module and a fake port.

import { b64urlDecode, b64urlEncode } from './b64';
import type { DeviceWrap } from './devicewrap';
import type { Dpop } from './dpop';
import {
  CryptoError,
  type CryptoErrorCode,
  type ApprovedKeyHandle,
  type DeviceKey,
  type EmergencyKeyHandle,
  type MasterKeyHandle,
  type NewAccount,
  type NewSpaceResult,
  type OpaqueLoginFinished,
  type OpaqueRegisterFinished,
  type OpaqueStart,
  type OpName,
  type KitPieceRead,
  type KitProblem,
  type MadeKit,
  type PrfWrap,
  type Ops,
  type SealedCollection,
  type SealedItem,
  type SealedSend,
  type TotpEnrolment,
  type WorkerRequest,
  type WorkerResponse,
} from './types';
import type { WasmFactory, WasmLoader, WasmVault } from './wasm';

export interface DispatcherDeps {
  loadWasm: WasmLoader;
  dpop: Dpop;
  /** This browser's trusted-device key; without it the device-copy operations are unavailable. */
  deviceWrap?: DeviceWrap;
}

export type Dispatcher = <Op extends OpName>(
  op: Op,
  args: Ops[Op]['args'],
) => Promise<Ops[Op]['result']>;

const DEFAULT_ISSUER = 'Kemlock';
const DEFAULT_ACCOUNT = 'account';

/** Maps whatever was thrown to a code. The wasm side throws `invalid` or `locked` and nothing
 * else; a panic or a type error is `invalid`, and a module that will not start is `unavailable`. */
export function codeOf(error: unknown): CryptoErrorCode {
  if (error instanceof CryptoError) return error.code;
  if (error instanceof Error && error.message === 'locked') return 'locked';
  return 'invalid';
}

function parse<T>(text: string): T {
  return JSON.parse(text) as T;
}

/** The text of a password, NFC-normalised as the master key's input requires. A byte password is
 * decoded and its buffer wiped at once. */
function passwordText(password: string | Uint8Array): string {
  if (typeof password === 'string') return password.normalize('NFC');
  const text = new TextDecoder().decode(password).normalize('NFC');
  password.fill(0);
  return text;
}

export function createDispatcher(deps: DispatcherDeps): Dispatcher {
  let factory: Promise<WasmFactory> | undefined;
  let vault: WasmVault | undefined;

  async function current(): Promise<WasmVault> {
    if (vault) return vault;
    factory ??= deps.loadWasm().catch(() => {
      factory = undefined;
      throw new CryptoError('unavailable');
    });
    vault = (await factory)();
    return vault;
  }

  /** Wipes the vault and drops its memory; the next operation gets a fresh instance. */
  function lock(): void {
    if (!vault) return;
    try {
      vault.lock();
    } finally {
      vault.free?.();
      vault = undefined;
    }
  }

  function deviceWrap(): DeviceWrap {
    if (!deps.deviceWrap) throw new CryptoError('unavailable');
    return deps.deviceWrap;
  }

  const handlers: { [Op in OpName]: (...args: Ops[Op]['args']) => Promise<Ops[Op]['result']> } = {
    async masterKey(password, kdf) {
      const v = await current();
      let text = passwordText(password);
      try {
        return v.masterKey(
          text,
          kdf.memoryKib,
          kdf.iterations,
          kdf.parallelism,
          kdf.salt,
        ) as MasterKeyHandle;
      } finally {
        // The string itself cannot be wiped, but nothing here keeps a reference to it.
        text = '';
      }
    },
    async opaqueRegisterStart(masterKey) {
      return parse<OpaqueStart>((await current()).opaqueRegisterStart(masterKey));
    },
    async opaqueRegisterFinish(state, masterKey, response) {
      return parse<OpaqueRegisterFinished>(
        (await current()).opaqueRegisterFinish(state, masterKey, response),
      );
    },
    async opaqueLoginStart(masterKey) {
      return parse<OpaqueStart>((await current()).opaqueLoginStart(masterKey));
    },
    async opaqueLoginFinish(state, masterKey, response) {
      return parse<OpaqueLoginFinished>(
        (await current()).opaqueLoginFinish(state, masterKey, response),
      );
    },
    async newSsoAccount(accountId) {
      return parse<NewAccount>((await current()).newSsoAccount(accountId));
    },
    async deviceCopySeal(accountId, deviceId, keyVersion) {
      const wrap = deviceWrap();
      const root = b64urlDecode((await current()).exportRoot());
      try {
        return b64urlEncode(await wrap.seal(root, accountId, deviceId, keyVersion));
      } finally {
        root.fill(0);
      }
    },
    async deviceCopyOpen(accountId, deviceId, keyVersion, sealed) {
      const root = await deviceWrap().open(b64urlDecode(sealed), accountId, deviceId, keyVersion);
      try {
        return (await current()).importRoot(b64urlEncode(root)) as ApprovedKeyHandle;
      } finally {
        root.fill(0);
      }
    },
    async deviceCopyReset() {
      await deviceWrap().reset();
    },
    async newAccount(accountId, masterKey, exportKey) {
      return parse<NewAccount>((await current()).newAccount(accountId, masterKey, exportKey));
    },
    async unlock(accountId, wrappedRootKey, masterKey, exportKey, options) {
      (await current()).unlock(
        accountId,
        wrappedRootKey,
        masterKey,
        exportKey,
        options?.keyVersion ?? 1,
        options?.sealedPrivateKeys,
      );
    },
    async sealItem(input) {
      const { id, owner, kind, revision, json } = input;
      return parse<SealedItem>(
        (await current()).sealItem(id, owner, kind, toRevision(revision), json),
      );
    },
    async openItem(input) {
      const { id, owner, kind, revision, ciphertext, itemKey, keyVersion } = input;
      return (await current()).openItem(
        id,
        owner,
        kind,
        toRevision(revision),
        ciphertext,
        itemKey,
        keyVersion,
      );
    },
    dpopProof(htm, htu, nonce, accessToken) {
      return deps.dpop.proof(htm, htu, nonce, accessToken);
    },
    async totpUri(secret, options) {
      return parse<TotpEnrolment>(
        (await current()).totpEnrol(
          secret,
          options?.issuer ?? DEFAULT_ISSUER,
          options?.account ?? DEFAULT_ACCOUNT,
        ),
      );
    },
    async sendNewKey() {
      return (await current()).sendNewKey();
    },
    async sealSend(input) {
      const { id, kind, linkKey, payloadJson, metaJson } = input;
      return parse<SealedSend>(
        (await current()).sendSeal(id, kind, linkKey, payloadJson, metaJson),
      );
    },
    async openSendPayload(input) {
      return (await current()).sendOpenPayload(input.id, input.kind, input.linkKey, input.sealed);
    },
    async openSendMeta(input) {
      return (await current()).sendOpenMeta(input.id, input.kind, input.sealedKey, input.sealed);
    },
    async wrapSendKey(id, linkKey) {
      return (await current()).sendWrapKey(id, linkKey);
    },
    async unwrapSendKey(id, sealedKey) {
      return (await current()).sendOpenKey(id, sealedKey);
    },
    async sendProof(id, linkKey, password) {
      return (await current()).sendProof(id, linkKey, password);
    },
    async sealSendFile(linkKey, bytes) {
      return (await current()).sendSealFile(linkKey, bytes);
    },
    async openSendFile(linkKey, file) {
      return (await current()).sendOpenFile(linkKey, file);
    },
    async lock() {
      lock();
    },
    async fingerprint(publicBundle) {
      return (await current()).fingerprint(publicBundle);
    },
    async verifyBundle(publicBundle, bundleSignature) {
      return (await current()).verifyBundle(publicBundle, bundleSignature);
    },
    async ownFingerprint() {
      return (await current()).ownFingerprint();
    },
    async release(handle) {
      (await current()).release(handle);
    },
    dpopReset() {
      return deps.dpop.reset();
    },
    async sealRootKey(recipientKx1, context, aad) {
      return (await current()).sealRootKey(recipientKx1, context, aad);
    },
    async confirmationStatement({ space, member, memberKeyVersion, fingerprint }) {
      return (await current()).confirmationStatement(
        space,
        member,
        toKeyVersion(memberKeyVersion),
        fingerprint,
      );
    },
    async signStatement(statement, context) {
      return (await current()).signStatement(statement, context);
    },
    async verifyConfirmation(check) {
      return (await current()).verifyConfirmation(
        check.confirmerBundle,
        check.space,
        check.member,
        toKeyVersion(check.memberKeyVersion),
        check.fingerprint,
        check.statement,
        check.signature,
      );
    },
    async openEmergencyKey(sealed) {
      return (await current()).openEmergencyKey(sealed) as EmergencyKeyHandle;
    },
    async openEmergencyItem(handle, input) {
      const { id, owner, kind, revision, ciphertext, itemKey, keyVersion } = input;
      return (await current()).openEmergencyItem(
        handle,
        id,
        owner,
        kind,
        toRevision(revision),
        ciphertext,
        itemKey,
        keyVersion,
      );
    },
    async newSpace({ spaceId, collectionId, spaceName, collectionName }) {
      return parse<NewSpaceResult>(
        (await current()).newSpace(spaceId, collectionId, spaceName, collectionName),
      );
    },
    async openSpace({ spaceId, keyVersion, sealed }) {
      (await current()).openSpace(spaceId, toKeyVersion(keyVersion), sealed);
    },
    async openCollection({ spaceId, collectionId, keyVersion, sealed }) {
      (await current()).openCollection(spaceId, collectionId, toKeyVersion(keyVersion), sealed);
    },
    async openName({ spaceId, keyVersion, kind, id, ciphertext }) {
      return (await current()).openName(spaceId, toKeyVersion(keyVersion), kind, id, ciphertext);
    },
    async sealName({ spaceId, keyVersion, kind, id, name }) {
      return (await current()).sealName(spaceId, toKeyVersion(keyVersion), kind, id, name);
    },
    async newCollection({ spaceId, collectionId, name }) {
      return parse<SealedCollection>((await current()).newCollection(spaceId, collectionId, name));
    },
    async sealSpaceKeyTo({ spaceId, recipientKx1, recipientId }) {
      return (await current()).sealSpaceKeyTo(spaceId, recipientKx1, recipientId);
    },
    async sealCollectionKeyTo({ spaceId, collectionId, recipientKx1, recipientId }) {
      return (await current()).sealCollectionKeyTo(spaceId, collectionId, recipientKx1, recipientId);
    },
    async newDeviceKey() {
      return parse<DeviceKey>((await current()).newDeviceKey());
    },
    async openApprovedKey(deviceKey, accountId, requestId, sealed) {
      return (await current()).openApprovedKey(
        deviceKey,
        accountId,
        requestId,
        sealed,
      ) as ApprovedKeyHandle;
    },
    async prfWrapRoot(prfOutput, credentialId) {
      return parse<PrfWrap>((await current()).prfWrapRoot(prfOutput, credentialId));
    },
    async prfOpenRoot(prfOutput, credentialId, accountId, keyVersion, wrapped) {
      return (await current()).prfOpenRoot(
        prfOutput,
        credentialId,
        accountId,
        keyVersion,
        wrapped,
      ) as ApprovedKeyHandle;
    },
    async kitMake() {
      return parse<MadeKit>((await current()).kitMake());
    },
    async kitReadPiece(text) {
      return parse<KitPieceRead>((await current()).kitReadPiece(text));
    },
    async kitCheckPieces(pieces) {
      return parse<{ problem?: KitProblem }>((await current()).kitCheckPieces(JSON.stringify(pieces)));
    },
    async kitOpenRoot(pieces, kitId, accountId, keyVersion, wrapped) {
      return (await current()).kitOpenRoot(
        JSON.stringify(pieces),
        kitId,
        accountId,
        keyVersion,
        wrapped,
      ) as ApprovedKeyHandle;
    },
    async unlockWithRoot(accountId, root, options) {
      (await current()).unlockWithRoot(
        accountId,
        root,
        options?.keyVersion ?? 1,
        options?.sealedPrivateKeys,
      );
    },
    async sealSpaceItem({ spaceId, collectionId, id, kind, revision, json }) {
      return parse<SealedItem>(
        (await current()).sealSpaceItem(spaceId, collectionId, id, kind, toRevision(revision), json),
      );
    },
    async openSpaceItem(input) {
      const { spaceId, collectionId, id, kind, revision, ciphertext, itemKey, keyVersion } = input;
      return (await current()).openSpaceItem(
        spaceId,
        collectionId,
        id,
        kind,
        toRevision(revision),
        ciphertext,
        itemKey,
        toKeyVersion(keyVersion),
      );
    },
  };

  const dispatch = (op: string, args: unknown[]): Promise<unknown> => {
    if (!Object.prototype.hasOwnProperty.call(handlers, op)) {
      return Promise.reject(new CryptoError('invalid'));
    }
    const handler = handlers[op as OpName] as (...a: unknown[]) => Promise<unknown>;
    try {
      return handler(...args);
    } catch (error) {
      return Promise.reject(error);
    }
  };
  return dispatch as Dispatcher;
}

/** A key version is a u32; anything else never reaches the module. */
function toKeyVersion(version: number): number {
  if (!Number.isInteger(version) || version < 0 || version > 0xffff_ffff) {
    throw new CryptoError('invalid');
  }
  return version;
}

function toRevision(revision: number): bigint {
  if (!Number.isSafeInteger(revision) || revision < 0) throw new CryptoError('invalid');
  return BigInt(revision);
}

/** What `attachWorker` needs of a worker's global scope. */
export interface WorkerScope {
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  postMessage(message: WorkerResponse): void;
}

function isRequest(value: unknown): value is WorkerRequest {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.id === 'number' && typeof v.op === 'string' && Array.isArray(v.args);
}

/**
 * Answers requests one at a time, in the order they came: a `lock` can never overtake the
 * `unlock` before it, and wasm calls never interleave.
 */
export function attachWorker(scope: WorkerScope, dispatch: Dispatcher): void {
  let queue: Promise<void> = Promise.resolve();
  scope.addEventListener('message', (event) => {
    const request = event.data;
    if (!isRequest(request)) return;
    queue = queue.then(async () => {
      try {
        const result = await dispatch(request.op, request.args);
        scope.postMessage({ id: request.id, ok: true, result });
      } catch (error) {
        scope.postMessage({ id: request.id, ok: false, code: codeOf(error) });
      }
    });
  });
}
