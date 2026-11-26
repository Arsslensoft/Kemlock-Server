// The page's side of the crypto worker: `crypto` is the only way the web vault touches a key. It
// starts the worker on first use and turns each call into a typed message.
//
// Binary values are base64url strings (the wire form of docs/crypto.md); secrets that stay in the
// browser are handles. A password given as a `Uint8Array` is transferred to the worker, which
// wipes it.

import {
  CryptoError,
  type CryptoApi,
  type OpName,
  type Ops,
  type WorkerRequest,
  type WorkerResponse,
} from './types';
import { spawnCryptoWorker } from '@/crypto/spawn';

export * from './types';

/** What the client needs of a `Worker`; the tests give it a fake. */
export interface WorkerPort {
  postMessage(message: WorkerRequest, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'error' | 'messageerror', listener: (event: unknown) => void): void;
  terminate?(): void;
}

interface Pending {
  resolve(value: unknown): void;
  reject(error: unknown): void;
}

/** Makes a client over any worker; `crypto` below is one over the real worker. */
export function createCryptoClient(factory: () => WorkerPort): CryptoApi {
  let port: WorkerPort | undefined;
  let nextId = 1;
  const pending = new Map<number, Pending>();

  function failAll(code: 'unavailable'): void {
    const error = new CryptoError(code);
    for (const entry of pending.values()) entry.reject(error);
    pending.clear();
    port?.terminate?.();
    port = undefined;
  }

  function start(): WorkerPort {
    if (port) return port;
    const created = factory();
    created.addEventListener('message', (event) => {
      const response = event.data as WorkerResponse;
      const entry = pending.get(response.id);
      if (!entry) return;
      pending.delete(response.id);
      if (response.ok) entry.resolve(response.result);
      else entry.reject(new CryptoError(response.code));
    });
    created.addEventListener('error', () => failAll('unavailable'));
    created.addEventListener('messageerror', () => failAll('unavailable'));
    port = created;
    return created;
  }

  function call<Op extends OpName>(
    op: Op,
    args: Ops[Op]['args'],
    transfer: Transferable[] = [],
  ): Promise<Ops[Op]['result']> {
    return new Promise((resolve, reject) => {
      let worker: WorkerPort;
      try {
        worker = start();
      } catch {
        reject(new CryptoError('unavailable'));
        return;
      }
      const id = nextId++;
      pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      try {
        worker.postMessage({ id, op, args }, transfer);
      } catch {
        pending.delete(id);
        reject(new CryptoError('invalid'));
      }
    });
  }

  return {
    masterKey: (password, kdf) =>
      call('masterKey', [password, kdf], typeof password === 'string' ? [] : [password.buffer as ArrayBuffer]),
    opaqueRegisterStart: (masterKey) => call('opaqueRegisterStart', [masterKey]),
    opaqueRegisterFinish: (state, masterKey, response) =>
      call('opaqueRegisterFinish', [state, masterKey, response]),
    opaqueLoginStart: (masterKey) => call('opaqueLoginStart', [masterKey]),
    opaqueLoginFinish: (state, masterKey, response) =>
      call('opaqueLoginFinish', [state, masterKey, response]),
    newSsoAccount: (accountId) => call('newSsoAccount', [accountId]),
    deviceCopySeal: (accountId, deviceId, keyVersion, tabId) =>
      call('deviceCopySeal', [accountId, deviceId, keyVersion, tabId]),
    deviceCopyOpen: (accountId, deviceId, keyVersion, sealed, tabId) =>
      call('deviceCopyOpen', [accountId, deviceId, keyVersion, sealed, tabId]),
    deviceCopyReset: (tabId) => call('deviceCopyReset', [tabId]),
    tabSeal: (tabId, accountId, deviceId, data) => call('tabSeal', [tabId, accountId, deviceId, data]),
    tabOpen: (tabId, accountId, deviceId, sealed) => call('tabOpen', [tabId, accountId, deviceId, sealed]),
    newAccount: (accountId, masterKey, exportKey) =>
      call('newAccount', [accountId, masterKey, exportKey]),
    rewrapRoot: (masterKey, exportKey) => call('rewrapRoot', [masterKey, exportKey]),
    unlock: (accountId, wrappedRootKey, masterKey, exportKey, options) =>
      call('unlock', [accountId, wrappedRootKey, masterKey, exportKey, options]),
    sealItem: (input) => call('sealItem', [input]),
    openItem: (input) => call('openItem', [input]),
    dpopProof: (htm, htu, nonce, accessToken) => call('dpopProof', [htm, htu, nonce, accessToken]),
    totpUri: (secret, options) => call('totpUri', [secret, options]),
    sendNewKey: () => call('sendNewKey', []),
    sealSend: (input) => call('sealSend', [input]),
    openSendPayload: (input) => call('openSendPayload', [input]),
    openSendMeta: (input) => call('openSendMeta', [input]),
    wrapSendKey: (id, linkKey) => call('wrapSendKey', [id, linkKey]),
    unwrapSendKey: (id, sealedKey) => call('unwrapSendKey', [id, sealedKey]),
    sendProof: (id, linkKey, password) => call('sendProof', [id, linkKey, password]),
    // The page's array is copied first: a transferred buffer is detached, and the caller still holds it.
    sealSendFile: (linkKey, bytes) => {
      const copy = bytes.slice();
      return call('sealSendFile', [linkKey, copy], [copy.buffer as ArrayBuffer]);
    },
    openSendFile: (linkKey, file) => {
      const copy = file.slice();
      return call('openSendFile', [linkKey, copy], [copy.buffer as ArrayBuffer]);
    },
    lock: () => call('lock', []),
    fingerprint: (publicBundle) => call('fingerprint', [publicBundle]),
    verifyBundle: (publicBundle, bundleSignature) =>
      call('verifyBundle', [publicBundle, bundleSignature]),
    ownFingerprint: () => call('ownFingerprint', []),
    release: (handle) => call('release', [handle]),
    dpopReset: () => call('dpopReset', []),
    sealRootKey: (recipientKx1, context, aad) => call('sealRootKey', [recipientKx1, context, aad]),
    confirmationStatement: (facts) => call('confirmationStatement', [facts]),
    signStatement: (statement, context) => call('signStatement', [statement, context]),
    verifyConfirmation: (check) => call('verifyConfirmation', [check]),
    openEmergencyKey: (sealed) => call('openEmergencyKey', [sealed]),
    openEmergencyItem: (handle, input) => call('openEmergencyItem', [handle, input]),
    newSpace: (input) => call('newSpace', [input]),
    openSpace: (input) => call('openSpace', [input]),
    openCollection: (input) => call('openCollection', [input]),
    openName: (input) => call('openName', [input]),
    sealName: (input) => call('sealName', [input]),
    newCollection: (input) => call('newCollection', [input]),
    sealSpaceKeyTo: (input) => call('sealSpaceKeyTo', [input]),
    sealCollectionKeyTo: (input) => call('sealCollectionKeyTo', [input]),
    newDeviceKey: () => call('newDeviceKey', []),
    openApprovedKey: (deviceKey, accountId, requestId, sealed) =>
      call('openApprovedKey', [deviceKey, accountId, requestId, sealed]),
    prfWrapRoot: (prfOutput, credentialId) => call('prfWrapRoot', [prfOutput, credentialId]),
    prfOpenRoot: (prfOutput, credentialId, accountId, keyVersion, wrapped) =>
      call('prfOpenRoot', [prfOutput, credentialId, accountId, keyVersion, wrapped]),
    kitMake: () => call('kitMake', []),
    kitReadPiece: (text) => call('kitReadPiece', [text]),
    kitCheckPieces: (pieces) => call('kitCheckPieces', [pieces]),
    kitOpenRoot: (pieces, kitId, accountId, keyVersion, wrapped) =>
      call('kitOpenRoot', [pieces, kitId, accountId, keyVersion, wrapped]),
    unlockWithRoot: (accountId, root, options) => call('unlockWithRoot', [accountId, root, options]),
    sealSpaceItem: (input) => call('sealSpaceItem', [input]),
    openSpaceItem: (input) => call('openSpaceItem', [input]),
    manifestSign: (manifest) => call('manifestSign', [manifest]),
    manifestVerifyOwn: (manifest, signature) => call('manifestVerifyOwn', [manifest, signature]),
    manifestVerify: (signerBundle, manifest, signature) =>
      call('manifestVerify', [signerBundle, manifest, signature]),
    verifySpaceChain: (input) => call('verifySpaceChain', [input]),
    newChainedSpace: (input) => call('newChainedSpace', [input]),
    buildChainRecords: (input) => call('buildChainRecords', [input]),
    sealLocal: (label, text) => call('sealLocal', [label, text]),
    openLocal: (label, sealed) => call('openLocal', [label, sealed]),
    spaceChainView: (spaceId) => call('spaceChainView', [spaceId]),
    acceptFirstContact: (spaceId) => call('acceptFirstContact', [spaceId]),
    openChainKey: (input) => call('openChainKey', [input]),
  };
}

/** The web vault's crypto. Starts its worker on first use. */
export const crypto: CryptoApi = createCryptoClient(spawnCryptoWorker);
