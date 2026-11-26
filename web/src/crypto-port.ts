// The web vault's view of the crypto client that src/crypto/index.ts implements: a WebAssembly
// build of kemlock-crypto in a Web Worker, so keys never reach React. Everything in the app
// imports `vaultCrypto` from here, never `@/crypto` directly, so the contract is stated once and
// a mismatch with the implementation is a type error on the last line of this file.
//
// Bytes are Uint8Array; the API client turns them into base64url at the HTTP edge. The worker's
// own contract (src/crypto/types.ts) speaks base64url strings and numeric handles; `fromWorker`
// below adapts it, and under Vitest `@/crypto-port` is aliased to the fake in src/test.
import { crypto as worker } from '@/crypto';
import type {
  CryptoApi,
  Handle,
  ItemWriteFields,
  ItemWriteSignature,
  KitPieceRead,
  KitProblem,
  OpaqueStateHandle,
} from '@/crypto/types';
import { decodeB64, encodeB64 } from '@/lib/b64url';

/** Argon2id settings from /auth/prelogin, with the salt decoded. */
export interface Kdf {
  memoryKib: number;
  iterations: number;
  parallelism: number;
  salt: Uint8Array;
}

/** An in-progress OPAQUE exchange. Opaque to React: pass it back to the matching finish call. */
export type OpaqueState = unknown;

/** The pieces of a new account's key bundle that /accounts/register/finish takes. */
export interface NewAccountKeys {
  publicBundle: Uint8Array;
  bundleSignature: Uint8Array;
  sealedPrivateKeys: Uint8Array;
  wrappedRootKey: Uint8Array;
}

export interface SealInput {
  /** The item's UUID in its canonical text form. */
  id: string;
  /** `user:<uuid>` or `space:<uuid>`. */
  owner: string;
  kind: string;
  revision: number;
  /** The item's plaintext JSON. */
  json: string;
}

export interface SealedItem {
  ciphertext: Uint8Array;
  itemKey: Uint8Array;
  keyVersion: number;
}

export interface OpenInput {
  id: string;
  owner: string;
  kind: string;
  revision: number;
  keyVersion: number;
  ciphertext: Uint8Array;
  itemKey: Uint8Array;
}

/** What binds a Send's seals (docs/crypto.md, "Sends"): its id, its kind and the link key. */
export interface SendAddress {
  /** The Send's UUID, or the access id its link carries. */
  id: string;
  kind: 'text' | 'file';
  /** The link key, base64url: the one key that leaves the worker, because it goes in the link. */
  linkKey: string;
}

export interface SealSendInput extends SendAddress {
  /** The payload JSON a recipient opens. */
  payloadJson: string;
  /** The owner's name and notes as JSON. */
  metaJson: string;
}

export interface SealedSend {
  payload: Uint8Array;
  meta: Uint8Array;
}

export interface OpenSendPartInput extends SendAddress {
  /** The sealed payload. */
  sealed: Uint8Array;
}

/** The owner's meta opens with the account's key; `sealedKey` names the key version it needs. */
export interface OpenSendMetaInput {
  id: string;
  kind: 'text' | 'file';
  sealedKey: Uint8Array;
  sealed: Uint8Array;
}

/** An item of a space's collection, to seal; the owner is `space:<spaceId>`. */
export interface SealSpaceItemInput {
  spaceId: string;
  collectionId: string;
  id: string;
  kind: string;
  revision: number;
  json: string;
}

export interface OpenSpaceItemInput {
  spaceId: string;
  collectionId: string;
  id: string;
  kind: string;
  revision: number;
  /** The collection key's version. */
  keyVersion: number;
  ciphertext: Uint8Array;
  itemKey: Uint8Array;
}

/** A new device's one-time key for an approval request. */
export interface DeviceKeyPair {
  /** Names the private key inside the worker (4 opaque bytes). */
  handle: Uint8Array;
  /** The kx1 public key, 1,600 bytes: it goes in the request and the phrase is worked out from it. */
  publicKey: Uint8Array;
}

export interface CryptoPort {
  /** Argon2id over the NFC password. The key stays in the worker; the handle is opaque bytes. */
  masterKey(password: string, kdf: Kdf): Promise<Uint8Array>;
  opaqueRegisterStart(masterKey: Uint8Array): Promise<{ request: Uint8Array; state: OpaqueState }>;
  opaqueRegisterFinish(
    state: OpaqueState,
    masterKey: Uint8Array,
    response: Uint8Array,
  ): Promise<{ upload: Uint8Array; exportKey: Uint8Array }>;
  opaqueLoginStart(masterKey: Uint8Array): Promise<{ request: Uint8Array; state: OpaqueState }>;
  opaqueLoginFinish(
    state: OpaqueState,
    masterKey: Uint8Array,
    response: Uint8Array,
  ): Promise<{ finalization: Uint8Array; exportKey: Uint8Array }>;
  /** Makes the root key and the key bundle for a new account. */
  newAccount(
    accountId: string,
    masterKey: Uint8Array,
    exportKey: Uint8Array,
  ): Promise<NewAccountKeys>;
  /**
   * Wraps the open account's root key under a new master key and OPAQUE export key (both made for
   * the new password, or the new address), for a change of either: the 92-byte wrap the server
   * keeps. The root key, the key version and the vault stay as they are; both handles are spent.
   */
  rewrapRoot(masterKey: Uint8Array, exportKey: Uint8Array): Promise<Uint8Array>;
  /**
   * Opens the vault: unwraps the root key inside the worker. With `sealedPrivateKeys` it opens the
   * account's exchange and signing private keys too, which spaces, device approval and
   * confirmations need.
   */
  unlock(
    accountId: string,
    wrappedRootKey: Uint8Array,
    masterKey: Uint8Array,
    exportKey: Uint8Array,
    options?: { keyVersion?: number; sealedPrivateKeys?: Uint8Array },
  ): Promise<void>;
  sealItem(input: SealInput): Promise<SealedItem>;
  openItem(input: OpenInput): Promise<string>;
  /** An RFC 9449 proof signed with the device's DPoP key, which never leaves the worker. */
  dpopProof(htm: string, htu: string, nonce?: string, accessToken?: string): Promise<string>;
  /** An `otpauth://` URI for a base32 secret, or for a fresh one when none is given. */
  totpUri(secret?: string): Promise<string>;
  /** A new Send link key: 32 random bytes, base64url. */
  sendNewKey(): Promise<string>;
  /** Seals a Send's payload (key from the link key) and meta (key from the account's), binding id and kind. */
  sealSend(input: SealSendInput): Promise<SealedSend>;
  openSendPayload(input: OpenSendPartInput): Promise<string>;
  /** The owner's name and notes; only the unlocked account opens them, never the link key. */
  openSendMeta(input: OpenSendMetaInput): Promise<string>;
  /** The Send's `sealedKey`: the link key under the unlocked account's item-wrap key. */
  wrapSendKey(id: string, linkKey: string): Promise<Uint8Array>;
  /** The link key of one of the account's own Sends. */
  unwrapSendKey(id: string, sealedKey: Uint8Array): Promise<string>;
  /** The password proof the server checks (32 bytes): Argon2id bound to the Send. */
  sendProof(id: string, linkKey: string, password: string): Promise<Uint8Array>;
  /** A file as the `KMA1` file a file Send stores. */
  sealSendFile(linkKey: string, bytes: Uint8Array): Promise<Uint8Array>;
  openSendFile(linkKey: string, file: Uint8Array): Promise<Uint8Array>;
  /** A public bundle's fingerprint: 12 groups of 5 digits (docs/crypto.md). */
  fingerprint(publicBundle: Uint8Array): Promise<string>;
  /** Whether the signature is the bundle's own `sig1` signature. */
  verifyBundle(publicBundle: Uint8Array, bundleSignature: Uint8Array): Promise<boolean>;
  /** Forgets every key. */
  lock(): Promise<void>;
  /** A one-time kx1 key pair for a device-approval request; the private half stays in the worker. */
  newDeviceKey(): Promise<DeviceKeyPair>;
  /**
   * Opens the root key an approving device sealed to the one-time key (aad = account id ‖ request
   * id) and keeps it in the worker. Spends the one-time key whether or not the box opens.
   */
  openApprovedKey(
    deviceKey: Uint8Array,
    accountId: string,
    requestId: string,
    sealed: Uint8Array,
  ): Promise<Uint8Array>;
  /**
   * Wraps the open account's root key under a passkey's PRF output and raw credential id, for
   * the server to keep (docs/crypto.md, "The passkey PRF wrap of the root key").
   */
  prfWrapRoot(
    prfOutput: Uint8Array,
    credentialId: Uint8Array,
  ): Promise<{ wrappedKey: Uint8Array; keyVersion: number }>;
  /**
   * Opens a passkey's PRF wrap and keeps the root key in the worker; `unlockWithRoot` opens the
   * vault with the handle returned. Refuses another PRF output, credential, account or version.
   */
  prfOpenRoot(
    prfOutput: Uint8Array,
    credentialId: Uint8Array,
    accountId: string,
    keyVersion: number,
    wrapped: Uint8Array,
  ): Promise<Uint8Array>;
  /**
   * Makes a 2-of-3 Recovery Kit for the open account (docs/crypto.md, "The Recovery Kit"). The
   * pieces are text to show once; the wrap is for the server. The root key stays in the worker.
   */
  kitMake(): Promise<{ kitId: string; pieces: string[]; wrappedKey: Uint8Array; keyVersion: number }>;
  /** Reads one piece however it was typed, or says what is wrong with it. */
  kitReadPiece(text: string): Promise<KitPieceRead>;
  /** Whether the pieces are of one kit with none twice; fewer than the kit needs pass. */
  kitCheckPieces(pieces: string[]): Promise<{ problem?: KitProblem }>;
  /**
   * Opens a kit's wrap with enough pieces and keeps the root key in the worker; `unlockWithRoot`
   * opens the vault with the handle returned. Refuses too few pieces, another kit, account or
   * key version.
   */
  kitOpenRoot(
    pieces: string[],
    kitId: string,
    accountId: string,
    keyVersion: number,
    wrapped: Uint8Array,
  ): Promise<Uint8Array>;
  /**
   * Makes the keys of an account that has no password (single sign-on made it), leaves the vault
   * open, and returns what `POST /kem/v1/account/keys/enrol` takes. `wrappedRootKey` is empty.
   */
  newSsoAccount(accountId: string): Promise<NewAccountKeys>;
  /**
   * This browser's copy of the root key, sealed in the worker under a non-extractable key that
   * never leaves this browser (docs/crypto.md, "The trusted-device copy of the root key"). The
   * root key does not reach the page. The server keeps the blob (`PUT /devices/key-copy`).
   */
  deviceCopySeal(
    accountId: string,
    deviceId: string,
    keyVersion: number,
    tabId?: string,
  ): Promise<Uint8Array>;
  /** Opens that copy into a root-key handle for `unlockWithRoot`; refuses any other copy. */
  deviceCopyOpen(
    accountId: string,
    deviceId: string,
    keyVersion: number,
    sealed: Uint8Array,
    tabId?: string,
  ): Promise<Uint8Array>;
  /** Forgets this browser's key, so its copies stop opening. */
  deviceCopyReset(tabId?: string): Promise<void>;
  /**
   * With a `tabId`, the three calls above use that one tab's own key and not the trusted-device
   * key: the copy a reload of the tab opens the vault from, which a closed tab cannot leave behind
   * (src/app/tabKey.ts). `tabSeal` seals the session's tokens under the same key.
   */
  tabSeal(tabId: string, accountId: string, deviceId: string, data: Uint8Array): Promise<Uint8Array>;
  /** Opens what `tabSeal` sealed; refuses anything else, and everything once the tab's key is gone. */
  tabOpen(tabId: string, accountId: string, deviceId: string, sealed: Uint8Array): Promise<Uint8Array>;
  /** Forgets this browser's DPoP key: the next sign-in makes a new one. */
  dpopReset(): Promise<void>;
  /**
   * Opens the vault with the approved root key; consumes it. With `publicBundle` (and the sealed
   * private keys) it refuses unless the keys they hold are the bundle's: a root key that an
   * approving device sent is authenticated by nothing this device holds, so that path passes it.
   */
  unlockWithRoot(
    accountId: string,
    root: Uint8Array,
    options?: { keyVersion?: number; sealedPrivateKeys?: Uint8Array; publicBundle?: Uint8Array },
  ): Promise<void>;
  /** The open account's own fingerprint: 12 groups of 5 digits. Needs the sealed private keys at unlock. */
  ownFingerprint(): Promise<string>;
  /** The key version the account is unlocked at. */
  ownKeyVersion(): Promise<number>;
  /** Drops a handle that will not be used (a one-time key whose request was refused). */
  release(handle: Uint8Array): Promise<void>;
  /** Seals an item of a space's collection under the collection's key. */
  sealSpaceItem(input: SealSpaceItemInput): Promise<SealedItem>;
  openSpaceItem(input: OpenSpaceItemInput): Promise<string>;
  /**
   * A sig1 signature (3,373 bytes) of the unlocked account over a manifest's exact bytes
   * (docs/crypto.md, "Signed manifest"). Only a manifest of the account's own vault or of a space.
   */
  manifestSign(manifest: Uint8Array): Promise<Uint8Array>;
  /** Whether the signature is the unlocked account's own, by its own key, over a manifest of its own vault. */
  manifestVerifyOwn(manifest: Uint8Array, signature: Uint8Array): Promise<boolean>;
  /** Whether the signature is the signer's (the bundle's sig1 key) over a space's manifest. */
  manifestVerify(
    signerBundle: Uint8Array,
    manifest: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean>;
  /**
   * Signs a write as the unlocked account (docs/crypto.md, "Signed item writes"): the three members
   * the server takes with the item. Only a write for the account's own vault or a space is signed.
   */
  itemWriteSign(fields: ItemWriteFields): Promise<ItemWriteSignature>;
  /** Whether the signature is the unlocked account's own, by its own key, over a write naming it as writer. */
  itemWriteVerifyOwn(fields: ItemWriteFields, signature: string): Promise<boolean>;
  /** Whether the signature is the signer's (the bundle's sig1 key) over the write. */
  itemWriteVerify(
    signerBundle: Uint8Array,
    fields: ItemWriteFields,
    signature: string,
  ): Promise<boolean>;
}

// A worker handle crosses the app as 4 opaque bytes, so the app's Uint8Array-typed secrets stay
// secrets it cannot read: the bytes only name a key inside WebAssembly memory.
function handleBytes(handle: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, handle);
  return out;
}

function handleOf<Kind extends string>(bytes: Uint8Array): Handle<Kind> {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0) as Handle<Kind>;
}

/** The app's crypto port over a worker client. */
export function fromWorker(api: CryptoApi): CryptoPort {
  return {
    async masterKey(password, kdf) {
      const handle = await api.masterKey(password, { ...kdf, salt: encodeB64(kdf.salt) });
      return handleBytes(handle);
    },
    async opaqueRegisterStart(masterKey) {
      const started = await api.opaqueRegisterStart(handleOf<'master-key'>(masterKey));
      return { request: decodeB64(started.request), state: started.state };
    },
    async opaqueRegisterFinish(state, masterKey, response) {
      const done = await api.opaqueRegisterFinish(
        state as OpaqueStateHandle,
        handleOf<'master-key'>(masterKey),
        encodeB64(response),
      );
      return { upload: decodeB64(done.upload), exportKey: handleBytes(done.exportKey) };
    },
    async opaqueLoginStart(masterKey) {
      const started = await api.opaqueLoginStart(handleOf<'master-key'>(masterKey));
      return { request: decodeB64(started.request), state: started.state };
    },
    async opaqueLoginFinish(state, masterKey, response) {
      const done = await api.opaqueLoginFinish(
        state as OpaqueStateHandle,
        handleOf<'master-key'>(masterKey),
        encodeB64(response),
      );
      return { finalization: decodeB64(done.finalization), exportKey: handleBytes(done.exportKey) };
    },
    async newAccount(accountId, masterKey, exportKey) {
      const made = await api.newAccount(
        accountId,
        handleOf<'master-key'>(masterKey),
        handleOf<'export-key'>(exportKey),
      );
      return {
        publicBundle: decodeB64(made.publicBundle),
        bundleSignature: decodeB64(made.bundleSignature),
        sealedPrivateKeys: decodeB64(made.sealedPrivateKeys),
        wrappedRootKey: decodeB64(made.wrappedRootKey),
      };
    },
    async rewrapRoot(masterKey, exportKey) {
      return decodeB64(
        await api.rewrapRoot(handleOf<'master-key'>(masterKey), handleOf<'export-key'>(exportKey)),
      );
    },
    unlock: (accountId, wrappedRootKey, masterKey, exportKey, options) =>
      api.unlock(
        accountId,
        encodeB64(wrappedRootKey),
        handleOf<'master-key'>(masterKey),
        handleOf<'export-key'>(exportKey),
        {
          ...(options?.keyVersion !== undefined ? { keyVersion: options.keyVersion } : {}),
          ...(options?.sealedPrivateKeys
            ? { sealedPrivateKeys: encodeB64(options.sealedPrivateKeys) }
            : {}),
        },
      ),
    async sealItem(input) {
      const sealed = await api.sealItem(input);
      return {
        ciphertext: decodeB64(sealed.ciphertext),
        itemKey: decodeB64(sealed.itemKey),
        keyVersion: sealed.keyVersion,
      };
    },
    openItem: (input) =>
      api.openItem({
        id: input.id,
        owner: input.owner,
        kind: input.kind,
        revision: input.revision,
        keyVersion: input.keyVersion,
        ciphertext: encodeB64(input.ciphertext),
        itemKey: encodeB64(input.itemKey),
      }),
    dpopProof: (htm, htu, nonce, accessToken) => api.dpopProof(htm, htu, nonce, accessToken),
    async totpUri(secret) {
      return (await api.totpUri(secret)).uri;
    },
    sendNewKey: () => api.sendNewKey(),
    async sealSend(input) {
      const sealed = await api.sealSend(input);
      return { payload: decodeB64(sealed.payload), meta: decodeB64(sealed.meta) };
    },
    openSendPayload: ({ sealed, ...address }) =>
      api.openSendPayload({ ...address, sealed: encodeB64(sealed) }),
    openSendMeta: ({ sealedKey, sealed, ...address }) =>
      api.openSendMeta({ ...address, sealedKey: encodeB64(sealedKey), sealed: encodeB64(sealed) }),
    async wrapSendKey(id, linkKey) {
      return decodeB64(await api.wrapSendKey(id, linkKey));
    },
    unwrapSendKey: (id, sealedKey) => api.unwrapSendKey(id, encodeB64(sealedKey)),
    async sendProof(id, linkKey, password) {
      return decodeB64(await api.sendProof(id, linkKey, password));
    },
    sealSendFile: (linkKey, bytes) => api.sealSendFile(linkKey, bytes),
    openSendFile: (linkKey, file) => api.openSendFile(linkKey, file),
    fingerprint: (publicBundle) => api.fingerprint(encodeB64(publicBundle)),
    verifyBundle: (publicBundle, bundleSignature) =>
      api.verifyBundle(encodeB64(publicBundle), encodeB64(bundleSignature)),
    lock: () => api.lock(),
    release: (handle) => api.release(handleOf<'device-key'>(handle)),
    async newDeviceKey() {
      const made = await api.newDeviceKey();
      return { handle: handleBytes(made.handle), publicKey: decodeB64(made.publicKey) };
    },
    async openApprovedKey(deviceKey, accountId, requestId, sealed) {
      const root = await api.openApprovedKey(
        handleOf<'device-key'>(deviceKey),
        accountId,
        requestId,
        encodeB64(sealed),
      );
      return handleBytes(root);
    },
    async prfWrapRoot(prfOutput, credentialId) {
      const wrap = await api.prfWrapRoot(encodeB64(prfOutput), encodeB64(credentialId));
      return { wrappedKey: decodeB64(wrap.wrappedKey), keyVersion: wrap.keyVersion };
    },
    async prfOpenRoot(prfOutput, credentialId, accountId, keyVersion, wrapped) {
      const root = await api.prfOpenRoot(
        encodeB64(prfOutput),
        encodeB64(credentialId),
        accountId,
        keyVersion,
        encodeB64(wrapped),
      );
      return handleBytes(root);
    },
    async kitMake() {
      const made = await api.kitMake();
      return { ...made, wrappedKey: decodeB64(made.wrappedKey) };
    },
    kitReadPiece: (text) => api.kitReadPiece(text),
    kitCheckPieces: (pieces) => api.kitCheckPieces(pieces),
    async kitOpenRoot(pieces, kitId, accountId, keyVersion, wrapped) {
      const root = await api.kitOpenRoot(pieces, kitId, accountId, keyVersion, encodeB64(wrapped));
      return handleBytes(root);
    },
    async newSsoAccount(accountId) {
      const made = await api.newSsoAccount(accountId);
      return {
        publicBundle: decodeB64(made.publicBundle),
        bundleSignature: decodeB64(made.bundleSignature),
        sealedPrivateKeys: decodeB64(made.sealedPrivateKeys),
        wrappedRootKey: decodeB64(made.wrappedRootKey),
      };
    },
    async deviceCopySeal(accountId, deviceId, keyVersion, tabId) {
      return decodeB64(await api.deviceCopySeal(accountId, deviceId, keyVersion, tabId));
    },
    async deviceCopyOpen(accountId, deviceId, keyVersion, sealed, tabId) {
      const root = await api.deviceCopyOpen(accountId, deviceId, keyVersion, encodeB64(sealed), tabId);
      return handleBytes(root);
    },
    deviceCopyReset: (tabId) => api.deviceCopyReset(tabId),
    async tabSeal(tabId, accountId, deviceId, data) {
      return decodeB64(await api.tabSeal(tabId, accountId, deviceId, encodeB64(data)));
    },
    async tabOpen(tabId, accountId, deviceId, sealed) {
      return decodeB64(await api.tabOpen(tabId, accountId, deviceId, encodeB64(sealed)));
    },
    dpopReset: () => api.dpopReset(),
    unlockWithRoot: (accountId, root, options) =>
      api.unlockWithRoot(accountId, handleOf<'approved-key'>(root), {
        ...(options?.keyVersion !== undefined ? { keyVersion: options.keyVersion } : {}),
        ...(options?.sealedPrivateKeys
          ? { sealedPrivateKeys: encodeB64(options.sealedPrivateKeys) }
          : {}),
        ...(options?.publicBundle ? { publicBundle: encodeB64(options.publicBundle) } : {}),
      }),
    ownFingerprint: () => api.ownFingerprint(),
    ownKeyVersion: () => api.ownKeyVersion(),
    async sealSpaceItem(input) {
      const sealed = await api.sealSpaceItem(input);
      return {
        ciphertext: decodeB64(sealed.ciphertext),
        itemKey: decodeB64(sealed.itemKey),
        keyVersion: sealed.keyVersion,
      };
    },
    openSpaceItem: (input) =>
      api.openSpaceItem({
        ...input,
        ciphertext: encodeB64(input.ciphertext),
        itemKey: encodeB64(input.itemKey),
      }),
    async manifestSign(manifest) {
      return decodeB64(await api.manifestSign(encodeB64(manifest)));
    },
    manifestVerifyOwn: (manifest, signature) =>
      api.manifestVerifyOwn(encodeB64(manifest), encodeB64(signature)),
    manifestVerify: (signerBundle, manifest, signature) =>
      api.manifestVerify(encodeB64(signerBundle), encodeB64(manifest), encodeB64(signature)),
    itemWriteSign: (fields) => api.itemWriteSign(fields),
    itemWriteVerifyOwn: (fields, signature) => api.itemWriteVerifyOwn(fields, signature),
    itemWriteVerify: (signerBundle, fields, signature) =>
      api.itemWriteVerify(encodeB64(signerBundle), fields, signature),
  };
}

export const vaultCrypto: CryptoPort = fromWorker(worker);
