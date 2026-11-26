// The shape of the wasm-bindgen module built from crates/kemlock-wasm (web/scripts/build-wasm.sh
// writes it to ./pkg), and the loader that starts it. The interface is written by hand so the
// worker type-checks and its tests run before the module is built.

/** The `Vault` class of crates/kemlock-wasm/src/wasm.rs. Methods that return several values
 * return one JSON string. Failures throw an `Error` whose message is `invalid` or `locked`. */
export interface WasmVault {
  masterKey(
    password: string,
    memoryKib: number,
    iterations: number,
    parallelism: number,
    salt: string,
  ): number;
  release(handle: number): void;
  opaqueRegisterStart(master: number): string;
  opaqueRegisterFinish(state: number, master: number, response: string): string;
  opaqueLoginStart(master: number): string;
  opaqueLoginFinish(state: number, master: number, response: string): string;
  newAccount(accountId: string, master: number, exportKey: number): string;
  /** The open account's root key under a new master key and export key: base64url, 92 bytes. */
  rewrapRoot(master: number, exportKey: number): string;
  /** Like `newAccount` with no password wrap, leaving the account unlocked. */
  newSsoAccount(accountId: string): string;
  /** The open account's root key, base64url: for the worker to seal under the device's key. */
  exportRoot(): string;
  /** Keeps a root key the worker opened behind a handle, for `unlockWithRoot`. */
  importRoot(root: string): number;
  unlock(
    accountId: string,
    wrappedRootKey: string,
    master: number,
    exportKey: number,
    keyVersion: number,
    sealedPrivateKeys?: string,
  ): void;
  isUnlocked(): boolean;
  sealItem(id: string, owner: string, kind: string, revision: bigint, itemJson: string): string;
  openItem(
    id: string,
    owner: string,
    kind: string,
    revision: bigint,
    ciphertext: string,
    itemKey: string,
    keyVersion?: number,
  ): string;
  ownFingerprint(): string;
  fingerprint(publicBundle: string): string;
  verifyBundle(publicBundle: string, bundleSignature: string): boolean;
  totpEnrol(secret: string | undefined, issuer: string, account: string): string;
  sendNewKey(): string;
  /** `{payload, meta}`, base64url. */
  sendSeal(
    id: string,
    kind: string,
    linkKey: string,
    payloadJson: string,
    metaJson: string,
  ): string;
  sendOpenPayload(id: string, kind: string, linkKey: string, payload: string): string;
  /** Opens the owner's meta with the account's key; `sealedKey` names the key version. */
  sendOpenMeta(id: string, kind: string, sealedKey: string, meta: string): string;
  sendWrapKey(id: string, linkKey: string): string;
  sendOpenKey(id: string, sealedKey: string): string;
  sendProof(id: string, linkKey: string, password: string): string;
  sendSealFile(linkKey: string, plain: Uint8Array): Uint8Array;
  sendOpenFile(linkKey: string, file: Uint8Array): Uint8Array;
  sealRootKey(recipientKx1: string, context: string, aad: string): string;
  sealRootKeyForRecovery(spaceId: string, recoveryKx1: string, keySeq: number): string;
  confirmationStatement(
    spaceId: string,
    memberId: string,
    memberKeyVersion: number,
    fingerprint: string,
  ): string;
  signStatement(statement: string, context: string): string;
  verifyConfirmation(
    confirmerBundle: string,
    spaceId: string,
    memberId: string,
    memberKeyVersion: number,
    fingerprint: string,
    statement: string,
    signature: string,
  ): boolean;
  openEmergencyKey(sealed: string): number;
  openEmergencyItem(
    handle: number,
    id: string,
    owner: string,
    kind: string,
    revision: bigint,
    ciphertext: string,
    itemKey: string,
    keyVersion?: number,
  ): string;
  /** `{handle, publicKey}`: a new device's one-time kx1 key, private half behind the handle. */
  newDeviceKey(): string;
  /** Opens the root key sealed to the one-time key; the root key stays behind the handle returned. */
  openApprovedKey(deviceKey: number, accountId: string, requestId: string, sealed: string): number;
  /** `{wrappedKey, keyVersion}`: the open account's root key under a passkey's PRF output. */
  prfWrapRoot(prfOutput: string, credentialId: string): string;
  /** Opens a passkey's PRF wrap; the root key stays behind the handle returned. */
  prfOpenRoot(
    prfOutput: string,
    credentialId: string,
    accountId: string,
    keyVersion: number,
    wrapped: string,
  ): number;
  /** `{kitId, pieces, wrappedKey, keyVersion}`: a 2-of-3 Recovery Kit for the open account. */
  kitMake(): string;
  /** `{kitId, threshold, shares, index}` or `{problem}` (format, checksum) for one piece's text. */
  kitReadPiece(text: string): string;
  /** `{problem}` (other-kit, duplicate, format, checksum), or `{}`, for a JSON array of pieces. */
  kitCheckPieces(piecesJson: string): string;
  /** Opens a kit's wrap with enough pieces (a JSON array); the root key stays behind the handle. */
  kitOpenRoot(
    piecesJson: string,
    kitId: string,
    accountId: string,
    keyVersion: number,
    wrapped: string,
  ): number;
  /** With `publicBundle` it refuses unless the opened private keys are that bundle's. */
  unlockWithRoot(
    accountId: string,
    rootHandle: number,
    keyVersion: number,
    sealedPrivateKeys?: string,
    publicBundle?: string,
  ): void;
  /** `{ciphertext, itemKey, keyVersion}`, the item key wrapped under the collection's newest key. */
  sealSpaceItem(
    spaceId: string,
    collectionId: string,
    id: string,
    kind: string,
    revision: bigint,
    itemJson: string,
  ): string;
  openSpaceItem(
    spaceId: string,
    collectionId: string,
    id: string,
    kind: string,
    revision: bigint,
    ciphertext: string,
    itemKey: string,
    keyVersion: number,
  ): string;
  newSpace(spaceId: string, collectionId: string, spaceName: string, collectionName: string): string;
  openSpace(spaceId: string, keyVersion: number, sealed: string): void;
  openCollection(spaceId: string, collectionId: string, keyVersion: number, sealed: string): void;
  openName(spaceId: string, keyVersion: number, kind: string, id: string, ciphertext: string): string;
  sealName(spaceId: string, keyVersion: number, kind: string, id: string, name: string): string;
  newCollection(spaceId: string, collectionId: string, name: string): string;
  sealSpaceKeyTo(spaceId: string, recipientKx1: string, recipientId: string): string;
  sealCollectionKeyTo(
    spaceId: string,
    collectionId: string,
    recipientKx1: string,
    recipientId: string,
  ): string;
  /** A sig1 signature of the unlocked account over a manifest (base64url, exact bytes). */
  manifestSign(manifest: string): string;
  /** Whether the signature is the unlocked account's own over a manifest of its own vault. */
  manifestVerifyOwn(manifest: string, signature: string): boolean;
  /** Whether the signature is the bundle's sig1 key over a space's manifest. */
  manifestVerify(signerBundle: string, manifest: string, signature: string): boolean;
  /** A write's fields as JSON in; `{writer, writerKeyVersion, writeSignature}` as JSON out. */
  itemWriteSign(fields: string): string;
  /** Whether the signature is the unlocked account's own over the write (fields as JSON). */
  itemWriteVerifyOwn(fields: string, signature: string): boolean;
  /** Whether the signature is the bundle's sig1 key over the write (fields as JSON). */
  itemWriteVerify(signerBundle: string, fields: string, signature: string): boolean;
  // The space chain: JSON in and out (see crates/kemlock-wasm/src/chain.rs).
  verifySpaceChain(spaceId: string, records: string, anchor?: string): string;
  spaceChainView(spaceId: string): string | undefined;
  sealLocal(label: string, text: string): string;
  openLocal(label: string, sealed: string): string;
  acceptFirstContact(spaceId: string): void;
  openChainKey(
    spaceId: string,
    key: string,
    servedVersion: number,
    sealed: string,
    list?: string,
  ): void;
  lock(): void;
  /** Frees the instance's WebAssembly memory (wasm-bindgen). */
  free?(): void;
}

/** Makes a fresh `Vault`; called again after `lock` so no old memory is reused. */
export type WasmFactory = () => WasmVault;

/** Starts the WebAssembly module and returns the factory for its `Vault`. */
export type WasmLoader = () => Promise<WasmFactory>;

export const loadWasm: WasmLoader = async () => {
  // The module is generated by scripts/build-wasm.sh, so it is absent until that has run.
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const module = (await import('./pkg/kemlock_wasm.js')) as {
    default: () => Promise<unknown>;
    Vault: new () => WasmVault;
  };
  await module.default();
  return () => new module.Vault();
};
