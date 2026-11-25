// The contract between the page and the crypto worker. Everything that crosses is a string, a
// number or a plain object: binary values are base64url strings in the wire form of
// docs/crypto.md, and secrets that stay in the browser (master keys, OPAQUE export keys,
// half-finished OPAQUE exchanges) are opaque handles into the worker's WebAssembly memory.

declare const handleBrand: unique symbol;

/** A number that names a secret held in WebAssembly memory. It carries no key material. */
export type Handle<Kind extends string> = number & { readonly [handleBrand]: Kind };

export type MasterKeyHandle = Handle<'master-key'>;
export type ExportKeyHandle = Handle<'export-key'>;
export type OpaqueStateHandle = Handle<'opaque-state'>;
/** Another account's root key, opened from an emergency-access box; it never leaves the worker. */
export type EmergencyKeyHandle = Handle<'emergency-key'>;
/** A new device's one-time kx1 private key, waiting for an approval to be sealed to it. */
export type DeviceKeyHandle = Handle<'device-key'>;
/** The root key an approval carried, opened and not yet used to unlock; it never leaves the worker. */
export type ApprovedKeyHandle = Handle<'approved-key'>;

/** The account's Argon2id settings, as the server returns them (`KdfDto`). */
export interface KdfSettings {
  memoryKib: number;
  iterations: number;
  parallelism: number;
  /** base64url */
  salt: string;
}

export interface OpaqueStart {
  state: OpaqueStateHandle;
  /** base64url, for the server */
  request: string;
}

export interface OpaqueRegisterFinished {
  /** OPAQUE's `RegistrationUpload`, base64url */
  upload: string;
  exportKey: ExportKeyHandle;
}

export interface OpaqueLoginFinished {
  /** OPAQUE's `CredentialFinalization`, base64url */
  finalization: string;
  exportKey: ExportKeyHandle;
}

/** The fields the register route stores, plus the fingerprint to show the owner. */
export interface NewAccount {
  publicBundle: string;
  bundleSignature: string;
  sealedPrivateKeys: string;
  wrappedRootKey: string;
  keyVersion: number;
  /** 12 groups of 5 digits, joined by spaces */
  fingerprint: string;
}

/** A passkey's wrap of the root key, as the server stores it. */
export interface PrfWrap {
  /** base64url, 92 bytes. */
  wrappedKey: string;
  keyVersion: number;
}

/** A new Recovery Kit: the pieces to show once, and the record for the server. */
export interface MadeKit {
  kitId: string;
  /** The text of each piece, `BMCKIT1-...`; the only copy there will be. */
  pieces: string[];
  /** base64url, 92 bytes: the root key under the kit key. */
  wrappedKey: string;
  keyVersion: number;
}

/** What is wrong with a piece or the pieces entered so far (docs/crypto.md, "The Recovery Kit"). */
export type KitProblem = 'format' | 'checksum' | 'other-kit' | 'duplicate' | 'not-enough';

/** A piece read from its text, or the problem with it. */
export type KitPieceRead =
  | { problem?: undefined; kitId: string; threshold: number; shares: number; index: number }
  | { problem: KitProblem };

export interface UnlockOptions {
  /** The account's key version; 1 when omitted. */
  keyVersion?: number;
  /** Also opens the kx1 and sig1 private keys (`ownFingerprint` needs them). */
  sealedPrivateKeys?: string;
}

/** What identifies an item inside its ciphertext's AAD. */
export interface ItemAddress {
  /** hyphenated lower-case UUID */
  id: string;
  /** `user:<uuid>` or `space:<uuid>` */
  owner: string;
  /** 1 to 64 characters of `a-z0-9_-` */
  kind: string;
  revision: number;
}

export interface SealItemInput extends ItemAddress {
  /** The item's JSON, as text. */
  json: string;
}

export interface SealedItem {
  /** base64url `nonce ‖ ciphertext ‖ tag` */
  ciphertext: string;
  /** base64url, the item key wrapped under the owner's item-wrap key */
  itemKey: string;
  keyVersion: number;
}

export interface OpenItemInput extends ItemAddress {
  ciphertext: string;
  itemKey: string;
  /** The key version the item says it was wrapped under; the account's when omitted. */
  keyVersion?: number;
}

/** What binds a Send's seals: its id (the UUID the client chose, or the access id the link
 * carries), its kind and the link key from the link's fragment (base64url, 32 bytes). */
export interface SendAddress {
  id: string;
  /** `text` or `file` */
  kind: string;
  linkKey: string;
}

export interface SealSendInput extends SendAddress {
  /** The payload JSON a recipient opens: `{name, text}` or `{name, mime, size}`. */
  payloadJson: string;
  /** The owner's `{name, notes}`. */
  metaJson: string;
}

/** The two sealed parts the server stores of a Send's content, base64url. */
export interface SealedSend {
  payload: string;
  meta: string;
}

export interface OpenSendPartInput extends SendAddress {
  /** base64url of the sealed payload */
  sealed: string;
}

/**
 * The owner's meta opens with the account's key, not the link key: `sealedKey` only names the
 * key version it needs.
 */
export interface OpenSendMetaInput {
  id: string;
  /** `text` or `file` */
  kind: string;
  /** base64url of the Send's `sealedKey` */
  sealedKey: string;
  /** base64url of the sealed meta */
  sealed: string;
}

export interface TotpEnrolment {
  /** base32, for typing into an authenticator app */
  secret: string;
  /** an `otpauth://` URI for a QR code */
  uri: string;
}

export interface TotpOptions {
  issuer?: string;
  account?: string;
}

/** The sealed-box contexts under which the worker seals the root key (docs/crypto.md). */
export type RootKeyContext = 'device-approval' | 'emergency-access';

/** What a space name names. */
export type NameKind = 'space' | 'collection' | 'group';

/** What a member confirmation says (docs/crypto.md, "Member confirmation"). */
export interface ConfirmationFacts {
  /** hyphenated lower-case UUID */
  space: string;
  /** hyphenated lower-case UUID */
  member: string;
  memberKeyVersion: number;
  /** The 64 fingerprint bytes the confirmer compared, base64url. */
  fingerprint: string;
}

/** A confirmation to check: its facts, the statement and signature, and the confirmer's bundle. */
export interface ConfirmationCheck extends ConfirmationFacts {
  /** The confirmer's public bundle, base64url. */
  confirmerBundle: string;
  statement: string;
  signature: string;
}

/** A new device's one-time key: the public half for the approval request (base64url, 1,600 bytes). */
export interface DeviceKey {
  handle: DeviceKeyHandle;
  publicKey: string;
}

/**
 * An item of a space's collection, to seal. Its owner is `space:<spaceId>`; the collection's newest
 * key held wraps the item key, and its version comes back as the item's `keyVersion`.
 */
export interface SealSpaceItemInput {
  spaceId: string;
  collectionId: string;
  /** hyphenated lower-case UUID */
  id: string;
  kind: string;
  revision: number;
  json: string;
}

/** An item of a space's collection, to open. `keyVersion` is the collection key's. */
export interface OpenSpaceItemInput {
  spaceId: string;
  collectionId: string;
  id: string;
  kind: string;
  revision: number;
  keyVersion: number;
  ciphertext: string;
  itemKey: string;
}

/** A collection's name and its key sealed to its maker (base64url). */
export interface SealedCollection {
  name: string;
  sealedKey: string;
}

export interface NewSpaceInput {
  spaceId: string;
  collectionId: string;
  spaceName: string;
  collectionName: string;
}

export interface NewSpaceResult {
  name: string;
  sealedSpaceKey: string;
  collection: SealedCollection;
}

/** The names of a space's parts are encrypted under the space key of a key version. */
export interface NameAddress {
  spaceId: string;
  keyVersion: number;
  kind: NameKind;
  /** The id of the space, collection or group named. */
  id: string;
}

/**
 * Why an operation failed, and no more: a wrong password, a wrong key and a tampered byte all
 * look the same on purpose.
 *
 * - `invalid`: malformed input, a stale handle, or a key that did not open what it was given;
 * - `locked`: no account is unlocked;
 * - `unavailable`: the WebAssembly module or the worker could not start.
 */
export type CryptoErrorCode = 'invalid' | 'locked' | 'unavailable';

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode) {
    super(code);
    this.name = 'CryptoError';
    this.code = code;
  }
}

/** The page's view of the worker: `crypto` in index.ts. */
export interface CryptoApi {
  /** `Argon2id(password, salt, m, t, p)`. A `Uint8Array` is transferred and wiped. */
  masterKey(password: string | Uint8Array, kdf: KdfSettings): Promise<MasterKeyHandle>;
  opaqueRegisterStart(masterKey: MasterKeyHandle): Promise<OpaqueStart>;
  opaqueRegisterFinish(
    state: OpaqueStateHandle,
    masterKey: MasterKeyHandle,
    response: string,
  ): Promise<OpaqueRegisterFinished>;
  opaqueLoginStart(masterKey: MasterKeyHandle): Promise<OpaqueStart>;
  opaqueLoginFinish(
    state: OpaqueStateHandle,
    masterKey: MasterKeyHandle,
    response: string,
  ): Promise<OpaqueLoginFinished>;
  /** Makes the keys of a new account; consumes both handles. */
  newAccount(
    accountId: string,
    masterKey: MasterKeyHandle,
    exportKey: ExportKeyHandle,
  ): Promise<NewAccount>;
  /**
   * Wraps the open account's root key under a new master key and OPAQUE export key, for a change
   * of master password or sign-in address (docs/crypto.md, "Changing the master password and the
   * sign-in address"). Returns the wrap, base64url, 92 bytes. The root key, the key version and
   * the vault stay as they are. Consumes both handles on success.
   */
  rewrapRoot(masterKey: MasterKeyHandle, exportKey: ExportKeyHandle): Promise<string>;
  /**
   * Makes the keys of an account that has no password (single sign-on made it) and leaves the
   * vault open: `wrappedRootKey` is empty. Seal this device's copy of the root key next with
   * `deviceCopySeal`, since nothing else opens it here.
   */
  newSsoAccount(accountId: string): Promise<NewAccount>;
  /**
   * This browser's copy of the root key (docs/crypto.md, "The trusted-device copy of the root
   * key"): sealed in the worker under a non-extractable key that never leaves this browser. The
   * root key does not reach the page. Returns the blob (base64url) the server keeps.
   */
  deviceCopySeal(accountId: string, deviceId: string, keyVersion: number): Promise<string>;
  /**
   * Opens this browser's copy into a root-key handle for `unlockWithRoot`. Refuses a copy made
   * for another account, device or key version, or by another browser.
   */
  deviceCopyOpen(
    accountId: string,
    deviceId: string,
    keyVersion: number,
    sealed: string,
  ): Promise<ApprovedKeyHandle>;
  /** Forgets this browser's key: its copies stop opening. */
  deviceCopyReset(): Promise<void>;
  /** Opens the password wrap of the root key; consumes both handles. */
  unlock(
    accountId: string,
    wrappedRootKey: string,
    masterKey: MasterKeyHandle,
    exportKey: ExportKeyHandle,
    options?: UnlockOptions,
  ): Promise<void>;
  sealItem(input: SealItemInput): Promise<SealedItem>;
  /** Resolves with the item's JSON text. */
  openItem(input: OpenItemInput): Promise<string>;
  /**
   * An ES256 DPoP proof (RFC 9449) from a non-extractable key the worker keeps in IndexedDB.
   * `htu` may carry a query; it is dropped.
   */
  dpopProof(htm: string, htu: string, nonce?: string, accessToken?: string): Promise<string>;
  /** A TOTP enrolment: a fresh secret, or the URI for `secret` (base32) when given. */
  totpUri(secret?: string, options?: TotpOptions): Promise<TotpEnrolment>;

  // Sends (docs/crypto.md, "Sends"). The link key is the one key that leaves the worker, as
  // base64url text, because it belongs in the link's fragment.

  /** A new Send link key: 32 random bytes, base64url. */
  sendNewKey(): Promise<string>;
  /**
   * Seals a Send's payload under a key from the link key, and its meta under one from the
   * unlocked account's key (so a link holder can't open it), binding id and kind.
   */
  sealSend(input: SealSendInput): Promise<SealedSend>;
  /** A Send's payload JSON, opened with the link key. */
  openSendPayload(input: OpenSendPartInput): Promise<string>;
  /** The owner's name and notes of a Send, as JSON; needs the unlocked account. */
  openSendMeta(input: OpenSendMetaInput): Promise<string>;
  /** The `sealedKey` the server stores: the link key under the account's item-wrap key. */
  wrapSendKey(id: string, linkKey: string): Promise<string>;
  /** The link key of one of the account's own Sends, from its `sealedKey`. */
  unwrapSendKey(id: string, sealedKey: string): Promise<string>;
  /** The password proof the server checks: Argon2id bound to the Send, base64url. */
  sendProof(id: string, linkKey: string, password: string): Promise<string>;
  /** A file as the `KMA1` file a file Send stores. The bytes are transferred. */
  sealSendFile(linkKey: string, bytes: Uint8Array): Promise<Uint8Array>;
  /** The plaintext of a file Send's `KMA1` file. The bytes are transferred. */
  openSendFile(linkKey: string, file: Uint8Array): Promise<Uint8Array>;
  /** Wipes every key and handle in WebAssembly memory. The DPoP key stays. */
  lock(): Promise<void>;

  // Beyond the core contract:

  /** A public bundle's fingerprint (base64url in), as 12 groups of 5 digits. */
  fingerprint(publicBundle: string): Promise<string>;
  /** Whether the signature is the bundle's own `sig1` signature. */
  verifyBundle(publicBundle: string, bundleSignature: string): Promise<boolean>;
  /** The unlocked account's own fingerprint; needs `unlock` with `sealedPrivateKeys`. */
  ownFingerprint(): Promise<string>;
  /** Drops a handle that will not be used. */
  release(
    handle:
      | MasterKeyHandle
      | ExportKeyHandle
      | OpaqueStateHandle
      | EmergencyKeyHandle
      | DeviceKeyHandle
      | ApprovedKeyHandle,
  ): Promise<void>;

  // Sharing: the account's keys given to someone else. Binary values are base64url.

  /**
   * Seals the unlocked account's root key to a kx1 public key as a sealed box. `device-approval`
   * takes `aad` = account id ‖ approval request id (32 bytes), `emergency-access` the contact's
   * account id (16 bytes); no other context is sealed.
   */
  sealRootKey(recipientKx1: string, context: RootKeyContext, aad: string): Promise<string>;
  /** The 134-byte confirmation statement, the unlocked account as the confirmer. */
  confirmationStatement(facts: ConfirmationFacts): Promise<string>;
  /** A sig1 signature over a confirmation statement of this account; context `confirm` only. */
  signStatement(statement: string, context: string): Promise<string>;
  /** Whether the signature is the confirmer's over exactly the statement these facts give. */
  verifyConfirmation(check: ConfirmationCheck): Promise<boolean>;
  /** Opens a root key sealed to this account for emergency access, behind a handle. */
  openEmergencyKey(sealed: string): Promise<EmergencyKeyHandle>;
  /** Opens one of the grantor's own items with an emergency key; resolves with its JSON. */
  openEmergencyItem(handle: EmergencyKeyHandle, input: OpenItemInput): Promise<string>;

  // Spaces: space and collection keys live in the worker; only boxes and ciphertexts cross.

  /** A new space: a space key and first collection key sealed to the maker, names under the key. */
  newSpace(input: NewSpaceInput): Promise<NewSpaceResult>;
  /** Opens the space key sealed to me and keeps it for `spaceId` at `keyVersion`. */
  openSpace(input: { spaceId: string; keyVersion: number; sealed: string }): Promise<void>;
  /** Opens a collection key sealed to me and keeps it. */
  openCollection(input: {
    spaceId: string;
    collectionId: string;
    keyVersion: number;
    sealed: string;
  }): Promise<void>;
  openName(input: NameAddress & { ciphertext: string }): Promise<string>;
  sealName(input: NameAddress & { name: string }): Promise<string>;
  /** A new collection: its key sealed to me, and its name under the newest space key held. */
  newCollection(input: {
    spaceId: string;
    collectionId: string;
    name: string;
  }): Promise<SealedCollection>;
  /** The newest space key held, sealed to a member (bound to space, key version and member). */
  sealSpaceKeyTo(input: {
    spaceId: string;
    recipientKx1: string;
    recipientId: string;
  }): Promise<string>;
  /** The newest key held of a collection, sealed to a member (bound to space, collection, version). */
  sealCollectionKeyTo(input: {
    spaceId: string;
    collectionId: string;
    recipientKx1: string;
    recipientId: string;
  }): Promise<string>;
  /** Forgets the DPoP key (sign-out of this device). */
  dpopReset(): Promise<void>;

  // Device approval, the new device's side: it makes a one-time key, shows the phrase from the
  // public half, and opens the root key an approving device sealed to it.

  /** A one-time kx1 key pair for an approval request; the private half stays in the worker. */
  newDeviceKey(): Promise<DeviceKey>;
  /**
   * Opens the root key sealed to the one-time key under `device-approval`, with
   * `aad = accountId ‖ requestId`. Spends the one-time key, whether or not the box opens.
   */
  openApprovedKey(
    deviceKey: DeviceKeyHandle,
    accountId: string,
    requestId: string,
    sealed: string,
  ): Promise<ApprovedKeyHandle>;
  /**
   * Wraps the open account's root key under a passkey's PRF output and credential id
   * (docs/crypto.md, "The passkey PRF wrap of the root key"), for the server to keep.
   */
  prfWrapRoot(prfOutput: string, credentialId: string): Promise<PrfWrap>;
  /**
   * Opens a passkey's PRF wrap of the root key and keeps the root key in the worker; unlock with
   * `unlockWithRoot`. Refuses another PRF output, credential, account or key version.
   */
  prfOpenRoot(
    prfOutput: string,
    credentialId: string,
    accountId: string,
    keyVersion: number,
    wrapped: string,
  ): Promise<ApprovedKeyHandle>;
  /** Makes a 2-of-3 Recovery Kit for the open account; the root key never leaves the worker. */
  kitMake(): Promise<MadeKit>;
  /** Reads one piece however it was typed. */
  kitReadPiece(text: string): Promise<KitPieceRead>;
  /** Whether pieces are of one kit with none twice; fewer than the kit needs pass. */
  kitCheckPieces(pieces: string[]): Promise<{ problem?: KitProblem }>;
  /**
   * Opens a kit's wrap of the root key with enough pieces and keeps the root key in the worker;
   * unlock with `unlockWithRoot`. Refuses too few pieces, another kit, account or key version.
   */
  kitOpenRoot(
    pieces: string[],
    kitId: string,
    accountId: string,
    keyVersion: number,
    wrapped: string,
  ): Promise<ApprovedKeyHandle>;
  /** Opens the vault with an approved root key; consumes the handle. */
  unlockWithRoot(
    accountId: string,
    root: ApprovedKeyHandle,
    options?: UnlockOptions,
  ): Promise<void>;

  // Items of a space's collection: the item key is wrapped under the collection key.

  sealSpaceItem(input: SealSpaceItemInput): Promise<SealedItem>;
  /** Resolves with the item's JSON text. */
  openSpaceItem(input: OpenSpaceItemInput): Promise<string>;
}

/** Every operation the worker answers, with its arguments and result. */
export interface Ops {
  masterKey: { args: [password: string | Uint8Array, kdf: KdfSettings]; result: MasterKeyHandle };
  opaqueRegisterStart: { args: [masterKey: MasterKeyHandle]; result: OpaqueStart };
  opaqueRegisterFinish: {
    args: [state: OpaqueStateHandle, masterKey: MasterKeyHandle, response: string];
    result: OpaqueRegisterFinished;
  };
  opaqueLoginStart: { args: [masterKey: MasterKeyHandle]; result: OpaqueStart };
  opaqueLoginFinish: {
    args: [state: OpaqueStateHandle, masterKey: MasterKeyHandle, response: string];
    result: OpaqueLoginFinished;
  };
  newAccount: {
    args: [accountId: string, masterKey: MasterKeyHandle, exportKey: ExportKeyHandle];
    result: NewAccount;
  };
  rewrapRoot: { args: [masterKey: MasterKeyHandle, exportKey: ExportKeyHandle]; result: string };
  unlock: {
    args: [
      accountId: string,
      wrappedRootKey: string,
      masterKey: MasterKeyHandle,
      exportKey: ExportKeyHandle,
      options?: UnlockOptions,
    ];
    result: void;
  };
  sealItem: { args: [input: SealItemInput]; result: SealedItem };
  openItem: { args: [input: OpenItemInput]; result: string };
  dpopProof: {
    args: [htm: string, htu: string, nonce?: string, accessToken?: string];
    result: string;
  };
  totpUri: { args: [secret?: string, options?: TotpOptions]; result: TotpEnrolment };
  sendNewKey: { args: []; result: string };
  sealSend: { args: [input: SealSendInput]; result: SealedSend };
  openSendPayload: { args: [input: OpenSendPartInput]; result: string };
  openSendMeta: { args: [input: OpenSendMetaInput]; result: string };
  wrapSendKey: { args: [id: string, linkKey: string]; result: string };
  unwrapSendKey: { args: [id: string, sealedKey: string]; result: string };
  sendProof: { args: [id: string, linkKey: string, password: string]; result: string };
  sealSendFile: { args: [linkKey: string, bytes: Uint8Array]; result: Uint8Array };
  openSendFile: { args: [linkKey: string, file: Uint8Array]; result: Uint8Array };
  lock: { args: []; result: void };
  fingerprint: { args: [publicBundle: string]; result: string };
  verifyBundle: { args: [publicBundle: string, bundleSignature: string]; result: boolean };
  ownFingerprint: { args: []; result: string };
  release: { args: [handle: number]; result: void };
  dpopReset: { args: []; result: void };
  sealRootKey: {
    args: [recipientKx1: string, context: RootKeyContext, aad: string];
    result: string;
  };
  confirmationStatement: { args: [facts: ConfirmationFacts]; result: string };
  signStatement: { args: [statement: string, context: string]; result: string };
  verifyConfirmation: { args: [check: ConfirmationCheck]; result: boolean };
  openEmergencyKey: { args: [sealed: string]; result: EmergencyKeyHandle };
  openEmergencyItem: {
    args: [handle: EmergencyKeyHandle, input: OpenItemInput];
    result: string;
  };
  newSpace: { args: [input: NewSpaceInput]; result: NewSpaceResult };
  openSpace: {
    args: [input: { spaceId: string; keyVersion: number; sealed: string }];
    result: void;
  };
  openCollection: {
    args: [input: { spaceId: string; collectionId: string; keyVersion: number; sealed: string }];
    result: void;
  };
  openName: { args: [input: NameAddress & { ciphertext: string }]; result: string };
  sealName: { args: [input: NameAddress & { name: string }]; result: string };
  newCollection: {
    args: [input: { spaceId: string; collectionId: string; name: string }];
    result: SealedCollection;
  };
  sealSpaceKeyTo: {
    args: [input: { spaceId: string; recipientKx1: string; recipientId: string }];
    result: string;
  };
  sealCollectionKeyTo: {
    args: [
      input: { spaceId: string; collectionId: string; recipientKx1: string; recipientId: string },
    ];
    result: string;
  };
  newDeviceKey: { args: []; result: DeviceKey };
  openApprovedKey: {
    args: [deviceKey: DeviceKeyHandle, accountId: string, requestId: string, sealed: string];
    result: ApprovedKeyHandle;
  };
  prfWrapRoot: { args: [prfOutput: string, credentialId: string]; result: PrfWrap };
  prfOpenRoot: {
    args: [
      prfOutput: string,
      credentialId: string,
      accountId: string,
      keyVersion: number,
      wrapped: string,
    ];
    result: ApprovedKeyHandle;
  };
  kitMake: { args: []; result: MadeKit };
  kitReadPiece: { args: [text: string]; result: KitPieceRead };
  kitCheckPieces: { args: [pieces: string[]]; result: { problem?: KitProblem } };
  kitOpenRoot: {
    args: [pieces: string[], kitId: string, accountId: string, keyVersion: number, wrapped: string];
    result: ApprovedKeyHandle;
  };
  newSsoAccount: { args: [accountId: string]; result: NewAccount };
  deviceCopySeal: {
    args: [accountId: string, deviceId: string, keyVersion: number];
    result: string;
  };
  deviceCopyOpen: {
    args: [accountId: string, deviceId: string, keyVersion: number, sealed: string];
    result: ApprovedKeyHandle;
  };
  deviceCopyReset: { args: []; result: void };
  unlockWithRoot: {
    args: [accountId: string, root: ApprovedKeyHandle, options?: UnlockOptions];
    result: void;
  };
  sealSpaceItem: { args: [input: SealSpaceItemInput]; result: SealedItem };
  openSpaceItem: { args: [input: OpenSpaceItemInput]; result: string };
}

export type OpName = keyof Ops;

export interface WorkerRequest<Op extends OpName = OpName> {
  id: number;
  op: Op;
  args: Ops[Op]['args'];
}

export type WorkerResponse =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; code: CryptoErrorCode };
