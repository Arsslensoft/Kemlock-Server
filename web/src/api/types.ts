// The JSON bodies of /kem/v1, as crates/kemlock-api-kem/src/dto.rs writes them. Every binary
// value is base64url without padding. src/api/wire.check.ts ties these to the generated OpenAPI
// types, so a changed route breaks `npm run gen:api` instead of a user.

export type SetupPhase = 'needs-admin' | 'pending' | 'complete';

export interface ConfigResponse {
  server: string;
  apiVersions: string[];
  version: string;
  /** The git commit the server was built from; absent when the build did not know it. */
  commit?: string | null;
  /** The SPDX identifier of the server's licence: `AGPL-3.0-only`. */
  license: string;
  /** Where the source of this exact version is offered (AGPL-3.0 section 13). */
  sourceUrl: string;
  serverId: string;
  domain: string;
  setup: SetupPhase;
  signupsAllowed: boolean;
  features: string[];
}

export interface SetupVerifyRequest {
  code: string;
}
export interface SetupVerifyResponse {
  grant: string;
  expiresIn: number;
}

export interface EmailRequest {
  email: string;
}

export interface KdfDto {
  memoryKib: number;
  iterations: number;
  parallelism: number;
  salt: string;
}

export interface PreloginResponse {
  kdf: KdfDto;
}

export interface MethodsResponse {
  methods: string[];
  /** The provider's name when an OpenID Connect provider is on for this email. */
  sso?: { providerName: string } | null;
}

export interface RegisterStartRequest {
  email: string;
  request: string;
  setupGrant?: string | null;
}
export interface RegisterStartResponse {
  response: string;
}

export interface RegisterFinishRequest {
  userId: string;
  email: string;
  name?: string | null;
  upload: string;
  kdf: KdfDto;
  publicBundle: string;
  bundleSignature: string;
  sealedPrivateKeys: string;
  wrappedRootKey: string;
  setupGrant?: string | null;
}
export interface RegisterFinishResponse {
  userId: string;
  admin: boolean;
}

export interface OpaqueStartRequest {
  email: string;
  request: string;
}
export interface OpaqueStartResponse {
  response: string;
  loginState: string;
}

export type DeviceKind =
  | 'kemlock-android'
  | 'kemlock-ios'
  | 'kemlock-web'
  | 'kemlock-browser'
  | 'kemlock-cli'
  | 'amethystora'
  | 'bitwarden'
  | 'other';

export interface DeviceDto {
  id?: string | null;
  name: string;
  kind?: DeviceKind | null;
}

export interface OpaqueFinishRequest {
  email: string;
  loginState: string;
  finalization: string;
  device: DeviceDto;
}

export interface TokenResponse {
  tokenType: 'DPoP';
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresIn: number;
  userId: string;
  deviceId: string;
  admin: boolean;
}

export interface SignInResponse {
  status: 'signed_in' | 'two_factor_required';
  tokens?: TokenResponse | null;
  challenge?: string | null;
  methods?: string[] | null;
}

export interface TwoFactorRequest {
  challenge: string;
  method: 'totp';
  code: string;
}

export interface RefreshRequest {
  grantType: 'refresh_token';
  refreshToken: string;
}

export interface TotpEnrolResponse {
  secret: string;
  uri: string;
}
export interface TotpConfirmRequest {
  code: string;
}

export interface ItemDto {
  id: string;
  /** `user:<uuid>` or `space:<uuid>`. */
  owner: string;
  kind: string;
  format: 'kem1' | 'bw';
  revision: number;
  keyVersion: number;
  /** Absent on a tombstone. */
  ciphertext?: string | null;
  /** Absent on a tombstone. */
  itemKey?: string | null;
  /** True on a tombstone, which carries no ciphertext or itemKey. */
  deleted?: boolean;
  /** The collection an item of a space is in: required to write one, absent for a vault's items. */
  collectionId?: string | null;
  /**
   * When the server recorded the deletion, RFC 3339 in UTC. Present on a tombstone only, set by
   * the server; it may be sent back unchanged and is ignored.
   */
  deletedAt?: string | null;
  /**
   * The account that wrote this revision and signed it (docs/crypto.md, "Signed item writes"): all
   * three members come together or not at all. The server stores and serves them; it never makes
   * one.
   */
  writer?: string | null;
  /** The key version of the writer's bundle that signed. */
  writerKeyVersion?: number | null;
  /** The writer's sig1 signature of the write, base64url. */
  writeSignature?: string | null;
}

export interface BatchWrite {
  expectedRevision?: number | null;
  item: ItemDto;
}
export interface BatchRequest {
  writes: BatchWrite[];
}
export interface BatchResponse {
  items: ItemDto[];
}

export interface SyncResponse {
  items: ItemDto[];
  cursor: string;
  more: boolean;
}

/**
 * `GET /kem/v1/account/keys` (crates/kemlock-api-kem/src/routes/contract.rs): the account's
 * wrapped and public key material, for a browser that has none of it yet.
 */
export interface AccountKeysResponse {
  keyVersion: number;
  kdf: KdfDto;
  /** The root key under the password wrap. */
  wrappedRootKey: string;
  /** The signed public-key bundle. */
  publicBundle: string;
  /** The `sig1` signature over the bundle. */
  bundleSignature: string;
  /** The exchange and signing private keys sealed under the user key. */
  sealedPrivateKeys: string;
}

/** An RFC 9457 problem. `type` is `urn:kemlock:problem:<slug>`. */
export interface ProblemBody {
  type: string;
  title: string;
  status: number;
  detail?: string;
  [extra: string]: unknown;
}
