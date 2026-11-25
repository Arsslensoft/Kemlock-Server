// The /admin/v1 client for the admin console. The shapes follow crates/kemlock-api-admin
// (routes.rs and dto.rs): camelCase, times as Unix seconds, ids as UUIDs, binaries as base64url
// without padding, RFC 9457 problems. Federation is served by crates/kemlock-api-fed/src/admin.rs,
// whose shapes are in ./federation.ts; the types under "Federation" below are what the screens
// draw, and ./federation.ts turns the answers into them.
//
// Every route needs an admin's DPoP-bound access token. Every write also needs a step-up token
// (design: "admin actions ask for a fresh passkey or password check"): `POST
// /admin/v1/step-up/totp { code }`, or the two OPAQUE messages of `step-up/password/*`, answer a
// short-lived token that goes in the `Step-Up-Token` header of the write. A write without a good
// token is answered 403 `step-up-required`; a wrong code or password, 403 `step-up-failed`.
import type { FeatureCall } from './client';
import {
  type WireAwaiting,
  type WireConfirm,
  type WireConsistency,
  type WireHomeRecord,
  type WireKeyChange,
  type WireMismatch,
  type WireOverview,
  type WirePeerCheck,
  type WirePeerSecurity,
  type WireSelf,
  type WireShareable,
  keyMismatchOf,
  overviewOf,
  pairingOf,
  peerOf,
  peerSecurityOf,
  selfSecurityOf,
  sessionOf,
  shareableOf,
} from './federation';

/** What the admin client needs of the API client: it is `api` from src/app/services.ts. */
export interface AdminTransport {
  request<T>(call: FeatureCall): Promise<T>;
  send(call: FeatureCall): Promise<void>;
  raw(call: FeatureCall): Promise<Response>;
}

const BASE = '/admin/v1';

/** The header that carries a step-up token on a write. */
export const STEP_UP_HEADER = 'Step-Up-Token';

// ---- Who am I, and step-up -----------------------------------------------------------------

export interface AdminMe {
  userId: string;
  deviceId: string;
  /** How long a step-up token lasts, in seconds. */
  stepUpTtlSeconds: number;
}

/** OPAQUE's `CredentialRequest`, unpadded base64url. */
export interface StepUpStartRequest {
  request: string;
}

export interface StepUpStartResponse {
  /** OPAQUE's `CredentialResponse`. */
  response: string;
  /** The sealed server state; send it back unread with the last message. */
  loginState: string;
}

export interface StepUpFinishRequest {
  loginState: string;
  /** OPAQUE's `CredentialFinalization`. */
  finalization: string;
}

/** `POST /step-up/passkey/options`: what `navigator.credentials.get` needs, and the sealed challenge. */
export interface StepUpPasskeyOptions {
  /** `PublicKeyCredentialRequestOptions` as JSON, listing the admin's own passkeys. */
  options: Record<string, unknown>;
  /** Send it back unread with the answer, within two minutes, from the same device. Good once. */
  challenge: string;
}

export interface StepUpToken {
  /** Send it as the `Step-Up-Token` header on writes. */
  token: string;
  /** When it stops working, in Unix seconds. */
  expiresAt: number;
}

// ---- Overview ------------------------------------------------------------------------------

export interface AdminOverview {
  users: number;
  admins: number;
  disabledUsers: number;
  devices: number;
  spaces: number;
  liveItems: number;
  events24h: number;
  pendingInvites: number;
  openRequests: number;
  overdueRequests: number;
  mailConfigured: boolean;
}

// ---- Users, invitations and spaces ---------------------------------------------------------

export type UserRole = 'user' | 'admin';
/** `compatible`: an account that also signs in on the Bitwarden API. */
export type AccountMode = 'kemlock-only' | 'compatible';

export interface AdminUser {
  id: string;
  email: string;
  name: string | null;
  role: UserRole;
  mode: AccountMode;
  createdAt: number;
  /** Set while the account is disabled. */
  disabledAt: number | null;
  devices: number;
  /** Whether the account has a confirmed two-step method. */
  twoStep: boolean;
  lastSeenAt: number | null;
  /**
   * The owner deleted the account and its grace period is running: it can't sign in, and only an
   * admin cancels the deletion.
   */
  erasurePending: boolean;
}

/** Where Kemlock's push relay stands (`GET /admin/v1/push-relay`). */
export interface PushRelay {
  /** Whether this server has registered with the relay, so pushes to the mobile apps go out. */
  enabled: boolean;
  /** The relay's id for this server. The key it holds is never shown. */
  installationId: string | null;
  /** The relay the server talks to. */
  relayUrl: string;
}

/** The address and data folder (`GET /admin/v1/server-address`): configuration, shown not edited. */
export interface ServerAddress {
  /** `DOMAIN` as the server runs with it. */
  domain: string;
  /** The address chosen at setup, when one was recorded. */
  recordedDomain: string | null;
  /** A recorded address that is not the one in use. */
  differs: boolean;
  /** `DATA_FOLDER`, which only the environment sets. */
  dataFolder: string | null;
}

export interface UsersQuery {
  search?: string;
  limit?: number;
  offset?: number;
}

export interface UsersPage {
  users: AdminUser[];
  /** Every account that matches, not only this page. */
  total: number;
}

export interface AdminInvite {
  id: string;
  email: string;
  invitedBy: string;
  createdAt: number;
  expiresAt: number;
  lastSentAt: number;
  sent: number;
  accepted: boolean;
  /** Neither accepted nor expired. */
  pending: boolean;
}

export interface InviteIssued {
  invite: AdminInvite;
  /** The link that accepts the invitation: shown only now, the server keeps no copy of its token. */
  link: string;
  /** Whether the mail went out. When it didn't, pass the link on by hand. */
  mailed: boolean;
}

export interface SpaceOwner {
  userId: string;
  email: string;
}

/** A space as the server can describe it: its name is sealed under its key, so it has none here. */
export interface AdminSpace {
  id: string;
  createdAt: number;
  members: number;
  confirmed: number;
  owners: SpaceOwner[];
  liveItems: number;
  /** Set while the space waits for its keys to be replaced. */
  keysPendingSince: number | null;
}

export interface SpacesPage {
  spaces: AdminSpace[];
  total: number;
}

export interface PageQuery {
  limit?: number;
  offset?: number;
}

export interface ChangeOwnerRequest {
  /** A confirmed member of the space. */
  newOwner: string;
  /** Make the other owners admins, so the space has the one owner named here. Default true. */
  demotePrevious?: boolean;
}

// ---- Event log -----------------------------------------------------------------------------

export interface AdminEvent {
  id: string;
  at: number;
  actor: string | null;
  actorEmail: string | null;
  device: string | null;
  /** A code such as `signin.ok`; the console words it. Unknown codes are shown as is. */
  action: string;
  /** An item id, an address or a space: what the action was about. Never an item's contents. */
  target: string | null;
  /** The client's address cut to its /24 or /48. */
  ip: string | null;
}

export interface EventsQuery {
  actor?: string;
  /** A name, or a prefix ending in `*`. */
  action?: string;
  target?: string;
  /** Unix seconds. */
  from?: number;
  to?: number;
  limit?: number;
  cursor?: string;
}

export interface EventsPage {
  /** Newest first. */
  events: AdminEvent[];
  /** Send it as `cursor` for the next page; absent on the last one. */
  next?: string | null;
}

// ---- Server settings -----------------------------------------------------------------------

export type SettingGroup = 'smtp' | 'signups' | 'files' | 'trash' | 'retention' | 'rate-limits';
export type SettingKind = 'bool' | 'int' | 'text' | 'choice' | 'secret' | 'email' | 'domains';
/** Where the value in effect comes from; `env` settings can't be changed here. */
export type SettingSource = 'default' | 'saved' | 'env';

/** One setting. Values travel as text: `"true"`, `"587"`. */
export interface AdminSetting {
  key: string;
  /** The console's section; a group the console doesn't know is shown after the known ones. */
  group: string;
  kind: SettingKind;
  min?: number | null;
  max?: number | null;
  maxLength?: number | null;
  choices?: string[] | null;
  default?: string | null;
  /** The value in effect. Absent for a secret and for a text setting that is unset. */
  value?: string | null;
  /** For a secret: whether one is set. */
  secretSet: boolean;
  source: SettingSource;
  /** The environment sets it: the console can't change it. */
  readOnly: boolean;
  /** The environment variable that sets it. */
  env: string;
}

export interface SettingsResponse {
  settings: AdminSetting[];
}

/** Setting name to its new value as text, or `null` to go back to the default. All or none apply. */
export type SettingChanges = Record<string, string | null>;

// ---- Single sign-on ------------------------------------------------------------------------

export type GroupRole = 'member' | 'admin' | 'owner';

export interface GroupRule {
  /** A value of the ID token's `groups` claim, compared exactly. */
  group: string;
  space: string;
  role: GroupRole;
  /** Collection ids the rule grants. */
  collections: string[];
}

export interface SsoConfig {
  /** Whether a provider has been set up at all. */
  configured: boolean;
  enabled: boolean;
  displayName: string;
  issuer: string;
  clientId: string;
  /** Write-only: the server says whether one is stored and never returns it. */
  clientSecretSet: boolean;
  scopes: string[];
  allowUnknownEmailVerification: boolean;
  linkByEmail: boolean;
  createAccounts: boolean;
  requireVerifiedDomain: boolean;
  groupRules: GroupRule[];
  updatedAt: number | null;
  /** The redirect address to register at the provider. */
  callbackUrl: string;
}

/** What is sent to save. The server replaces everything; a left-out flag goes to its default. */
export interface SsoUpdate {
  enabled: boolean;
  displayName: string;
  issuer: string;
  clientId: string;
  /** A new client secret. Absent keeps the stored one. */
  clientSecret?: string;
  /** Remove the stored secret (a public client). Ignored when `clientSecret` is given. */
  clearClientSecret?: boolean;
  scopes: string[];
  allowUnknownEmailVerification: boolean;
  linkByEmail: boolean;
  createAccounts: boolean;
  requireVerifiedDomain: boolean;
  groupRules: GroupRule[];
}

export interface VerifiedDomain {
  domain: string;
  /** Publish this as a TXT record at the domain. */
  txtValue: string;
  createdAt: number;
  verifiedAt: number | null;
  verified: boolean;
}

// ---- Moving from Vaultwarden ---------------------------------------------------------------

export type MigrationState = 'idle' | 'planned' | 'running' | 'done' | 'failed';

export interface MigrationStatus {
  state: MigrationState;
  source: string | null;
  /** The dry-run plan, in words. */
  plan: string | null;
  error: string | null;
  at: number | null;
  startedBy: string | null;
  /** While running: what it is doing now (`reading the Vaultwarden data`, `writing`, ...). */
  stage: string | null;
  /** When done: what was written, in words. */
  report: string | null;
  /** When it ended, done or failed, in Unix seconds. */
  finishedAt: number | null;
  /** Whether a move writes to Kemlock Server: `start` runs the import in the background. */
  applies: boolean;
}

export interface MigrationStartRequest {
  /** A Vaultwarden data folder on this server, or a `mysql://` or `postgres://` URL. */
  from: string;
  /** The data folder beside a MySQL or PostgreSQL server (attachments, sends, `rsa_key.pem`). */
  files?: string;
}

// ---- Compliance requests -------------------------------------------------------------------

export type RequestKind = 'access' | 'erasure' | 'correction' | 'opt-out' | 'other';
export type RequestStatus = 'open' | 'in-progress' | 'done' | 'rejected';

export interface ComplianceRequest {
  id: string;
  kind: RequestKind;
  requester: string;
  userId: string | null;
  receivedAt: number;
  dueAt: number;
  /** Whether the deadline was extended once. */
  extended: boolean;
  status: RequestStatus;
  note: string | null;
  closedAt: number | null;
  handledBy: string | null;
  /** Open and past its due date. */
  overdue: boolean;
}

export interface LogRequestRequest {
  kind: RequestKind;
  /** Who asked, as they gave it (an email, a name). */
  requester: string;
  userId?: string;
  /** When it arrived, in Unix seconds; default now. */
  receivedAt?: number;
  /** A due date that overrides the CCPA's 45 days (15 business days for an opt-out). */
  dueAt?: number;
  note?: string;
}

export interface UpdateRequestRequest {
  status?: RequestStatus;
  note?: string;
  /** Push the due date out by another 45 days, once. */
  extend?: boolean;
}

// ---- Federation ---------------------------------------------------------------------------

export type PeerState = 'online' | 'offline' | 'catching-up' | 'revoked';
export type PeerOperator = 'own' | 'other';

/** A server's identity as the console shows it. `identityKey` is the `sig1` public key, base64url. */
export interface ServerView {
  serverId: string;
  name: string;
  address: string;
  database: string | null;
  country: string | null;
  operator: PeerOperator;
  operatorName: string | null;
  identityKey: string;
}

export interface Peer extends ServerView {
  state: PeerState;
  offlineSince: number | null;
  lagSeconds: number | null;
  lagChanges: number | null;
  lastChangeAt: number | null;
  lastChangeVault: string | null;
  pinnedAt: number;
  /** Event logs: this server sends ours, and pulls theirs. Both start off. */
  sendLogs: boolean;
  pullLogs: boolean;
  /** Whether the peer sends its logs to us, for "It sends, but Pull is off here". */
  theySendLogs: boolean;
  /** Set while a key mismatch against this peer is unresolved. */
  mismatch: boolean;
}

export interface FedVault {
  id: string;
  /** Plain text the server can know: the owner's email for a personal vault, else a space's name. */
  name: string | null;
  kind: 'personal' | 'space';
  members: number | null;
  ownerEmail: string | null;
  federated: boolean;
  homeId: string;
  /** The vault's home epoch; a promotion makes it epoch + 1. */
  epoch: number;
  replicas: string[];
  /** Null while the server does not say how big a vault is. */
  sizeBytes: number | null;
  waitingChanges: number;
  waitingNote: string | null;
  request: { by: string; at: number } | null;
  /**
   * Another server signed a promotion that would make it this vault's home. It waits for this
   * server's admin, and the vault doesn't sync until then (absent from servers that predate it).
   */
  heldDemotion?: { newHomeId: string; epoch: number; at: number } | null;
}

export interface ConsistencyEntry {
  at: number;
  peerId: string;
  vaults: string[];
  ok: boolean;
}

export interface FederationOverview {
  self: ServerView & { state: PeerState };
  peers: Peer[];
  vaults: FedVault[];
  consistency: ConsistencyEntry[];
}

export interface PromoteRequest {
  /** The admin says the old home is down, not only cut off from this server. */
  homeIsDown: boolean;
}

export interface PairingCode {
  code: string;
  expiresAt: number;
}

export interface ShareableVault {
  id: string;
  name: string | null;
  kind: 'personal' | 'space';
  members: number | null;
  sizeBytes: number;
}

/** A pairing in progress: the admins compare six words. `id` is the other server's id. */
export interface PairingSession {
  id: string;
  self: ServerView;
  peer: ServerView;
  shareable: ShareableVault[];
  /** The six words as the server worked them out, for when a key is missing to work them out here. */
  words?: string | null;
}

/** The code this server shows (kept by the page: the server does not repeat it), and the pairing that waits. */
export interface PairingState {
  code: PairingCode | null;
  session: PairingSession | null;
}

export type PairingAck = 'metadata' | 'no-delete' | 'cross-border';

/** What a peer run by another organisation needs the admin to give. */
export const ALL_ACKNOWLEDGEMENTS: PairingAck[] = ['metadata', 'no-delete', 'cross-border'];

export interface PairingConfirm {
  wordsMatch: boolean;
  /** Every acknowledgement a peer run by another organisation needs. */
  acknowledged: PairingAck[];
  /** Vaults (`user:<uuid>` or `space:<uuid>`) to make federated, with the new peer as replica. */
  offer: string[];
  sendLogs: boolean;
  pullLogs: boolean;
}

/** One suite in the two servers' lists: their place in the peer's list and in this server's. */
export interface SuiteChoice {
  name: string;
  /** Its place in the peer's list, from 1; null when the peer does not list it. */
  theirs: number | null;
  /** Its place in this server's list, from 1; null when it is off here. */
  ours: number | null;
  /** The suite a session between the two would use. */
  inUse: boolean;
}

/** What is known of a peer's keys and descriptor (`GET /federation/peers/{id}/security`). */
export interface PeerSecurity {
  peer: Peer;
  /** The descriptor's identity key is the pinned one and no run met another. */
  keysMatch: boolean;
  /** The descriptor's signature holds and it is inside its window. */
  signatureOk: boolean;
  lastHandshakeAt: number | null;
  /** When the descriptor shown was read from the peer. */
  fetchedAt: number | null;
  /** Why a fresh read failed, when an older copy is shown instead. */
  fetchError: string | null;
  kem: {
    algorithm: string;
    /** A KEM key's creation time is not in the descriptor: this is when this server first saw it. */
    firstSeenAt: number | null;
    nextRotationAt: number | null;
    /** SHA-256 of the key, first 8 bytes, as 4 groups of hex. */
    fingerprint: string;
  } | null;
  descriptor: {
    operator: string;
    addresses: string[];
    notBefore: number;
    notAfter: number;
  } | null;
  suites: SuiteChoice[];
}

/** This server keeps its keys sealed under `server.key`; there is no other way yet. */
export type KeyHolding = 'sealed';

export interface SuiteSetting {
  name: string;
  on: boolean;
  /** This build can run it. */
  available?: boolean;
}

export interface SelfSecurity {
  server: ServerView;
  /** First 16 bytes of SHA-256 of the identity key, as eight groups of hex. */
  identityFingerprint: string;
  validFrom: number;
  validTo: number;
  addresses: string[];
  kemMadeAt: number | null;
  kemNextRotationAt: number | null;
  keyHolding: KeyHolding;
  /** Most preferred first. */
  suites: SuiteSetting[];
}

/** How a visit to one peer went (`POST /federation/check`). */
export interface PeerCheck {
  peerId: string;
  /** `reached`, `busy`, `not-paired`, `nothing-shared`, `key-mismatch` or `unreachable`. */
  reach: string;
  detail: string | null;
}

/** What comparing hash trees with one peer found (`POST /federation/consistency`). */
export interface PeerConsistency {
  peerId: string;
  reach: string;
  vaults: Array<{ vault: string; inStep: boolean | null; detail: string | null }>;
  detail: string | null;
}

/** What replacing the identity key did (`POST /federation/self/identity-rotation`). */
export interface KeyChange {
  kind: string;
  identityKey: string;
  peersTold: number;
}

export interface KeyMismatch {
  peer: Peer;
  pinnedKey: string;
  pinnedAt: number;
  offeredKey: string;
  /** When the key was first offered. */
  offeredAt: number;
  attempts: number;
  lastAttemptAt: number;
  /** The address this server dialled when it met the key. */
  fromAddress: string;
  fromHost: string;
  /** The addresses the peer is known by. */
  usualAddresses: string[];
  /** The address is `https`, so the descriptor came over a verified TLS connection. */
  tlsValid: boolean;
  /** The offered key is not signed by the pinned one: this is not a rotation. */
  signedByPinned: boolean;
  seenBefore: boolean;
  /** When an admin chose to keep blocking, and who. */
  keptBlockingAt: number | null;
  keptBlockingBy: string | null;
  /** A vault's name is ciphertext: the owner's email (an account's vault) or the id. */
  pausedVaults: Array<{
    id: string;
    ownerEmail: string | null;
    members: number | null;
    sizeBytes: number | null;
    waitingChanges: number;
  }>;
  localVaults: number;
}

// ---- The client ----------------------------------------------------------------------------

function query(values: Record<string, string | number | undefined>): FeatureCall['query'] {
  return values;
}

function withToken(token: string | undefined): Record<string, string> | undefined {
  return token ? { [STEP_UP_HEADER]: token } : undefined;
}

/**
 * `token` is a step-up token. Every write takes one; without it the server answers 403
 * `step-up-required`, and `useReauth().guard` (features/admin/reauth.tsx) asks for a code and
 * runs the call again with a token.
 */
export function createAdminApi(api: AdminTransport) {
  const get = <T>(path: string, q?: FeatureCall['query']) =>
    api.request<T>({ method: 'GET', path: `${BASE}${path}`, query: q });
  const post = <T>(path: string, body?: unknown, token?: string) =>
    api.request<T>({ method: 'POST', path: `${BASE}${path}`, body, headers: withToken(token) });
  const put = <T>(path: string, body: unknown, token?: string) =>
    api.request<T>({ method: 'PUT', path: `${BASE}${path}`, body, headers: withToken(token) });
  const patch = <T>(path: string, body: unknown, token?: string) =>
    api.request<T>({ method: 'PATCH', path: `${BASE}${path}`, body, headers: withToken(token) });
  const act = (
    method: 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: unknown,
    token?: string,
  ) => api.send({ method, path: `${BASE}${path}`, body, headers: withToken(token) });

  return {
    /** `GET /admin/v1/me`: the caller is an admin (anyone else gets 403). */
    me: () => get<AdminMe>('/me'),
    /** `POST /admin/v1/step-up/totp { code }`: a step-up token for a code from the authenticator app. */
    stepUpTotp: (code: string) => post<StepUpToken>('/step-up/totp', { code }),
    /** `POST /admin/v1/step-up/password/start`: the first OPAQUE message of the admin's own login, run again. */
    /** `POST /admin/v1/step-up/passkey/options`: the options for a passkey assertion over the admin's own passkeys. */
    stepUpPasskeyOptions: () => post<StepUpPasskeyOptions>('/step-up/passkey/options'),
    /** `POST /admin/v1/step-up/passkey/finish`: the browser's `PublicKeyCredential` as JSON, for a step-up token. */
    stepUpPasskeyFinish: (challenge: string, credential: unknown) =>
      post<StepUpToken>('/step-up/passkey/finish', { challenge, credential }),
    stepUpPasswordStart: (request: string) =>
      post<StepUpStartResponse>('/step-up/password/start', { request } satisfies StepUpStartRequest),
    /** `POST /admin/v1/step-up/password/finish`: the last message; a token when the password was right. */
    stepUpPasswordFinish: (loginState: string, finalization: string) =>
      post<StepUpToken>('/step-up/password/finish', {
        loginState,
        finalization,
      } satisfies StepUpFinishRequest),

    /** `GET /admin/v1/server-address` */
    serverAddress: () => get<ServerAddress>('/server-address'),
    /** `GET /admin/v1/push-relay`: 409 when this server has no relay to control. */
    pushRelay: () => get<PushRelay>('/push-relay'),
    /** `POST /admin/v1/push-relay/enable`: registers this server with the relay. */
    enablePushRelay: (token?: string) => post<PushRelay>('/push-relay/enable', undefined, token),
    /** `POST /admin/v1/push-relay/disable`: erases the installation at the relay and here. */
    disablePushRelay: (token?: string) => post<PushRelay>('/push-relay/disable', undefined, token),

    /** `GET /admin/v1/overview` */
    overview: () => get<AdminOverview>('/overview'),

    /** `GET /admin/v1/users?search&limit&offset` */
    users: (q: UsersQuery = {}) =>
      get<UsersPage>('/users', query({ search: q.search, limit: q.limit, offset: q.offset })),
    /** `POST /admin/v1/users/{id}/sign-out`: ends every session of the account. */
    signOutEverywhere: (id: string, token?: string) =>
      act('POST', `/users/${id}/sign-out`, undefined, token),
    /** `POST /admin/v1/users/{id}/disable` and `/enable` */
    setDisabled: (id: string, disabled: boolean, token?: string) =>
      act('POST', `/users/${id}/${disabled ? 'disable' : 'enable'}`, undefined, token),
    /** `POST /admin/v1/users/{id}/reset-two-step` */
    resetTwoStep: (id: string, token?: string) =>
      act('POST', `/users/${id}/reset-two-step`, undefined, token),
    /**
     * `POST /admin/v1/users/{id}/cancel-erasure`: the owner deleted the account and its grace period
     * is running; this takes it off the schedule (409 when none is pending). Its owner signs in again.
     */
    cancelErasure: (id: string, token?: string) =>
      act('POST', `/users/${id}/cancel-erasure`, undefined, token),
    /** `DELETE /admin/v1/users/{id}`: erases the account. */
    eraseUser: (id: string, token?: string) => act('DELETE', `/users/${id}`, undefined, token),

    /** `GET /admin/v1/invitations` */
    invitations: () => get<AdminInvite[]>('/invitations'),
    /** `POST /admin/v1/invitations { email }` answers 201 with the link, shown only now. */
    invite: (email: string, token?: string) => post<InviteIssued>('/invitations', { email }, token),
    /** `POST /admin/v1/invitations/{id}/resend` */
    resendInvitation: (id: string, token?: string) =>
      post<InviteIssued>(`/invitations/${id}/resend`, undefined, token),
    /** `DELETE /admin/v1/invitations/{id}` */
    revokeInvitation: (id: string, token?: string) =>
      act('DELETE', `/invitations/${id}`, undefined, token),

    /** `GET /admin/v1/spaces?limit&offset` */
    spaces: (q: PageQuery = {}) => get<SpacesPage>('/spaces', query({ limit: q.limit, offset: q.offset })),
    /** `GET /admin/v1/spaces/{id}` */
    space: (id: string) => get<AdminSpace>(`/spaces/${id}`),
    /** `PUT /admin/v1/spaces/{id}/owner { newOwner, demotePrevious }` */
    changeOwner: (spaceId: string, request: ChangeOwnerRequest, token?: string) =>
      put<AdminSpace>(`/spaces/${spaceId}/owner`, request, token),

    /** `GET /admin/v1/events?actor&action&target&from&to&limit&cursor` */
    events: (q: EventsQuery = {}) =>
      get<EventsPage>(
        '/events',
        query({
          actor: q.actor,
          action: q.action,
          target: q.target,
          from: q.from,
          to: q.to,
          limit: q.limit,
          cursor: q.cursor,
        }),
      ),
    /**
     * `GET /admin/v1/events.csv`: the same filters as CSV, at most 100,000 rows (the
     * `X-Export-Truncated` header says when it was cut short). An export is a write for the
     * step-up check, and is recorded.
     */
    eventsCsv: (q: EventsQuery = {}, token?: string) =>
      api.raw({
        method: 'GET',
        path: `${BASE}/events.csv`,
        query: query({
          actor: q.actor,
          action: q.action,
          target: q.target,
          from: q.from,
          to: q.to,
          limit: q.limit,
          cursor: q.cursor,
        }),
        headers: withToken(token),
      }),

    /** `GET /admin/v1/settings` */
    settings: () => get<SettingsResponse>('/settings').then((r) => r.settings),
    /** `PUT /admin/v1/settings { changes }` answers every setting as it is now. */
    saveSettings: (changes: SettingChanges, token?: string) =>
      put<SettingsResponse>('/settings', { changes }, token).then((r) => r.settings),

    /** `GET /admin/v1/sso` */
    sso: () => get<SsoConfig>('/sso'),
    /** `PUT /admin/v1/sso` */
    saveSso: (update: SsoUpdate, token?: string) => put<SsoConfig>('/sso', update, token),
    /** `GET /admin/v1/sso/domains` */
    ssoDomains: () => get<VerifiedDomain[]>('/sso/domains'),
    /** `POST /admin/v1/sso/domains { domain }`: claims a domain, or returns the claim that is there. */
    addSsoDomain: (domain: string, token?: string) =>
      post<VerifiedDomain>('/sso/domains', { domain }, token),
    /** `POST /admin/v1/sso/domains/{domain}/verify`: looks for the DNS record; 409 until it is there. */
    verifySsoDomain: (domain: string, token?: string) =>
      post<VerifiedDomain>(`/sso/domains/${encodeURIComponent(domain)}/verify`, undefined, token),
    /** `DELETE /admin/v1/sso/domains/{domain}` */
    removeSsoDomain: (domain: string, token?: string) =>
      act('DELETE', `/sso/domains/${encodeURIComponent(domain)}`, undefined, token),

    /** `GET /admin/v1/migration` */
    migration: () => get<MigrationStatus>('/migration'),
    /** `POST /admin/v1/migration/start { from, files }`: reads the data (read-only) and records the plan. */
    startMigration: (request: MigrationStartRequest, token?: string) =>
      post<MigrationStatus>('/migration/start', request, token),

    /** `GET /admin/v1/compliance/requests?open`: soonest due first. */
    complianceRequests: (open = true) =>
      get<{ requests: ComplianceRequest[] }>('/compliance/requests', { open: String(open) }).then(
        (r) => r.requests,
      ),
    /** `POST /admin/v1/compliance/requests`: logs a request that arrived. */
    logRequest: (request: LogRequestRequest, token?: string) =>
      post<ComplianceRequest>('/compliance/requests', request, token),
    /** `PATCH /admin/v1/compliance/requests/{id}`: answer, close, reopen or extend. */
    updateRequest: (id: string, update: UpdateRequestRequest, token?: string) =>
      patch<ComplianceRequest>(`/compliance/requests/${id}`, update, token),

    // ---- Federation: crates/kemlock-api-fed/src/admin.rs ----
    // Every write sends the step-up token it is given; the server answers 403 `step-up-required`
    // without one, and `useReauth().guard` asks for a code and tries again. It decides for itself
    // whether a request is fresh enough (promotion is the one that asks).

    /** `GET /admin/v1/federation`: this server, its peers, pairings, vaults and offers. */
    federation: () => get<WireOverview>('/federation').then(overviewOf),
    /** `PUT /admin/v1/federation/peers/{id}/logs { send, pull }` */
    setLogs: (peerId: string, send: boolean, pull: boolean, token?: string) =>
      act('PUT', `/federation/peers/${peerId}/logs`, { send, pull }, token),
    /** `GET /admin/v1/federation/shareable`: the vaults an admin may federate. */
    shareable: () => get<WireShareable[]>('/federation/shareable').then((all) => all.map(shareableOf)),
    /** `POST /admin/v1/federation/check`: visits every peer and checks its pinned key again. Needs a step-up token. */
    checkKeys: (token?: string) =>
      post<WirePeerCheck[]>('/federation/check', undefined, token).then((checks) =>
        checks.map((check): PeerCheck => ({ peerId: check.peer, reach: check.reach, detail: check.detail })),
      ),
    /** `POST /admin/v1/federation/consistency`: compares hash trees with every peer now. Needs a step-up token. */
    runConsistency: (token?: string) =>
      post<WireConsistency[]>('/federation/consistency', undefined, token).then((all) =>
        all.map((entry): PeerConsistency => ({ ...entry, peerId: entry.peer })),
      ),
    /**
     * `POST /admin/v1/federation/vaults/{owner}/promote` (no body): makes this server the home of a
     * vault it holds as a replica. The server accepts a fresh check or a step-up token.
     * `request.homeIsDown` is the admin's own statement; the server does not take it.
     */
    promote: (owner: string, _request: PromoteRequest, grant?: string) =>
      post<{ record: string }>(`/federation/vaults/${encodeURIComponent(owner)}/promote`, undefined, grant),
    /**
     * `POST /admin/v1/federation/vaults/{owner}/demotion` (no body): lets the server whose
     * promotion is held become the home of a vault this server is the home of. Needs a fresh
     * check or a step-up token.
     */
    acceptDemotion: (owner: string, grant?: string) =>
      post<unknown>(`/federation/vaults/${encodeURIComponent(owner)}/demotion`, undefined, grant),
    /** `PUT /admin/v1/federation/vaults/{owner} { policy, replicas }`: a vault's policy at its home. */
    setVaultPolicy: (
      owner: string,
      policy: 'local' | 'federated',
      replicas: string[],
      token?: string,
    ) => put<unknown>(`/federation/vaults/${encodeURIComponent(owner)}`, { policy, replicas }, token),
    /** `GET /admin/v1/federation/vaults/{owner}/quarantined`: home records of an older epoch. */
    quarantined: (owner: string) =>
      get<WireHomeRecord[]>(`/federation/vaults/${encodeURIComponent(owner)}/quarantined`),

    /** `POST /admin/v1/federation/offers/{owner}/accept`: copy a vault its home offered. */
    federate: (owner: string, token?: string) =>
      post<unknown>(`/federation/offers/${encodeURIComponent(owner)}/accept`, undefined, token),
    /** `POST /admin/v1/federation/offers/{owner}/decline` */
    declineFederation: (owner: string, token?: string) =>
      act('POST', `/federation/offers/${encodeURIComponent(owner)}/decline`, undefined, token),

    /**
     * `GET /admin/v1/federation`, read for its pairings: the one that waits for the words, with the
     * vaults this server could offer the new peer (`GET .../shareable`).
     */
    pairing: async (): Promise<PairingState> => {
      const overview = await get<WireOverview>('/federation');
      if (overview.pairings.length === 0) return pairingOf(overview);
      return pairingOf(overview, await get<WireShareable[]>('/federation/shareable'));
    },
    /** `POST /admin/v1/federation/pairing/code`: a new one-time code (the old one stops working). */
    newPairingCode: () => post<PairingCode>('/federation/pairing/code'),
    /** `POST /admin/v1/federation/pairing { address, code }`: runs the exchange, then waits for the words. */
    connectPairing: async (address: string, code: string, grant?: string): Promise<PairingSession> => {
      const awaiting = await post<WireAwaiting>('/federation/pairing', { address, code }, grant);
      const overview = await get<WireOverview>('/federation');
      return sessionOf(awaiting, overview.server, await get<WireShareable[]>('/federation/shareable'));
    },
    /**
     * `POST /admin/v1/federation/pairings/{peer}/confirm`, then what the admin chose on the same
     * page: the log switches (`PUT .../peers/{id}/logs`) and the vaults to offer (`PUT
     * .../vaults/{owner} { policy: "federated", replicas: [peer] }`). Answers the new peer.
     */
    confirmPairing: async (id: string, confirm: PairingConfirm, grant?: string): Promise<Peer> => {
      const body: WireConfirm = { fingerprintMatches: confirm.wordsMatch };
      if (ALL_ACKNOWLEDGEMENTS.every((ack) => confirm.acknowledged.includes(ack))) {
        const me = await get<AdminMe>('/me');
        body.acknowledgement = { metadata: true, deletion: true, crossBorder: true, by: me.userId };
      }
      await post<unknown>(`/federation/pairings/${id}/confirm`, body, grant);
      if (confirm.sendLogs || confirm.pullLogs) {
        await put<unknown>(
          `/federation/peers/${id}/logs`,
          { send: confirm.sendLogs, pull: confirm.pullLogs },
          grant,
        );
      }
      for (const owner of confirm.offer) {
        await put<unknown>(
          `/federation/vaults/${encodeURIComponent(owner)}`,
          { policy: 'federated', replicas: [id] },
          grant,
        );
      }
      const overview = await get<WireOverview>('/federation');
      const peer = overview.peers.find((candidate) => candidate.id === id);
      if (!peer) throw new Error('the server did not list the peer it just paired with');
      return peerOf(peer, overview.server.operator);
    },
    /** `DELETE /admin/v1/federation/pairings/{peer}` */
    cancelPairing: (id: string, grant?: string) =>
      act('DELETE', `/federation/pairings/${id}`, undefined, grant),

    /** `POST /admin/v1/federation/peers/{id}/revoke`: no session is accepted from it or opened to it. */
    revokePeer: (id: string, grant?: string) =>
      act('POST', `/federation/peers/${id}/revoke`, undefined, grant),
    /** `DELETE /admin/v1/federation/peers/{id}`: forgets a peer with its cursors and switches. */
    removePeer: (id: string, grant?: string) => act('DELETE', `/federation/peers/${id}`, undefined, grant),
    /** `GET /fed/v1/descriptor`: this server's signed descriptor, public, as a file. */
    selfDescriptor: () => api.raw({ method: 'GET', path: '/fed/v1/descriptor' }),

    /** `GET /admin/v1/federation/peers/{id}/security`, with the peer as the overview lists it. */
    peerSecurity: async (id: string): Promise<PeerSecurity> => {
      const [wire, overview] = await Promise.all([
        get<WirePeerSecurity>(`/federation/peers/${id}/security`),
        get<WireOverview>('/federation'),
      ]);
      const peer = overview.peers.find((candidate) => candidate.id === id);
      if (!peer) throw new Error('the server did not list that peer');
      return peerSecurityOf(wire, peerOf(peer, overview.server.operator));
    },
    /** `GET /admin/v1/federation/peers/{id}/descriptor`: the peer's descriptor as a file. */
    peerDescriptor: (id: string) =>
      api.raw({ method: 'GET', path: `${BASE}/federation/peers/${id}/descriptor` }),
    /** `GET /admin/v1/federation/self`: this server's keys, suites and descriptor. */
    selfSecurity: () => get<WireSelf>('/federation/self').then(selfSecurityOf),
    /** `POST /admin/v1/federation/self/kem-rotation`: a new KEM key. Needs a step-up token. */
    rotateKem: (token?: string) =>
      post<WireSelf>('/federation/self/kem-rotation', undefined, token).then(selfSecurityOf),
    /**
     * `POST /admin/v1/federation/self/identity-rotation`: a new identity key, signed by the old one,
     * and every paired peer told. Needs a step-up token.
     */
    rotateIdentity: (token?: string) =>
      post<WireKeyChange>('/federation/self/identity-rotation', undefined, token).then(
        (change): KeyChange => change,
      ),
    /** `PUT /admin/v1/federation/self/suites { suites, keyHolding }`: re-signs the descriptor. Needs a step-up token. */
    saveSuites: (suites: SuiteSetting[], keyHolding: KeyHolding, token?: string) =>
      put<WireSelf>(
        '/federation/self/suites',
        { suites: suites.map(({ name, on }) => ({ name, on })), keyHolding },
        token,
      ).then(selfSecurityOf),
    /** `GET /admin/v1/federation/mismatches/{peerId}`: 404 when no mismatch is on record. */
    keyMismatch: async (peerId: string): Promise<KeyMismatch> => {
      const [wire, overview] = await Promise.all([
        get<WireMismatch>(`/federation/mismatches/${peerId}`),
        get<WireOverview>('/federation'),
      ]);
      const peer = overview.peers.find((candidate) => candidate.id === peerId);
      if (!peer) throw new Error('the server did not list that peer');
      return keyMismatchOf(wire, peerOf(peer, overview.server.operator));
    },
    /** `POST /admin/v1/federation/mismatches/{peerId}/keep-blocking`: records the choice. Needs a step-up token. */
    keepBlocking: (peerId: string, token?: string) =>
      post<WireMismatch>(`/federation/mismatches/${peerId}/keep-blocking`, undefined, token).then(
        () => undefined,
      ),
  };
}

export type AdminApi = ReturnType<typeof createAdminApi>;
