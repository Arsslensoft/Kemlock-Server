// What `/admin/v1/federation` answers, as crates/kemlock-api-fed/src/admin.rs and
// src/admin/console.rs write them, and the step that turns it into the shapes the federation
// screens draw (`Peer`, `FedVault`, ... in ./admin.ts).
//
// The wire types are the server's own, one for one: camelCase, times as Unix seconds, ids as UUIDs,
// an owner as `user:<uuid>` or `space:<uuid>`, identity keys as lower-case hex. What a server cannot
// know it does not say, and the screens say nothing of it either:
//   - a vault has no name (it is ciphertext only its members read): the owner's email for an
//     account's vault, the short id for a space;
//   - a peer's `name` is the host of its first address (a descriptor carries no name), and its
//     database and country are not in its descriptor: only this server knows its own.
import { encodeB64 } from '@/lib/b64url';
import type {
  ConsistencyEntry,
  FedVault,
  FederationOverview,
  KeyMismatch,
  PairingSession,
  PairingState,
  Peer,
  PeerSecurity,
  PeerState,
  SelfSecurity,
  ServerView,
  ShareableVault,
} from './admin';

// ---- The server's shapes ------------------------------------------------------------------

export interface WireServer {
  serverId: string;
  /** The name of the server, or the host of its first address. */
  name: string;
  operator: string;
  addresses: string[];
  /** The `sig1` identity key, hex. */
  identityKey: string;
  descriptorNotAfter: number;
  /** The kind of database, when the process that runs the server says. Only for this server. */
  database: string | null;
  /** The country the server runs in, when the process that runs the server says. Only for this server. */
  country: string | null;
}

export interface WireAcknowledgement {
  metadata: boolean;
  deletion: boolean;
  crossBorder: boolean;
  by: string;
  at: number;
}

export interface WireVaultStatus {
  vault: string;
  at: number;
  offer: 'pending' | 'accepted' | 'declined' | null;
  pulled: { applied: number; siblings: number; duplicates: number; refused: number };
  homeApplied: number;
  homeQuarantined: number;
  behind: boolean;
  filesFetched: number;
  filesDeferred: number;
  eventsPulled: number;
  tagsPulled: number;
  /** Hash trees were compared this run: `true` when they matched. */
  inStep: boolean | null;
  note: string | null;
}

export interface WirePeerStatus {
  lastAttempt: number | null;
  lastSuccess: number | null;
  downSince: number | null;
  lastError: string | null;
  /** Hex of the identity key a peer offered that was not the pinned one. */
  keyMismatch: string | null;
  vaults: WireVaultStatus[];
}

export interface WirePeer {
  id: string;
  /** The host of its first address. */
  name: string;
  operator: string;
  addresses: string[];
  state: 'paired' | 'revoked' | 'contested';
  /** The pinned `sig1` identity key, hex. */
  identityKey: string;
  pairedAt: number;
  /** When the peer last answered: a session or a probe, whichever was later. */
  lastSeen: number | null;
  /** Whether the peer answers, as the server's probes found (absent from servers that predate them). */
  health?: 'unknown' | 'online' | 'degraded' | 'offline' | 'key-mismatch';
  /** How long its last answer took, in milliseconds. */
  latencyMs?: number | null;
  /** Why the last probe failed, until one answers. */
  probeError?: string | null;
  /** Since when the probes have been failing, Unix seconds. */
  failingSince?: number | null;
  /** The six words of the pairing. */
  fingerprint: string[];
  switches: { send: boolean; pull: boolean };
  acknowledgement: WireAcknowledgement | null;
  /** Null until the peer has been visited since the server started. */
  status: WirePeerStatus | null;
  /** Versions this server holds that the peer may still be waiting for, counted to a limit. */
  lagChanges: number;
  /** The age of the oldest of those versions in seconds; null when no vault is shared. */
  lagSeconds: number | null;
  /** When the peer last wrote a change to a shared vault. */
  lastChangeAt: number | null;
  lastChangeVault: string | null;
  /** This server holds event-log entries the peer sent. */
  theySendLogs: boolean;
}

export interface WireAwaiting {
  peerId: string;
  operator: string;
  addresses: string[];
  /** The six words both admins compare. */
  fingerprint: string[];
  /** The peer's operator is not this server's: three acknowledgements are needed. */
  otherOrganisation: boolean;
  /** The peer's `sig1` identity key from its descriptor, hex: what this pairing would pin. */
  identityKey: string;
  /** `typed` when the admin here typed the code, `showed` when they showed it. */
  side: 'typed' | 'showed';
  since: number;
}

export interface WireVault {
  vault: string;
  policy: 'local' | 'federated';
  home: string;
  epoch: number;
  replicas: string[];
  isHome: boolean;
  /** The signed promotion record that made this epoch, base64url. */
  promotion: string | null;
  /** The owner's email, for an account's vault. A vault's name is ciphertext: the server has none. */
  ownerEmail: string | null;
  /** People who can open the vault, when this server holds it. */
  members: number | null;
  /** What the vault takes here in bytes, when this server holds it. */
  sizeBytes: number | null;
  /** Versions waiting to reach the vault's other servers, counted to a limit. */
  waitingChanges: number;
  waitingNote: string | null;
  /** A promotion another server signed to become this vault's home, waiting for this server's admin. */
  heldDemotion?: { newHome: string; epoch: number; issuedAt: number } | null;
  /** Every promotion that waits, one for each server that would become the home. */
  heldPromotions?: Array<{ newHome: string; epoch: number; issuedAt: number }>;
}

export interface WireOffer {
  vault: string;
  home: string;
  epoch: number;
  replicas: string[];
  state: 'pending' | 'accepted' | 'declined';
  receivedAt: number;
}

export interface WireOverview {
  server: WireServer;
  peers: WirePeer[];
  pairings: WireAwaiting[];
  vaults: WireVault[];
  offers: WireOffer[];
}

export interface WireHomeRecord {
  index: number;
  epoch: number;
  kind: string;
  signer: string;
  status: 'applied' | 'quarantined';
  payloadLength: number;
}

/** `GET /federation/shareable`: a vault an admin may federate. */
export interface WireShareable {
  vault: string;
  ownerEmail: string | null;
  members: number;
  sizeBytes: number;
}

/** `POST /federation/check`: how a visit to one peer went. */
export interface WirePeerCheck {
  peer: string;
  /** `reached`, `busy`, `not-paired`, `nothing-shared`, `key-mismatch` or `unreachable`. */
  reach: string;
  detail: string | null;
}

/** `POST /federation/consistency`: what comparing hash trees with one peer found. */
export interface WireConsistency {
  peer: string;
  reach: string;
  vaults: Array<{ vault: string; inStep: boolean | null; detail: string | null }>;
  detail: string | null;
}

export interface WirePeerSecurity {
  peerId: string;
  operator: string;
  /** The descriptor's identity key is the pinned one and no run met another. */
  keysMatch: boolean;
  /** The descriptor's signature holds and it is inside its window. */
  signatureOk: boolean;
  fetchedAt: number | null;
  fetchError: string | null;
  descriptor: {
    identityKey: string;
    operator: string;
    addresses: string[];
    notBefore: number;
    notAfter: number;
  } | null;
  kem: {
    algorithm: string;
    /** When this server first saw the key: a KEM key's creation time is not in the descriptor. */
    firstSeenAt: number | null;
    nextRotationAt: number | null;
    fingerprint: string;
  } | null;
  suites: Array<{ name: string; theirs: number | null; ours: number | null; inUse: boolean }>;
  lastHandshakeAt: number | null;
}

export interface WireSelf {
  server: WireServer;
  /** First 16 bytes of SHA-256 of the identity key, as eight groups of hex. */
  identityFingerprint: string;
  /** The signed descriptor this server publishes, base64url. */
  descriptor: string;
  validFrom: number;
  validTo: number;
  kemMadeAt: number | null;
  kemNextRotationAt: number | null;
  /** In this server's order, most preferred first; the ones left off follow. */
  suites: Array<{ name: string; on: boolean; available: boolean }>;
}

/** `POST /federation/self/identity-rotation`. */
export interface WireKeyChange {
  /** `rotation` or `revocation`. */
  kind: string;
  identityKey: string;
  peersTold: number;
}

export interface WireMismatch {
  peerId: string;
  pinnedKey: string;
  pinnedAt: number;
  offeredKey: string;
  firstOfferedAt: number;
  lastAttemptAt: number;
  attempts: number;
  /** The address this server dialled when it met the key. */
  fromAddress: string;
  fromHost: string;
  usualAddresses: string[];
  /** The address is `https`, so the descriptor came over a verified TLS connection. */
  tlsValid: boolean;
  signedByPinned: boolean;
  seenBefore: boolean;
  keptBlockingAt: number | null;
  keptBlockingBy: string | null;
  pausedVaults: Array<{
    vault: string;
    ownerEmail: string | null;
    members: number | null;
    sizeBytes: number | null;
    waitingChanges: number;
  }>;
  localVaults: number;
}

/** `POST /pairings/{peer}/confirm`: the three acknowledgements of a peer run by another operator. */
export interface WireConfirm {
  fingerprintMatches: boolean;
  acknowledgement?: { metadata: boolean; deletion: boolean; crossBorder: boolean; by: string };
}

// ---- Small helpers ------------------------------------------------------------------------

/** Lower- or upper-case hex as unpadded base64url; empty when it is not hex. */
export function hexToB64(hex: string | undefined): string {
  if (hex === undefined || !/^(?:[0-9a-fA-F]{2})+$/.test(hex)) return '';
  return encodeB64(Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16)));
}

/** The first eight characters of an id, without the `user:` or `space:` of an owner. */
export function shortId(id: string): string {
  return id.replace(/^(?:user|space):/, '').slice(0, 8);
}

/** The host of an address (`https://vault.example.co:443/x` is `vault.example.co`). */
export function hostName(address: string | undefined): string {
  if (!address) return '';
  const bare = address.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0] ?? '';
  return bare.replace(/:\d+$/, '');
}

// ---- Wire to view -------------------------------------------------------------------------

/** A server as the screens show it. Only this server knows its own database and country. */
function serverView(
  id: string,
  name: string,
  operator: string,
  addresses: string[],
  identityKeyHex: string | undefined,
  ownOperator: string,
  own?: { database: string | null; country: string | null },
): ServerView {
  const mine = operator === ownOperator;
  return {
    serverId: id,
    name: name || hostName(addresses[0]) || shortId(id),
    address: addresses[0] ?? '',
    database: own?.database ?? null,
    country: own?.country ?? null,
    operator: mine ? 'own' : 'other',
    operatorName: mine ? null : operator,
    identityKey: hexToB64(identityKeyHex),
  };
}

function peerState(peer: WirePeer): PeerState {
  if (peer.state === 'revoked') return 'revoked';
  if (peer.state === 'contested') return 'contested';
  const status = peer.status;
  if (peer.health === 'offline') return 'offline';
  if (status?.downSince !== null && status?.downSince !== undefined) return 'offline';
  if (peer.health === 'degraded') return 'degraded';
  if (status?.vaults.some((vault) => vault.inStep === false || vault.behind)) return 'catching-up';
  return 'online';
}

export function peerOf(peer: WirePeer, ownOperator: string): Peer {
  const status = peer.status;
  return {
    ...serverView(peer.id, peer.name, peer.operator, peer.addresses, peer.identityKey, ownOperator),
    state: peerState(peer),
    offlineSince: peer.failingSince ?? status?.downSince ?? null,
    lastSeen: peer.lastSeen,
    latencyMs: peer.latencyMs ?? null,
    lagSeconds: peer.lagSeconds,
    lagChanges: peer.lagChanges,
    lastChangeAt: peer.lastChangeAt,
    lastChangeVault: peer.lastChangeVault,
    pinnedAt: peer.pairedAt,
    sendLogs: peer.switches.send,
    pullLogs: peer.switches.pull,
    theySendLogs: peer.theySendLogs,
    mismatch: (status?.keyMismatch !== null && status?.keyMismatch !== undefined) || peer.health === 'key-mismatch',
  };
}

function vaultOf(vault: WireVault): FedVault {
  return {
    id: vault.vault,
    // A vault has no name the server can read: the owner's email, or the id the screens shorten.
    name: null,
    kind: vault.vault.startsWith('space:') ? 'space' : 'personal',
    members: vault.members,
    ownerEmail: vault.ownerEmail,
    federated: vault.policy === 'federated',
    homeId: vault.home,
    epoch: vault.epoch,
    replicas: vault.replicas,
    sizeBytes: vault.sizeBytes,
    waitingChanges: vault.waitingChanges,
    waitingNote: vault.waitingNote,
    request: null,
    heldDemotion: vault.heldDemotion
      ? { newHomeId: vault.heldDemotion.newHome, epoch: vault.heldDemotion.epoch, at: vault.heldDemotion.issuedAt }
      : null,
    heldPromotions: (vault.heldPromotions ?? []).map((p) => ({ newHomeId: p.newHome, epoch: p.epoch, at: p.issuedAt })),
  };
}

/**
 * The vaults federation knows of here, with every offer still waiting for this server's admin as a
 * request on its vault: a home offered it, and the admin accepts or declines.
 */
function vaultsOf(wire: WireOverview): FedVault[] {
  const vaults = wire.vaults.map(vaultOf);
  const homeName = (id: string) => {
    const known = wire.peers.find((peer) => peer.id === id);
    return known ? known.name || hostName(known.addresses[0]) || shortId(id) : shortId(id);
  };
  for (const offer of wire.offers) {
    if (offer.state !== 'pending') continue;
    const request = { by: homeName(offer.home), at: offer.receivedAt };
    const existing = vaults.find((vault) => vault.id === offer.vault);
    if (existing) {
      existing.request = request;
    } else {
      vaults.push({
        ...vaultOf({
          vault: offer.vault,
          policy: 'federated',
          home: offer.home,
          epoch: offer.epoch,
          replicas: offer.replicas,
          isHome: false,
          promotion: null,
          ownerEmail: null,
          members: null,
          sizeBytes: null,
          waitingChanges: 0,
          waitingNote: null,
        }),
        request,
      });
    }
  }
  return vaults;
}

/** The hash-tree comparisons the last runs made, newest first, one line per peer. */
function consistencyOf(peers: WirePeer[]): ConsistencyEntry[] {
  const entries: ConsistencyEntry[] = [];
  for (const peer of peers) {
    const compared = peer.status?.vaults.filter((vault) => vault.inStep !== null) ?? [];
    if (compared.length === 0) continue;
    entries.push({
      at: Math.max(...compared.map((vault) => vault.at)),
      peerId: peer.id,
      vaults: compared.map((vault) => shortId(vault.vault)),
      ok: compared.every((vault) => vault.inStep === true),
    });
  }
  return entries.sort((a, b) => b.at - a.at);
}

function selfView(server: WireServer): ServerView {
  return serverView(
    server.serverId,
    server.name,
    server.operator,
    server.addresses,
    server.identityKey,
    server.operator,
    { database: server.database, country: server.country },
  );
}

export function overviewOf(wire: WireOverview): FederationOverview {
  const own = wire.server.operator;
  const peers = wire.peers.map((peer) => peerOf(peer, own));
  return {
    self: { ...selfView(wire.server), state: 'online' },
    peers,
    vaults: vaultsOf(wire),
    consistency: consistencyOf(wire.peers),
  };
}

/** A vault an admin may offer a new peer: named by its owner's email, or the id of a space. */
export function shareableOf(wire: WireShareable): ShareableVault {
  return {
    id: wire.vault,
    name: wire.ownerEmail,
    kind: wire.vault.startsWith('space:') ? 'space' : 'personal',
    members: wire.members,
    sizeBytes: wire.sizeBytes,
  };
}

/** A pairing that waits for the admin to compare the words: the other server's view of it. */
export function sessionOf(
  awaiting: WireAwaiting,
  server: WireServer,
  shareable: WireShareable[] = [],
): PairingSession {
  const own = server.operator;
  return {
    id: awaiting.peerId,
    self: selfView(server),
    peer: serverView(awaiting.peerId, '', awaiting.operator, awaiting.addresses, awaiting.identityKey, own),
    shareable: shareable.map(shareableOf),
    words: awaiting.fingerprint.join('-'),
  };
}

/** The newest pairing that waits, if there is one. The server does not say what code it shows. */
export function pairingOf(wire: WireOverview, shareable: WireShareable[] = []): PairingState {
  const newest = wire.pairings.reduce<WireAwaiting | undefined>(
    (latest, current) => (latest === undefined || current.since >= latest.since ? current : latest),
    undefined,
  );
  return { code: null, session: newest ? sessionOf(newest, wire.server, shareable) : null };
}

/** What the peer security page draws: the peer's descriptor, its KEM key, the suites and the keys. */
export function peerSecurityOf(wire: WirePeerSecurity, peer: Peer): PeerSecurity {
  return {
    peer,
    keysMatch: wire.keysMatch,
    signatureOk: wire.signatureOk,
    lastHandshakeAt: wire.lastHandshakeAt,
    fetchedAt: wire.fetchedAt,
    fetchError: wire.fetchError,
    kem: wire.kem,
    descriptor: wire.descriptor
      ? {
          operator: wire.descriptor.operator,
          addresses: wire.descriptor.addresses,
          notBefore: wire.descriptor.notBefore,
          notAfter: wire.descriptor.notAfter,
        }
      : null,
    suites: wire.suites,
  };
}

/** This server's own keys, suites and descriptor. */
export function selfSecurityOf(wire: WireSelf): SelfSecurity {
  return {
    server: selfView(wire.server),
    identityFingerprint: wire.identityFingerprint,
    validFrom: wire.validFrom,
    validTo: wire.validTo,
    addresses: wire.server.addresses,
    kemMadeAt: wire.kemMadeAt,
    kemNextRotationAt: wire.kemNextRotationAt,
    // This server keeps its keys sealed under server.key and offers no other way.
    keyHolding: 'sealed',
    suites: wire.suites,
  };
}

/** A key mismatch against a peer: what was pinned, what was offered and what is paused. */
export function keyMismatchOf(wire: WireMismatch, peer: Peer): KeyMismatch {
  return {
    peer,
    pinnedKey: hexToB64(wire.pinnedKey),
    pinnedAt: wire.pinnedAt,
    offeredKey: hexToB64(wire.offeredKey),
    offeredAt: wire.firstOfferedAt,
    attempts: wire.attempts,
    lastAttemptAt: wire.lastAttemptAt,
    fromAddress: wire.fromAddress,
    fromHost: wire.fromHost,
    usualAddresses: wire.usualAddresses,
    tlsValid: wire.tlsValid,
    signedByPinned: wire.signedByPinned,
    seenBefore: wire.seenBefore,
    keptBlockingAt: wire.keptBlockingAt,
    keptBlockingBy: wire.keptBlockingBy,
    pausedVaults: wire.pausedVaults.map((vault) => ({
      id: vault.vault,
      ownerEmail: vault.ownerEmail,
      members: vault.members,
      sizeBytes: vault.sizeBytes,
      waitingChanges: vault.waitingChanges,
    })),
    localVaults: wire.localVaults,
  };
}
