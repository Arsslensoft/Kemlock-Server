// Where each vault lives, for the failover banner and "Where your vault is stored".
//
// `GET /kem/v1/placement` answers from the federation state: the servers of the account's own
// vault and its spaces (home first), and the apps that use this server. A server that federates
// none of them answers 404 and the web vault shows nothing, which is right for a single server.
// The server probes each peer: `status` is `unknown` until the first probe, then `online`,
// `degraded` or `offline`, or `key-mismatch` when the server met a key other than the pinned one
// (not an outage: no banner, and nothing waiting for it can be dropped). `pending` is the changes of a vault waiting for another server, and
// cancelling them drops the queued push to a server that is offline. A server has no place or name
// beyond the host of its address.
import type { Api } from './client';
import { isApiError } from './errors';

export type ServerRole = 'home' | 'replica';

export interface PlacementServer {
  id: string;
  /** What the person calls it: "Home server", "VPS". */
  name: string;
  /** "Home · France". */
  place?: string | null;
  /** Its position in the vault's set: the home first, then the replicas in order. */
  role: ServerRole;
  /** `unknown` until the server's first probe of it; this server itself is always `online`. */
  status: 'online' | 'degraded' | 'offline' | 'key-mismatch' | 'unknown';
  /** ISO time it went offline, while it is. */
  offlineSince?: string | null;
  /** ISO time it last answered. */
  lastSeen?: string | null;
  /** How long its last answer took, in milliseconds. */
  latencyMs?: number | null;
  /** A cancel is in force: this vault's waiting changes are withheld from this server. */
  withheld?: boolean;
  /** The apps of this vault are on it right now. */
  inUse: boolean;
}

export interface PendingChange {
  id: string;
  /** What waits, in words the server wrote: "3 changes waiting for vps.example.net". */
  summary: string;
  /** ISO time the oldest was written. */
  askedAt?: string | null;
}

export interface PlacementVault {
  /** `me` for the person's own vault, else the space's id. */
  id: string;
  name: string;
  /** Home first, then replicas in order. */
  servers: PlacementServer[];
  pending?: PendingChange | null;
}

export interface PlacementApp {
  name: string;
  /** The server it uses now, by name. */
  server: string;
  /** ISO time it moved there, for Kemlock apps that switch on their own. */
  since?: string | null;
  /** A Bitwarden-compatible app that stays on its address and works from its local copy. */
  localCopy?: boolean;
  /** The address it stays on, when `localCopy`. */
  address?: string | null;
}

export interface Placement {
  vaults: PlacementVault[];
  apps: PlacementApp[];
}

export interface PlacementApi {
  placement(): Promise<Placement | null>;
  cancelPending(vault: string, change: string): Promise<void>;
  /** Takes back a cancel: the changes withheld from that server are offered to it again. */
  resumePending(vault: string, server: string): Promise<void>;
}

export function createPlacementApi(api: Pick<Api, 'request' | 'send'>): PlacementApi {
  return {
    /** `null` when the server has no such route (404): a single server. */
    async placement() {
      try {
        return await api.request<Placement>({ method: 'GET', path: '/kem/v1/placement' });
      } catch (error) {
        if (isApiError(error) && error.status === 404) return null;
        throw error;
      }
    },
    resumePending: (vault, server) =>
      api.send({
        method: 'POST',
        path: `/kem/v1/placement/${encodeURIComponent(vault)}/pending/${encodeURIComponent(server)}/resume`,
      }),
    cancelPending: (vault, change) =>
      api.send({
        method: 'DELETE',
        path: `/kem/v1/placement/${encodeURIComponent(vault)}/pending/${encodeURIComponent(change)}`,
      }),
  };
}

/** The vaults whose home is offline, with the server that took over. */
export function offlineHomes(
  placement: Placement | null | undefined,
): Array<{ vault: PlacementVault; home: PlacementServer; replica: PlacementServer | undefined }> {
  const out: Array<{ vault: PlacementVault; home: PlacementServer; replica: PlacementServer | undefined }> = [];
  for (const vault of placement?.vaults ?? []) {
    const home = vault.servers.find((server) => server.role === 'home');
    if (!home || home.status !== 'offline') continue;
    out.push({ vault, home, replica: vault.servers.find((server) => server.inUse) });
  }
  return out;
}
