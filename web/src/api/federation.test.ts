import { describe, expect, it } from 'vitest';
import type { FeatureCall } from './client';
import { type AdminTransport, createAdminApi } from './admin';
import {
  type WireAwaiting,
  type WireMismatch,
  type WireOverview,
  type WirePeer,
  type WirePeerSecurity,
  type WireSelf,
  type WireShareable,
  type WireVault,
  hexToB64,
  hostName,
  overviewOf,
  pairingOf,
  shortId,
} from './federation';

const SELF = '11111111-1111-4111-8111-111111111111';
const HOME = '22222222-2222-4222-8222-222222222222';
const OFFICE = '33333333-3333-4333-8333-333333333333';
const FAMILY = 'space:44444444-4444-4444-8444-444444444444';
const SIDE = 'space:55555555-5555-4555-8555-555555555555';

function peer(patch: Partial<WirePeer> = {}): WirePeer {
  return {
    id: HOME,
    name: 'home.example.co',
    operator: 'Example Co',
    addresses: ['home.example.co:443'],
    state: 'paired',
    pairedAt: 1_000,
    lastSeen: 1_500,
    fingerprint: ['a', 'b', 'c', 'd', 'e', 'f'],
    switches: { send: true, pull: false },
    acknowledgement: null,
    status: null,
    identityKey: '0a0b0c',
    lagChanges: 0,
    lagSeconds: null,
    lastChangeAt: 1_500,
    lastChangeVault: null,
    theySendLogs: false,
    ...patch,
  };
}

const wireVault = (patch: Partial<WireVault> = {}): WireVault => ({
  vault: FAMILY,
  policy: 'local',
  home: SELF,
  epoch: 1,
  replicas: [],
  isHome: true,
  promotion: null,
  ownerEmail: null,
  members: null,
  sizeBytes: null,
  waitingChanges: 0,
  waitingNote: null,
  ...patch,
});

function overview(patch: Partial<WireOverview> = {}): WireOverview {
  return {
    server: {
      serverId: SELF,
      name: 'VPS',
      operator: 'Example Co',
      addresses: ['vps.example.org:443'],
      identityKey: '010203',
      descriptorNotAfter: 9_000,
      database: 'PostgreSQL',
      country: 'Germany',
    },
    peers: [peer()],
    pairings: [],
    vaults: [],
    offers: [],
    ...patch,
  };
}

const awaiting = (patch: Partial<WireAwaiting> = {}): WireAwaiting => ({
  peerId: OFFICE,
  operator: 'Other Org',
  addresses: ['https://vault.other.example/'],
  fingerprint: ['tulip', 'anchor', 'rover', 'mint', 'ladle', 'orbit'],
  otherOrganisation: true,
  identityKey: '040506',
  side: 'showed',
  since: 100,
  ...patch,
});

describe('the helpers', () => {
  it('turns hex into unpadded base64url, and refuses what is not hex', () => {
    expect(hexToB64('010203')).toBe('AQID');
    expect(hexToB64('0102zz')).toBe('');
    expect(hexToB64('')).toBe('');
    expect(hexToB64(undefined)).toBe('');
  });

  it('names a server by its host and a vault by its short id', () => {
    expect(hostName('https://vault.example.co:8443/x')).toBe('vault.example.co');
    expect(hostName('vps.example.org:443')).toBe('vps.example.org');
    expect(hostName(undefined)).toBe('');
    expect(shortId(FAMILY)).toBe('44444444');
  });
});

describe('overviewOf', () => {
  it('shows this server with its key as base64url, and a peer of the same operator as your own', () => {
    const view = overviewOf(overview());
    expect(view.self).toMatchObject({
      serverId: SELF,
      name: 'VPS',
      address: 'vps.example.org:443',
      operator: 'own',
      identityKey: 'AQID',
      // Only this server knows its own database and country.
      database: 'PostgreSQL',
      country: 'Germany',
      state: 'online',
    });
    expect(view.peers[0]).toMatchObject({
      serverId: HOME,
      name: 'home.example.co',
      operator: 'own',
      operatorName: null,
      identityKey: 'CgsM',
      sendLogs: true,
      pullLogs: false,
      pinnedAt: 1_000,
      lastChangeAt: 1_500,
      mismatch: false,
    });
  });

  it('marks a peer of another operator', () => {
    const view = overviewOf(overview({ peers: [peer({ operator: 'Other Org' })] }));
    expect(view.peers[0]).toMatchObject({ operator: 'other', operatorName: 'Other Org' });
  });

  it('leaves out what a server cannot know of a peer, instead of inventing it', () => {
    const view = overviewOf(overview());
    // A descriptor carries no database or country: a peer has none.
    expect(view.peers[0]).toMatchObject({ database: null, country: null, name: 'home.example.co' });
  });

  it('shows the lag, the last change and whether the peer sends its logs, as the server counts them', () => {
    const view = overviewOf(
      overview({
        peers: [
          peer({
            lagChanges: 7,
            lagSeconds: 90,
            lastChangeAt: 2_222,
            lastChangeVault: FAMILY,
            theySendLogs: true,
          }),
        ],
      }),
    );
    expect(view.peers[0]).toMatchObject({
      lagChanges: 7,
      lagSeconds: 90,
      lastChangeAt: 2_222,
      lastChangeVault: FAMILY,
      theySendLogs: true,
    });
  });

  it('reads a peer as offline, catching up, revoked or online from what the last runs found', () => {
    const status = (patch: Partial<NonNullable<WirePeer['status']>>) => ({
      lastAttempt: 2_000,
      lastSuccess: 1_900,
      downSince: null,
      lastError: null,
      keyMismatch: null,
      vaults: [],
      ...patch,
    });
    const behind = {
      vault: FAMILY,
      at: 2_000,
      offer: null,
      pulled: { applied: 0, siblings: 0, duplicates: 0, refused: 0 },
      homeApplied: 0,
      homeQuarantined: 0,
      behind: false,
      filesFetched: 0,
      filesDeferred: 0,
      eventsPulled: 0,
      tagsPulled: 0,
      inStep: false,
      note: null,
    };
    const states = (p: WirePeer) => overviewOf(overview({ peers: [p] })).peers[0]?.state;
    expect(states(peer())).toBe('online');
    expect(states(peer({ status: status({ downSince: 1_800 }) }))).toBe('offline');
    expect(states(peer({ status: status({ vaults: [behind] }) }))).toBe('catching-up');
    expect(states(peer({ state: 'revoked' }))).toBe('revoked');
    const down = overviewOf(overview({ peers: [peer({ status: status({ downSince: 1_800 }) })] }));
    expect(down.peers[0]?.offlineSince).toBe(1_800);
  });

  it('reads what the probes found: offline, slow, and when the peer last answered', () => {
    const states = (p: WirePeer) => overviewOf(overview({ peers: [p] })).peers[0];
    expect(states(peer({ health: 'online', latencyMs: 40 }))).toMatchObject({
      state: 'online',
      lastSeen: 1_500,
      latencyMs: 40,
    });
    expect(states(peer({ health: 'degraded' }))?.state).toBe('degraded');
    expect(states(peer({ health: 'offline', failingSince: 1_900 }))).toMatchObject({
      state: 'offline',
      offlineSince: 1_900,
    });
    // A server that predates the probes says nothing, and the peer reads as before.
    expect(states(peer())).toMatchObject({ state: 'online', latencyMs: null });
    // A revoked peer stays revoked whatever the probes say.
    expect(states(peer({ state: 'revoked', health: 'offline' }))?.state).toBe('revoked');
  });

  it('flags a peer that offered another key', () => {
    const status = {
      lastAttempt: 2_000,
      lastSuccess: null,
      downSince: null,
      lastError: null,
      keyMismatch: 'ff',
      vaults: [],
    };
    const view = overviewOf(overview({ peers: [peer({ status })] }));
    expect(view.peers[0]?.mismatch).toBe(true);
  });

  it('lists the vaults with their kind, policy, home and replicas', () => {
    const view = overviewOf(
      overview({
        vaults: [
          wireVault({ policy: 'federated', home: HOME, epoch: 3, replicas: [SELF], isHome: false }),
          wireVault({
            vault: 'user:66666666-6666-4666-8666-666666666666',
            ownerEmail: 'sam@example.co',
            members: 1,
            sizeBytes: 2_000_000,
            waitingChanges: 4,
            waitingNote: 'Four changes wait.',
          }),
        ],
      }),
    );
    expect(view.vaults[0]).toMatchObject({
      id: FAMILY,
      kind: 'space',
      federated: true,
      homeId: HOME,
      epoch: 3,
      replicas: [SELF],
      sizeBytes: null,
      request: null,
    });
    // A vault has no name: the owner's email, its size and what waits, as the server says them.
    expect(view.vaults[1]).toMatchObject({
      kind: 'personal',
      federated: false,
      name: null,
      ownerEmail: 'sam@example.co',
      members: 1,
      sizeBytes: 2_000_000,
      waitingChanges: 4,
      waitingNote: 'Four changes wait.',
    });
  });

  it('shows a pending offer as a request, on its vault when there is one and as a vault when not', () => {
    const view = overviewOf(
      overview({
        vaults: [wireVault()],
        offers: [
          { vault: FAMILY, home: HOME, epoch: 2, replicas: [SELF], state: 'pending', receivedAt: 5_000 },
          { vault: SIDE, home: HOME, epoch: 4, replicas: [SELF], state: 'pending', receivedAt: 6_000 },
          { vault: 'user:77777777-7777-4777-8777-777777777777', home: HOME, epoch: 1, replicas: [], state: 'declined', receivedAt: 1 },
        ],
      }),
    );
    expect(view.vaults).toHaveLength(2);
    expect(view.vaults[0]?.request).toEqual({ by: 'home.example.co', at: 5_000 });
    expect(view.vaults[1]).toMatchObject({ id: SIDE, federated: true, homeId: HOME, epoch: 4 });
    expect(view.vaults[1]?.request).toEqual({ by: 'home.example.co', at: 6_000 });
  });

  it('turns the hash-tree comparisons of the last runs into one line per peer, newest first', () => {
    const run = (vault: string, at: number, inStep: boolean | null) => ({
      vault,
      at,
      offer: null,
      pulled: { applied: 0, siblings: 0, duplicates: 0, refused: 0 },
      homeApplied: 0,
      homeQuarantined: 0,
      behind: false,
      filesFetched: 0,
      filesDeferred: 0,
      eventsPulled: 0,
      tagsPulled: 0,
      inStep,
      note: null,
    });
    const status = (vaults: ReturnType<typeof run>[]) => ({
      lastAttempt: 1,
      lastSuccess: 1,
      downSince: null,
      lastError: null,
      keyMismatch: null,
      vaults,
    });
    const view = overviewOf(
      overview({
        peers: [
          peer({ id: HOME, status: status([run(FAMILY, 3_000, true), run(SIDE, 3_100, null)]) }),
          peer({ id: OFFICE, status: status([run(FAMILY, 4_000, true), run(SIDE, 4_000, false)]) }),
          peer({ id: SELF, status: status([run(SIDE, 5_000, null)]) }),
        ],
      }),
    );
    expect(view.consistency).toEqual([
      { at: 4_000, peerId: OFFICE, vaults: ['44444444', '55555555'], ok: false },
      { at: 3_000, peerId: HOME, vaults: ['44444444'], ok: true },
    ]);
  });
});

describe('pairingOf', () => {
  it('has no session when nothing waits', () => {
    expect(pairingOf(overview())).toEqual({ code: null, session: null });
  });

  it('makes the newest waiting pairing a session, with the server\'s words and the vaults it could offer', () => {
    const shareable: WireShareable[] = [
      { vault: 'user:66666666-6666-4666-8666-666666666666', ownerEmail: 'sam@example.co', members: 1, sizeBytes: 2_000 },
      { vault: SIDE, ownerEmail: null, members: 3, sizeBytes: 9_000 },
    ];
    const state = pairingOf(
      overview({ pairings: [awaiting({ peerId: HOME, since: 50 }), awaiting({ identityKey: '040506' })] }),
      shareable,
    );
    expect(state.session).toMatchObject({
      id: OFFICE,
      words: 'tulip-anchor-rover-mint-ladle-orbit',
    });
    // A vault has no name: the owner's email names an account's, and a space is its short id.
    expect(state.session?.shareable).toEqual([
      { id: 'user:66666666-6666-4666-8666-666666666666', name: 'sam@example.co', kind: 'personal', members: 1, sizeBytes: 2_000 },
      { id: SIDE, name: null, kind: 'space', members: 3, sizeBytes: 9_000 },
    ]);
    expect(state.session?.self).toMatchObject({ serverId: SELF, identityKey: 'AQID', operator: 'own', country: 'Germany' });
    expect(state.session?.peer).toMatchObject({
      serverId: OFFICE,
      name: 'vault.other.example',
      operator: 'other',
      operatorName: 'Other Org',
      identityKey: 'BAUG',
    });
  });

  it('shows the key the pairing would pin, as the descriptor carries it', () => {
    expect(pairingOf(overview({ pairings: [awaiting()] })).session?.peer.identityKey).toBe('BAUG');
  });
});

describe('the calls', () => {
  function transport(answers: Record<string, unknown>) {
    const calls: FeatureCall[] = [];
    const answer = async (call: FeatureCall) => {
      calls.push(call);
      return answers[`${call.method} ${call.path}`];
    };
    const api: AdminTransport = {
      request: (call) => answer(call) as never,
      send: async (call) => {
        await answer(call);
      },
      raw: async () => new Response(),
    };
    return { calls, admin: createAdminApi(api) };
  }

  const BASE = '/admin/v1/federation';

  it('reads the overview from /federation', async () => {
    const { admin, calls } = transport({ [`GET ${BASE}`]: overview() });
    const view = await admin.federation();
    expect(calls).toHaveLength(1);
    expect(view.peers[0]?.serverId).toBe(HOME);
  });

  it('connects with POST /pairing and reads this server for the other half of the session', async () => {
    const { admin, calls } = transport({
      [`POST ${BASE}/pairing`]: awaiting(),
      [`GET ${BASE}`]: overview(),
      [`GET ${BASE}/shareable`]: [{ vault: SIDE, ownerEmail: null, members: 2, sizeBytes: 10 }],
    });
    const session = await admin.connectPairing('vault.other.example', 'ABCD-EFGH-JKLM', 'grant');
    expect(calls[0]).toMatchObject({ method: 'POST', path: `${BASE}/pairing`, body: { address: 'vault.other.example', code: 'ABCD-EFGH-JKLM' } });
    expect(calls[0]?.headers).toEqual({ 'Step-Up-Token': 'grant' });
    expect(session.id).toBe(OFFICE);
    expect(session.self.serverId).toBe(SELF);
    expect(session.shareable).toHaveLength(1);
  });

  it('confirms a pairing, then sets the log switches and offers the chosen vaults', async () => {
    const { admin, calls } = transport({
      [`GET /admin/v1/me`]: { userId: 'admin-1', deviceId: 'd', stepUpTtlSeconds: 300 },
      [`GET ${BASE}`]: overview({ peers: [peer({ id: OFFICE, operator: 'Other Org' })] }),
    });
    const paired = await admin.confirmPairing(
      OFFICE,
      { wordsMatch: true, acknowledged: ['metadata', 'no-delete', 'cross-border'], offer: [FAMILY], sendLogs: true, pullLogs: false },
      'grant',
    );
    expect(paired.serverId).toBe(OFFICE);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /admin/v1/me',
      `POST ${BASE}/pairings/${OFFICE}/confirm`,
      `PUT ${BASE}/peers/${OFFICE}/logs`,
      `PUT ${BASE}/vaults/${encodeURIComponent(FAMILY)}`,
      `GET ${BASE}`,
    ]);
    expect(calls[1]?.body).toEqual({
      fingerprintMatches: true,
      acknowledgement: { metadata: true, deletion: true, crossBorder: true, by: 'admin-1' },
    });
    expect(calls[2]?.body).toEqual({ send: true, pull: false });
    expect(calls[3]?.body).toEqual({ policy: 'federated', replicas: [OFFICE] });
    expect(calls[1]?.headers).toEqual({ 'Step-Up-Token': 'grant' });
  });

  it('sends no acknowledgement for a peer of the same organisation, and no extra calls', async () => {
    const { admin, calls } = transport({ [`GET ${BASE}`]: overview({ peers: [peer({ id: OFFICE })] }) });
    await admin.confirmPairing(OFFICE, { wordsMatch: true, acknowledged: [], offer: [], sendLogs: false, pullLogs: false });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `POST ${BASE}/pairings/${OFFICE}/confirm`,
      `GET ${BASE}`,
    ]);
    expect(calls[0]?.body).toEqual({ fingerprintMatches: true });
  });

  it('accepts and declines an offer, and promotes, by the vault\'s owner', async () => {
    const { admin, calls } = transport({});
    await admin.federate(FAMILY);
    await admin.declineFederation(SIDE);
    await admin.promote(FAMILY, { homeIsDown: true });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `POST ${BASE}/offers/${encodeURIComponent(FAMILY)}/accept`,
      `POST ${BASE}/offers/${encodeURIComponent(SIDE)}/decline`,
      `POST ${BASE}/vaults/${encodeURIComponent(FAMILY)}/promote`,
    ]);
  });

  it('cancels a pairing and revokes a peer on the routes the server has', async () => {
    const { admin, calls } = transport({});
    await admin.cancelPairing(OFFICE, 'grant');
    await admin.revokePeer(OFFICE, 'grant');
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      `DELETE ${BASE}/pairings/${OFFICE}`,
      `POST ${BASE}/peers/${OFFICE}/revoke`,
    ]);
    expect(calls.map((c) => c.headers)).toEqual([{ 'Step-Up-Token': 'grant' }, { 'Step-Up-Token': 'grant' }]);
  });

  it('sends the step-up token on the writes that need one, and reads what a visit found', async () => {
    const { admin, calls } = transport({
      [`POST ${BASE}/check`]: [{ peer: HOME, reach: 'reached', detail: null }],
      [`POST ${BASE}/consistency`]: [{ peer: HOME, reach: 'reached', vaults: [{ vault: FAMILY, inStep: true, detail: null }], detail: null }],
    });
    expect(await admin.checkKeys('tok')).toEqual([{ peerId: HOME, reach: 'reached', detail: null }]);
    const compared = await admin.runConsistency('tok');
    expect(compared[0]).toMatchObject({ peerId: HOME, vaults: [{ vault: FAMILY, inStep: true }] });
    await admin.declineFederation(SIDE, 'tok');
    await admin.setLogs(HOME, true, false, 'tok');
    for (const call of calls) expect(call.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });

  it('reads a peer\'s security as the server gives it: descriptor, KEM key and suites, no TLS or session', async () => {
    const wire: WirePeerSecurity = {
      peerId: HOME,
      operator: 'Example Co',
      keysMatch: true,
      signatureOk: true,
      fetchedAt: 1_800,
      fetchError: null,
      descriptor: { identityKey: '0a0b0c', operator: 'Example Co', addresses: ['https://home.example.co'], notBefore: 1, notAfter: 9 },
      kem: { algorithm: 'ML-KEM-1024 + X25519', firstSeenAt: 1_000, nextRotationAt: 2_592_000 + 1_000, fingerprint: 'E71A 0C5D 92B3 4F68' },
      suites: [{ name: 'kfed1-mlkem1024x25519-aes256gcm', theirs: 1, ours: 1, inUse: true }],
      lastHandshakeAt: 1_700,
    };
    const { admin, calls } = transport({
      [`GET ${BASE}/peers/${HOME}/security`]: wire,
      [`GET ${BASE}`]: overview(),
    });
    const view = await admin.peerSecurity(HOME);
    expect(calls.map((c) => `${c.method} ${c.path}`).sort()).toEqual([`GET ${BASE}`, `GET ${BASE}/peers/${HOME}/security`]);
    expect(view).toMatchObject({
      keysMatch: true,
      signatureOk: true,
      lastHandshakeAt: 1_700,
      kem: { firstSeenAt: 1_000 },
      descriptor: { addresses: ['https://home.example.co'] },
    });
    expect(view.peer.serverId).toBe(HOME);
    expect(view).not.toHaveProperty('tls');
    expect(view).not.toHaveProperty('session');
  });

  it('reads this server\'s own keys, rotates and saves suites with a step-up token', async () => {
    const self: WireSelf = {
      server: overview().server,
      identityFingerprint: 'AAAA BBBB',
      descriptor: 'ZGVzYw',
      validFrom: 10,
      validTo: 20,
      kemMadeAt: null,
      kemNextRotationAt: null,
      suites: [{ name: 'kfed1-mlkem1024x25519-aes256gcm', on: true, available: true }],
    };
    const { admin, calls } = transport({
      [`GET ${BASE}/self`]: self,
      [`POST ${BASE}/self/kem-rotation`]: self,
      [`POST ${BASE}/self/identity-rotation`]: { kind: 'rotation', identityKey: 'ab', peersTold: 2 },
      [`PUT ${BASE}/self/suites`]: self,
    });
    expect(await admin.selfSecurity()).toMatchObject({ identityFingerprint: 'AAAA BBBB', keyHolding: 'sealed', kemMadeAt: null });
    await admin.rotateKem('tok');
    expect(await admin.rotateIdentity('tok')).toEqual({ kind: 'rotation', identityKey: 'ab', peersTold: 2 });
    await admin.saveSuites([{ name: 'kfed1-mlkem1024x25519-aes256gcm', on: true, available: true }], 'sealed', 'tok');
    expect(calls[3]?.body).toEqual({ suites: [{ name: 'kfed1-mlkem1024x25519-aes256gcm', on: true }], keyHolding: 'sealed' });
    for (const call of calls.slice(1)) expect(call.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });

  it('reads a key mismatch by the address this server dialled, and keeps blocking with a token', async () => {
    const wire: WireMismatch = {
      peerId: HOME,
      pinnedKey: '010203',
      pinnedAt: 100,
      offeredKey: '040506',
      firstOfferedAt: 200,
      lastAttemptAt: 300,
      attempts: 3,
      fromAddress: 'https://203.0.113.77:8443',
      fromHost: '203.0.113.77',
      usualAddresses: ['https://home.example.co'],
      tlsValid: true,
      signedByPinned: false,
      seenBefore: false,
      keptBlockingAt: null,
      keptBlockingBy: null,
      pausedVaults: [{ vault: FAMILY, ownerEmail: null, members: null, sizeBytes: null, waitingChanges: 2 }],
      localVaults: 1,
    };
    const { admin, calls } = transport({
      [`GET ${BASE}/mismatches/${HOME}`]: wire,
      [`GET ${BASE}`]: overview(),
      [`POST ${BASE}/mismatches/${HOME}/keep-blocking`]: wire,
    });
    const view = await admin.keyMismatch(HOME);
    expect(view).toMatchObject({
      pinnedKey: 'AQID',
      offeredKey: 'BAUG',
      offeredAt: 200,
      fromAddress: 'https://203.0.113.77:8443',
      usualAddresses: ['https://home.example.co'],
      pausedVaults: [{ id: FAMILY, ownerEmail: null, waitingChanges: 2 }],
    });
    expect(view).not.toHaveProperty('fromIp');
    await admin.keepBlocking(HOME, 'tok');
    expect(calls[2]?.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });
});
