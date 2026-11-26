// Sample admin API answers, for the screens' tests and for nothing else. The keys are short
// stand-ins: no screen test checks cryptography, and the key words come from a fake.
import type {
  AdminEvent,
  AdminInvite,
  AdminOverview,
  AdminSetting,
  AdminSpace,
  AdminUser,
  FederationOverview,
  KeyMismatch,
  MigrationStatus,
  PairingSession,
  Peer,
  PeerSecurity,
  SelfSecurity,
  SsoConfig,
  VerifiedDomain,
} from '@/api/admin';
import type { KeyLabels } from './fingerprint';

export const NOW = 1_795_000_000;

export function user(patch: Partial<AdminUser> = {}): AdminUser {
  return {
    id: 'u1',
    email: 'jordan@example.co',
    name: 'Jordan Lee',
    role: 'user',
    mode: 'kemlock-only',
    createdAt: NOW - 90 * 86_400,
    disabledAt: null,
    devices: 2,
    twoStep: true,
    lastSeenAt: NOW - 720,
    erasurePending: false,
    ...patch,
  };
}

export const USERS: AdminUser[] = [
  user({ id: 'u0', email: 'sam@example.co', name: 'Sam Rivera', role: 'admin', devices: 4 }),
  user(),
  user({ id: 'u2', email: 'riley@example.net', name: 'Riley Moss', mode: 'compatible', twoStep: false }),
  user({ id: 'u3', email: 'ana@example.co', name: null, disabledAt: NOW - 86_400, devices: 0, lastSeenAt: null }),
];

export function invite(patch: Partial<AdminInvite> = {}): AdminInvite {
  return {
    id: 'i1',
    email: 'new@example.co',
    invitedBy: 'u0',
    createdAt: NOW - 2 * 86_400,
    expiresAt: NOW + 5 * 86_400,
    lastSentAt: NOW - 2 * 86_400,
    sent: 1,
    accepted: false,
    pending: true,
    ...patch,
  };
}

export const SPACES: AdminSpace[] = [
  {
    id: 's1aaaaaaaa',
    createdAt: NOW - 60 * 86_400,
    members: 6,
    confirmed: 5,
    owners: [{ userId: 'u0', email: 'sam@example.co' }],
    liveItems: 100,
    keysPendingSince: null,
    bitwardenOrganization: true,
    bitwardenInvitations: [{ userId: 'u1', email: 'jordan@example.co' }],
  },
  {
    id: 's2bbbbbbbb',
    createdAt: NOW - 10 * 86_400,
    members: 2,
    confirmed: 2,
    owners: [{ userId: 'u2', email: 'riley@example.net' }],
    liveItems: 17,
    keysPendingSince: NOW - 3_600,
    bitwardenOrganization: false,
    bitwardenInvitations: [],
  },
];

export const ADMIN_OVERVIEW: AdminOverview = {
  users: 42,
  admins: 2,
  disabledUsers: 1,
  devices: 97,
  spaces: 3,
  liveItems: 5302,
  events24h: 310,
  pendingInvites: 2,
  openRequests: 3,
  overdueRequests: 1,
  mailConfigured: false,
};

export function event(patch: Partial<AdminEvent> = {}): AdminEvent {
  return {
    id: 'e1',
    at: NOW,
    actor: 'u1',
    actorEmail: 'jordan@example.co',
    device: 'd1',
    action: 'signin.ok',
    target: null,
    ip: '203.0.113.0',
    ...patch,
  };
}

export const SSO: SsoConfig = {
  configured: true,
  enabled: true,
  displayName: 'Example Co',
  issuer: 'https://id.example.co/realms/staff',
  clientId: 'kemlock-server',
  clientSecretSet: true,
  scopes: ['openid', 'email', 'profile', 'groups'],
  allowUnknownEmailVerification: false,
  linkByEmail: true,
  createAccounts: true,
  requireVerifiedDomain: true,
  groupRules: [
    { group: 'engineering', space: 's1aaaaaaaa', role: 'member', collections: ['c1c1c1c1-0000-4000-8000-000000000001'] },
  ],
  updatedAt: NOW - 86_400,
  callbackUrl: 'https://vault.example.org/kem/v1/auth/sso/callback',
};

export const DOMAINS: VerifiedDomain[] = [
  { domain: 'example.co', txtValue: 'kemlock-verify=abc123', createdAt: NOW - 86_400, verifiedAt: NOW - 3_600, verified: true },
  { domain: 'example.dev', txtValue: 'kemlock-verify=def456', createdAt: NOW - 3_600, verifiedAt: null, verified: false },
];

export function setting(patch: Partial<AdminSetting> & Pick<AdminSetting, 'key' | 'group' | 'kind'>): AdminSetting {
  return { secretSet: false, source: 'default', readOnly: false, env: patch.key.toUpperCase(), ...patch };
}

/** A slice of the server's catalogue: one of most kinds, one set by the environment. */
export const SETTINGS: AdminSetting[] = [
  setting({ key: 'smtp_host', group: 'smtp', kind: 'text', maxLength: 253, default: null, value: 'smtp.example.org', source: 'saved' }),
  setting({ key: 'smtp_port', group: 'smtp', kind: 'int', min: 1, max: 65535, default: '587', value: '587' }),
  setting({ key: 'smtp_security', group: 'smtp', kind: 'choice', choices: ['starttls', 'force_tls', 'off'], default: 'starttls', value: 'starttls' }),
  setting({ key: 'smtp_password', group: 'smtp', kind: 'secret', secretSet: true, source: 'saved' }),
  setting({ key: 'smtp_from', group: 'smtp', kind: 'email', value: 'vault@example.org', source: 'saved' }),
  setting({ key: 'signups_allowed', group: 'signups', kind: 'bool', default: 'false', value: 'false' }),
  setting({ key: 'signups_domains_whitelist', group: 'signups', kind: 'domains', value: 'example.co', source: 'saved' }),
  setting({ key: 'max_file_size_mib', group: 'files', kind: 'int', min: 1, max: 5120, default: '100', value: '250', source: 'env', readOnly: true, env: 'KEMLOCK_MAX_FILE_SIZE_MIB' }),
  setting({ key: 'trash_days', group: 'trash', kind: 'int', min: 1, max: 365, default: '30', value: '30' }),
  setting({ key: 'event_log_days', group: 'retention', kind: 'int', min: 90, max: 2557, default: '365', value: '365' }),
  setting({ key: 'rate_sign_in_per_minute', group: 'rate-limits', kind: 'int', min: 1, max: 1000, default: '10', value: '10' }),
  setting({ key: 'security_contact', group: 'security', kind: 'text', maxLength: 254, default: '', value: '' }),
  setting({ key: 'security_encryption', group: 'security', kind: 'text', maxLength: 254, default: '', value: '' }),
];

export function migration(patch: Partial<MigrationStatus> = {}): MigrationStatus {
  return {
    state: 'idle',
    source: null,
    plan: null,
    error: null,
    at: null,
    startedBy: null,
    stage: null,
    report: null,
    finishedAt: null,
    applies: true,
    ...patch,
  };
}

export const SELF = {
  serverId: '01010101010101010101010101010101',
  name: 'VPS',
  address: 'vps.example.org',
  database: 'PostgreSQL',
  country: 'Germany',
  operator: 'own' as const,
  operatorName: null,
  identityKey: 'AQIDBA',
  state: 'online' as const,
};

export function peer(patch: Partial<Peer> = {}): Peer {
  return {
    serverId: '02020202020202020202020202020202',
    name: 'Office server',
    address: 'vault.example.co',
    database: 'PostgreSQL',
    country: 'France',
    operator: 'other',
    operatorName: 'Example Co IT',
    identityKey: 'BQYHCA',
    state: 'online',
    offlineSince: null,
    lastSeen: NOW - 12,
    latencyMs: 48,
    lagSeconds: null,
    lagChanges: null,
    lastChangeAt: NOW - 12,
    lastChangeVault: 'Example Co',
    pinnedAt: NOW - 30 * 86_400,
    sendLogs: false,
    pullLogs: false,
    theySendLogs: false,
    signedWrites: true,
    pastBundles: true,
    mismatch: false,
    ...patch,
  };
}

export const OVERVIEW: FederationOverview = {
  self: SELF,
  peers: [
    peer({ serverId: 'a'.repeat(32), name: 'Home server', identityKey: 'DQ4PEA', operator: 'own', operatorName: null, state: 'offline', offlineSince: NOW - 2820, sendLogs: true, pullLogs: true }),
    peer(),
  ],
  vaults: [
    { id: 'v1', name: 'Family', kind: 'space', members: 4, ownerEmail: null, federated: true, homeId: 'a'.repeat(32), epoch: 1, replicas: [SELF.serverId], sizeBytes: 112_000_000, waitingChanges: 1, waitingNote: 'One change is waiting: adding jordan@example.org as a member.', request: null },
    { id: 'v2', name: 'Side projects', kind: 'space', members: 3, ownerEmail: null, federated: false, homeId: SELF.serverId, epoch: 1, replicas: [], sizeBytes: 6_000_000, waitingChanges: 0, waitingNote: null, request: { by: 'Alex Chen', at: NOW - 2 * 86_400 } },
  ],
  consistency: [{ at: NOW - 3600, peerId: '02020202020202020202020202020202', vaults: ['Example Co'], ok: true }],
};

export const SESSION: PairingSession = {
  id: 'p1',
  self: { ...SELF },
  peer: { serverId: '02020202020202020202020202020202', name: 'Office server', address: 'vault.example.co', database: null, country: 'France', operator: 'other', operatorName: 'Example Co IT', identityKey: 'BQYHCA' },
  shareable: [{ id: 'v9', name: 'Lab notes', kind: 'space', members: 5, sizeBytes: 24_000_000 }],
};

export const SELF_SECURITY: SelfSecurity = {
  server: { ...SELF },
  identityFingerprint: '1A2B 3C4D 5E6F 7081 92A3 B4C5 D6E7 F809',
  kemMadeAt: NOW - 20 * 86_400,
  kemNextRotationAt: NOW + 10 * 86_400,
  validFrom: NOW - 20 * 86_400,
  validTo: NOW + 17 * 86_400,
  addresses: ['vps.example.org:443'],
  keyHolding: 'sealed',
  suites: [
    { name: 'kfed1-mlkem1024x25519-aes256gcm', on: true, available: true },
    { name: 'kfed1-mlkem1024x25519-chacha20poly1305', on: true, available: true },
    { name: 'kfed1-mlkem1024p384-aes256gcm', on: false, available: false },
  ],
};

export const PEER_SECURITY: PeerSecurity = {
  peer: peer(),
  keysMatch: true,
  signatureOk: true,
  lastHandshakeAt: NOW - 600,
  fetchedAt: NOW - 600,
  fetchError: null,
  kem: { algorithm: 'ML-KEM-1024 + X25519', firstSeenAt: NOW - 12 * 86_400, nextRotationAt: NOW + 18 * 86_400, fingerprint: 'E71A 0C5D 92B3 4F68' },
  descriptor: { operator: 'Example Co IT', notBefore: NOW - 12 * 86_400, notAfter: NOW + 25 * 86_400, addresses: ['https://vault.example.co'] },
  suites: [
    { name: 'kfed1-mlkem1024x25519-aes256gcm', theirs: 1, ours: 1, inUse: true },
    { name: 'kfed1-mlkem1024x25519-chacha20poly1305', theirs: 2, ours: 2, inUse: false },
    { name: 'kfed1-mlkem1024p384-aes256gcm', theirs: null, ours: null, inUse: false },
  ],
};

export const MISMATCH: KeyMismatch = {
  peer: peer({ mismatch: true }),
  pinnedKey: 'BQYHCA',
  pinnedAt: NOW - 30 * 86_400,
  offeredKey: 'CQoLDA',
  offeredAt: NOW - 600,
  attempts: 4,
  lastAttemptAt: NOW - 60,
  fromAddress: 'https://203.0.113.77:8443',
  fromHost: '203.0.113.77',
  usualAddresses: ['https://vault.example.co'],
  tlsValid: true,
  signedByPinned: false,
  seenBefore: false,
  keptBlockingAt: null,
  keptBlockingBy: null,
  pausedVaults: [{ id: 'user:v1', ownerEmail: 'sam@example.co', members: 1, sizeBytes: 2_000_000, waitingChanges: 3 }],
  localVaults: 2,
};

/** A fake for `labelsOf`: words and a short form that depend only on the key text. */
export const fakeLabels = async (key: string): Promise<KeyLabels> => ({
  words: `words-of-${key}`,
  short: `SHORT ${key.toUpperCase()}`,
});
