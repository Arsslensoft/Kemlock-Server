import { type Page, type Request, type Route, expect, test } from '@playwright/test';
import {
  ADMIN_OVERVIEW,
  DOMAINS,
  SETTINGS,
  SPACES,
  SSO,
  USERS,
  event,
  invite,
  migration,
} from '../src/features/admin/fixtures';
import { expectAccessible, watchForCspProblems } from './helpers';
import { chooseFromAccountMenu, signInAsAdmin } from './signin';

// The sign-in is real, but the console's calls are answered here with the shapes of
// crates/kemlock-api-admin (src/api/admin.ts): a real write needs a step-up token made from a
// current authenticator code, which a test can't produce. The federation calls are answered in
// the shapes of crates/kemlock-api-fed/src/admin.rs and admin/console.rs (src/api/federation.ts),
// the peer security, own security and key mismatch pages included. The console is reached through
// the shell's links, because a page reload would sign the admin out.

const PEER_ID = '02020202-0202-4202-8202-020202020202';
const HOME_ID = '0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a';
const SELF_ID = '01010101-0101-4101-8101-010101010101';

/** What GET /federation answers: this server, a home that is down and an office whose key changed. */
function federationOverview(now: number) {
  const noRuns = { lastAttempt: now, lastSuccess: null, downSince: null, lastError: null, keyMismatch: null, vaults: [] };
  const peer = (id: string, operator: string, address: string, key: string, status: object) => ({
    id,
    // A descriptor carries no name: the host of its first address.
    name: address.replace(/:\d+$/, ''),
    lagChanges: 0,
    lagSeconds: null,
    lastChangeAt: now - 12,
    lastChangeVault: null,
    theySendLogs: false,
    operator,
    addresses: [address],
    state: 'paired',
    pairedAt: now - 30 * 86_400,
    lastSeen: now - 12,
    fingerprint: ['tulip', 'anchor', 'rover', 'mint', 'ladle', 'orbit'],
    switches: { send: false, pull: false },
    acknowledgement: null,
    status,
    identityKey: key,
  });
  return {
    server: {
      serverId: SELF_ID,
      name: 'vps.example.org',
      operator: 'Example Co',
      addresses: ['vps.example.org:443'],
      identityKey: '01020304',
      descriptorNotAfter: now + 17 * 86_400,
      database: 'PostgreSQL',
      country: 'Germany',
    },
    peers: [
      peer(HOME_ID, 'Example Co', 'home.example.co:443', '0d0e0f10', { ...noRuns, downSince: now - 2820 }),
      peer(PEER_ID, 'Example Co IT', 'vault.example.co:443', '05060708', { ...noRuns, keyMismatch: '090a0b0c' }),
    ],
    pairings: [],
    vaults: [
      {
        vault: 'space:0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b',
        policy: 'federated',
        home: HOME_ID,
        epoch: 1,
        replicas: [SELF_ID],
        isHome: false,
        promotion: null,
        // A vault has no name: a space has no email either, so the console shows its short id.
        ownerEmail: null,
        members: 4,
        sizeBytes: 112_000_000,
        waitingChanges: 0,
        waitingNote: null,
      },
    ],
    offers: [],
  };
}

/** `GET /federation/peers/{id}/security`: no TLS, session or event block, because the server has none. */
function peerSecurityWire(now: number) {
  return {
    peerId: PEER_ID,
    operator: 'Example Co IT',
    keysMatch: false,
    signatureOk: true,
    fetchedAt: now - 600,
    fetchError: null,
    descriptor: {
      identityKey: '05060708',
      operator: 'Example Co IT',
      addresses: ['vault.example.co:443'],
      notBefore: now - 12 * 86_400,
      notAfter: now + 25 * 86_400,
    },
    kem: { algorithm: 'ML-KEM-1024 + X25519', firstSeenAt: now - 12 * 86_400, nextRotationAt: now + 18 * 86_400, fingerprint: 'E71A 0C5D 92B3 4F68' },
    suites: [{ name: 'kfed1-mlkem1024x25519-aes256gcm', theirs: 1, ours: 1, inUse: true }],
    lastHandshakeAt: now - 600,
  };
}

function selfWire(now: number) {
  return {
    server: federationOverview(now).server,
    identityFingerprint: '1A2B 3C4D 5E6F 7081 92A3 B4C5 D6E7 F809',
    descriptor: 'ZGVzY3JpcHRvcg',
    validFrom: now - 20 * 86_400,
    validTo: now + 17 * 86_400,
    kemMadeAt: now - 20 * 86_400,
    kemNextRotationAt: now + 10 * 86_400,
    suites: [
      { name: 'kfed1-mlkem1024x25519-aes256gcm', on: true, available: true },
      { name: 'kfed1-mlkem1024x25519-chacha20poly1305', on: true, available: true },
    ],
  };
}

function mismatchWire(now: number) {
  return {
    peerId: PEER_ID,
    pinnedKey: '05060708',
    pinnedAt: now - 30 * 86_400,
    offeredKey: '090a0b0c',
    firstOfferedAt: now - 600,
    lastAttemptAt: now - 60,
    attempts: 4,
    fromAddress: 'https://203.0.113.77:8443',
    fromHost: '203.0.113.77',
    usualAddresses: ['https://vault.example.co'],
    tlsValid: true,
    signedByPinned: false,
    seenBefore: false,
    keptBlockingAt: null,
    keptBlockingBy: null,
    pausedVaults: [{ vault: 'user:0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c', ownerEmail: 'sam@example.co', members: 1, sizeBytes: 2_000_000, waitingChanges: 3 }],
    localVaults: 2,
  };
}
const WORDS = /^([bdfghjklmnprstvz][aiou]){2}[bdfghjklmnprstvz](-([bdfghjklmnprstvz][aiou]){2}[bdfghjklmnprstvz]){5}$/;

interface Answer {
  status?: number;
  body?: unknown;
  /** A text body, such as the CSV, with its content type. */
  text?: { type: string; content: string };
}

/** What the server asks of a write: a step-up token in the `Step-Up-Token` header. */
const NEEDS_TOKEN = new Set([
  'POST /users/u2/disable',
  'GET /events.csv',
  'PUT /sso',
  'PUT /settings',
  'POST /migration/start',
  'POST /push-relay/enable',
  'POST /push-relay/disable',
]);

/** Where the push relay stands; the mock keeps it between calls. */
let pushRelayOn = false;
const pushRelay = () => ({
  enabled: pushRelayOn,
  installationId: pushRelayOn ? 'inst-4f2a' : null,
  relayUrl: 'https://push.kemlock.example',
});

function answer(request: Request): Answer {
  const path = new URL(request.url()).pathname.replace('/admin/v1', '');
  const key = `${request.method()} ${path}`;
  const now = Math.floor(Date.now() / 1000);
  if (NEEDS_TOKEN.has(key) && !request.headers()['step-up-token']) {
    return {
      status: 403,
      body: { type: 'urn:kemlock:problem:step-up-required', title: 'A fresh check is required', status: 403, stepUp: true },
    };
  }
  switch (key) {
    case 'GET /overview':
      return { body: ADMIN_OVERVIEW };
    case 'GET /users':
      return { body: { users: USERS, total: 42 } };
    case 'GET /invitations':
      return { body: [invite()] };
    case 'GET /spaces':
      return { body: { spaces: SPACES, total: SPACES.length } };
    case 'POST /users/u2/disable':
      return { status: 204 };
    case 'POST /step-up/totp':
      return { body: { token: 'T', expiresAt: now + 300 } };
    case 'GET /events':
      return {
        body: {
          events: [
            event({ at: now - 60 }),
            event({ id: 'e2', at: now - 600, action: 'device.approval_approved', actor: 'u0', actorEmail: 'sam@example.co' }),
          ],
          next: null,
        },
      };
    case 'GET /events.csv':
      return { text: { type: 'text/csv; charset=utf-8', content: 'id,at,actor,action\r\ne1,1,u1,signin.ok\r\n' } };
    case 'GET /sso':
    case 'PUT /sso':
      return { body: SSO };
    case 'GET /sso/domains':
      return { body: DOMAINS };
    case 'GET /settings':
    case 'PUT /settings':
      return { body: { settings: SETTINGS } };
    case 'GET /migration':
      return { body: migration() };
    case 'POST /migration/start':
      return {
        body: migration({ state: 'planned', source: '/srv/vaultwarden/data', plan: '42 users\n5302 items', at: now }),
      };
    case 'GET /me':
      return { body: { userId: 'u0', deviceId: 'd1', stepUpTtlSeconds: 300 } };
    case 'GET /push-relay':
      return { body: pushRelay() };
    case 'POST /push-relay/enable':
    case 'POST /push-relay/disable':
      pushRelayOn = key.endsWith('/enable');
      return { body: pushRelay() };
    case 'GET /federation':
      return { body: federationOverview(now) };
    case 'POST /federation/pairing/code':
      return { body: { code: 'HXQ7-42MD-R9KT', expiresAt: now + 540 } };
    case 'POST /federation/pairing':
      return {
        body: {
          peerId: PEER_ID,
          operator: 'Example Co IT',
          addresses: ['vault.example.co:443'],
          fingerprint: ['tulip', 'anchor', 'rover', 'mint', 'ladle', 'orbit'],
          otherOrganisation: true,
          side: 'typed',
          since: now,
          identityKey: '05060708',
        },
      };
    case `POST /federation/pairings/${PEER_ID}/confirm`:
      return { body: {} };
    case 'GET /federation/shareable':
      return { body: [{ vault: 'user:0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c', ownerEmail: 'sam@example.co', members: 1, sizeBytes: 2_000_000 }] };
    case `GET /federation/peers/${PEER_ID}/security`:
      return { body: peerSecurityWire(now) };
    case 'GET /federation/self':
      return { body: selfWire(now) };
    case `GET /federation/mismatches/${PEER_ID}`:
      return { body: mismatchWire(now) };
    case `POST /federation/mismatches/${PEER_ID}/keep-blocking`:
      return { body: mismatchWire(now) };
    default:
      return { status: 404, body: { type: 'urn:kemlock:problem:not-found', title: `No mock for ${key}`, status: 404 } };
  }
}

async function mockAdminApi(page: Page): Promise<string[]> {
  const seen: string[] = [];
  await page.route('**/admin/v1/**', async (route: Route) => {
    const request = route.request();
    seen.push(`${request.method()} ${new URL(request.url()).pathname}`);
    const { status = 200, body, text } = answer(request);
    await route.fulfill({
      status,
      contentType: text ? text.type : status >= 400 ? 'application/problem+json' : 'application/json',
      body: text ? text.content : body === undefined ? undefined : JSON.stringify(body),
    });
  });
  return seen;
}

test('the admin console: users, events, SSO, settings, migration and federation', async ({ page }) => {
  test.setTimeout(300_000);
  const problems = watchForCspProblems(page);
  const seen = await mockAdminApi(page);
  await signInAsAdmin(page);

  // Overview: what needs a look comes from the counts of the admin API.
  await chooseFromAccountMenu(page, 'Admin console');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expect(page.getByText('2 invitations are still waiting')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Push', exact: true })).toBeVisible();
  await expectAccessible(page);

  // Users & spaces: a write asks for a step-up token, made from an authenticator code.
  await page.getByRole('link', { name: 'Users & spaces' }).click();
  await expect(page.getByRole('heading', { name: 'Users & spaces', level: 1 })).toBeVisible();
  await expect(page.getByRole('row', { name: /Riley Moss/ })).toContainText('Kemlock and Bitwarden apps');
  await expect(page.getByText('s2bbbbbb')).toBeVisible();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Disable: Riley Moss' }).click();
  const check = page.getByRole('dialog');
  await expect(check.getByRole('heading', { name: "Confirm it's you" })).toBeVisible();
  await check.getByLabel('Code from your authenticator app').fill('123456');
  await check.getByRole('button', { name: 'Confirm' }).click();
  await expect(check).toBeHidden();
  expect(seen.filter((call) => call === 'POST /admin/v1/users/u2/disable')).toHaveLength(2);
  await page.getByLabel('Email to invite').fill('not-an-email');
  // Checked as it is typed: the reason shows and Invite stays off.
  await expect(page.getByRole('button', { name: 'Invite' })).toBeDisabled();
  await expect(page.getByText(/Type an email address/)).toBeVisible();

  // Event log: filters, and a CSV the server makes (an export is a write, so it carries the token).
  await page.getByRole('link', { name: 'Event log' }).click();
  await expect(page.getByRole('heading', { name: 'Event log', level: 1 })).toBeVisible();
  await expect(page.getByText('Approved a sign-in for a new device')).toBeVisible();
  await expectAccessible(page);
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Export as CSV' }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^kemlock-events-\d{4}-\d{2}-\d{2}\.csv$/);

  // Sign-in & SSO: the secret is write-only, and email domains are claimed and checked here.
  await page.getByRole('link', { name: 'Sign-in & SSO' }).click();
  await expect(page.getByRole('heading', { name: 'Sign-in & SSO', level: 1 })).toBeVisible();
  await expect(page.getByLabel('Client secret', { exact: true })).toHaveValue('');
  await expectAccessible(page);
  // Save waits for a change: the write-only secret is one.
  await page.getByLabel('Client secret', { exact: true }).fill('a-new-client-secret');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.getByText('Saved.')).toBeVisible();

  // Server settings: one group at a time, checked before it is sent.
  await page.getByRole('link', { name: 'Server settings' }).click();
  await expect(page.getByRole('heading', { name: 'Server settings', level: 1 })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Security contact' })).toBeVisible();
  await expect(page.getByLabel(/Who to tell about a problem with this server/)).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel('SMTP port', { exact: true }).fill('70000');
  await page.getByRole('button', { name: 'Save Email' }).click();
  await expect(page.getByText(/Type a whole number from/)).toBeVisible();
  await page.getByLabel('SMTP port', { exact: true }).fill('465');
  await page.getByRole('button', { name: 'Save Email' }).click();
  await expect(page.getByText('Saved.')).toBeVisible();

  // Move from Vaultwarden: the server reads the data and plans; copying is the CLI's job for now.
  await page.getByRole('link', { name: 'Move from Vaultwarden' }).click();
  await expect(page.getByRole('heading', { name: 'Move from Vaultwarden', level: 1 })).toBeVisible();
  await page.getByLabel(/Vaultwarden database in the import folder/).fill('db.sqlite3');
  await page.getByRole('button', { name: 'Check it' }).click();
  await expect(page.getByRole('heading', { name: 'What a move would do' })).toBeVisible();
  await expectAccessible(page);

  // Federation: peers, vaults, and a peer whose key no longer matches.
  await page.getByRole('link', { name: 'Federation' }).click();
  await expect(page.getByRole('heading', { name: 'Federation', level: 1 })).toBeVisible();
  await expect(page.locator('.adm-banner[role="status"]')).toContainText('home.example.co has been offline');
  await expect(page.getByRole('button', { name: 'Possible man in the middle with vault.example.co' })).toBeVisible();
  await expectAccessible(page);

  // Pair a server: the six words are worked out in the browser from both keys.
  await page.getByRole('button', { name: 'Pair a server' }).click();
  await expect(page.getByRole('heading', { name: 'Pair a server', level: 1 })).toBeVisible();
  await page.getByRole('button', { name: 'Make a code' }).click();
  await expect(page.getByText('HXQ7-42MD-R9KT')).toBeVisible();
  await page.getByLabel('Its address').fill('https://vault.example.co');
  await page.getByLabel('Its one-time code').fill('7KP2-WQ4N-D8RJ');
  await page.getByRole('button', { name: 'Connect' }).click();
  const words = page.locator('.words').first();
  await expect(words).toHaveText(WORDS);
  await expectAccessible(page);
  const pair = page.getByRole('button', { name: 'Pair with vault.example.co' });
  await expect(pair).toBeDisabled();
  // The checkboxes are React Aria's: the label is what a person clicks.
  for (const text of [/six words match/, /sees the metadata/, /make vault.example.co delete/, /cross-border transfer/]) {
    await page.locator('label', { hasText: text }).click();
  }
  await pair.click();
  await expect(page.getByText('Paired with vault.example.co. Its identity key is pinned.')).toBeVisible();
  await page.getByRole('button', { name: 'Back to Federation' }).click();

  // Peer security: its pinned key, the descriptor, the session, and this server's own keys.
  await page.getByRole('button', { name: 'Security of vault.example.co' }).click();
  await expect(page.getByRole('heading', { name: 'vault.example.co', level: 1 })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'This server publishes' })).toBeVisible();
  await expectAccessible(page);

  // Key mismatch: the pinned key beside the offered one, and what can and can't be done.
  await page.getByRole('button', { name: 'Federation' }).first().click();
  await page.getByRole('button', { name: 'Possible man in the middle with vault.example.co' }).click();
  await expect(page.getByRole('heading', { name: 'Possible man in the middle', level: 1 })).toBeVisible();
  await expect(page.locator('.words').first()).toHaveText(WORDS);
  await expect(page.locator('.words').nth(1)).toHaveText(WORDS);
  await expect(page.getByRole('button', { name: 'Accept signed rotation' })).toBeDisabled();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Keep blocking' }).click();
  await expect(page.getByText(/Still blocking\./)).toBeVisible();
  await page.getByRole('button', { name: 'Pair again with a new code' }).click();
  await expect(page.getByRole('region', { name: "Confirm it's you" })).toBeVisible();

  // The push relay (on the overview): registering is a write, so it asks for the step-up check
  // unless the token from the steps above is still good; then the relay's id shows.
  await page.getByRole('link', { name: 'Overview' }).click();
  await expect(page.getByRole('heading', { name: 'Push', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Turn on' }).click();
  const relayCheck = page.getByRole('dialog');
  await expect(page.getByText('inst-4f2a').or(relayCheck)).toBeVisible();
  if (await relayCheck.isVisible()) {
    await relayCheck.getByLabel('Code from your authenticator app').fill('123456');
    // This admin has an authenticator app and no passkey yet, so no passkey is offered.
    await expect(relayCheck.getByRole('button', { name: 'Use a passkey' })).toHaveCount(0);
    await relayCheck.getByRole('button', { name: 'Confirm' }).click();
  }
  await expect(page.getByText('inst-4f2a')).toBeVisible();
  await page.getByRole('button', { name: 'Turn off' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Turn off' }).click();
  await expect(page.getByRole('button', { name: 'Turn on' })).toBeVisible();

  expect(problems).toEqual([]);
});
