import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { type Page, expect, test } from '@playwright/test';
import { expectAccessible, freshCode, watchForCspProblems } from './helpers';
import { choosePassword } from './signin';
import { ADMIN, readState, saveState } from './state';

// The canvas's account screens (Account security, Spaces, Devices & apps) after sign-in. The
// emergency-access and space routes are the real server's. What the server lacks is stubbed with
// page.route and named as such: the request's public key on an approval, and a device list.

async function signIn(page: Page): Promise<void> {
  await page.goto('/sign-in');
  await page.getByLabel('Email').fill(ADMIN.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await choosePassword(page);
  await page.getByLabel('Master password', { exact: true }).fill(ADMIN.password);
  await page.getByRole('button', { name: 'Open the vault' }).click();
  const { totpSecret, totpStep } = readState();
  if (!totpSecret) throw new Error('the setup journey has not run');
  await expect(page.getByLabel('Code from your authenticator app')).toBeVisible({ timeout: 90_000 });
  const { code, step } = await freshCode(totpSecret, totpStep);
  await page.getByLabel('Code from your authenticator app').fill(code);
  await page.getByRole('button', { name: 'Open the vault' }).click();
  saveState({ totpStep: step });
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });
}

/** The phrase docs/crypto.md defines for a key, worked out here independently of the app. */
function phraseOf(key: Buffer): string {
  const words = readFileSync(fileURLToPath(new URL('../src/lib/eff_large_wordlist.txt', import.meta.url)), 'utf8')
    .split('\n')
    .filter(Boolean);
  const digest = createHash('sha256').update(Buffer.concat([Buffer.from('kemlock approval v1'), key])).digest();
  let head = 0n;
  for (let i = 0; i < 9; i += 1) head = (head << 8n) | BigInt(digest[i] as number);
  const bits = head >> 7n;
  const out: string[] = [];
  for (let i = 0; i < 5; i += 1) {
    const group = Number((bits >> BigInt(13 * (4 - i))) & 0x1fffn);
    out.push(words[group % 7776] as string);
  }
  return out.join(' ');
}

test('account security, spaces and devices & apps', async ({ page }) => {
  test.setTimeout(240_000);
  const problems = watchForCspProblems(page);

  // Devices: a request the server lists with its one-time key (stubbed: a real request needs a
  // second device to ask) and a device list (stubbed: for a Bitwarden app the test can't run). The
  // words shown are the ones this test works out from the key, never the server's.
  const key = Buffer.alloc(1600, 9);
  await page.route('**/kem/v1/devices/approvals', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        approvals: [
          {
            id: '50000000-0000-4000-8000-000000000001',
            deviceName: 'Firefox on Linux',
            deviceKind: 'other',
            ip: '203.0.113.0',
            phrase: 'words from the server that must never show',
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 600_000).toISOString(),
            ageSeconds: 40,
            publicKey: key.toString('base64url'),
          },
        ],
      }),
    }),
  );
  await page.route('**/kem/v1/devices', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        devices: [
          {
            id: '50000000-0000-4000-8000-0000000000aa',
            name: 'Bitwarden extension in Firefox',
            kind: 'bitwarden',
            createdAt: new Date(Date.now() - 86_400_000).toISOString(),
            lastSeenAt: new Date(Date.now() - 3_600_000).toISOString(),
            lastBitwardenUseAt: new Date(Date.now() - 3_600_000).toISOString(),
            current: false,
            trusted: false,
          },
        ],
      }),
    }),
  );

  await signIn(page);

  // Account security: the admin turned on an authenticator app during setup.
  await page.getByRole('link', { name: 'Account security' }).first().click();
  await expect(page.getByRole('heading', { name: 'Account security', level: 1 })).toBeVisible();
  await expect(page.getByText('Authenticator app')).toBeVisible();
  // The app's own row: the second-step card lists the recovery code as On too.
  await expect(
    page.locator('.row', { hasText: 'Authenticator app' }).getByText('On', { exact: true }),
  ).toBeVisible();
  await expectAccessible(page);

  // Emergency access: a contact is invited on the real route, then removed.
  await page.getByRole('button', { name: 'Add a contact' }).click();
  await page.getByLabel('Their email').fill('jordan@example.co');
  await page.getByRole('button', { name: 'Send the invitation' }).click();
  await expect(page.getByText('jordan@example.co')).toBeVisible();
  await expect(page.getByText('Invited', { exact: true })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Remove jordan@example.co' }).click();
  await expect(page.getByText('You have named no contact.')).toBeVisible();

  // Spaces: none yet. Making one seals its keys in this browser's worker and opens the new space.
  await page.getByRole('link', { name: 'Spaces' }).first().click();
  await expect(page.getByRole('heading', { name: 'Spaces', level: 1 })).toBeVisible();
  await expect(page.getByText('No spaces yet')).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel('Space name').fill('Example Co');
  await page.getByLabel('First collection').fill('Infrastructure');
  await page.getByRole('button', { name: 'Make the space' }).click();
  await expect(page.getByRole('heading', { name: 'Example Co', level: 1 })).toBeVisible({ timeout: 60_000 });

  // Devices & apps: this browser, the stubbed device, and the approval with its client-side words.
  await page.getByRole('link', { name: 'Devices & apps' }).first().click();
  await expect(page.getByRole('heading', { name: 'Devices & apps', level: 1 })).toBeVisible();
  await expect(page.getByText('This browser', { exact: true })).toBeVisible();
  await expect(page.getByText('Bitwarden extension in Firefox')).toBeVisible();
  await expect(page.getByText('Firefox on Linux is asking to sign in as you')).toBeVisible();
  await expect(page.getByText(phraseOf(key), { exact: true })).toBeVisible();
  await expect(page.getByText('words from the server that must never show')).toHaveCount(0);
  // The worker is there, and the words are shown, so approving is offered.
  await expect(page.getByRole('button', { name: 'Approve Firefox on Linux' })).toBeEnabled();
  await expectAccessible(page);

  expect(problems).toEqual([]);
});
