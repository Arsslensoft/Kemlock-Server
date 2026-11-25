import { expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { chooseFromAccountMenu, signInAsAdmin } from './signin';

// Devices & apps after a real sign-in: the Connect dialog (the server's own address, copied for
// real), and trust in the table: the shield and its tooltip, and each row's menu. The device list
// is stubbed, because a phone and a Bitwarden app can't be made here; the key-copy calls of this
// browser are the real server's.
//
// The file is named so that it runs after the numbered journeys, which make the admin it uses.

const PHONE = '50000000-0000-4000-8000-0000000000a1';
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
const DAY = 86_400_000;

test('Devices & apps: Connect, and trust in the table', async ({ page, context }) => {
  test.setTimeout(240_000);
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const problems = watchForCspProblems(page);

  // The address the server is set up with: what an app has to be given.
  const config = (await (await page.request.get('/kem/v1/config')).json()) as { domain: string };
  expect(config.domain).toMatch(/^https?:\/\//);

  // Other devices: a trusted Kemlock app, one that is not trusted, and the two Bitwarden-API apps.
  let phoneTrusted = true;
  const untrusted: string[] = [];
  await page.route('**/kem/v1/devices', (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        devices: [
          {
            id: PHONE,
            name: "Sam's iPhone 16",
            kind: 'kemlock-ios',
            createdAt: ago(90 * DAY),
            lastSeenAt: ago(120_000),
            lastKemlockUseAt: ago(120_000),
            current: false,
            trusted: phoneTrusted,
            trustedSince: phoneTrusted ? ago(61 * DAY) : null,
          },
          {
            id: '50000000-0000-4000-8000-0000000000a2',
            name: 'Pixel 9',
            kind: 'kemlock-android',
            createdAt: ago(30 * DAY),
            lastSeenAt: ago(720_000),
            lastKemlockUseAt: ago(720_000),
            current: false,
            trusted: false,
          },
          {
            id: '50000000-0000-4000-8000-0000000000a3',
            name: 'Workstation',
            kind: 'amethystora',
            createdAt: ago(30 * DAY),
            lastSeenAt: ago(360_000),
            lastBitwardenUseAt: ago(360_000),
            current: false,
            trusted: false,
          },
          {
            id: '50000000-0000-4000-8000-0000000000a4',
            name: 'Build server',
            kind: 'bitwarden',
            createdAt: ago(30 * DAY),
            lastSeenAt: ago(3 * DAY),
            lastBitwardenUseAt: ago(3 * DAY),
            current: false,
            trusted: false,
          },
        ],
      }),
    });
  });
  // Stopping trust in another device: the server's DELETE /kem/v1/devices/{id}/key-copy.
  await page.route('**/kem/v1/devices/*/key-copy', (route) => {
    if (route.request().method() !== 'DELETE') return route.continue();
    untrusted.push(new URL(route.request().url()).pathname.split('/')[4] ?? '');
    phoneTrusted = false;
    return route.fulfill({ status: 204 });
  });

  await signInAsAdmin(page);
  await chooseFromAccountMenu(page, 'Devices & apps');
  await expect(page.getByRole('heading', { name: 'Devices & apps', level: 1 })).toBeVisible();

  // The old panels are gone; the header has Connect and Sign out everyone else.
  await expect(page.getByRole('heading', { name: 'Connect another app' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Trust this device' })).toHaveCount(0);
  const header = page.locator('.card-head', { has: page.getByRole('heading', { name: 'Signed in' }) });
  await expect(header.getByRole('button')).toHaveText(['Connect', 'Sign out everyone else']);
  await expect(page.getByText(config.domain, { exact: true })).toHaveCount(0);

  // Connect: the real configured address and Copy, then the three steps stacked.
  await page.getByRole('button', { name: 'Connect an app or device' }).click();
  const connect = page.getByRole('dialog', { name: 'Connect an app or device' });
  await expect(connect.getByText(config.domain, { exact: true })).toBeVisible();
  await expect(connect.locator('.stack-steps > p')).toHaveText([
    'Kemlock: Settings, Sync, Kemlock Server, then sign in.',
    'Amethystora Vault: the Sync page, with this address as the server.',
    'Bitwarden apps: choose a self-hosted server and paste this address.',
  ]);
  await expectAccessible(page);
  await connect.getByRole('button', { name: 'Copy the address' }).click();
  await expect(connect.getByText('Copied', { exact: true })).toBeAttached();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(config.domain);
  await connect.getByRole('button', { name: 'Done' }).click();
  await expect(connect).toBeHidden();

  // The trusted phone has the shield; its tooltip shows on focus and goes away on Escape.
  const phone = page.locator('.row', { hasText: "Sam's iPhone 16" });
  const shield = phone.getByRole('button', { name: 'Trusted device' });
  await expect(shield).toBeVisible();
  await expect(phone.getByRole('tooltip')).toBeHidden();
  await shield.focus();
  await expect(phone.getByRole('tooltip')).toBeVisible();
  await expect(phone.getByRole('tooltip')).toContainText('Trusted since 2 months ago');
  await expect(phone.getByRole('tooltip')).toContainText('so it can open the vault without the master password');
  await page.keyboard.press('Escape');
  await expect(phone.getByRole('tooltip')).toBeHidden();
  await expectAccessible(page);

  // Rows' menus: Trust is for Kemlock apps only, and a Bitwarden-API app has Sign out alone, with no
  // note. Another Kemlock app that is not trusted lists Trust this device off, with the reason.
  await page.getByRole('button', { name: "Actions for Sam's iPhone 16" }).click();
  await expect(page.getByRole('menuitem')).toHaveText(['Stop trusting', 'Sign out']);
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Actions for Pixel 9' }).click();
  await expect(page.getByRole('menuitem')).toHaveText(['Trust this device', 'Sign out']);
  await expect(page.getByRole('menuitem', { name: 'Trust this device' })).toHaveAttribute('aria-disabled', 'true');
  const reason = 'Only that device can turn this on: open Kemlock on it.';
  await expect(page.locator('.menu-note')).toHaveText(reason);
  await expect(page.getByRole('menu', { name: 'Actions for Pixel 9' })).toHaveAccessibleDescription(reason);
  await page.keyboard.press('Escape');
  for (const name of ['Workstation', 'Build server']) {
    await page.getByRole('button', { name: `Actions for ${name}` }).click();
    await expect(page.getByRole('menuitem')).toHaveText(['Sign out']);
    await expect(page.locator('.menu-note')).toHaveCount(0);
    await page.keyboard.press('Escape');
  }
  await expect(page.locator('.row', { hasText: 'Build server' }).getByRole('button', { name: 'Trusted device' })).toHaveCount(0);

  // Stop trusting the phone: the server is asked for that device, and the shield goes.
  await page.getByRole('button', { name: "Actions for Sam's iPhone 16" }).click();
  await page.getByRole('menuitem', { name: 'Stop trusting' }).click();
  await expect(shield).toHaveCount(0);
  expect(untrusted).toEqual([PHONE]);

  // This browser: Trust this device is on for it (the crypto worker can make the copy), and trusting
  // it for real puts the shield on its row; Stop trusting takes it off again.
  await page.getByRole('button', { name: 'Actions for this browser' }).click();
  const trust = page.getByRole('menuitem', { name: 'Trust this device' });
  await expect(trust).toBeVisible();
  await expect(trust).not.toHaveAttribute('aria-disabled', 'true');
  await expect(page.getByRole('menuitem', { name: 'Sign out of this browser' })).toBeVisible();
  await trust.click();
  const mine = page.locator('.row', { hasText: 'This browser' });
  await expect(mine.getByRole('button', { name: 'Trusted device' })).toBeVisible({ timeout: 30_000 });
  await expect(mine.getByRole('tooltip')).toContainText('Trusted since');
  await page.getByRole('button', { name: 'Actions for this browser' }).click();
  await expect(page.getByRole('menuitem')).toHaveText(['Stop trusting', 'Sign out of this browser']);
  await page.getByRole('menuitem', { name: 'Stop trusting' }).click();
  await expect(mine.getByRole('button', { name: 'Trusted device' })).toHaveCount(0);

  expect(problems).toEqual([]);
});
