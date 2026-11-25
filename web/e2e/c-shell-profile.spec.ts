import { expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import {
  chooseFromAccountMenu,
  enterCode,
  openAccountMenu,
  signInAsAdmin,
  signInWithPassword,
} from './signin';
import { ADMIN } from './state';

// The page frame (the avatar menu, the New menu, the sidebar with a count per type) and Profile
// (name, address, master password), on the real server, as the admin the setup journey made.

const TYPES = [
  'Login',
  'Note',
  'File',
  'MFA code',
  'Backup codes',
  'Passkey',
  'Card',
  'Identity',
  'Contact',
  'Certificate',
  'SSH key',
  'PGP key',
];
const PLURALS = [
  'Logins',
  'Notes',
  'Files',
  'MFA codes',
  'Backup codes',
  'Passkeys',
  'Cards',
  'Identities',
  'Contacts',
  'Certificates',
  'SSH keys',
  'PGP keys',
];

const NEW_PASSWORD = 'a different long passphrase for the journey';

test('the avatar menu, the New menu and the sidebar', async ({ page }) => {
  test.setTimeout(240_000);
  const problems = watchForCspProblems(page);
  await page.route('**/kem/v1/placement', (route) =>
    route.fulfill({
      status: 404,
      contentType: 'application/problem+json',
      body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }),
    }),
  );
  await signInAsAdmin(page);
  await expect(page.getByPlaceholder('Search the vault')).toBeVisible();

  // The sidebar: All items and every type, each with its count, and no Account section.
  const sidebar = page.getByRole('navigation', { name: 'Vault' });
  await expect(sidebar.getByRole('heading', { name: 'Account' })).toHaveCount(0);
  await expect(sidebar.getByRole('link', { name: /^All items\d+$/ })).toBeVisible();
  for (const plural of PLURALS) {
    await expect(sidebar.getByRole('link', { name: new RegExp(`^${plural}\\d+$`) }), plural).toBeVisible();
  }
  await sidebar.getByRole('link', { name: /^MFA codes\d+$/ }).click();
  await expect(page).toHaveURL(/\/vault\?kind=otp$/);
  await sidebar.getByRole('link', { name: /^All items\d+$/ }).click();
  await expect(page).toHaveURL(/\/vault$/);

  // The New menu: every type, in order, each one a creation form.
  await page.getByRole('button', { name: 'New item' }).click();
  const types = page.getByRole('navigation', { name: 'New item' });
  await expect(types.getByRole('link')).toHaveText(TYPES);
  await expectAccessible(page);
  await page.keyboard.press('Escape');
  await expect(types).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'New item' })).toBeFocused();
  await page.getByRole('button', { name: 'New item' }).click();
  await types.getByRole('link', { name: 'Note', exact: true }).click();
  await expect(page).toHaveURL(/\/vault\/new\?kind=note$/);

  // The avatar menu: who, then the entries, the console's among them for an admin.
  const avatar = page.getByRole('button', { name: /^Account menu for / });
  await expect(avatar).toHaveText('SR');
  const menu = await openAccountMenu(page);
  await expect(page.getByText(ADMIN.email)).toBeVisible();
  await expect(menu.locator('a, button')).toHaveText([
    'Profile',
    'Security',
    'Devices & apps',
    /^Admin console/,
    'About',
    'Lock the vault',
    'Sign out',
  ]);
  await expectAccessible(page);
  await page.keyboard.press('Escape');
  await expect(menu).toHaveCount(0);
  await expect(avatar).toBeFocused();

  // The console has its own menu, and About is not in its sidebar.
  await chooseFromAccountMenu(page, 'Admin console');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Admin' }).getByRole('link', { name: 'About' })).toHaveCount(0);
  const adminMenu = await openAccountMenu(page);
  await expect(page.getByText(`Admin · ${ADMIN.email}`)).toBeVisible();
  await expect(adminMenu.locator('a, button')).toHaveText(['My Vault', 'About', 'Sign out']);
  await expectAccessible(page);
  await chooseFromAccountMenu(page, 'My Vault');
  await expect(page).toHaveURL(/\/vault$/);

  expect(problems).toEqual([]);
});

test('Profile: the name, the address and the master password', async ({ page }) => {
  test.setTimeout(420_000);
  const problems = watchForCspProblems(page);
  await page.route('**/kem/v1/placement', (route) =>
    route.fulfill({
      status: 404,
      contentType: 'application/problem+json',
      body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }),
    }),
  );
  await signInAsAdmin(page);

  await chooseFromAccountMenu(page, 'Profile');
  await expect(page.getByRole('heading', { name: 'Profile', level: 1 })).toBeVisible();
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue(ADMIN.name);
  await expect(page.getByLabel('Email', { exact: true })).toHaveValue(ADMIN.email);
  await expectAccessible(page);
  // The menu marks the page being shown.
  await openAccountMenu(page);
  await expect(page.getByRole('navigation', { name: 'Account' }).getByRole('link', { name: 'Profile' })).toHaveAttribute(
    'aria-current',
    'page',
  );
  await page.keyboard.press('Escape');

  // The name: saved on the server, and the avatar follows it.
  await page.getByLabel('Name', { exact: true }).fill('Samira Rivera');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Account menu for Samira Rivera' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill(ADMIN.name);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('button', { name: `Account menu for ${ADMIN.name}` })).toBeVisible();

  // The address: a new one asks the master password, and nothing changes until the link is opened.
  await page.getByLabel('Email', { exact: true }).fill('sam.new@example.co');
  const section = page.getByRole('region', { name: 'Name and email' });
  await expect(section.getByLabel('Current master password')).toBeVisible();
  await expect(section.getByRole('button', { name: 'Save' })).toBeDisabled();
  await section.getByLabel('Current master password').fill(ADMIN.password);
  await section.getByRole('button', { name: 'Save' }).click();
  // With the server's mail on, a link is sent and the change waits; with it off, the server says so.
  const sent = page.getByText(/We sent an email to sam\.new@example\.co/);
  await expect(sent.or(page.getByText(/This server sends no email/))).toBeVisible({ timeout: 60_000 });
  if (await sent.isVisible()) {
    await expect(page.getByText(/Waiting for the link sent to sam\.new@example\.co/)).toBeVisible();
    await expect(page.getByLabel('Email', { exact: true })).toHaveValue(ADMIN.email);
    await page.getByRole('button', { name: 'Cancel the change' }).click();
    await expect(page.getByText('The change of address is cancelled.')).toBeVisible();
  }

  // The master password: checks first, then the change and the way back.
  const pw = page.getByRole('region', { name: 'Master password' });
  await expect(pw.getByRole('checkbox', { name: /Sign out my other devices/ })).toBeChecked();
  await expect(pw.getByText('No one can reset it for you.')).toBeVisible();
  await pw.getByLabel('Current master password').fill(ADMIN.password);
  await pw.getByLabel('New master password').fill('too short');
  await pw.getByLabel('Type it again').fill('too short');
  await pw.getByRole('button', { name: 'Change master password' }).click();
  await expect(pw.getByRole('alert')).toContainText('at least 12 characters');
  await pw.getByLabel('New master password').fill(NEW_PASSWORD);
  await pw.getByLabel('Type it again').fill(`${NEW_PASSWORD} `);
  await pw.getByRole('button', { name: 'Change master password' }).click();
  await expect(pw.getByRole('alert')).toContainText("don't match");

  // A wrong current password stops it, and keeps what was typed.
  await pw.getByLabel('Current master password').fill('not the current password');
  await pw.getByLabel('Type it again').fill(NEW_PASSWORD);
  await pw.getByRole('button', { name: 'Change master password' }).click();
  await expect(page.getByText('That is not your current master password.')).toBeVisible({ timeout: 60_000 });
  await expect(pw.getByLabel('New master password')).toHaveValue(NEW_PASSWORD);

  // The change: the boxes empty, and the account opens with the new password.
  await pw.getByLabel('Current master password').fill(ADMIN.password);
  await pw.getByRole('button', { name: 'Change master password' }).click();
  await expect(page.getByText('Your master password is changed, and your other devices are signed out.')).toBeVisible({
    timeout: 60_000,
  });
  await expect(pw.getByLabel('Current master password')).toHaveValue('');

  // Back to the old one, with this tab still signed in: then a sign-in proves the final record.
  await pw.getByLabel('Current master password').fill(NEW_PASSWORD);
  await pw.getByLabel('New master password').fill(ADMIN.password);
  await pw.getByLabel('Type it again').fill(ADMIN.password);
  await pw.getByRole('checkbox', { name: /Sign out my other devices/ }).uncheck();
  await pw.getByRole('button', { name: 'Change master password' }).click();
  await expect(page.getByText('Your master password is changed.', { exact: true })).toBeVisible({ timeout: 60_000 });

  await chooseFromAccountMenu(page, 'Sign out');
  await expect(page).toHaveURL(/\/sign-in/);
  await signInWithPassword(page, ADMIN.email, ADMIN.password);
  await enterCode(page);
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });

  expect(problems).toEqual([]);
});

test('the link mailed to a new address says so when it is no good', async ({ page }) => {
  await page.goto('/confirm-email?token=not-a-token-the-server-knows');
  await expect(page.getByRole('heading', { name: 'New email address' })).toBeVisible();
  await expect(page.getByText(/expired or was already used/)).toBeVisible({ timeout: 30_000 });
  await expectAccessible(page);

  await page.goto('/confirm-email');
  await expect(page.getByText(/This link is incomplete/)).toBeVisible();
});
