import { type Page, expect, test } from '@playwright/test';
import { expectAccessible, freshCode, watchForCspProblems } from './helpers';
import { choosePassword } from './signin';
import { ADMIN, readState, saveState } from './state';

async function signInWithPassword(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/sign-in');
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await choosePassword(page);
  await page.getByLabel('Master password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Open the vault' }).click();
}

async function enterCode(page: Page): Promise<void> {
  const { totpSecret, totpStep } = readState();
  if (!totpSecret) throw new Error('the setup journey has not run');
  await expect(page.getByLabel('Code from your authenticator app')).toBeVisible({ timeout: 90_000 });
  const { code, step } = await freshCode(totpSecret, totpStep);
  await page.getByLabel('Code from your authenticator app').fill(code);
  await page.getByRole('button', { name: 'Open the vault' }).click();
  saveState({ totpStep: step });
}

// The canvas's sign-in journey (SignIn, Password) into Main, then the item screens and the Trash.
test('sign in, see the vault list, add an item, trash it and get it back', async ({ page }) => {
  test.setTimeout(240_000);
  const problems = watchForCspProblems(page);

  // The vault is for signed-in people only.
  await page.goto('/vault');
  await expect(page).toHaveURL(/\/sign-in/);
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expectAccessible(page);

  await signInWithPassword(page, ADMIN.email, ADMIN.password);
  await enterCode(page);

  // Main: an empty vault says so and offers the first item.
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });
  await expect(page.getByRole('heading', { name: 'All items', level: 1 })).toBeVisible();
  await expect(page.getByText('Nothing here yet')).toBeVisible();
  await expectAccessible(page);

  // NewItem: a login, with a generated password. The item is sealed in the worker.
  await page.getByRole('link', { name: 'New item' }).first().click();
  await expect(page.getByRole('heading', { name: 'New login' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('GitHub');
  await page.getByLabel('Username').fill('sam@example.org');
  await page.getByRole('button', { name: 'Generate' }).click();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue(/^.{20}$/);
  await page.getByLabel('Website 1', { exact: true }).fill('https://github.com');
  await page.getByRole('button', { name: 'Save' }).click();

  // Item: opened from what the server returned, then shown.
  await expect(page.getByRole('heading', { name: 'GitHub', level: 1 })).toBeVisible();
  await expect(page.getByText('sam@example.org')).toBeVisible();
  await expect(page.getByRole('link', { name: 'github.com' })).toBeVisible();
  await expectAccessible(page);

  // Main again: the item is in the list, read back through sync.
  await page.getByRole('link', { name: 'All items' }).first().click();
  const row = page.getByRole('row', { name: /GitHub/ });
  await expect(row).toBeVisible();
  await expect(row).toContainText('Login');
  await expectAccessible(page);

  // Search narrows it; a miss says so.
  await page.getByRole('searchbox', { name: 'Search the vault' }).fill('zzz-nothing');
  await expect(page.getByText('No matches')).toBeVisible();
  await page.getByRole('searchbox', { name: 'Search the vault' }).fill('');
  await expect(row).toBeVisible();

  // Trash: delete, find it there, restore.
  await row.getByRole('link', { name: /GitHub/ }).click();
  await page.getByRole('button', { name: 'More actions for GitHub' }).click();
  await page.getByRole('menuitem', { name: 'Move to Trash' }).click();
  await expect(page).toHaveURL(/\/vault$/);
  await expect(page.getByText('Nothing here yet')).toBeVisible();
  await page.getByRole('link', { name: /^Trash/ }).click();
  await expect(page.getByRole('heading', { name: 'Trash', level: 1 })).toBeVisible();
  await expect(page.getByRole('row', { name: /GitHub/ })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Restore GitHub' }).click();
  await expect(page.getByText('The Trash is empty')).toBeVisible();

  // Lock: the keys are forgotten; the master password and a fresh code open the vault again.
  await page.getByRole('button', { name: 'Lock the vault' }).click();
  await expect(page).toHaveURL(/\/unlock/);
  await expect(page.getByRole('heading', { name: 'Open your vault' })).toBeVisible();
  await expectAccessible(page);
  // The unlock screen's password section is named like its field, so ask for the field itself.
  await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(ADMIN.password);
  await page.getByRole('button', { name: 'Open the vault' }).click();
  await enterCode(page);
  // Unlocking goes back to where the vault was locked: the Trash, empty now.
  await expect(page).toHaveURL(/\/trash$/, { timeout: 60_000 });
  await expect(page.getByText('The Trash is empty')).toBeVisible();
  await page.getByRole('link', { name: /^All items/ }).click();
  await expect(page).toHaveURL(/\/vault$/);
  await expect(page.getByRole('row', { name: /GitHub/ })).toBeVisible();

  // The admin console shell is there for an admin.
  await page.getByRole('link', { name: 'Admin console' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
  await expectAccessible(page);

  expect(problems).toEqual([]);
});

test('a wrong master password is refused without saying which part was wrong', async ({ page }) => {
  await signInWithPassword(page, ADMIN.email, 'not the right password at all');
  await expect(page.getByRole('alert')).toContainText(/email or password is wrong/);
  await expect(page).toHaveURL(/\/sign-in\/password/);
});
