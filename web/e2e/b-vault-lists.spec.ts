import { type Locator, type Page, expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { newItem as openNewItem, signInAsAdmin } from './signin';

// The list pages: All items and a page per type (`/vault?kind=<kind id>`) with the Vault column and
// filter, Trash with its "Deleted from" column and filter, and Duplicates with its chips and filter.
// The journey makes its own space and items, with names no other journey uses, so it holds whatever
// the earlier ones left in the vault.

/** A link of the sidebar's Vault section, by the start of its name (the count follows it). */
function sidebar(page: Page, name: string): Locator {
  const section = page.getByRole('navigation', { name: 'Vault' });
  const start = new RegExp(`^${name}\\b`);
  return section.getByRole('link', { name: start }).or(section.getByRole('button', { name: start })).first();
}

/** Opens the New menu and picks a type, which opens that type's form. */
async function newItem(page: Page, type: 'Login' | 'Note'): Promise<void> {
  await openNewItem(page, type);
  await expect(page.getByRole('heading', { name: `New ${type.toLowerCase()}` })).toBeVisible();
}

async function saveLogin(page: Page, name: string, username: string, space?: string): Promise<void> {
  await newItem(page, 'Login');
  if (space) {
    const where = page.getByLabel('Save to');
    await expect(where).toBeVisible({ timeout: 60_000 });
    await where.selectOption({ label: space });
  }
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password', { exact: true }).fill('Lists-journey-pass-1!');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

async function saveNote(page: Page, name: string, text: string): Promise<void> {
  await newItem(page, 'Note');
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByLabel('Note', { exact: true }).fill(text);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

/** The row of an item in a list: the first row whose name cell holds exactly `name`. */
function row(page: Page, name: string): Locator {
  return page.getByRole('row').filter({ has: page.getByText(name, { exact: true }) });
}

const vaultFilter = (page: Page): Locator => page.getByRole('combobox', { name: 'Vault' });
const chosenVault = (page: Page): Locator => vaultFilter(page).locator('option:checked');

test('the lists filter by type and by vault, and Trash and Duplicates say which vault', async ({ page }) => {
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

  // A space of my own with one collection, so there is a second vault to filter by.
  await page.getByRole('link', { name: 'Spaces' }).first().click();
  await expect(page.getByRole('heading', { name: 'Spaces', level: 1 })).toBeVisible();
  await page.getByLabel('Space name').fill('Lists space');
  await page.getByLabel('First collection').fill('Shared');
  await page.getByRole('button', { name: 'Make the space' }).click();
  await expect(page.getByText('Lists space').first()).toBeVisible({ timeout: 60_000 });

  // Two logins, one in each vault, and two notes with the same text in the person's own.
  await saveLogin(page, 'Lists alpha', 'alpha@example.org');
  await saveLogin(page, 'Lists beta', 'beta@example.org', 'Lists space: Shared');
  await saveNote(page, 'Lists gamma', 'The same words, for the duplicate check');
  await saveNote(page, 'Lists delta', 'The same words, for the duplicate check');

  // All items: the title with its lock, the gray line, the type chips, the Vault filter and column.
  await sidebar(page, 'All items').click();
  await expect(page.getByRole('heading', { name: 'All items', level: 1 })).toBeVisible();
  await expect(page.getByText('Everything in your vault and in the spaces you belong to.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'End-to-end encrypted' })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Filter by type' })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Type' })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Vault' })).toBeVisible();
  await expect(row(page, 'Lists alpha')).toContainText('Personal');
  await expect(row(page, 'Lists alpha')).toContainText('Login');
  await expect(row(page, 'Lists beta')).toContainText('Lists space');
  await expect(row(page, 'Lists gamma')).toContainText('Note');
  await expect(page.getByText(/^Showing \d+ of \d+$/)).toBeVisible();
  await expectAccessible(page);

  // The lock's tooltip shows on keyboard focus.
  await page.getByRole('button', { name: 'End-to-end encrypted' }).focus();
  await expect(page.getByRole('tooltip')).toContainText('The server keeps ciphertext only');
  // Escape puts it away: open, it lies over the type chips.
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toBeHidden();

  // A type chip leads to that type's page: its title and line, no chips, only its items.
  await page.getByRole('group', { name: 'Filter by type' }).getByRole('button', { name: 'Notes' }).click();
  await expect(page).toHaveURL(/kind=note/);
  await expect(page.getByRole('heading', { name: 'Notes', level: 1 })).toBeVisible();
  await expect(page.getByText('Free text, kept encrypted like everything else.')).toBeVisible();
  await expect(page.getByRole('group', { name: 'Filter by type' })).toHaveCount(0);
  await expect(row(page, 'Lists gamma')).toBeVisible();
  await expect(row(page, 'Lists alpha')).toHaveCount(0);

  // The sidebar leads to the same pages.
  await sidebar(page, 'Logins').click();
  await expect(page).toHaveURL(/kind=login/);
  await expect(page.getByRole('heading', { name: 'Logins', level: 1 })).toBeVisible();
  await expect(page.getByText('Usernames and passwords for websites and apps.')).toBeVisible();
  await expect(page.getByRole('group', { name: 'Filter by type' })).toHaveCount(0);
  await expect(row(page, 'Lists alpha')).toBeVisible();
  await expect(row(page, 'Lists beta')).toBeVisible();
  await expect(row(page, 'Lists gamma')).toHaveCount(0);
  await expectAccessible(page);

  // The Vault filter narrows the type to one vault, and says so in the footer.
  await vaultFilter(page).selectOption({ label: 'Lists space' });
  await expect(row(page, 'Lists beta')).toBeVisible();
  await expect(row(page, 'Lists alpha')).toHaveCount(0);
  await expect(page.getByText('Showing 1 of 1 in Lists space')).toBeVisible();
  await vaultFilter(page).selectOption({ label: 'Personal' });
  await expect(row(page, 'Lists alpha')).toBeVisible();
  await expect(row(page, 'Lists beta')).toHaveCount(0);

  // The type and the vault combine, and the vault stays when the type changes: no notes in the space.
  await vaultFilter(page).selectOption({ label: 'Lists space' });
  await sidebar(page, 'Notes').click();
  await expect(page.getByRole('heading', { name: 'Notes', level: 1 })).toBeVisible();
  await expect(chosenVault(page)).toHaveText('Lists space');
  await expect(row(page, 'Lists gamma')).toHaveCount(0);
  await expect(page.getByText('No matches')).toBeVisible();
  await vaultFilter(page).selectOption({ label: 'All vaults' });
  await expect(row(page, 'Lists gamma')).toBeVisible();

  // Duplicates: the two notes are one group, with the reason, a chip for every type and the Vault filter.
  await page.getByRole('link', { name: 'Duplicates' }).first().click();
  await expect(page.getByRole('heading', { name: 'Duplicates', level: 1 })).toBeVisible();
  const chips = page.getByRole('group', { name: 'Kind of duplicate' });
  await expect(chips.getByRole('button', { name: 'Files' })).toBeVisible();
  await expect(chips.getByRole('button', { name: 'MFA codes' })).toBeVisible();
  await expect(chips.getByRole('button', { name: 'In two places' })).toBeVisible();
  await chips.getByRole('button', { name: 'Notes' }).click();
  const group = page.getByRole('article').filter({ hasText: 'Lists gamma' });
  await expect(group).toContainText('Lists delta');
  await expect(group).toContainText('Same note text');
  await expectAccessible(page);
  await chips.getByRole('button', { name: 'Logins' }).click();
  await expect(page.getByText('Same note text')).toHaveCount(0);
  await chips.getByRole('button', { name: 'Notes' }).click();
  await vaultFilter(page).selectOption({ label: 'Lists space' });
  await expect(page.getByRole('article').filter({ hasText: 'Lists gamma' })).toHaveCount(0);
  await vaultFilter(page).selectOption({ label: 'Personal' });
  await expect(page.getByRole('article').filter({ hasText: 'Lists gamma' })).toBeVisible();
  await vaultFilter(page).selectOption({ label: 'All vaults' });

  // Trash before anything of the space is in it: the Vault filter shows an empty list for the space.
  await page.getByRole('link', { name: /^Trash/ }).click();
  await expect(page.getByRole('heading', { name: 'Trash', level: 1 })).toBeVisible();
  await vaultFilter(page).selectOption({ label: 'Lists space' });
  await expect(row(page, 'Lists beta')).toHaveCount(0);
  // The Trash is empty, or holds only what was deleted from other vaults: either way, none for the space.
  await expect(page.getByText(/The Trash is empty|Nothing deleted from this vault/)).toBeVisible();
  await vaultFilter(page).selectOption({ label: 'All vaults' });

  // Trash: the login of the space goes there, and the table says where it was deleted from.
  await sidebar(page, 'Logins').click();
  await row(page, 'Lists beta').getByRole('link', { name: /Lists beta/ }).click();
  await expect(page.getByRole('heading', { name: 'Lists beta', level: 1 })).toBeVisible();
  await page.getByRole('button', { name: 'More actions for Lists beta' }).click();
  await page.getByRole('menuitem', { name: /Move to Trash/ }).click();
  await page.getByRole('link', { name: /^Trash/ }).click();
  await expect(page.getByRole('heading', { name: 'Trash', level: 1 })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Deleted from' })).toBeVisible();
  await expect(row(page, 'Lists beta')).toContainText('Lists space');
  await expect(row(page, 'Lists beta')).toContainText('Login');
  await expectAccessible(page);

  // Trash has the Vault filter too: the space's item is not in the Personal trash.
  await vaultFilter(page).selectOption({ label: 'Personal' });
  await expect(row(page, 'Lists beta')).toHaveCount(0);
  await vaultFilter(page).selectOption({ label: 'Lists space' });
  await expect(row(page, 'Lists beta')).toBeVisible();
  await vaultFilter(page).selectOption({ label: 'All vaults' });
  await page.getByRole('button', { name: 'Restore Lists beta' }).click();
  await expect(row(page, 'Lists beta')).toHaveCount(0);

  expect(problems).toEqual([]);
});
