import { type Page, expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { newItem, signInAsAdmin } from './signin';

// The item page: Edit as the only main button, the ⋯ menu and its keyboard, the round lock with its
// tooltip, What the server holds in a dialog, links that show on both items and unlink from both,
// Make a copy and Move to a space. Real server and real worker; nothing is stubbed but the
// placement probe the failover banner makes. A page reload signs you out (tokens live in memory),
// so the journey moves only by clicking links.

const PASSWORD = 'Item-page-pass-1!';

async function newLogin(page: Page, name: string, website: string): Promise<void> {
  await newItem(page, 'Login');
  await expect(page.getByRole('heading', { name: 'New login' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByLabel('Username').fill('item-page@example.org');
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Website 1', { exact: true }).fill(website);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

/** From the item list to one item, by clicking: the session lives only in memory. */
async function openItem(page: Page, name: string): Promise<void> {
  await page.getByRole('link', { name: 'All items' }).first().click();
  await page.getByRole('row', { name: new RegExp(`^.*${name}( |$)`) }).first().getByRole('link').first().click();
  await expect(page.getByRole('heading', { name, level: 1, exact: true })).toBeVisible();
}

test('the item page: menu, lock, server dialog, two-way links, copy and move', async ({ page }) => {
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

  await newLogin(page, 'Page GitHub', 'https://page-github.example');
  await newLogin(page, 'Page Mail', 'https://page-mail.example');

  // ---- The header: Edit is the only main button, the rest is in ⋯ ----
  await expect(page.getByRole('link', { name: 'Edit' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Move to Trash' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Websites and rules' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'End-to-end encrypted' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'What the server holds' })).toHaveCount(0);
  await expectAccessible(page);

  // ---- The round lock: its text shows on hover and on keyboard focus ----
  const lock = page.getByRole('button', { name: 'End-to-end encrypted' });
  const tooltip = page.getByRole('tooltip');
  await expect(tooltip).toBeHidden();
  await lock.hover();
  await expect(tooltip).toBeVisible();
  await expect(tooltip).toContainText('Each item has its own AES-256-GCM key');
  await page.mouse.move(0, 0);
  await expect(tooltip).toBeHidden();
  await lock.focus();
  await expect(tooltip).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(tooltip).toBeHidden();

  // ---- The ⋯ menu: entries, Escape, focus back on the button ----
  const more = page.getByRole('button', { name: 'More actions for Page Mail' });
  await more.click();
  const menu = page.getByRole('menu', { name: 'More actions for Page Mail' });
  await expect(menu).toBeVisible();
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Websites and rules',
    'Move to a space',
    'Make a copy',
    'What the server holds',
    'Move to TrashKept there for 30 days. You can restore it.',
  ]);
  await expectAccessible(page);
  await page.keyboard.press('Escape');
  await expect(menu).toBeHidden();
  await expect(more).toBeFocused();

  // From the keyboard alone: open, arrow down to What the server holds, choose it.
  await page.keyboard.press('Enter');
  await expect(menu).toBeVisible();
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');

  // ---- What the server holds, in a dialog ----
  const dialog = page.getByRole('dialog', { name: 'What the server holds' });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('This is everything the server stores for Page Mail.');
  await expect(dialog).toContainText(/owner\s+user:[0-9a-f-]{36}/);
  await expect(dialog).toContainText(/revision 1 · key version \d+/);
  await expect(dialog).toContainText(/key\s+\d+ B wrapped/);
  await expect(dialog).toContainText(/body\s+AES-256-GCM, \d+ B/);
  await expect(dialog).not.toContainText('Page Mail copy');
  await expectAccessible(page);
  // Focus stays inside while Tab goes round.
  for (let i = 0; i < 6; i += 1) {
    await page.keyboard.press('Tab');
    await expect(dialog.locator(':focus')).toHaveCount(1);
  }
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(more).toBeFocused();
  await more.click();
  await page.getByRole('menuitem', { name: 'What the server holds' }).click();
  await dialog.getByRole('button', { name: 'Close' }).last().click();
  await expect(dialog).toBeHidden();
  await expect(more).toBeFocused();

  // ---- Links: made from one item, shown on both ----
  const links = page.getByRole('region', { name: 'Linked items' });
  await expect(links).toContainText('Nothing linked yet.');
  await links.getByRole('button', { name: 'Link an item' }).click();
  const picker = page.getByRole('dialog', { name: 'Link an item' });
  await expect(picker.getByRole('searchbox', { name: 'Search the vault' })).toBeFocused();
  await picker.getByRole('searchbox', { name: 'Search the vault' }).fill('Page GitHub');
  await expect(picker.getByRole('button', { name: /^Link / })).toHaveCount(1);
  await expectAccessible(page);
  await picker.getByRole('button', { name: 'Link Page GitHub' }).click();
  await expect(picker).toBeHidden();
  const linked = links.getByRole('link', { name: /Page GitHub/ });
  await expect(linked).toContainText('Login');

  // Open the linked item: it lists this one, because the link was written on both.
  await linked.click();
  await expect(page.getByRole('heading', { name: 'Page GitHub', level: 1 })).toBeVisible();
  const backLinks = page.getByRole('region', { name: 'Linked items' });
  await expect(backLinks.getByRole('link', { name: /Page Mail/ })).toBeVisible();

  // Unlink from this side: the other item lets go too.
  await backLinks.getByRole('button', { name: 'Unlink Page Mail' }).click();
  await expect(backLinks).toContainText('Nothing linked yet.');
  await openItem(page, 'Page Mail');
  await expect(page.getByRole('region', { name: 'Linked items' })).toContainText('Nothing linked yet.');

  // ---- Make a copy: the create form, filled in, saved as a new item ----
  await page.getByRole('button', { name: 'More actions for Page Mail' }).click();
  await page.getByRole('menuitem', { name: 'Make a copy' }).click();
  await expect(page.getByRole('heading', { name: 'New login' })).toBeVisible();
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('Page Mail');
  await expect(page.getByLabel('Username')).toHaveValue('item-page@example.org');
  await expect(page.getByLabel('Website 1', { exact: true })).toHaveValue('https://page-mail.example');
  await page.getByLabel('Name', { exact: true }).fill('Page Mail copy');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name: 'Page Mail copy', level: 1 })).toBeVisible();
  await expect(page.getByText(/Login · revision 1\b/)).toBeVisible();

  // ---- Move to a space: a new place, the old one gone ----
  await page.getByRole('link', { name: 'Spaces' }).first().click();
  await expect(page.getByRole('heading', { name: 'Spaces', level: 1 })).toBeVisible();
  await page.getByLabel('Space name').fill('Move space');
  await page.getByLabel('First collection').fill('Moved items');
  await page.getByRole('button', { name: 'Make the space' }).click();
  await expect(page.getByText('Move space').first()).toBeVisible({ timeout: 60_000 });

  await openItem(page, 'Page Mail copy');
  await page.getByRole('button', { name: 'More actions for Page Mail copy' }).click();
  await page.getByRole('menuitem', { name: 'Move to a space' }).click();
  const move = page.getByRole('dialog', { name: 'Move to a space' });
  // Other journeys may have made spaces too: choose this one's collection by name.
  const place = move.getByRole('radio', { name: /Move space: Moved items/ });
  await expect(place).toBeAttached({ timeout: 60_000 });
  await move.getByText('Move space: Moved items').click();
  await expect(place).toBeChecked();
  await expectAccessible(page);
  await move.getByRole('button', { name: 'Move', exact: true }).click();
  await expect(move).toBeHidden({ timeout: 60_000 });
  await expect(page.getByRole('heading', { name: 'Page Mail copy', level: 1 })).toBeVisible();

  // The item the server holds now belongs to the space.
  await page.getByRole('button', { name: 'More actions for Page Mail copy' }).click();
  await page.getByRole('menuitem', { name: 'What the server holds' }).click();
  await expect(page.getByRole('dialog', { name: 'What the server holds' })).toContainText(/owner\s+space:[0-9a-f-]{36}/);
  await page.keyboard.press('Escape');

  // And only one "Page Mail copy" is left in the list.
  await page.getByRole('link', { name: 'All items' }).first().click();
  await expect(page.getByRole('row', { name: /Page Mail copy/ })).toHaveCount(1);

  expect(problems).toEqual([]);
});
