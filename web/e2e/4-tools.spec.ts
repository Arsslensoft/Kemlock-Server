import { fileURLToPath } from 'node:url';
import { type Page, expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { signInAsAdmin } from './signin';
import type { Placement } from '../src/api/placement';

// The canvas's vault tools after sign-in: Duplicates and DuplicateMerge, ItemWebsites, Vault
// health, Send, Import & export and the failover banner with "Where your vault is stored".
//
// Real server: items, sync and batches, and Send. What the server lacks is stubbed with page.route and
// named as such: /kem/v1/placement (failover) and Pwned Passwords. A page
// reload signs you out (tokens live in memory), so a journey moves only by clicking links.

const PASSWORD = 'Tools-journey-pass-1!';

async function newLogin(page: Page, name: string, website: string): Promise<void> {
  await page.getByRole('link', { name: 'New item' }).first().click();
  await expect(page.getByRole('heading', { name: 'New login' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByLabel('Username').fill('tools@example.org');
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Website 1', { exact: true }).fill(website);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

/** Nothing leaves for Have I Been Pwned from a journey. */
async function stubPwnedPasswords(page: Page): Promise<string[]> {
  const asked: string[] = [];
  await page.route('https://api.pwnedpasswords.com/**', async (route) => {
    asked.push(route.request().url());
    await route.fulfill({ status: 200, contentType: 'text/plain', body: '0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n' });
  });
  return asked;
}

test('two logins that hold the same values merge into one, and can be unmerged', async ({ page }) => {
  test.setTimeout(240_000);
  const problems = watchForCspProblems(page);
  await page.route('**/kem/v1/placement', (route) => route.fulfill({ status: 404, contentType: 'application/problem+json', body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }) }));
  await signInAsAdmin(page);

  await newLogin(page, 'Tools One', 'https://tools-journey.example');
  await newLogin(page, 'Tools Two', 'https://app.tools-journey.example');

  // Duplicates: found in this browser, with the reason.
  await page.getByRole('link', { name: 'Duplicates' }).click();
  await expect(page.getByRole('heading', { name: 'Duplicates', level: 1 })).toBeVisible();
  const group = page.getByRole('article').filter({ hasText: 'tools@example.org' });
  await expect(group.getByText('Same website, username and password')).toBeVisible();
  await expect(page.getByRole('switch', { name: 'Let the server match new items' })).toBeDisabled();
  await expectAccessible(page);

  // Merge from the preview: one batch, then the group is gone and Undo brings it back.
  await group.getByRole('button', { name: 'Review' }).click();
  await expect(page.getByRole('heading', { name: 'Merge preview' })).toBeVisible();
  await page.getByRole('button', { name: 'Merge', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Merged into' })).toBeVisible();
  await expect(group).toHaveCount(0);
  await page.getByRole('button', { name: 'Undo' }).click();
  await expect(group).toHaveCount(1);

  // DuplicateMerge: every field is a choice.
  await group.getByRole('button', { name: 'Review' }).click();
  await page.getByRole('link', { name: 'Choose every field' }).click();
  await expect(page.getByRole('heading', { name: 'Merge 2 items into one' })).toBeVisible();
  await expect(page.getByRole('checkbox', { name: /app\.tools-journey\.example/ })).toBeChecked();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Merge', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Merged' })).toBeVisible();

  // The kept login holds both websites, each with its own rule: ItemWebsites.
  await page.getByRole('link', { name: 'All items' }).first().click();
  await page.getByRole('row', { name: /Tools (One|Two)/ }).getByRole('link').first().click();
  await page.getByRole('link', { name: 'Websites and rules' }).click();
  await expect(page.getByRole('heading', { name: /^Websites of Tools (One|Two)$/, level: 1 })).toBeVisible();
  await expect(page.getByLabel('Website 1', { exact: true })).toHaveValue(/tools-journey\.example/);
  await expect(page.getByLabel('Website 2', { exact: true })).toHaveValue(/tools-journey\.example/);
  await page.getByRole('button', { name: 'Add a website' }).click();
  await page.getByLabel('Website 3', { exact: true }).fill('wiki.tools-journey.example');
  await page.getByLabel('Match for website 3').selectOption('never');
  await expect(page.getByText('Kept as a record, never filled').first()).toBeVisible();
  await page.getByLabel('Match for website 1').selectOption('regex');
  await expect(page.getByText(/dangerous if used carelessly/)).toBeVisible();
  await page.getByLabel('Match for website 1').selectOption('domain');
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name: /^Tools (One|Two)$/, level: 1 })).toBeVisible();

  expect(problems).toEqual([]);
});

test('vault health runs in the browser and asks Pwned Passwords only for a hash prefix', async ({ page }) => {
  test.setTimeout(180_000);
  const asked = await stubPwnedPasswords(page);
  await page.route('**/kem/v1/placement', (route) => route.fulfill({ status: 404, contentType: 'application/problem+json', body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }) }));
  await signInAsAdmin(page);

  await page.getByRole('link', { name: 'Vault health' }).click();
  await expect(page.getByRole('heading', { name: 'Vault health', level: 1 })).toBeVisible();
  await expectAccessible(page);

  // Every request carries five hex characters and nothing else of the password.
  await expect.poll(() => asked.length).toBeGreaterThan(0);
  for (const url of asked) expect(url).toMatch(/^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/);

  // The switch is the person's: off, and the page says nothing is exposed that it did not look up.
  const toggle = page.getByRole('switch', { name: 'Look passwords up in Pwned Passwords' });
  await expect(toggle).toBeChecked();
  await toggle.uncheck();
  await expect(toggle).not.toBeChecked();
  await expect(page.getByRole('switch', { name: 'Keep the breach list up to date' })).toBeDisabled();
});

test('a Send is encrypted here and its key stays out of what the server receives', async ({ page }) => {
  test.setTimeout(180_000);
  await page.route('**/kem/v1/placement', (route) => route.fulfill({ status: 404, contentType: 'application/problem+json', body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }) }));
  await signInAsAdmin(page);

  await page.getByRole('link', { name: 'Send', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Send', level: 1 })).toBeVisible();
  await expect(page.getByText(/No Sends yet/)).toBeVisible();
  await expectAccessible(page);

  await page.getByLabel('Name', { exact: true }).fill('Door code');
  await page.getByLabel('Text', { exact: true }).fill('4 7 1 9, then the green button');
  await page.getByLabel('Most views').fill('3');
  // The server has its Send routes now, so this goes through them; only what it is sent is read.
  const posted = page.waitForRequest((request) => request.method() === 'POST' && new URL(request.url()).pathname === '/kem/v1/sends');
  await page.getByRole('button', { name: 'Create link' }).click();
  const postBody = (await posted).postData() ?? '';

  // The link has the key after the #; the request has neither the key nor the text.
  const link = page.locator('.link-box');
  await expect(link).toContainText(/\/#\/send\/[A-Za-z0-9_-]{22}\/[A-Za-z0-9_-]{43}$/);
  const key = ((await link.textContent()) ?? '').split('/').pop() ?? '';
  expect(key).toHaveLength(43);
  expect(postBody).not.toContain(key);
  expect(postBody).not.toContain('green button');

  // The list shows it, named from the owner's own sealed copy.
  await expect(page.getByText('Door code').first()).toBeVisible();
  await expect(page.getByText(/Text · 0 of 3 views/)).toBeVisible();
  await page.getByRole('button', { name: 'Delete Door code' }).click();
  await page.getByRole('dialog', { name: 'Delete Door code?' }).getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText(/No Sends yet/)).toBeVisible();
});

test('the failover banner names the replica, and "Where your vault is stored" lists the servers', async ({ page }) => {
  test.setTimeout(180_000);
  const placement: Placement = {
    vaults: [
      {
        id: 'me',
        name: 'Your vault',
        servers: [
          { id: 's1', name: 'Home server', place: 'Home · France', role: 'home', status: 'offline', offlineSince: new Date(Date.now() - 3_600_000).toISOString(), inUse: false },
          { id: 's2', name: 'VPS', place: 'Germany', role: 'replica', status: 'online', inUse: true },
        ],
        pending: { id: 'c1', summary: 'Adding jordan@example.org to Family', askedAt: new Date(Date.now() - 1_800_000).toISOString() },
      },
    ],
    apps: [
      { name: 'This browser', server: 'VPS' },
      { name: 'Bitwarden extension', server: 'Home server', localCopy: true, address: 'nas.example.org' },
    ],
  };
  let cancelled = false;
  // STUB: the server has no placement route yet.
  await page.route('**/kem/v1/placement**', async (route) => {
    if (route.request().method() === 'DELETE') {
      cancelled = true;
      const [vault] = placement.vaults;
      if (vault) vault.pending = null;
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(placement) });
  });
  await signInAsAdmin(page);

  const banner = page.getByRole('status').filter({ hasText: 'Your home server' });
  await expect(banner).toContainText('Your home server, Home server, is offline. Syncing through VPS.');
  await expectAccessible(page);

  await banner.getByRole('link', { name: 'Where your vault is stored' }).click();
  await expect(page.getByRole('heading', { name: 'Where your vault is stored', level: 1 })).toBeVisible();
  const servers = page.getByRole('list', { name: 'Servers of Your vault' });
  await expect(servers.getByRole('listitem')).toHaveCount(2);
  await expect(servers.getByRole('listitem').nth(1)).toContainText('In use');
  await expect(page.getByText('nas.example.org, local copy')).toBeVisible();
  await expectAccessible(page);

  await page.getByRole('button', { name: 'Do not send these changes' }).click();
  await expect.poll(() => cancelled).toBe(true);
  await expect(page.getByRole('button', { name: 'Do not send these changes' })).toHaveCount(0);
});

test('Import & export: the page loads, and the installed importer refuses an empty export', async ({ page }) => {
  test.setTimeout(180_000);
  await page.route('**/kem/v1/placement', (route) => route.fulfill({ status: 404, contentType: 'application/problem+json', body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }) }));
  await signInAsAdmin(page);

  await page.getByRole('link', { name: 'Import & export' }).click();
  await expect(page.getByRole('heading', { name: 'Import & export', level: 1 })).toBeVisible();
  await expectAccessible(page);

  // The worker the page talks to is kemlock-import as WebAssembly, and the image builds it in. A file
  // with no items reaches it and comes back as the importer's own refusal, not as "can't start".
  await page.getByLabel(/Drop a file here/).setInputFiles({
    name: 'export.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ items: [] })),
  });
  await page.getByRole('button', { name: 'Read the file' }).click();
  await expect(page.getByRole('alert')).toContainText(/The export has no entries/);
  await expect(page.getByText(/importer can't start/)).toHaveCount(0);

  // Export works without the worker for CSV.
  await page.getByRole('radio', { name: /CSV, not encrypted/ }).check();
  await expect(page.getByText(/A CSV file isn't encrypted/)).toBeVisible();
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export', exact: true }).click()]);
  expect(download.suggestedFilename()).toMatch(/^kemlock-export-\d{4}-\d{2}-\d{2}\.csv$/);
});

test('Import & export: a Bitwarden JSON file is read, previewed and imported', async ({ page }) => {
  test.setTimeout(180_000);
  await page.route('**/kem/v1/placement', (route) => route.fulfill({ status: 404, contentType: 'application/problem+json', body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }) }));
  await signInAsAdmin(page);

  await page.getByRole('link', { name: 'Import & export' }).click();
  await expect(page.getByRole('heading', { name: 'Import & export', level: 1 })).toBeVisible();

  // A synthetic export (2 logins, 1 secure note, 1 folder) goes through the real import worker.
  await page.getByLabel(/Drop a file here/).setInputFiles(fileURLToPath(new URL('./fixtures/bitwarden-export.json', import.meta.url)));
  await expect(page.getByText(/bitwarden-export\.json · read as Bitwarden or Vaultwarden/)).toBeVisible();
  await page.getByRole('button', { name: 'Read the file' }).click();
  await expect(page.getByRole('status').filter({ hasText: '3 items are ready to import.' })).toBeVisible();

  await page.getByRole('button', { name: 'Import 3 items', exact: true }).click();
  await expect(page.getByText('Imported 3 items.')).toBeVisible();

  // The items are in the vault list by name.
  await page.getByRole('link', { name: 'All items' }).first().click();
  await expect(page.getByRole('heading', { name: 'All items', level: 1 })).toBeVisible();
  for (const name of ['Journey Mail', 'Journey Bank', 'Journey Note']) {
    await expect(page.getByRole('row', { name: new RegExp(name) })).toHaveCount(1);
  }
});
