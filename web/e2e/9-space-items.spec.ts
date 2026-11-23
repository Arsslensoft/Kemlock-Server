import { expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { signInAsAdmin } from './signin';

// Items for a space owner: New item offers the collections the account may write to, and the item
// is sealed in the worker under that collection's key and written with its `collectionId`.

test('a login saved to a space collection is sealed there and can be edited', async ({ page }) => {
  test.setTimeout(300_000);
  const problems = watchForCspProblems(page);
  await page.route('**/kem/v1/placement', (route) =>
    route.fulfill({
      status: 404,
      contentType: 'application/problem+json',
      body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }),
    }),
  );
  await signInAsAdmin(page);

  // A space of my own, with one collection: the worker makes both keys and seals them to me.
  await page.getByRole('link', { name: 'Spaces' }).first().click();
  await expect(page.getByRole('heading', { name: 'Spaces', level: 1 })).toBeVisible();
  await page.getByLabel('Space name').fill('Item space');
  await page.getByLabel('First collection').fill('Shared logins');
  await page.getByRole('button', { name: 'Make the space' }).click();
  await expect(page.getByText('Item space').first()).toBeVisible({ timeout: 60_000 });

  // New item: pick the collection, and watch what the server is sent.
  await page.getByRole('link', { name: 'New item' }).first().click();
  await expect(page.getByRole('heading', { name: 'New login' })).toBeVisible();
  const where = page.getByLabel('Save to');
  await expect(where).toBeVisible({ timeout: 60_000 });
  await where.selectOption({ label: 'Item space: Shared logins' });
  await expectAccessible(page);
  await page.getByLabel('Name', { exact: true }).fill('Team VPN');
  await page.getByLabel('Username').fill('ops@example.org');
  await page.getByLabel('Password', { exact: true }).fill('Space-journey-pass-1!');
  await page.getByLabel('Website').fill('https://vpn.example.org');
  const put = page.waitForRequest(
    (request) => request.method() === 'PUT' && new URL(request.url()).pathname.startsWith('/kem/v1/items/'),
  );
  await page.getByRole('button', { name: 'Save' }).click();
  const body = JSON.parse((await put).postData() ?? '{}') as Record<string, unknown>;
  expect(body['owner']).toMatch(/^space:[0-9a-f-]{36}$/);
  expect(body['collectionId']).toMatch(/^[0-9a-f-]{36}$/);
  expect(body['revision']).toBe(1);
  expect(JSON.stringify(body)).not.toContain('Space-journey-pass-1!');
  expect(JSON.stringify(body)).not.toContain('Team VPN');
  await expect(page.getByRole('heading', { name: 'Team VPN', level: 1 })).toBeVisible();

  // Edit: the item stays in its collection, one revision on, and the page says where it lives.
  await page.getByRole('link', { name: 'Edit' }).first().click();
  await expect(page.getByText(/In the space collection Item space: Shared logins/)).toBeVisible();
  await expect(page.getByLabel('Save to')).toHaveCount(0);
  const edit = page.waitForRequest(
    (request) => request.method() === 'PUT' && new URL(request.url()).pathname.startsWith('/kem/v1/items/'),
  );
  await page.getByLabel('Name', { exact: true }).fill('Team VPN (new)');
  await page.getByRole('button', { name: 'Save' }).click();
  const second = JSON.parse((await edit).postData() ?? '{}') as Record<string, unknown>;
  expect(second['revision']).toBe(2);
  expect(second['collectionId']).toBe(body['collectionId']);
  expect(second['owner']).toBe(body['owner']);
  await expect(page.getByRole('heading', { name: 'Team VPN (new)', level: 1 })).toBeVisible();

  expect(problems).toEqual([]);
});
