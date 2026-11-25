import { type Page, expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { signInAsAdmin } from './signin';

// The recipient's side of a Send: a link `/#/send/<accessId>/<key>` opened by someone with no
// account. The key is in the fragment, so it must never appear in anything the page sends.

const NOT_FOUND = {
  status: 404,
  contentType: 'application/problem+json',
  body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }),
};

async function makeLink(page: Page, fill: () => Promise<void>): Promise<string> {
  await page.route('**/kem/v1/placement', (route) => route.fulfill(NOT_FOUND));
  await signInAsAdmin(page);
  await page.getByRole('link', { name: 'Send', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Send', level: 1 })).toBeVisible();
  await fill();
  await page.getByRole('button', { name: 'Create link' }).click();
  const link = page.locator('.link-box');
  await expect(link).toContainText(/\/#\/send\/[A-Za-z0-9_-]{22}\/[A-Za-z0-9_-]{43}$/);
  return ((await link.textContent()) ?? '').trim();
}

/** What the page sends must never hold the key: not the URL, the body or the Referer. */
function watchForTheKey(page: Page, key: string): string[] {
  const leaks: string[] = [];
  page.on('request', (request) => {
    const seen = [request.url(), request.postData() ?? '', request.headers()['referer'] ?? ''];
    if (seen.some((part) => part.includes(key))) leaks.push(`${request.method()} ${request.url()}`);
  });
  return leaks;
}

test('a note with a password opens for someone with the link, and the key never leaves the browser', async ({
  page,
  browser,
}) => {
  test.setTimeout(240_000);
  const link = await makeLink(page, async () => {
    await page.getByLabel('Name', { exact: true }).fill('Door code');
    await page.getByLabel('Text', { exact: true }).fill('4 7 1 9, then the green button');
    await page.getByLabel('Password, optional').fill('swordfish');
  });
  const key = link.split('/').pop() ?? '';
  expect(key).toHaveLength(43);

  // Someone else: a new browser context holds no session and no storage.
  const context = await browser.newContext();
  const recipient = await context.newPage();
  const problems = watchForCspProblems(recipient);
  const leaks = watchForTheKey(recipient, key);
  await recipient.goto(link);

  await expect(recipient.getByRole('heading', { name: 'This Send has a password' })).toBeVisible({
    timeout: 60_000,
  });
  await expectAccessible(recipient);
  await recipient.getByLabel('Password', { exact: true }).fill('not the password');
  await recipient.getByRole('button', { name: 'Open the Send' }).click();
  await expect(recipient.getByText('That password is wrong.')).toBeVisible({ timeout: 60_000 });
  await recipient.getByLabel('Password', { exact: true }).fill('swordfish');
  await recipient.getByRole('button', { name: 'Open the Send' }).click();
  await expect(recipient.getByRole('heading', { name: 'Door code', level: 1 })).toBeVisible({
    timeout: 60_000,
  });
  await expect(recipient.getByText('4 7 1 9, then the green button')).toBeVisible();
  await expectAccessible(recipient);

  expect(leaks, 'the key appeared in a request').toEqual([]);
  expect(problems).toEqual([]);
  await context.close();
});

test('a file Send downloads as the bytes that went in', async ({ page, browser }) => {
  test.setTimeout(240_000);
  const link = await makeLink(page, async () => {
    await page.getByRole('button', { name: 'File', exact: true }).click();
    await page.getByLabel('Name', { exact: true }).fill('Notes file');
    await page.getByLabel('File', { exact: true }).setInputFiles({
      name: 'notes.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from('a file that only the link opens'),
    });
  });
  const key = link.split('/').pop() ?? '';

  const context = await browser.newContext({ acceptDownloads: true });
  const recipient = await context.newPage();
  const leaks = watchForTheKey(recipient, key);
  await recipient.goto(link);
  await expect(recipient.getByRole('heading', { name: 'notes.txt', level: 1 })).toBeVisible({
    timeout: 60_000,
  });
  const download = recipient.waitForEvent('download');
  await recipient.getByRole('button', { name: 'Download notes.txt' }).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toBe('notes.txt');
  const path = await saved.path();
  const { readFileSync } = await import('node:fs');
  expect(readFileSync(path, 'utf8')).toBe('a file that only the link opens');
  expect(leaks, 'the key appeared in a request').toEqual([]);
  await context.close();
});

test('a link with a wrong key says the Send is not available, not what is in it', async ({ page, browser }) => {
  test.setTimeout(240_000);
  const link = await makeLink(page, async () => {
    await page.getByLabel('Name', { exact: true }).fill('Wrong key');
    await page.getByLabel('Text', { exact: true }).fill('secret words');
  });
  const wrong = `${link.slice(0, -43)}${'A'.repeat(43)}`;
  const context = await browser.newContext();
  const recipient = await context.newPage();
  await recipient.goto(wrong);
  await expect(recipient.getByRole('heading', { name: 'This Send is not available' })).toBeVisible({
    timeout: 60_000,
  });
  await expect(recipient.getByText('secret words')).toHaveCount(0);
  await context.close();
});
