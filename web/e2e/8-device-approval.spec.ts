import { expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { chooseFromAccountMenu, choosePassword, signInAsAdmin } from './signin';
import { ADMIN } from './state';

// Signing in on a new device with another device (docs/crypto.md, "Device-approval phrase"). Two
// browser contexts play the two devices against the real server: the admin's open vault approves,
// and a fresh browser with no session asks. The phrase on each screen is worked out client-side
// from the request's one-time key, so the two must show the same five words.

test('a new browser signs in through an open device, with the phrase matching on both', async ({
  page,
  browser,
}) => {
  test.setTimeout(300_000);
  await page.route('**/kem/v1/placement', (route) =>
    route.fulfill({
      status: 404,
      contentType: 'application/problem+json',
      body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }),
    }),
  );
  await signInAsAdmin(page);

  // The new device: no session, no storage.
  const context = await browser.newContext();
  const fresh = await context.newPage();
  const problems = watchForCspProblems(fresh);
  await fresh.goto('/sign-in');
  await fresh.getByLabel('Email').fill(ADMIN.email);
  await fresh.getByRole('button', { name: 'Continue' }).click();
  await choosePassword(fresh);
  await fresh.getByRole('link', { name: 'Sign in with another device' }).click();
  await expect(fresh).toHaveURL(/\/sign-in\/device/);

  const phrase = fresh.getByLabel('The words on this screen');
  await expect(phrase).toHaveText(/^[a-z-]+( [a-z-]+){4}$/, { timeout: 60_000 });
  const words = ((await phrase.textContent()) ?? '').trim();
  await expectAccessible(fresh);

  // The open device lists the request, shows the phrase it worked out itself, and approves.
  await chooseFromAccountMenu(page, 'Devices & apps');
  await expect(page.getByRole('heading', { name: 'Devices & apps', level: 1 })).toBeVisible();
  const approver = page.getByLabel("The phrase worked out from the request's key");
  await expect(approver.first()).toHaveText(words, { timeout: 60_000 });
  await page.getByRole('button', { name: /^Approve / }).first().click();

  // The new device signs in with the key it was sent, without the master password.
  await expect(fresh).toHaveURL(/\/vault$/, { timeout: 90_000 });
  await expect(fresh.getByRole('button', { name: 'New item' })).toBeVisible();
  expect(problems).toEqual([]);
  await context.close();
});
