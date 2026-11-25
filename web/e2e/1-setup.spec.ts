import { expect, test } from '@playwright/test';
import { expectAccessible, freshCode, watchForCspProblems } from './helpers';
import { ADMIN, readState, saveState } from './state';

// The canvas's first-run journey: SetupCode, SetupAdmin, SetupTwoStep, SetupServer, SetupDone.
test('first-run setup, from the setup code to a ready server', async ({ page }) => {
  test.setTimeout(180_000);
  const problems = watchForCspProblems(page);
  const { setupCode } = readState();

  // A new server sends everyone to setup, whatever they asked for.
  await page.goto('/vault');
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole('heading', { name: 'Welcome to Kemlock Server' })).toBeVisible();
  // localhost is a secure context: the not-HTTPS warning stays hidden.
  await expect(page.getByText(/This address isn't HTTPS or localhost/)).toHaveCount(0);
  await expectAccessible(page);

  // A wrong code is refused with a reason; the right one moves on.
  await page.getByLabel('Setup code').fill('0000-0000-0000');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('alert')).toContainText('setup code is wrong');
  await page.getByLabel('Setup code').fill(setupCode);
  await page.getByRole('button', { name: 'Continue' }).click();

  // The first admin: keys are made in this browser (Argon2id, then OPAQUE).
  await expect(page).toHaveURL(/\/setup\/admin$/);
  await expect(page.getByRole('heading', { name: 'Make the first admin' })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel('Name', { exact: true }).fill(ADMIN.name);
  await page.getByLabel('Email').fill(ADMIN.email);
  await page.getByLabel('Master password', { exact: true }).fill(ADMIN.password);
  await page.getByLabel('Type it again').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Make my account' }).click();

  // Two-step login: scan, or type the key; the test types it and computes the code.
  await expect(page).toHaveURL(/\/setup\/two-step$/, { timeout: 90_000 });
  await expect(page.getByRole('heading', { name: 'Turn on two-step login' })).toBeVisible();
  const typedKey = await page.locator('.scan .cmd code').innerText();
  const secret = typedKey.replace(/\s+/g, '');
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await expect(page.getByRole('img', { name: /QR code that adds/ })).toBeVisible();
  await expectAccessible(page);
  const { code, step } = await freshCode(secret);
  await page.getByLabel('Code from the app').fill(code);
  await page.getByRole('button', { name: 'Turn on and continue' }).click();
  saveState({ totpSecret: secret, totpStep: step });

  // Server basics: the defaults are fine.
  await expect(page).toHaveURL(/\/setup\/server$/);
  await expect(page.getByRole('heading', { name: 'Server basics' })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole('button', { name: 'Save and finish' }).click();

  await expect(page).toHaveURL(/\/setup\/done$/);
  await expect(page.getByRole('heading', { name: 'Your server is ready' })).toBeVisible();
  await expectAccessible(page);

  // Setup is closed for good: its screens now lead to sign-in.
  await page.goto('/setup');
  await expect(page).toHaveURL(/\/sign-in$/);

  expect(problems).toEqual([]);
});

test('the setup screens are closed once setup is done', async ({ page }) => {
  // The setup code stops working with the first admin, and its screens stop opening.
  await page.goto('/setup/admin');
  await expect(page).toHaveURL(/\/sign-in$/);
});
