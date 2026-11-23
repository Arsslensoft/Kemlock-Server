// Signing in as the admin that the setup journey made: the master password, then the code from
// its authenticator. Journeys that need a signed-in session share this, so none of them repeats
// the dance. A page reload signs you out (tokens live in memory only), so after this a journey
// moves only by clicking links.
import { type Page, expect } from '@playwright/test';
import { freshCode } from './helpers';
import { ADMIN, readState, saveState } from './state';

/** After the email: the sign-in choices come first where the browser has passkeys; pick the
 * master password, so a journey lands on the password page either way. */
export async function choosePassword(page: Page): Promise<void> {
  const use = page.getByRole('button', { name: 'Use my master password' });
  await expect(use.or(page.getByLabel('Master password', { exact: true }))).toBeVisible();
  if (await use.isVisible()) await use.click();
  await expect(page).toHaveURL(/\/sign-in\/password/);
}

export async function signInWithPassword(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/sign-in');
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await choosePassword(page);
  await page.getByLabel('Master password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Open the vault' }).click();
}

/** Types a fresh code from the admin's authenticator secret and remembers which step it used. */
export async function enterCode(page: Page): Promise<void> {
  const { totpSecret, totpStep } = readState();
  if (!totpSecret) throw new Error('the setup journey has not run');
  await expect(page.getByLabel('Code from your authenticator app')).toBeVisible({ timeout: 90_000 });
  const { code, step } = await freshCode(totpSecret, totpStep);
  await page.getByLabel('Code from your authenticator app').fill(code);
  await page.getByRole('button', { name: 'Open the vault' }).click();
  saveState({ totpStep: step });
}

/** Signs in as the setup admin and waits for the open vault. */
export async function signInAsAdmin(page: Page): Promise<void> {
  await signInWithPassword(page, ADMIN.email, ADMIN.password);
  await enterCode(page);
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });
}
