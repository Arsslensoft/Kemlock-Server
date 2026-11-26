// Signing in as the admin that the setup journey made: the master password, then the code from
// its authenticator. Journeys that need a signed-in session share this, so none of them repeats
// the dance. A page reload signs you out (tokens live in memory only), so after this a journey
// moves only by clicking links.
import { type Locator, type Page, expect } from '@playwright/test';
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

/**
 * A fresh code of the admin's authenticator, for a proof a page asks beside the password (changing
 * the master password or the address). It waits for a step the server has not used yet.
 */
export async function nextCode(): Promise<string> {
  const { totpSecret, totpStep } = readState();
  if (!totpSecret) throw new Error('the setup journey has not run');
  const { code, step } = await freshCode(totpSecret, totpStep);
  saveState({ totpStep: step });
  return code;
}

/** Opens the avatar menu at the top right of a shell, and returns the menu. */
export async function openAccountMenu(page: Page): Promise<Locator> {
  const avatar = page.getByRole('button', { name: /^Account menu for / });
  if ((await avatar.getAttribute('aria-expanded')) !== 'true') await avatar.click();
  return page.getByRole('navigation', { name: 'Account' });
}

/** Picks one entry of the avatar menu: Profile, Security, Devices & apps, Admin console, About,
 * Lock the vault or Sign out. The last two are buttons, the rest links. */
export async function chooseFromAccountMenu(page: Page, entry: string | RegExp): Promise<void> {
  const menu = await openAccountMenu(page);
  await menu.getByRole(/^(Lock the vault|Sign out)$/.test(String(entry)) ? 'button' : 'link', { name: entry }).click();
}

/** Opens the + menu and picks a type: lands on that type's creation form. */
export async function newItem(page: Page, type = 'Login'): Promise<void> {
  await page.getByRole('button', { name: 'New item' }).click();
  await page.getByRole('navigation', { name: 'New item' }).getByRole('link', { name: type, exact: true }).click();
}

/** Signs in as the setup admin and waits for the open vault. */
export async function signInAsAdmin(page: Page): Promise<void> {
  await signInWithPassword(page, ADMIN.email, ADMIN.password);
  await enterCode(page);
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });
}
