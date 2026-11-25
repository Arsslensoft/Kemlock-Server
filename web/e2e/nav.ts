// Getting to a page from the shell, whichever way the shell offers it: a link in the sidebar, or an
// item of the account menu at the top right. A journey never reloads the page (that signs it out),
// so it moves by clicking.
import { type Locator, type Page, expect } from '@playwright/test';

/** The link or menu item with this name, wherever the shell keeps it right now. */
function target(page: Page, name: string | RegExp): Locator {
  return page.getByRole('link', { name }).or(page.getByRole('menuitem', { name })).first();
}

/** Opens the account menu (the initials at the top right) when the shell has one. */
async function openAccountMenu(page: Page): Promise<void> {
  const menu = page.getByLabel(/^Account menu/).first();
  await expect(menu).toBeVisible();
  await menu.click();
}

/** Clicks `name` where it is: in view already, or in the account menu. */
export async function openFromShell(page: Page, name: string | RegExp): Promise<void> {
  const item = target(page, name);
  if (await item.isVisible()) {
    await item.click();
    return;
  }
  await openAccountMenu(page);
  await item.click();
}

/** From the open vault to the admin console's Overview. */
export async function openAdminConsole(page: Page): Promise<void> {
  await openFromShell(page, /Admin console/);
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
}
