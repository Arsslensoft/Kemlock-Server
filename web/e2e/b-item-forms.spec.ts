import { type Page, expect, test } from '@playwright/test';
import { watchForCspProblems } from './helpers';
import { newItem, signInAsAdmin } from './signin';

// One form for each kind of item: make one of each from its own form, with the pieces the forms
// share (websites, the generator, custom fields, linked items, files) and the password eye inside
// its box. A page reload signs the journey out, so it only clicks: the New menu of the shell opens
// each kind's form.

/** Opens the form of a kind from the shell's New menu. */
async function openNew(page: Page, kind: string): Promise<void> {
  await newItem(page, kind);
  const chips = page.getByRole('group', { name: 'Kind of item' });
  await expect(chips.getByRole('button', { name: kind, exact: true })).toHaveAttribute('aria-pressed', 'true');
}

async function save(page: Page, heading: string): Promise<void> {
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible({ timeout: 60_000 });
}

test('every kind of item has its own form', async ({ page }) => {
  test.setTimeout(900_000);
  const problems = watchForCspProblems(page);
  await signInAsAdmin(page);

  // Login: the eye inside the password box, the generator under it, two websites with rules, and a
  // field of the person's own.
  await openNew(page, 'Login');
  await expect(page.getByRole('heading', { name: 'New login' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms GitHub');
  await page.getByLabel('Username', { exact: true }).fill('sam@example.org');
  await page.getByRole('button', { name: 'Generate' }).click();
  const password = page.getByLabel('Password', { exact: true });
  await expect(password).toHaveValue(/^.{20}$/);
  await expect(password).toHaveAttribute('type', 'password');
  await page.getByRole('button', { name: 'Show the password' }).click();
  await expect(password).toHaveAttribute('type', 'text');
  await expect(page.getByText('Strength', { exact: true })).toBeVisible();
  await page.getByLabel('Website 1', { exact: true }).fill('https://github.com');
  await page.getByRole('button', { name: 'Add a website' }).click();
  await page.getByLabel('Website 2', { exact: true }).fill('https://gist.github.com');
  await page.getByLabel('Match rule for website 2', { exact: true }).selectOption({ label: 'Host' });
  await page.getByRole('button', { name: 'Add a field' }).click();
  await page.getByRole('button', { name: /Your own field/ }).click();
  await page.getByLabel('Field 1 name', { exact: true }).fill('Recovery email');
  await page.getByLabel('Field 1 value', { exact: true }).fill('sam.backup@example.org');
  await save(page, 'Forms GitHub');
  await expect(page.getByText('sam@example.org')).toBeVisible();

  // MFA code, linked to the login: its Website is the login's, read-only.
  await openNew(page, 'MFA code');
  await expect(page.getByRole('heading', { name: 'New MFA code' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms GitHub code');
  await page.getByLabel('Issuer', { exact: true }).fill('GitHub');
  await page.getByLabel('Secret key', { exact: true }).fill('JBSWY3DPEHPK3PXP');
  await expect(page.getByLabel('Website', { exact: true })).not.toHaveAttribute('readonly', '');
  await page.getByRole('button', { name: 'Link an item' }).click();
  await page.getByRole('button', { name: /Forms GitHub\s*Login/ }).click();
  await expect(page.getByLabel('Website', { exact: true })).toHaveAttribute('readonly', '');
  await expect(page.getByLabel('Website', { exact: true })).toHaveValue('github.com, gist.github.com');
  await expect(page.getByText(/From the linked login/)).toBeVisible();
  await save(page, 'Forms GitHub code');

  // Backup codes.
  await openNew(page, 'Backup codes');
  await expect(page.getByRole('heading', { name: 'New backup codes' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms GitHub recovery codes');
  await page.getByLabel('Website', { exact: true }).fill('github.com');
  await page.getByLabel('Service', { exact: true }).fill('GitHub');
  await page.getByLabel('Codes', { exact: true }).fill('4f2a-91c0\n7b3e-0d58');
  await save(page, 'Forms GitHub recovery codes');

  // Note, with a file attached: encrypted in the browser, then sent to the item's files route.
  await openNew(page, 'Note');
  await expect(page.getByRole('heading', { name: 'New note' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms recovery plan');
  await page.getByLabel('Note', { exact: true }).fill('If I am unreachable for two weeks.');
  await page.getByLabel('Add a file').setInputFiles({
    name: 'recovery-codes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('4f2a-91c0\n7b3e-0d58\n'),
  });
  await expect(page.getByText(/Text · 20 B · ready to encrypt and upload/)).toBeVisible();
  const sent = page.waitForResponse(
    (response) => response.request().method() === 'PUT' && /\/kem\/v1\/items\/[^/]+\/files\//.test(response.url()),
  );
  await save(page, 'Forms recovery plan');
  const upload = await sent;
  expect(upload.ok()).toBe(true);
  // What went up is the KMA1 file of the bytes, not the bytes.
  expect((await upload.request().postDataBuffer())?.subarray(0, 4).toString('latin1')).toBe('KMA1');

  // File.
  await openNew(page, 'File');
  await expect(page.getByRole('heading', { name: 'New file' })).toBeVisible();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Choose a file.')).toBeVisible();
  await page.getByLabel('Choose a file').setInputFiles({
    name: 'Lease agreement.pdf',
    mimeType: 'application/pdf',
    buffer: Buffer.from('%PDF-1.4 a lease'),
  });
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('Lease agreement.pdf');
  await expect(page.getByText('Custom fields')).toHaveCount(0);
  await save(page, 'Lease agreement.pdf');

  // Passkey: nothing to type, and Done goes back.
  await openNew(page, 'Passkey');
  await expect(page.getByRole('heading', { name: 'Passkeys come from websites' })).toBeVisible();
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByRole('heading', { name: 'Passkeys come from websites' })).toHaveCount(0);

  // Card: the brand from the number, grouped, checked, and a security code that fits the brand.
  await openNew(page, 'Card');
  await expect(page.getByRole('heading', { name: 'New card' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms travel card');
  await page.getByLabel('Card number').fill('4111111111111111');
  await expect(page.getByLabel('Card number')).toHaveValue('4111 1111 1111 1111');
  await expect(page.getByText('Visa', { exact: true })).toBeVisible();
  await page.getByLabel('Expires').fill('11/27');
  await page.getByLabel('Security code').fill('1234');
  await expect(page.getByText('Visa uses 3 digits.')).toBeVisible();
  await page.getByLabel('Security code').fill('381');
  await page.getByLabel('PIN').fill('4821');
  await save(page, 'Forms travel card');

  // Identity.
  await openNew(page, 'Identity');
  await expect(page.getByRole('heading', { name: 'New identity' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms passport');
  await page.getByLabel('First name').fill('Sam');
  await page.getByLabel('Last name').fill('Rivera');
  await save(page, 'Forms passport');

  // Contact: a person, with no PGP key.
  await openNew(page, 'Contact');
  await expect(page.getByRole('heading', { name: 'New contact' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms Alex Chen');
  await page.getByLabel('Company').fill('Example Co');
  await page.getByLabel('Email').fill('alex@example.org');
  await page.getByLabel('Phone').fill('+1 555 0142');
  await page.getByLabel('Address').fill('48 Pine Street\nPortland, OR 97205');
  await expect(page.getByRole('heading', { name: /PGP public key/ })).toBeVisible();
  await save(page, 'Forms Alex Chen');

  // SSH key: made in the browser.
  await openNew(page, 'SSH key');
  await expect(page.getByRole('heading', { name: 'New SSH key' })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('Forms deploy key');
  await page.getByRole('button', { name: 'Generate an Ed25519 key' }).click();
  await expect(page.getByText(/A new Ed25519 key was made in this browser/)).toBeVisible();
  await save(page, 'Forms deploy key');

  expect(problems).toEqual([]);
});

test('a link is written on both items, and removed from both', async ({ page }) => {
  test.setTimeout(600_000);
  const problems = watchForCspProblems(page);
  await signInAsAdmin(page);

  await openNew(page, 'Login');
  await page.getByLabel('Name', { exact: true }).fill('Linked login');
  await save(page, 'Linked login');

  await openNew(page, 'Note');
  await page.getByLabel('Name', { exact: true }).fill('Linked note');
  await page.getByRole('button', { name: 'Link an item' }).click();
  await page.getByRole('button', { name: /Linked login\s*Login/ }).click();
  await save(page, 'Linked note');

  // The login now names the note: edit it and the chip is there.
  await page.getByRole('link', { name: 'All items' }).first().click();
  await page.getByRole('link', { name: /Linked login/ }).first().click();
  await expect(page.getByRole('heading', { name: 'Linked login', level: 1 })).toBeVisible();
  await page.getByRole('link', { name: 'Edit' }).first().click();
  await expect(page.getByRole('button', { name: 'Unlink Linked note (Note)' })).toBeVisible();

  // Unlink it from this side, and the note loses it too.
  await page.getByRole('button', { name: 'Unlink Linked note (Note)' }).click();
  await save(page, 'Linked login');
  await page.getByRole('link', { name: 'All items' }).first().click();
  await page.getByRole('link', { name: /Linked note/ }).first().click();
  await page.getByRole('link', { name: 'Edit' }).first().click();
  await expect(page.getByText('Nothing linked yet.')).toBeVisible();

  expect(problems).toEqual([]);
});
