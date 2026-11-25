import { type CDPSession, type Page, expect, test } from '@playwright/test';
import { expectAccessible, watchForCspProblems } from './helpers';
import { chooseFromAccountMenu, signInAsAdmin } from './signin';
import { ADMIN } from './state';

// A passkey with a virtual authenticator (the DevTools protocol's WebAuthn domain), so no key or
// prompt is needed. The authenticator has the PRF extension (`hasPrf`), so the passkey the admin
// makes in Account security also keeps a wrap of the root key. An admin write then asks for a fresh
// check and is answered with that passkey instead of a code, and a new sign-in with the passkey
// opens the vault with no master password and no code.
//
// A security key as the second step is not here: the web vault has no screen for it yet.
//
// The file is named so that it runs after the numbered journeys, which make the admin it uses.

interface Credential {
  credentialId: string;
  rpId: string;
  isResidentCredential: boolean;
  signCount: number;
}

async function addAuthenticator(page: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      // The PRF extension (hmac-secret), which the passkey's wrap of the root key is made from.
      hasPrf: true,
      // Answers the "touch it" step by itself.
      automaticPresenceSimulation: true,
    } as never,
  });
  return { cdp, authenticatorId };
}

async function credentials(cdp: CDPSession, authenticatorId: string): Promise<Credential[]> {
  const result = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  return result.credentials as Credential[];
}

test('a passkey is made, confirms an admin change and signs in with no master password', async ({ page }) => {
  test.setTimeout(300_000);
  const problems = watchForCspProblems(page);
  const { cdp, authenticatorId } = await addAuthenticator(page);
  await signInAsAdmin(page);

  // Make one. A reload would sign the page out, so the journey moves by links.
  await chooseFromAccountMenu(page, 'Security');
  await expect(page.getByRole('heading', { name: 'Account security', level: 1 })).toBeVisible();
  await expectAccessible(page);
  await expect(page.getByRole('button', { name: 'Add a passkey' })).toBeEnabled();
  expect(await credentials(cdp, authenticatorId)).toHaveLength(0);
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await expect(page.getByTestId('passkey')).toHaveCount(1);
  const [made] = await credentials(cdp, authenticatorId);
  expect(made?.isResidentCredential).toBe(true);
  expect(made?.rpId).toBe(new URL(page.url()).hostname);
  // Making it counts for nothing, except that an authenticator which doesn't answer the PRF input at
  // creation is asked once more with an assertion to get its output: that is one signature.
  expect(made?.signCount).toBeLessThanOrEqual(1);
  // It made a wrap of the root key too, so this passkey opens the vault.
  await expect(page.getByTestId('passkey').getByText('Opens the vault')).toBeVisible();

  // An admin write asks again; the passkey answers.
  await chooseFromAccountMenu(page, 'Admin console');
  await page.getByRole('link', { name: 'Server settings' }).click();
  await expect(page.getByRole('heading', { name: 'Server settings', level: 1 })).toBeVisible();
  await page.getByLabel(/Who to tell about a problem with this server/).fill('security@example.co');
  await page.getByRole('button', { name: 'Save Security contact' }).click();
  const check = page.getByRole('dialog');
  await expect(check.getByRole('heading', { name: "Confirm it's you" })).toBeVisible();
  await check.getByRole('button', { name: 'Use a passkey' }).click();
  await expect(check).toBeHidden();
  await expect(page.getByText('Saved.')).toBeVisible();
  // The authenticator signed: its counter moved.
  const [used] = await credentials(cdp, authenticatorId);
  expect(used?.signCount ?? 0).toBeGreaterThan(made?.signCount ?? 0);

  // Sign in with it: a new page load has no session. The passkey alone opens the vault.
  await page.goto('/sign-in');
  await page.getByLabel('Email').fill(ADMIN.email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });
  await expect(page.getByRole('button', { name: 'New item' })).toBeVisible();

  // Remove it again.
  await chooseFromAccountMenu(page, 'Security');
  await expect(page.getByTestId('passkey')).toHaveCount(1);
  await page.getByRole('button', { name: /^Remove / }).click();
  await expect(page.getByTestId('passkey')).toHaveCount(0);
  expect(problems).toEqual([]);
});
