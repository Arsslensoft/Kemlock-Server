import { type Page, expect, test } from '@playwright/test';
import { DpopClient, pkce } from '../e2e/dpop';
import { freshCode } from '../e2e/helpers';
import { chooseFromAccountMenu, enterCode } from '../e2e/signin';
import { ADMIN, readState, saveState } from '../e2e/state';

// Single sign-on against Keycloak (deploy/e2e/compose.yml; its realm has the two users below). The
// server was started with the SSO_* variables of deploy/e2e/server.env, and the setup journey has
// made the admin sam@example.co, who is also a user in the realm: the SSO sign-in finds the account
// by its verified email.
//
// SSO says who is signing in and holds no vault key. A new account makes its keys in the browser,
// which keeps its own copy of the root key and opens the vault with it at the next sign-in; a new
// browser of an existing account opens the vault the way it does after any sign-in without a
// password: another device approves it.

const KEYCLOAK = 'http://localhost:8180';
const SAM = { username: 'sam.rivera', password: 'sso-user-password' };
const NEW_USER = { username: 'new.user', password: 'sso-user-password', email: 'new.user@example.co' };
const PROTO_USER = { username: 'proto.user', password: 'sso-user-password' };

interface FinishBody {
  status: string;
  tokens: { tokenType: string; accessToken: string; userId: string; deviceId: string; admin: boolean };
  newAccount: boolean;
  mfaViaSso: boolean;
}

test.beforeAll(async () => {
  // Keycloak takes a while to import the realm.
  await expect
    .poll(
      async () => {
        try {
          return (await fetch(`${KEYCLOAK}/realms/kemlock/.well-known/openid-configuration`)).status;
        } catch {
          return 0;
        }
      },
      { timeout: 120_000, intervals: [2_000] },
    )
    .toBe(200);
});

/** The vault's calls to a server that has no placement are answered with a 404, as in the other journeys. */
async function withoutPlacement(page: Page): Promise<void> {
  await page.route('**/kem/v1/placement', (route) =>
    route.fulfill({
      status: 404,
      contentType: 'application/problem+json',
      body: JSON.stringify({ type: 'urn:kemlock:problem:not-found', title: 'Not found', status: 404 }),
    }),
  );
}

async function chooseEmail(page: Page, email: string): Promise<void> {
  await page.goto('/sign-in');
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
}

async function keycloakLogin(page: Page, user: { username: string; password: string }): Promise<void> {
  await page.locator('#username').fill(user.username);
  await page.locator('#password').fill(user.password);
  await page.locator('#kc-login').click();
}

test('the sign-in screen offers SSO, named for the provider', async ({ page }) => {
  await withoutPlacement(page);
  await chooseEmail(page, ADMIN.email);
  await expect(page.getByRole('button', { name: 'Sign in with Keycloak' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Use my master password' })).toBeVisible();
});

test('an SSO user is made and signed in with no master password, and the server accepts the session', async ({
  page,
}) => {
  const origin = readState().baseURL;
  const device = new DpopClient(origin);
  const { verifier, challenge, state } = pkce();
  // A path on the server ends the browser's trip: the page below is served by the test, so the
  // web vault's router never sees the code.
  const redirect = `${origin}/sso-done`;

  const start = await device.call<{ authorizationUrl: string; providerName: string }>(
    'POST',
    '/kem/v1/auth/sso/start',
    { body: { challenge, state, redirect } },
  );
  expect(start.status, JSON.stringify(start.body)).toBe(200);
  expect(start.body.providerName).toBe('Keycloak');
  expect(start.body.authorizationUrl).toContain(`${KEYCLOAK}/realms/kemlock/`);

  await page.route(`${origin}/sso-done*`, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>done</title>' }),
  );
  await page.goto(start.body.authorizationUrl);
  await keycloakLogin(page, PROTO_USER);
  await page.waitForURL(/\/sso-done\?/, { timeout: 60_000 });
  const returned = new URL(page.url());
  expect(returned.searchParams.get('state')).toBe(state);
  const code = returned.searchParams.get('code');
  expect(code, 'the one-time code').toBeTruthy();

  const finish = await device.call<FinishBody>('POST', '/kem/v1/auth/sso/finish', {
    body: { code, verifier, device: { name: 'Playwright', kind: 'other' } },
  });
  expect(finish.status, JSON.stringify(finish.body)).toBe(200);
  expect(finish.body.status).toBe('signed_in');
  expect(finish.body.newAccount).toBe(true);
  expect(finish.body.tokens.tokenType).toBe('DPoP');
  expect(finish.body.tokens.admin).toBe(false);

  // The tokens work, bound to the key that asked for them: an authenticated read answers, and
  // another key's proof for the same token is refused.
  const { accessToken } = finish.body.tokens;
  const mine = await device.call('GET', '/kem/v1/account/passkeys', { accessToken });
  expect(mine.status, JSON.stringify(mine.body)).toBe(200);
  const other = await new DpopClient(origin).call('GET', '/kem/v1/account/passkeys', { accessToken });
  expect([401, 403]).toContain(other.status);
});

test('a new SSO user gets keys, opens the vault with no password, and opens it again with the browser copy', async ({
  page,
}) => {
  test.setTimeout(300_000);
  await withoutPlacement(page);

  // The first sign-in makes the account; this browser makes its keys and keeps its copy of the
  // root key, and the vault opens with no master password and no other device.
  await chooseEmail(page, NEW_USER.email);
  await page.getByRole('button', { name: 'Sign in with Keycloak' }).click();
  await page.waitForURL(`${KEYCLOAK}/**`, { timeout: 60_000 });
  await keycloakLogin(page, NEW_USER);
  await expect(page).toHaveURL(/\/vault$/, { timeout: 90_000 });
  await expect(page.getByRole('button', { name: 'New item' })).toBeVisible();
  // Profile: the identity provider owns the name and the address, which show locked; this account
  // has no master password, and says so.
  await chooseFromAccountMenu(page, 'Profile');
  await expect(page.getByRole('heading', { name: 'Profile', level: 1 })).toBeVisible();
  await expect(page.getByLabel('Name', { exact: true })).toHaveAttribute('readonly', '');
  await expect(page.getByLabel('Email', { exact: true })).toHaveAttribute('readonly', '');
  await expect(page.getByLabel('Email', { exact: true })).toHaveValue(NEW_USER.email);
  await expect(page.getByText('Comes from your identity provider. Change it there.').first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Master password' }).getByText(/no master password/)).toBeVisible();
  await chooseFromAccountMenu(page, 'Devices & apps');
  await expect(page.getByText('Trusted', { exact: true }).first()).toBeVisible();

  // A new page load has no session and no keys in memory. Signing in with SSO again in this
  // browser opens the vault from the copy the server returns, which only this browser can open:
  // no approval is asked for.
  await chooseEmail(page, NEW_USER.email);
  await page.getByRole('button', { name: 'Sign in with Keycloak' }).click();
  // Keycloak remembers the person, so its login page may not show at all.
  try {
    await page.locator('#username').waitFor({ state: 'visible', timeout: 10_000 });
    await keycloakLogin(page, NEW_USER);
  } catch {
    // Already signed in at Keycloak.
  }
  await expect(page).toHaveURL(/\/vault$/, { timeout: 90_000 });
  await expect(page.getByRole('button', { name: 'New item' })).toBeVisible();
});

test('an SSO user signs in from the web vault and another device opens the vault', async ({
  page,
  browser,
}) => {
  test.setTimeout(300_000);
  await withoutPlacement(page);

  // The open device: the admin, signed in with the master password and the authenticator code.
  await chooseEmail(page, ADMIN.email);
  await page.getByRole('button', { name: 'Use my master password' }).click();
  await expect(page).toHaveURL(/\/sign-in\/password/);
  await page.getByLabel('Master password').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Open the vault' }).click();
  await enterCode(page);
  await expect(page).toHaveURL(/\/vault$/, { timeout: 60_000 });

  // The new browser: "Sign in with Keycloak", Keycloak's page, then Kemlock's own second step,
  // because the provider did not do multi-factor authentication.
  const context = await browser.newContext();
  const fresh = await context.newPage();
  await withoutPlacement(fresh);
  await chooseEmail(fresh, ADMIN.email);
  await fresh.getByRole('button', { name: 'Sign in with Keycloak' }).click();
  await fresh.waitForURL(`${KEYCLOAK}/**`, { timeout: 60_000 });
  await keycloakLogin(fresh, SAM);
  await expect(fresh).toHaveURL(/\/sign-in\/sso/, { timeout: 60_000 });
  const field = fresh.getByLabel('Code from your authenticator app');
  await expect(field).toBeVisible({ timeout: 60_000 });
  const { totpSecret, totpStep } = readState();
  if (!totpSecret) throw new Error('the setup journey has not run');
  const { code, step } = await freshCode(totpSecret, totpStep);
  await field.fill(code);
  await fresh.getByRole('button', { name: 'Open the vault' }).click();
  saveState({ totpStep: step });

  // No master password: the vault key comes from the open device, which the phrase proves is ours.
  await expect(fresh).toHaveURL(/\/sign-in\/device/, { timeout: 60_000 });
  const phrase = fresh.getByLabel('The words on this screen');
  await expect(phrase).toHaveText(/^[a-z-]+( [a-z-]+){4}$/, { timeout: 60_000 });
  const words = ((await phrase.textContent()) ?? '').trim();

  await chooseFromAccountMenu(page, 'Devices & apps');
  const approver = page.getByLabel("The phrase worked out from the request's key");
  await expect(approver.first()).toHaveText(words, { timeout: 60_000 });
  await page.getByRole('button', { name: /^Approve / }).first().click();

  await expect(fresh).toHaveURL(/\/vault$/, { timeout: 90_000 });
  await expect(fresh.getByRole('button', { name: 'New item' })).toBeVisible();
  await context.close();
});
