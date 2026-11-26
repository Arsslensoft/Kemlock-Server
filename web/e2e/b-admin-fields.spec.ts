import { type Page, type Route, expect, test } from '@playwright/test';
import { ADMIN_OVERVIEW, SETTINGS } from '../src/features/admin/fixtures';
import { expectAccessible, watchForCspProblems } from './helpers';
import { chooseFromAccountMenu, signInAsAdmin } from './signin';

// The admin console's Overview, the hints under the Server settings switches and the Custom fields
// page, after a real sign-in. The console's calls are answered here in the shapes of
// crates/kemlock-api-admin (src/api/admin.ts): a real write needs a step-up token made from a
// current authenticator code, which a test can't produce. The fields are kept by this file, so the
// page is seen to add, change and delete them and to turn the switch.
//
// The file is named so that it runs after the numbered journeys, which make the admin it uses.

interface Field {
  id: string;
  name: string;
  type: 'text' | 'hidden' | 'checkbox';
  kinds: 'all' | string[];
}

interface FieldsApi {
  fields: Field[];
  allowOwn: boolean;
  /** `METHOD /path` of every call, in order. */
  seen: string[];
  /** The bodies of the writes, by `METHOD /path`. */
  bodies: Map<string, unknown>;
}

const PROBLEM = (slug: string, status: number, extra: object = {}) => ({
  type: `urn:kemlock:problem:${slug}`,
  title: slug,
  status,
  ...extra,
});

async function mockAdminApi(page: Page): Promise<FieldsApi> {
  const api: FieldsApi = { fields: [], allowOwn: true, seen: [], bodies: new Map() };
  let made = 0;
  await page.route('**/admin/v1/**', async (route: Route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace('/admin/v1', '');
    const key = `${request.method()} ${path}`;
    api.seen.push(key);
    const now = Math.floor(Date.now() / 1000);
    const reply = (status: number, body?: unknown) =>
      route.fulfill({
        status,
        contentType: status >= 400 ? 'application/problem+json' : 'application/json',
        body: body === undefined ? undefined : JSON.stringify(body),
      });

    // Every write but the step-up itself asks for a token, as the server does.
    const isWrite = request.method() !== 'GET' && !path.startsWith('/step-up');
    if (isWrite && !request.headers()['step-up-token']) {
      return reply(403, PROBLEM('step-up-required', 403, { stepUp: true }));
    }
    if (isWrite) api.bodies.set(key.replace(/\/f\d+$/, '/{id}'), request.postDataJSON());

    const one = /^\/custom-fields\/(f\d+)$/.exec(path);
    switch (true) {
      case key === 'GET /me':
        return reply(200, { userId: 'u0', deviceId: 'd1', stepUpTtlSeconds: 300 });
      case key === 'POST /step-up/totp':
        return reply(200, { token: 'T', expiresAt: now + 300 });
      case key === 'GET /overview':
        return reply(200, ADMIN_OVERVIEW);
      case key === 'GET /push-relay':
        return reply(200, {
          enabled: false,
          installationId: null,
          relayUrl: 'https://push.kemlock.example',
          apnsConfigured: false,
          apnsSandbox: false,
          unifiedPush: true,
        });
      case key === 'GET /settings':
        return reply(200, { settings: SETTINGS });
      case key === 'GET /server-address':
        return reply(404, PROBLEM('not-found', 404));
      case key === 'GET /custom-fields':
        return reply(200, { fields: api.fields, allowOwn: api.allowOwn });
      case key === 'POST /custom-fields': {
        made += 1;
        const body = request.postDataJSON() as Omit<Field, 'id'>;
        const field: Field = { id: `f${made}`, ...body };
        api.fields.push(field);
        return reply(201, field);
      }
      case key === 'PUT /custom-fields/allow-own': {
        api.allowOwn = (request.postDataJSON() as { allow: boolean }).allow;
        return reply(200, { allowOwn: api.allowOwn });
      }
      case request.method() === 'PUT' && one !== null: {
        const index = api.fields.findIndex((field) => field.id === one?.[1]);
        if (index < 0) return reply(404, PROBLEM('not-found', 404));
        const field: Field = { id: one?.[1] ?? '', ...(request.postDataJSON() as Omit<Field, 'id'>) };
        api.fields[index] = field;
        return reply(200, field);
      }
      case request.method() === 'DELETE' && one !== null: {
        api.fields = api.fields.filter((field) => field.id !== one?.[1]);
        return reply(204);
      }
      default:
        return reply(404, PROBLEM('not-found', 404, { title: `No mock for ${key}` }));
    }
  });
  return api;
}

/** The step-up check a write asks for the first time: a code from the authenticator app. */
async function confirmItsYou(page: Page): Promise<void> {
  const check = page
    .getByRole('dialog')
    .filter({ has: page.getByRole('heading', { name: "Confirm it's you" }) });
  await expect(check).toBeVisible();
  await check.getByLabel('Code from your authenticator app').fill('123456');
  await check.getByRole('button', { name: 'Confirm' }).click();
  await expect(check).toBeHidden();
}

test('the admin console: the Overview, the switch hints and the custom fields', async ({ page }) => {
  test.setTimeout(300_000);
  const problems = watchForCspProblems(page);
  const api = await mockAdminApi(page);
  await signInAsAdmin(page);
  await chooseFromAccountMenu(page, 'Admin console');
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();

  // Overview: one row of five numbers, each with an icon; no Version and no Setup card.
  const stats = page.locator('.adm-stats .stat');
  await expect(stats).toHaveCount(5);
  await expect(stats.locator('.si svg')).toHaveCount(5);
  await expect(stats.nth(0)).toContainText('Users');
  await expect(stats.nth(4)).toContainText('Features');
  await expect(page.locator('.adm-stats')).not.toContainText('Version');
  await expect(page.locator('.adm-stats')).not.toContainText('Setup');
  // Checks and Users to look at share the left column, with the push relay beside them.
  const split = page.locator('.adm-split');
  await expect(split.locator('.adm-col').getByRole('heading', { name: 'Checks' })).toBeVisible();
  await expect(split.locator('.adm-col').getByRole('heading', { name: 'Users to look at' })).toBeVisible();
  await expect(split.locator(':scope > .card').getByRole('heading', { name: 'Push', exact: true })).toBeVisible();
  await expectAccessible(page);

  // Server settings: each switch has its gray hint under the label.
  await page.getByRole('link', { name: 'Server settings' }).click();
  await expect(page.getByRole('heading', { name: 'Server settings', level: 1 })).toBeVisible();
  const signups = page.getByRole('switch', { name: 'Anyone may make an account' });
  await expect(page.getByText('Anyone may make an account', { exact: true })).toBeVisible();
  await expect(page.getByText('When off, people join only by an invitation or through SSO.')).toBeVisible();
  await expect(signups).toHaveAccessibleDescription(/When off, people join only by an invitation/);
  await expectAccessible(page);

  // Custom fields: under Settings in the sidebar, empty at first.
  await page.getByRole('link', { name: 'Custom fields' }).click();
  await expect(page.getByRole('heading', { name: 'Custom fields', level: 1 })).toBeVisible();
  await expect(page.getByText(/No fields yet/)).toBeVisible();
  await expect(page.getByRole('switch', { name: 'People may add their own fields' })).toBeChecked();
  await expect(page.getByText(/Every field is optional/)).toBeVisible();
  await expectAccessible(page);

  // Add a field on all types. The write asks for the step-up check once.
  await page.getByRole('button', { name: 'Add a field' }).click();
  const form = page.getByRole('dialog', { name: 'Add a field' });
  await form.getByLabel('Name', { exact: true }).fill('Employee ID');
  await expect(form.getByText(/required/i)).toHaveCount(0);
  await form.getByRole('button', { name: 'Save' }).click();
  await confirmItsYou(page);
  await expect(form).toBeHidden();
  const table = page.getByRole('table');
  await expect(table.getByRole('row', { name: /Employee ID/ })).toContainText('Text');
  await expect(table.getByRole('row', { name: /Employee ID/ })).toContainText('All types');
  expect(api.bodies.get('POST /custom-fields')).toEqual({ name: 'Employee ID', type: 'text', kinds: 'all' });

  // A second one: hidden, on cards only. The step-up token is still good.
  await page.getByRole('button', { name: 'Add a field' }).click();
  await form.getByLabel('Name', { exact: true }).fill('Cost center');
  await form.getByLabel('Type', { exact: true }).selectOption('hidden');
  // The choices are React Aria's: the label is what a person clicks.
  await form.getByText('Only these types', { exact: true }).click();
  await expect(form.getByRole('checkbox')).toHaveCount(10);
  await expect(form.getByRole('checkbox', { name: 'Passkeys' })).toHaveCount(0);
  await expect(form.getByRole('checkbox', { name: 'Files' })).toHaveCount(0);
  await form.getByRole('button', { name: 'Save' }).click();
  // No type picked: refused here, nothing sent.
  await expect(form.getByText('Pick at least one type.')).toBeVisible();
  await form.getByText('Cards', { exact: true }).click();
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(form).toBeHidden();
  await expect(table.getByRole('row', { name: /Cost center/ })).toContainText('Hidden');
  await expect(table.getByRole('row', { name: /Cost center/ })).toContainText('Cards');
  expect(api.bodies.get('POST /custom-fields')).toEqual({ name: 'Cost center', type: 'hidden', kinds: ['card'] });

  // Change it from its row menu.
  await page.getByRole('button', { name: 'Actions for Cost center' }).click();
  await page.getByRole('menuitem', { name: 'Edit' }).click();
  const change = page.getByRole('dialog', { name: 'Change Cost center' });
  await expect(change.getByLabel('Name', { exact: true })).toHaveValue('Cost center');
  await change.getByLabel('Name', { exact: true }).fill('Cost centre');
  await change.getByText('Logins', { exact: true }).click();
  await change.getByRole('button', { name: 'Save' }).click();
  await expect(change).toBeHidden();
  await expect(table.getByRole('row', { name: /Cost centre/ })).toContainText('Logins, Cards');
  expect(api.bodies.get('PUT /custom-fields/{id}')).toEqual({
    name: 'Cost centre',
    type: 'hidden',
    kinds: ['login', 'card'],
  });

  // People may add their own fields: turn it off, and back on.
  const own = page.getByRole('switch', { name: 'People may add their own fields' });
  await page.getByText('People may add their own fields', { exact: true }).click();
  await expect(own).not.toBeChecked();
  expect(api.allowOwn).toBe(false);
  await page.getByText('People may add their own fields', { exact: true }).click();
  await expect(own).toBeChecked();
  expect(api.allowOwn).toBe(true);

  // Delete one: it asks first, and says what happens to the values already on items.
  await page.getByRole('button', { name: 'Actions for Employee ID' }).click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  const ask = page.getByRole('dialog', { name: 'Delete Employee ID?' });
  await expect(ask).toContainText('Items that already have a value for it keep that value');
  await expectAccessible(page);
  await ask.getByRole('button', { name: 'Delete' }).click();
  await expect(ask).toBeHidden();
  await expect(table.getByRole('row', { name: /Employee ID/ })).toHaveCount(0);
  await expect(table.getByRole('row', { name: /Cost centre/ })).toBeVisible();
  expect(api.fields.map((field) => field.name)).toEqual(['Cost centre']);

  expect(problems).toEqual([]);
});
