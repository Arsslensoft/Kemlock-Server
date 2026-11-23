import { defineConfig, devices } from '@playwright/test';

// The single sign-on journeys (e2e-sso/) against Keycloak (deploy/e2e/compose.yml). It needs a server
// of its own, because with a provider on, the sign-in screen offers SSO for every email and the
// other journeys would take a different path. Global setup starts one on E2E_PORT (default 18081,
// one of the realm's redirect URIs) and passes it the SSO_* variables of deploy/e2e/server.env that
// are in the environment. BASE_URL (or E2E_BASE_URL) uses a server that is already running, which
// must be fresh (the setup journey runs first: SSO signs in as the admin it makes, by email).
const baseURL =
  process.env['BASE_URL'] ??
  process.env['E2E_BASE_URL'] ??
  `http://localhost:${process.env['E2E_PORT'] ?? '18081'}`;
process.env['E2E_PORT'] ??= '18081';

export default defineConfig({
  fullyParallel: false,
  workers: 1,
  retries: process.env['CI'] ? 1 : 0,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  reporter: process.env['CI'] ? [['github'], ['html', { open: 'never' }]] : 'list',
  globalSetup: './e2e/global-setup.ts',
  use: { baseURL, trace: 'retain-on-failure' },
  projects: [
    // The admin the SSO user is linked to by email (sam@example.co, in Keycloak's realm too).
    { name: 'setup', testDir: 'e2e', testMatch: '1-setup.spec.ts', use: { ...devices['Desktop Chrome'] } },
    {
      name: 'sso',
      testDir: 'e2e-sso',
      dependencies: ['setup'],
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
