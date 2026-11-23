import { defineConfig, devices } from '@playwright/test';

// The journeys run against a real kemlock-server that embeds the built web vault
// (`cargo build -p kemlock-server --features web` after `npm run build`), so the CSP, the
// isolation headers and the real crypto worker are all in play. e2e/global-setup.ts starts it on
// a free port with a fresh data folder; see the README for the environment variables.
// Set BASE_URL (or E2E_BASE_URL) to run against a server that is already running; otherwise
// global setup starts one on E2E_PORT.
export const baseURL =
  process.env['BASE_URL'] ??
  process.env['E2E_BASE_URL'] ??
  `http://localhost:${process.env['E2E_PORT'] ?? '18080'}`;

export default defineConfig({
  testDir: 'e2e',
  // The setup journey makes the admin account the vault journey signs in as: run in order.
  fullyParallel: false,
  workers: 1,
  retries: process.env['CI'] ? 1 : 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: process.env['CI'] ? [['github'], ['html', { open: 'never' }]] : 'list',
  globalSetup: './e2e/global-setup.ts',
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
