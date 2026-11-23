import { expect, test } from '@playwright/test';
import { watchForCspProblems } from './helpers';
import { ADMIN } from './state';
import { signInWithPassword } from './signin';

// The server's CSP has `require-trusted-types-for 'script'; trusted-types kemlock` (design: Security,
// "Trusted Types"). A Worker made from a plain URL is a violation, so the crypto worker's URL has to
// come out of the `kemlock` policy. This journey runs under the real headers and checks it starts.
test.describe('trusted types', () => {
  test('the page cannot make a worker from a plain URL: the policy is enforced', async ({ page }) => {
    const response = await page.goto('/sign-in');
    expect(response?.headers()['content-security-policy']).toContain("require-trusted-types-for 'script'");
    const outcome = await page.evaluate(() => {
      try {
        new Worker('/assets/does-not-matter.js');
        return 'started';
      } catch (error) {
        return (error as Error).name;
      }
    });
    expect(outcome).toBe('TypeError');
  });

  test('the crypto worker starts from a script URL the kemlock policy made', async ({ page }) => {
    const problems = watchForCspProblems(page);
    const workers: string[] = [];
    page.on('worker', (worker) => workers.push(worker.url()));

    // The master password is the first thing that needs the worker (Argon2id runs in it). A wrong
    // password is enough: the sign-in fails in the client, after the worker has answered.
    await signInWithPassword(page, ADMIN.email, 'not the admin password at all');
    await expect(page.getByRole('alert').first()).toBeVisible({ timeout: 60_000 });

    expect(workers.length, 'a worker started').toBeGreaterThan(0);
    for (const url of workers) {
      expect(new URL(url).origin).toBe(new URL(page.url()).origin);
      expect(new URL(url).pathname).toMatch(/^\/assets\/.+\.js$/);
    }
    // No violation was reported and the page did not crash on the way.
    expect(problems).toEqual([]);
  });
});
