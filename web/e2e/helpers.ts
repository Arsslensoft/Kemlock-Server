import { createHmac } from 'node:crypto';
import AxeBuilder from '@axe-core/playwright';
import { type Page, expect } from '@playwright/test';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(text: string): Buffer {
  const bits = text
    .replace(/[\s=]/g, '')
    .toUpperCase()
    .split('')
    .map((c) => BASE32.indexOf(c).toString(2).padStart(5, '0'))
    .join('');
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** RFC 6238: HMAC-SHA1, 30-second steps, 6 digits, as an authenticator app computes it. */
export function totp(secret: string, at: number = Date.now()): { code: string; step: number } {
  const step = Math.floor(at / 1000 / 30);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hmac = createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = (hmac[hmac.length - 1] as number) & 0x0f;
  const value = hmac.readUInt32BE(offset) & 0x7fffffff;
  return { code: String(value % 1_000_000).padStart(6, '0'), step };
}

/** A code for a later 30-second step than `after`, waiting for it if need be. */
export async function freshCode(secret: string, after?: number): Promise<{ code: string; step: number }> {
  for (;;) {
    const candidate = totp(secret);
    if (after === undefined || candidate.step > after) return candidate;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

/** Fails the test on any WCAG 2.x A or AA violation, listing each with its selector. */
export async function expectAccessible(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  const summary = results.violations.map(
    (v) => `${v.id}: ${v.help}\n  ${v.nodes.map((n) => n.target.join(' ')).join('\n  ')}`,
  );
  // Soft: the journey goes on, so one run lists every page's violations, and still fails.
  expect.soft(summary, 'accessibility violations').toEqual([]);
}

/** Collects what the page logs that would mean a broken CSP or a crash. */
export function watchForCspProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (message) => {
    const text = message.text();
    if (/content security policy|trusted type/i.test(text)) problems.push(text);
  });
  page.on('pageerror', (error) => problems.push(error.message));
  return problems;
}
