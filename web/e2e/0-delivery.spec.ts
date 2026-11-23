import { createHash } from 'node:crypto';
import { expect, test } from '@playwright/test';

// What the server sends with the web vault (design: Security, "Web vault hardening"; Performance
// targets, "Precompressed web vault, immutable cache").
test.describe('delivery', () => {
  test('every page carries the strict CSP and the isolation headers', async ({ request }) => {
    const res = await request.get('/');
    expect(res.status()).toBe(200);
    const csp = res.headers()['content-security-policy'] ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).toContain("require-trusted-types-for 'script'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain("'unsafe-eval'");
    expect(res.headers()['cross-origin-opener-policy']).toBe('same-origin');
    expect(res.headers()['cross-origin-embedder-policy']).toBe('require-corp');
    expect(res.headers()['cross-origin-resource-policy']).toBe('same-origin');
  });

  test('index.html is revalidated; hashed assets are immutable and carry SRI', async ({ request }) => {
    const index = await request.get('/');
    expect(index.headers()['cache-control']).toMatch(/no-cache|max-age=0/);
    const html = await index.text();
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/); // no inline script
    const script = /<script[^>]*src="(\/assets\/[^"]+)"[^>]*integrity="sha384-[^"]+"/.exec(html);
    expect(script, 'the entry script has an integrity attribute').not.toBeNull();
    const asset = await request.get(script?.[1] ?? '/');
    expect(asset.headers()['cache-control']).toContain('immutable');
    expect(asset.headers()['cache-control']).toContain('max-age=31536000');

    // A hash that does not match the served bytes makes the browser block the script.
    for (const tag of html.match(/<(?:script|link)[^>]*integrity="[^>]*>/g) ?? []) {
      const path = /(?:src|href)="([^"]+)"/.exec(tag)?.[1] ?? '';
      const claimed = /integrity="([^"]+)"/.exec(tag)?.[1];
      const body = await (await request.get(path)).body();
      expect(claimed, `${path} integrity`).toBe(`sha384-${createHash('sha384').update(body).digest('base64')}`);
    }
  });

  test('a route that is not a file falls back to the app', async ({ request }) => {
    const res = await request.get('/vault/abc');
    expect(res.status()).toBe(200);
    expect(await res.text()).toContain('<div id="root">');
  });

  test('the API is untouched by the web handler', async ({ request }) => {
    const res = await request.get('/kem/v1/config');
    expect(res.status()).toBe(200);
    expect((await res.json()).server).toBe('kemlock-server');
  });
});
