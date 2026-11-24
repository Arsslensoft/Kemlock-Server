import { describe, expect, it, vi } from 'vitest';
import { jsonResponse, problem } from '@/test/render';
import { type Tokens, createApi } from './client';
import { ApiError, NetworkError } from './errors';
import type { ItemDto, TokenResponse } from './types';

const ORIGIN = 'https://vault.example.org';

function setup(responses: Response[], tokens?: Tokens) {
  let stored = tokens;
  const queue = [...responses];
  const fetch = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => {
    const next = queue.shift();
    if (!next) throw new Error('no response queued');
    return next;
  });
  const dpop = vi.fn(
    async (htm: string, htu: string, nonce?: string, access?: string) =>
      `proof|${htm}|${htu}|${nonce ?? ''}|${access ?? ''}`,
  );
  const onSessionEnded = vi.fn();
  const api = createApi({
    origin: ORIGIN,
    fetch: fetch as unknown as typeof globalThis.fetch,
    dpop,
    onSessionEnded,
    now: () => 1_000_000,
    tokens: {
      get: () => stored,
      set: (next) => {
        stored = next;
      },
      clear: () => {
        stored = undefined;
      },
    },
  });
  const headersOf = (call: number) =>
    (fetch.mock.calls[call]?.[1]?.headers ?? {}) as Record<string, string>;
  return { api, fetch, dpop, headersOf, onSessionEnded, tokens: () => stored };
}

const fresh: Tokens = {
  access: 'access-1',
  refresh: 'refresh-1',
  accessExpiresAt: 1_000_000 + 600_000,
  refreshExpiresAt: 1_000_000 + 86_400_000,
};

const tokenBody: TokenResponse = {
  tokenType: 'DPoP',
  accessToken: 'access-2',
  expiresIn: 600,
  refreshToken: 'refresh-2',
  refreshExpiresIn: 86_400,
  userId: 'u1',
  deviceId: 'd1',
  admin: false,
};

const item: ItemDto = {
  id: '00000000-0000-4000-8000-000000000001',
  owner: 'user:00000000-0000-4000-8000-000000000002',
  kind: 'login',
  format: 'kem1',
  revision: 1,
  keyVersion: 1,
  ciphertext: 'AAAA',
  itemKey: 'BBBB',
};

describe('the public routes', () => {
  it('reads the config without a proof or a token', async () => {
    const t = setup([jsonResponse({ server: 'kemlock-server', setup: 'needs-admin' })]);
    const config = await t.api.config();
    expect(config.setup).toBe('needs-admin');
    expect(t.fetch.mock.calls[0]?.[0]).toBe('/kem/v1/config');
    expect(t.headersOf(0)['DPoP']).toBeUndefined();
    expect(t.headersOf(0)['Authorization']).toBeUndefined();
  });

  it('posts JSON bodies as written', async () => {
    const t = setup([jsonResponse({ grant: 'g', expiresIn: 600 })]);
    await t.api.setupVerify('ABCD-EFGH-JKMN');
    const init = t.fetch.mock.calls[0]?.[1];
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(JSON.stringify({ code: 'ABCD-EFGH-JKMN' }));
    expect(t.headersOf(0)['Content-Type']).toBe('application/json');

  it('sends the server basics with setup finish, and nothing without them', async () => {
    const t = setup([new Response(null, { status: 204 }), new Response(null, { status: 204 })], fresh);
    const basics = {
      join: 'domains',
      joinDomains: 'example.org',
      mailHost: 'smtp.example.org',
      mailPort: '465',
      mailSecurity: 'tls',
      mailFrom: 'ops@example.org',
      mailUser: 'ops',
    } as const;
    await t.api.setupFinish(basics);
    await t.api.setupFinish();
    expect(t.fetch.mock.calls[0]?.[0]).toBe('/kem/v1/setup/finish');
    expect(t.fetch.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ basics }));
    expect(t.fetch.mock.calls[1]?.[1]?.body).toBeUndefined();
  });
  });

  it('unwraps prelogin and methods', async () => {
    const kdf = { memoryKib: 65536, iterations: 3, parallelism: 4, salt: 'c2FsdA' };
    const t = setup([jsonResponse({ kdf }), jsonResponse({ methods: ['password'] })]);
    expect(await t.api.prelogin('a@b.co')).toEqual(kdf);
    expect(await t.api.methods('a@b.co')).toEqual(['password']);
  });
});

describe('DPoP', () => {
  it('sends a proof with no token on the sign-in routes', async () => {
    const t = setup([jsonResponse({ status: 'two_factor_required', challenge: 'c', methods: ['totp'] })]);
    await t.api.opaqueFinish({
      email: 'a@b.co',
      loginState: 's',
      finalization: 'f',
      device: { name: 'Web', kind: 'kemlock-web' },
    });
    expect(t.dpop).toHaveBeenCalledWith('POST', `${ORIGIN}/kem/v1/auth/opaque/finish`, undefined);
    expect(t.headersOf(0)['DPoP']).toContain('proof|POST');
    expect(t.headersOf(0)['Authorization']).toBeUndefined();
  });

  it('binds an authenticated call to its access token', async () => {
    const t = setup([jsonResponse({ secret: 'S', uri: 'otpauth://x' })], fresh);
    await t.api.totpEnrol();
    expect(t.dpop).toHaveBeenCalledWith(
      'POST',
      `${ORIGIN}/kem/v1/account/two-factor/totp`,
      undefined,
      'access-1',
    );
    expect(t.headersOf(0)['Authorization']).toBe('DPoP access-1');
  });

  it('names the URL without the query in the proof', async () => {
    const t = setup([jsonResponse({ items: [], cursor: 'c', more: false })], fresh);
    await t.api.sync('abc', 500);
    expect(t.fetch.mock.calls[0]?.[0]).toBe('/kem/v1/sync?since=abc&limit=500');
    expect(t.dpop.mock.calls[0]?.[1]).toBe(`${ORIGIN}/kem/v1/sync`);
  });

  it('retries once with the nonce the server asked for', async () => {
    const t = setup(
      [
        problem(401, 'use-dpop-nonce', {}, { 'DPoP-Nonce': 'nonce-1' }),
        jsonResponse({ secret: 'S', uri: 'u' }),
      ],
      fresh,
    );
    await t.api.totpEnrol();
    expect(t.fetch).toHaveBeenCalledTimes(2);
    expect(t.dpop.mock.calls[1]?.[2]).toBe('nonce-1');
  });

  it('remembers the nonce from any response', async () => {
    const t = setup(
      [
        jsonResponse({ server: 'kemlock-server' }, { headers: { 'DPoP-Nonce': 'n-2' } }),
        jsonResponse({ secret: 'S', uri: 'u' }),
      ],
      fresh,
    );
    await t.api.config();
    await t.api.totpEnrol();
    expect(t.dpop.mock.calls[0]?.[2]).toBe('n-2');
  });

  it('gives up after one nonce retry', async () => {
    const t = setup(
      [
        problem(401, 'use-dpop-nonce', {}, { 'DPoP-Nonce': 'a' }),
        problem(401, 'use-dpop-nonce', {}, { 'DPoP-Nonce': 'b' }),
      ],
      fresh,
    );
    await expect(t.api.totpEnrol()).rejects.toMatchObject({ slug: 'use-dpop-nonce' });
    expect(t.fetch).toHaveBeenCalledTimes(2);
  });
});

describe('tokens', () => {
  it('refreshes once on a 401 and repeats the call with the new token', async () => {
    const t = setup(
      [
        problem(401, 'unauthorized'),
        jsonResponse(tokenBody),
        jsonResponse({ items: [], cursor: 'c', more: false }),
      ],
      fresh,
    );
    const result = await t.api.sync();
    expect(result.notModified).toBe(false);
    expect(t.fetch.mock.calls[1]?.[0]).toBe('/kem/v1/auth/token');
    expect(t.fetch.mock.calls[1]?.[1]?.body).toBe(
      JSON.stringify({ grantType: 'refresh_token', refreshToken: 'refresh-1' }),
    );
    expect(t.headersOf(2)['Authorization']).toBe('DPoP access-2');
    expect(t.tokens()?.refresh).toBe('refresh-2');
  });

  it('refreshes before sending when the access token is about to expire', async () => {
    const expiring: Tokens = { ...fresh, accessExpiresAt: 1_000_000 + 5_000 };
    const t = setup([jsonResponse(tokenBody), jsonResponse({ items: [], cursor: 'c', more: false })], expiring);
    await t.api.sync();
    expect(t.fetch.mock.calls[0]?.[0]).toBe('/kem/v1/auth/token');
  });

  it('ends the session when the refresh token is refused', async () => {
    const t = setup([problem(401, 'unauthorized'), problem(401, 'unauthorized')], fresh);
    await expect(t.api.sync()).rejects.toBeInstanceOf(ApiError);
    expect(t.onSessionEnded).toHaveBeenCalledOnce();
    expect(t.tokens()).toBeUndefined();
  });

  it('refuses an authenticated call with no tokens', async () => {
    const t = setup([]);
    await expect(t.api.sync()).rejects.toMatchObject({ status: 401 });
    expect(t.fetch).not.toHaveBeenCalled();
  });
});

describe('items', () => {
  it('creates with If-None-Match and replaces with If-Match', async () => {
    const t = setup(
      [
        jsonResponse(item, { status: 201, headers: { ETag: '"1"' } }),
        jsonResponse({ ...item, revision: 2 }, { headers: { ETag: '"2"' } }),
      ],
      fresh,
    );
    const created = await t.api.putItem(item, { ifNoneMatch: true });
    expect(created.etag).toBe('"1"');
    expect(t.headersOf(0)['If-None-Match']).toBe('*');
    expect(t.headersOf(0)['If-Match']).toBeUndefined();
    expect(t.fetch.mock.calls[0]?.[0]).toBe(`/kem/v1/items/${item.id}`);
    expect(t.fetch.mock.calls[0]?.[1]?.method).toBe('PUT');

    await t.api.putItem({ ...item, revision: 2 }, { ifMatch: 1 });
    expect(t.headersOf(1)['If-Match']).toBe('1');
  });

  it('surfaces a stale write with the server revision', async () => {
    const t = setup([problem(409, 'stale-revision', { currentRevision: 7 })], fresh);
    const error = await t.api.putItem(item, { ifMatch: 1 }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).currentRevision).toBe(7);
  });

  it('batches writes to items:batch', async () => {
    const t = setup([jsonResponse({ items: [item] })], fresh);
    const items = await t.api.putBatch({ writes: [{ expectedRevision: null, item }] });
    expect(items).toEqual([item]);
    expect(t.fetch.mock.calls[0]?.[0]).toBe('/kem/v1/items:batch');
  });
});

describe('sync', () => {
  it('treats a 304 as "nothing changed"', async () => {
    const t = setup([jsonResponse(null, { status: 304 })], fresh);
    expect(await t.api.sync('cursor-1')).toEqual({ notModified: true, cursor: 'cursor-1' });
  });

  it('reads a page', async () => {
    const t = setup([jsonResponse({ items: [item], cursor: 'c2', more: true })], fresh);
    const result = await t.api.sync();
    expect(result).toEqual({ notModified: false, page: { items: [item], cursor: 'c2', more: true } });
  });

  it('never lets the browser cache a sync', async () => {
    const t = setup([jsonResponse({ items: [], cursor: 'c', more: false })], fresh);
    await t.api.sync();
    expect(t.fetch.mock.calls[0]?.[1]?.cache).toBe('no-store');
  });
});

describe('errors', () => {
  it('reads an RFC 9457 problem', async () => {
    const t = setup([problem(403, 'setup-code-wrong')]);
    const error = await t.api.setupVerify('x').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 403, slug: 'setup-code-wrong' });
  });

  it('reads Retry-After from a rate limit', async () => {
    const t = setup([problem(429, 'rate-limited', { retryAfter: 12 })]);
    const error = (await t.api.setupVerify('x').catch((e: unknown) => e)) as ApiError;
    expect(error.retryAfter).toBe(12);
  });

  it('survives a non-JSON error page from a proxy', async () => {
    const t = setup([new Response('<html>bad gateway</html>', { status: 502 })]);
    await expect(t.api.config()).rejects.toMatchObject({ status: 502, slug: 'unknown' });
  });

  it('wraps a failed fetch', async () => {
    const api = createApi({
      origin: ORIGIN,
      fetch: (async () => {
        throw new TypeError('Failed to fetch');
      }) as unknown as typeof fetch,
      dpop: async () => 'p',
      tokens: { get: () => undefined, set: () => undefined, clear: () => undefined },
    });
    await expect(api.config()).rejects.toBeInstanceOf(NetworkError);
  });
});
