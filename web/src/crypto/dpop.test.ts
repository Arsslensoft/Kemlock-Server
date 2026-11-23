// @vitest-environment node
// DPoP proofs, signed by real WebCrypto and checked the way crates/kemlock-api-kem/src/dpop.rs
// checks them: typ, alg, the jwk, htm, htu without a query, iat, jti, nonce, ath and the ES256
// signature itself.

import { describe, expect, it } from 'vitest';

import { b64urlEncode, utf8 } from './b64';
import { createDpop, normaliseHtu } from './dpop';
import type { KeyStore } from './keystore';

function memoryStore() {
  let pair: CryptoKeyPair | undefined;
  const calls = { load: 0, save: 0, clear: 0 };
  const store: KeyStore = {
    async load() {
      calls.load++;
      return pair;
    },
    async save(p) {
      calls.save++;
      pair = p;
    },
    async clear() {
      calls.clear++;
      pair = undefined;
    },
  };
  return { store, calls };
}

function decode(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
}

async function verify(proof: string): Promise<{ header: Record<string, unknown>; claims: Record<string, unknown>; ok: boolean }> {
  const [h, p, s] = proof.split('.') as [string, string, string];
  const header = decode(h);
  const claims = decode(p);
  const key = await crypto.subtle.importKey(
    'jwk',
    header.jwk as JsonWebKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  const signature = new Uint8Array(Buffer.from(s, 'base64url'));
  expect(signature.length).toBe(64);
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature,
    utf8(`${h}.${p}`),
  );
  return { header, claims, ok };
}

describe('DPoP proofs', () => {
  it('are ES256 JWSs with typ dpop+jwt and the public key as jwk', async () => {
    const { store } = memoryStore();
    const dpop = createDpop({ store, now: () => 1_800_000_000_500 });
    const proof = await dpop.proof('post', 'https://vault.example.org/kem/v1/auth/token');
    expect(proof.split('.')).toHaveLength(3);
    const { header, claims, ok } = await verify(proof);
    expect(ok).toBe(true);
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(Object.keys(header.jwk as object).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(header.jwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(claims.htm).toBe('POST');
    expect(claims.htu).toBe('https://vault.example.org/kem/v1/auth/token');
    expect(claims.iat).toBe(1_800_000_000);
    expect(typeof claims.jti).toBe('string');
    expect(claims).not.toHaveProperty('nonce');
    expect(claims).not.toHaveProperty('ath');
  });

  it('carry the nonce and the hash of the access token when given', async () => {
    const { store } = memoryStore();
    const dpop = createDpop({ store });
    const proof = await dpop.proof('GET', 'https://v.test/kem/v1/items', 'server-nonce', 'access.token');
    const { claims, ok } = await verify(proof);
    expect(ok).toBe(true);
    expect(claims.nonce).toBe('server-nonce');
    const hash = await crypto.subtle.digest('SHA-256', utf8('access.token'));
    expect(claims.ath).toBe(b64urlEncode(new Uint8Array(hash)));
  });

  it('drop the query and the fragment from htu', async () => {
    const { store } = memoryStore();
    const dpop = createDpop({ store });
    const proof = await dpop.proof('GET', 'https://V.test:443/kem/v1/items?cursor=1#top');
    expect((await verify(proof)).claims.htu).toBe('https://v.test/kem/v1/items');
    expect(normaliseHtu('http://localhost:8080/a/b?c')).toBe('http://localhost:8080/a/b');
  });

  it('refuse an htu that is not an http(s) URL', async () => {
    const { store } = memoryStore();
    const dpop = createDpop({ store });
    for (const bad of ['/kem/v1/items', 'ftp://x.test/a', 'not a url', '']) {
      await expect(dpop.proof('GET', bad)).rejects.toMatchObject({ code: 'invalid' });
    }
  });

  it('each have a fresh jti', async () => {
    const { store } = memoryStore();
    const dpop = createDpop({ store });
    const ids = new Set<unknown>();
    for (let i = 0; i < 20; i++) ids.add((await verify(await dpop.proof('GET', 'https://v.test/a'))).claims.jti);
    expect(ids.size).toBe(20);
  });

  it('use one key, made once, kept in the store and not extractable', async () => {
    const { store, calls } = memoryStore();
    const dpop = createDpop({ store });
    const first = await verify(await dpop.proof('GET', 'https://v.test/a'));
    const second = await verify(await dpop.proof('GET', 'https://v.test/b'));
    expect(second.header.jwk).toEqual(first.header.jwk);
    expect(calls.save).toBe(1);

    const stored = await store.load();
    expect(stored?.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', stored!.privateKey)).rejects.toThrow();
    expect(stored?.privateKey.usages).toEqual(['sign']);
  });

  it('make one key for concurrent first calls', async () => {
    const { store, calls } = memoryStore();
    const dpop = createDpop({ store });
    const proofs = await Promise.all([1, 2, 3, 4].map(() => dpop.proof('GET', 'https://v.test/a')));
    expect(calls.save).toBe(1);
    const jwks = await Promise.all(proofs.map(async (p) => (await verify(p)).header.jwk));
    expect(new Set(jwks.map((j) => JSON.stringify(j))).size).toBe(1);
  });

  it('are signed by the stored key after a restart', async () => {
    const { store, calls } = memoryStore();
    const before = await verify(await createDpop({ store }).proof('GET', 'https://v.test/a'));
    const after = await verify(await createDpop({ store }).proof('GET', 'https://v.test/a'));
    expect(after.header.jwk).toEqual(before.header.jwk);
    expect(calls.save).toBe(1);
  });

  it('start over with a new key after reset', async () => {
    const { store, calls } = memoryStore();
    const dpop = createDpop({ store });
    const before = await verify(await dpop.proof('GET', 'https://v.test/a'));
    await dpop.reset();
    expect(calls.clear).toBe(1);
    const after = await verify(await dpop.proof('GET', 'https://v.test/a'));
    expect(after.header.jwk).not.toEqual(before.header.jwk);
  });

  it('a signature does not verify under another message', async () => {
    const { store } = memoryStore();
    const proof = await createDpop({ store }).proof('GET', 'https://v.test/a');
    const [h, p, s] = proof.split('.') as [string, string, string];
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...decode(p), htm: 'DELETE' })).toString('base64url')}.${s}`;
    expect((await verify(tampered)).ok).toBe(false);
  });
});
