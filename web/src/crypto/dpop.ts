// DPoP proofs (RFC 9449) for the kem API. The signing key is a non-extractable WebCrypto P-256 key
// kept in IndexedDB, so a stolen access token is useless without this browser profile, and a
// script that reads the page cannot read the key. The server (crates/kemlock-api-kem/src/dpop.rs)
// wants typ dpop+jwt, alg ES256 with the public key as jwk, htm, htu without a query, iat, a jti,
// the server's nonce, and on authenticated calls ath, the hash of the access token.

import { b64urlEncode, b64urlOfText, utf8 } from './b64';
import type { KeyStore } from './keystore';
import { CryptoError } from './types';

export interface DpopDeps {
  store: KeyStore;
  subtle?: SubtleCrypto;
  /** Milliseconds since the epoch. */
  now?: () => number;
  randomId?: () => string;
}

export interface Dpop {
  proof(htm: string, htu: string, nonce?: string, accessToken?: string): Promise<string>;
  /** Forgets the key: the next proof makes a new one. */
  reset(): Promise<void>;
}

interface PublicJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

/** scheme://host[:port]/path: no query, no fragment, default port dropped. */
export function normaliseHtu(htu: string): string {
  let url: URL;
  try {
    url = new URL(htu);
  } catch {
    throw new CryptoError('invalid');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new CryptoError('invalid');
  return `${url.origin}${url.pathname}`;
}

export function createDpop(deps: DpopDeps): Dpop {
  const subtle = deps.subtle ?? globalThis.crypto.subtle;
  const now = deps.now ?? (() => Date.now());
  const randomId = deps.randomId ?? (() => globalThis.crypto.randomUUID());
  const { store } = deps;

  let loaded: Promise<{ pair: CryptoKeyPair; jwk: PublicJwk }> | undefined;

  async function loadOrCreate(): Promise<{ pair: CryptoKeyPair; jwk: PublicJwk }> {
    let pair = await store.load();
    if (!pair) {
      pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ]);
      await store.save(pair);
    }
    const exported = await subtle.exportKey('jwk', pair.publicKey);
    const { kty, crv, x, y } = exported;
    if (kty !== 'EC' || crv !== 'P-256' || !x || !y) throw new CryptoError('unavailable');
    return { pair, jwk: { kty, crv, x, y } };
  }

  function key() {
    loaded ??= loadOrCreate().catch((error: unknown) => {
      loaded = undefined;
      throw error;
    });
    return loaded;
  }

  return {
    async proof(htm, htu, nonce, accessToken) {
      const { pair, jwk } = await key();
      const header = { typ: 'dpop+jwt', alg: 'ES256', jwk };
      const claims: Record<string, string | number> = {
        jti: randomId(),
        htm: htm.toUpperCase(),
        htu: normaliseHtu(htu),
        iat: Math.floor(now() / 1000),
      };
      if (nonce) claims.nonce = nonce;
      if (accessToken) {
        const hash = await subtle.digest('SHA-256', utf8(accessToken));
        claims.ath = b64urlEncode(new Uint8Array(hash));
      }
      const signingInput = `${b64urlOfText(JSON.stringify(header))}.${b64urlOfText(JSON.stringify(claims))}`;
      // WebCrypto's ECDSA output is r || s, which is what a JWS ES256 signature is.
      const signature = await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        pair.privateKey,
        utf8(signingInput),
      );
      return `${signingInput}.${b64urlEncode(new Uint8Array(signature))}`;
    },

    async reset() {
      loaded = undefined;
      await store.clear();
    },
  };
}
