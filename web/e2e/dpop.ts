// A client of the Kemlock API for a journey that has no browser session: it signs the DPoP proofs
// (RFC 9449, crates/kemlock-api-kem/src/dpop.rs) with a key of its own, the way a phone does. The
// proof is an ES256 JWS with `typ: dpop+jwt` and the public key as `jwk`; its claims are the method,
// the URL without its query, the time, a fresh id, the hash of the access token on an
// authenticated call and the server's nonce, which the first call is refused for and learns.
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';

const b64url = (data: Buffer | string): string => Buffer.from(data).toString('base64url');

export interface Answer<T = unknown> {
  status: number;
  body: T;
}

export class DpopClient {
  private readonly privateKey;
  private readonly jwk;
  private nonce: string | undefined;

  /** `origin` is the server's `DOMAIN`, with no trailing slash: the proofs name it. */
  constructor(private readonly origin: string) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.privateKey = pair.privateKey;
    const { kty, crv, x, y } = pair.publicKey.export({ format: 'jwk' });
    this.jwk = { kty, crv, x, y };
  }

  proof(method: string, path: string, accessToken?: string): string {
    const header = b64url(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: this.jwk }));
    const claims: Record<string, unknown> = {
      htm: method,
      htu: `${this.origin}${path}`,
      iat: Math.floor(Date.now() / 1000),
      jti: randomUUID(),
    };
    if (this.nonce) claims['nonce'] = this.nonce;
    if (accessToken) claims['ath'] = b64url(createHash('sha256').update(accessToken).digest());
    const input = `${header}.${b64url(JSON.stringify(claims))}`;
    const signature = sign('sha256', Buffer.from(input), { key: this.privateKey, dsaEncoding: 'ieee-p1363' });
    return `${input}.${b64url(signature)}`;
  }

  /** One call, retried once with the nonce the server hands out when it asks for one. */
  async call<T = unknown>(
    method: 'GET' | 'POST',
    path: string,
    options: { body?: unknown; accessToken?: string } = {},
  ): Promise<Answer<T>> {
    for (let attempt = 0; ; attempt += 1) {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        DPoP: this.proof(method, path, options.accessToken),
      };
      if (options.body !== undefined) headers['Content-Type'] = 'application/json';
      if (options.accessToken) headers['Authorization'] = `DPoP ${options.accessToken}`;
      const response = await fetch(`${this.origin}${path}`, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });
      const nonce = response.headers.get('dpop-nonce');
      if (nonce) this.nonce = nonce;
      if (response.status === 401 && nonce && attempt === 0) continue;
      const text = await response.text();
      let body: unknown = text;
      try {
        body = text === '' ? undefined : JSON.parse(text);
      } catch {
        // Not JSON: keep the text for the failure message.
      }
      return { status: response.status, body: body as T };
    }
  }
}

/** A PKCE pair (RFC 7636, S256) and a `state` of the lengths the server accepts. */
export function pkce(): { verifier: string; challenge: string; state: string } {
  const verifier = b64url(Buffer.from(randomUUID() + randomUUID()));
  return {
    verifier: verifier.slice(0, 64),
    challenge: b64url(createHash('sha256').update(verifier.slice(0, 64)).digest()),
    state: b64url(Buffer.from(randomUUID())),
  };
}
