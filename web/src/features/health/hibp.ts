// Pwned Passwords by k-anonymity (haveibeenpwned.com/API/v3#PwnedPasswords): the browser hashes a
// password with SHA-1, sends only the first 5 hex characters, asks for padded answers so the
// response size doesn't give the prefix's real size away, and looks for the rest of the hash in
// what comes back. The password and the rest of its hash never leave the page.
//
// The server's CSP allows exactly one origin besides itself: connect-src 'self'
// https://api.pwnedpasswords.com (crates/kemlock-server/src/web.rs). `baseUrl` is a parameter so
// an operator who proxies the range API through the server can point it there.

export const DEFAULT_HIBP_URL = 'https://api.pwnedpasswords.com';

export interface HibpDeps {
  fetch: typeof fetch;
  baseUrl?: string;
}

export async function sha1Hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** `SUFFIX:COUNT` lines to a map. Padding entries have a count of 0 and are dropped. */
export function parseRange(body: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const line of body.split(/\r?\n/)) {
    const [suffix, count] = line.trim().split(':');
    if (!suffix || count === undefined) continue;
    const n = Number.parseInt(count, 10);
    if (Number.isFinite(n) && n > 0) out.set(suffix.toUpperCase(), n);
  }
  return out;
}

export class HibpError extends Error {
  constructor(readonly status: number) {
    super(`Pwned Passwords answered ${status}`);
    this.name = 'HibpError';
  }
}

async function range(prefix: string, deps: HibpDeps): Promise<Map<string, number>> {
  const base = (deps.baseUrl ?? DEFAULT_HIBP_URL).replace(/\/+$/, '');
  const response = await deps.fetch(`${base}/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' },
    referrerPolicy: 'no-referrer',
    credentials: 'omit',
    cache: 'no-store',
  });
  if (!response.ok) throw new HibpError(response.status);
  return parseRange(await response.text());
}

/**
 * How many times each password is in Pwned Passwords (0 when it isn't). One request per distinct
 * 5-character prefix, however many passwords share it.
 */
export async function pwnedCounts(
  passwords: string[],
  deps: HibpDeps,
  onProgress?: (done: number, total: number) => void,
): Promise<Map<string, number>> {
  const hashes = new Map<string, string>();
  for (const password of new Set(passwords)) hashes.set(password, await sha1Hex(password));
  const prefixes = new Set([...hashes.values()].map((hash) => hash.slice(0, 5)));
  const answers = new Map<string, Map<string, number>>();
  let done = 0;
  for (const prefix of prefixes) {
    answers.set(prefix, await range(prefix, deps));
    done += 1;
    onProgress?.(done, prefixes.size);
  }
  const out = new Map<string, number>();
  for (const [password, hash] of hashes) {
    out.set(password, answers.get(hash.slice(0, 5))?.get(hash.slice(5)) ?? 0);
  }
  return out;
}
