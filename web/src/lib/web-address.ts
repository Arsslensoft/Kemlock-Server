/**
 * An address the server named, if it is one a link may point at: `http:` or `https:` and nothing
 * else, so a server (or a proxy in front of it) can never turn a link into `javascript:`.
 */
export function webAddress(raw: string | null | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch {
    return undefined;
  }
}
