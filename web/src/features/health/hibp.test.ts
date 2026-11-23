// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { HibpError, parseRange, pwnedCounts, sha1Hex } from './hibp';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, the example the HIBP docs use.
const PASSWORD_HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';

function fakeFetch(body: string, status = 200) {
  return vi.fn<typeof fetch>(async () => new Response(body, { status }));
}

describe('sha1Hex', () => {
  it('is upper-case hex SHA-1', async () => {
    expect(await sha1Hex('password')).toBe(PASSWORD_HASH);
  });
});

describe('parseRange', () => {
  it('reads SUFFIX:COUNT lines and drops padding entries of count 0', () => {
    const map = parseRange('0018A45C4D1DEF81644B54AB7F969B88D65:21\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\nbad line\r\n');
    expect([...map.entries()]).toEqual([['0018A45C4D1DEF81644B54AB7F969B88D65', 21]]);
  });
});

describe('pwnedCounts', () => {
  it('sends only the 5-character prefix, with padding asked for, and matches the suffix here', async () => {
    const fetcher = fakeFetch(`${PASSWORD_HASH.slice(5)}:9545824\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n`);
    const counts = await pwnedCounts(['password', 'password'], { fetch: fetcher });
    expect(counts.get('password')).toBe(9545824);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(String(url)).toBe('https://api.pwnedpasswords.com/range/5BAA6');
    // Neither the password nor the rest of its hash is in the request.
    expect(JSON.stringify([url, init])).not.toContain(PASSWORD_HASH.slice(5));
    expect((init?.headers as Record<string, string>)['Add-Padding']).toBe('true');
    expect(init?.credentials).toBe('omit');
    expect(init?.referrerPolicy).toBe('no-referrer');
  });

  it('counts 0 for a password the range does not list', async () => {
    const counts = await pwnedCounts(['correct horse battery staple'], {
      fetch: fakeFetch('0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n'),
    });
    expect(counts.get('correct horse battery staple')).toBe(0);
  });

  it('asks once per prefix and reports progress', async () => {
    const fetcher = fakeFetch('');
    const progress: Array<[number, number]> = [];
    await pwnedCounts(['a', 'b', 'c'], { fetch: fetcher, baseUrl: 'https://proxy.example/pwned/' }, (d, t) =>
      progress.push([d, t]),
    );
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(String(fetcher.mock.calls[0]?.[0])).toMatch(/^https:\/\/proxy\.example\/pwned\/range\/[0-9A-F]{5}$/);
    expect(progress.at(-1)).toEqual([3, 3]);
  });

  it('throws on a failed answer', async () => {
    await expect(pwnedCounts(['a'], { fetch: fakeFetch('', 503) })).rejects.toBeInstanceOf(HibpError);
  });
});
