import { describe, expect, it } from 'vitest';
import {
  hintOf,
  isRisky,
  phoneDomains,
  readWebsites,
  writeWebsites,
  type WebsiteRule,
} from './websites';

describe('readWebsites', () => {
  it('reads the app\'s uris with Bitwarden rule numbers', () => {
    const rules = readWebsites({
      uris: [
        { uri: 'example.co' },
        { uri: 'accounts.example.co', match: 0 },
        { uri: 'okta.example.co', match: 1 },
        { uri: 'https://intranet.example.co/login', match: 2 },
        { uri: 'https://intranet.example.co/home', match: 3 },
        { uri: '^https://x', match: 4 },
        { uri: 'wiki.example.co', match: 5 },
        { uri: 'later.example.co', match: 9 },
      ],
    });
    expect(rules.map((r) => r.match)).toEqual([
      'default',
      'domain',
      'host',
      'startsWith',
      'exact',
      'regex',
      'never',
      'default',
    ]);
  });

  it('falls back to the web vault\'s urls, then the app\'s websites', () => {
    expect(readWebsites({ urls: ['https://a.example', 'b.example'] })).toEqual([
      { uri: 'https://a.example', match: 'default' },
      { uri: 'b.example', match: 'default' },
    ]);
    expect(readWebsites({ websites: ['c.example'] })).toEqual([{ uri: 'c.example', match: 'default' }]);
    expect(readWebsites(null)).toEqual([]);
  });
});

describe('writeWebsites', () => {
  const rules: WebsiteRule[] = [
    { uri: 'example.co', match: 'default' },
    { uri: ' https://intranet.example.co/login ', match: 'startsWith' },
    { uri: '^https://([a-z]+\\.)?example\\.co/', match: 'regex' },
    { uri: '', match: 'default' },
  ];

  it('writes the three forms in step and drops a blank website', () => {
    const out = writeWebsites(rules);
    expect(out.uris).toEqual([
      { uri: 'example.co' },
      { uri: 'https://intranet.example.co/login', match: 2 },
      { uri: '^https://([a-z]+\\.)?example\\.co/', match: 4 },
    ]);
    // A regular expression is no host, so older readers get only the real addresses.
    expect(out.urls).toEqual(['example.co', 'https://intranet.example.co/login']);
    expect(out.websites).toEqual(['example.co', 'intranet.example.co']);
  });

  it('round-trips through readWebsites', () => {
    const out = writeWebsites(rules);
    expect(readWebsites({ ...out })).toEqual(rules.slice(0, 3).map((r) => ({ ...r, uri: r.uri.trim() })));
  });
});

describe('hintOf and phoneDomains', () => {
  it('says what each rule does', () => {
    expect(hintOf({ uri: 'accounts.example.co', match: 'domain' })).toEqual({
      id: 'sites.hint.domain',
      values: { domain: 'example.co' },
    });
    expect(hintOf({ uri: 'https://a.example.co/x', match: 'host' }).values).toEqual({ host: 'a.example.co' });
    expect(hintOf({ uri: '', match: 'default' }).id).toBe('sites.hint.empty');
    expect(hintOf({ uri: '', match: 'regex' }).id).toBe('sites.hint.regex');
    expect(hintOf({ uri: 'x.example', match: 'never' }).id).toBe('sites.hint.never');
  });

  it('flags the rules Bitwarden calls dangerous', () => {
    expect(isRisky('startsWith')).toBe(true);
    expect(isRisky('regex')).toBe(true);
    expect(isRisky('host')).toBe(false);
  });

  it('lists where phones fill: hosts only, never for regex or never', () => {
    expect(
      phoneDomains([
        { uri: 'example.co', match: 'default' },
        { uri: 'www.example.co', match: 'domain' },
        { uri: 'okta.example.co', match: 'host' },
        { uri: 'https://i.example.co/login', match: 'startsWith' },
        { uri: '^x', match: 'regex' },
        { uri: 'wiki.example.co', match: 'never' },
      ]),
    ).toEqual(['example.co', 'okta.example.co', 'i.example.co']);
  });
});
