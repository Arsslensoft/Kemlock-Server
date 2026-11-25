// The scenarios docs/crypto.md names for `dedup-normalise.json` (test-vectors/, added with the
// server's dedup work): `İstanbul`, `ΣΑΣ`, `Straße` against `STRASSE`, a decomposed `é`, a base32
// secret with spaces, lower case and padding, a note with CRLF and trailing blanks, duplicate
// backup codes. The vector file itself is not in this branch; when it lands its cases belong here.
import { describe, expect, it } from 'vitest';
import {
  canonicalInput,
  decodeBase32,
  encodeBase32,
  lowerSimple,
  normaliseCardNumber,
  normaliseCodes,
  normaliseCredentialId,
  normaliseExpiry,
  normaliseFingerprint,
  normaliseNote,
  normaliseSecret,
  normaliseSite,
  normaliseUsername,
} from './normalise';

describe('lower case by simple mapping', () => {
  it('maps İ to i, Σ always to σ and ẞ to ß', () => {
    expect(lowerSimple('İstanbul')).toBe('istanbul');
    expect(lowerSimple('ΣΑΣ')).toBe('σασ');
    expect(lowerSimple('ẞ')).toBe('ß');
  });

  it('leaves ß alone, so Straße and STRASSE do not match', () => {
    expect(lowerSimple('Straße')).toBe('straße');
    expect(lowerSimple('STRASSE')).toBe('strasse');
    expect(lowerSimple('Straße')).not.toBe(lowerSimple('STRASSE'));
  });
});

describe('usernames', () => {
  it('trims, NFC-normalises and lower-cases', () => {
    expect(normaliseUsername('  Alice@Example.ORG ')).toBe('alice@example.org');
    // A decomposed é (e + U+0301) equals the composed one.
    expect(normaliseUsername('Café')).toBe(normaliseUsername('Café'));
  });
});

describe('sites', () => {
  it('is the registrable domain, or the whole host for an IP address', () => {
    expect(normaliseSite('https://Accounts.Example.com/login')).toBe('example.com');
    expect(normaliseSite('http://192.0.2.10:8080/a')).toBe('192.0.2.10');
    expect(normaliseSite('www.bbc.co.uk')).toBe('bbc.co.uk');
  });
});

describe('secrets', () => {
  it('re-encodes any spelling of the same bytes as upper-case base32 without padding', () => {
    expect(normaliseSecret('jbsw y3dp ehpk 3pxp')).toBe('JBSWY3DPEHPK3PXP');
    expect(normaliseSecret('MZXW6YTBOI======')).toBe('MZXW6YTBOI');
    expect(normaliseSecret('mzxw6ytboi')).toBe('MZXW6YTBOI');
    expect(normaliseSecret('otpauth://totp/Mail:ada?secret=jbswy3dpehpk3pxp&issuer=Mail')).toBe(
      'JBSWY3DPEHPK3PXP',
    );
  });

  it('refuses text that is not base32', () => {
    expect(normaliseSecret('not base32!')).toBeNull();
    expect(normaliseSecret('')).toBeNull();
  });

  it('round-trips bytes through base32', () => {
    const bytes = Uint8Array.from([0, 68, 50, 20, 199, 1, 2, 3, 4, 5, 6, 7, 8]);
    expect(decodeBase32(encodeBase32(bytes))).toEqual(bytes);
    expect(encodeBase32(new TextEncoder().encode('foobar'))).toBe('MZXW6YTBOI');
  });
});

describe('other values', () => {
  it('keeps only the digits of a card number and formats the expiry', () => {
    expect(normaliseCardNumber('4111 1111-1111 1111')).toBe('4111111111111111');
    expect(normaliseExpiry(5, 2029)).toBe('2029-05');
    expect(normaliseExpiry('12', '2027')).toBe('2027-12');
    expect(normaliseExpiry(undefined, undefined)).toBe('');
    expect(normaliseExpiry(13, 2029)).toBe('');
  });

  it('normalises a note: NFC, LF, no trailing blanks or blank lines', () => {
    expect(normaliseNote('Line one  \r\nLine\ttwo\t\r\n\r\n\r\n')).toBe('Line one\nLine\ttwo');
    expect(normaliseNote('a\rb')).toBe('a\nb');
  });

  it('drops duplicate backup codes and sorts the rest by code point', () => {
    expect(normaliseCodes([' b-2 ', 'a-1', 'b-2', 'B-3', ''])).toEqual(['B-3', 'a-1', 'b-2']);
  });

  it('writes credential ids as base64url and fingerprints canonically', () => {
    expect(normaliseCredentialId('ab+/cd==')).toBe('ab-_cd');
    expect(normaliseFingerprint('SHA256:AbC+/xyz')).toBe('SHA256:AbC+/xyz');
    expect(normaliseFingerprint(' 9f3a 77c1 0b2e 45d6 8a19 c0de 12f4 5b6a 7788 9900')).toBe(
      '9F3A77C10B2E45D68A19C0DE12F45B6A77889900',
    );
    // Not a fingerprint: no value, as in Rust, so two items with one such value are not copies.
    expect(normaliseFingerprint('ab12 cd34')).toBe('');
  });
});

describe('canonicalInput', () => {
  it('is the tag name then the values, as JSON without whitespace', () => {
    expect(canonicalInput('cred', ['example.com', 'alice', 'hunter2'])).toBe(
      '["cred","example.com","alice","hunter2"]',
    );
  });

  it('escapes as RFC 8785 does', () => {
    expect(canonicalInput('note', ['a"b\\c\n\u0001'])).toBe('["note","a\\"b\\\\c\\n\\u0001"]');
  });

  it('matches the first case of test-vectors/dedup.json', () => {
    expect(canonicalInput('secret', ['JBSWY3DPEHPK3PXP'])).toBe('["secret","JBSWY3DPEHPK3PXP"]');
    expect(canonicalInput('account', ['example.com', 'alice'])).toBe('["account","example.com","alice"]');
  });
});
