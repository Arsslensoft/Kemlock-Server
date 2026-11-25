// The normalisation of the values docs/crypto.md added for contacts, identity documents, files and
// certificates. The Rust side has the same cases (crates/kemlock-crypto/src/dedup/normalise.rs).
import { describe, expect, it } from 'vitest';
import {
  canonicalInput,
  normaliseContentHash,
  normaliseDocumentNumber,
  normaliseFingerprint,
  normalisePhone,
} from './normalise';

describe('contact phones', () => {
  it('are their ASCII digits only', () => {
    expect(normalisePhone('+1 (555) 0142')).toBe('15550142');
    expect(normalisePhone('1-555-0142')).toBe('15550142');
    expect(normalisePhone('\u0664 12')).toBe('12');
    expect(normalisePhone('call me')).toBe('');
  });
});

describe('identity document numbers', () => {
  it('keep letters and digits, in lower case', () => {
    expect(normaliseDocumentNumber('X 1234-567')).toBe('x1234567');
    expect(normaliseDocumentNumber('x1234567')).toBe('x1234567');
    expect(normaliseDocumentNumber(' ab.12 ')).toBe('ab12');
    expect(normaliseDocumentNumber('Cafe\u0301 9')).toBe('caf\u00e99');
  });

  it('are nothing below four letters and digits', () => {
    expect(normaliseDocumentNumber('123')).toBe('');
    expect(normaliseDocumentNumber('1-2-3')).toBe('');
    expect(normaliseDocumentNumber('--  ')).toBe('');
    expect(normaliseDocumentNumber('')).toBe('');
  });
});

describe('file content hashes', () => {
  it('are 64 hex digits in lower case', () => {
    const hex = '0123456789ABCDEF'.repeat(4);
    expect(normaliseContentHash(hex)).toBe(hex.toLowerCase());
    expect(normaliseContentHash(` ${hex.toLowerCase()} `)).toBe(hex.toLowerCase());
  });

  it('are nothing when they are not a SHA-256', () => {
    expect(normaliseContentHash('0123456789abcdef'.repeat(4).slice(1))).toBe('');
    expect(normaliseContentHash(`${'0123456789abcdef'.repeat(4)}0`)).toBe('');
    expect(normaliseContentHash('zz'.repeat(32))).toBe('');
    expect(normaliseContentHash('sha256:abc')).toBe('');
    expect(normaliseContentHash('')).toBe('');
  });
});

describe('key and certificate fingerprints', () => {
  it('lose the colons, the spaces and a leading 0x, and are upper case', () => {
    const hex = 'ab'.repeat(32);
    const colons = Array.from({ length: 32 }, () => 'ab').join(':');
    expect(normaliseFingerprint(colons)).toBe(hex.toUpperCase());
    expect(normaliseFingerprint(hex)).toBe(hex.toUpperCase());
    expect(normaliseFingerprint(`0x${hex}`)).toBe(hex.toUpperCase());
    expect(normaliseFingerprint('9f3a 77c1 0b2e')).toBe('9F3A77C10B2E');
  });

  it('leave an SSH fingerprint exactly as it is', () => {
    expect(normaliseFingerprint(' SHA256:q38FRmSR0cmF/Hng ')).toBe('SHA256:q38FRmSR0cmF/Hng');
  });
});

describe('the canonical inputs of the new tags', () => {
  it('are the tag name, then its values, with an empty string for a missing one', () => {
    expect(canonicalInput('contact', ['a@b.c', '15550142'])).toBe('["contact","a@b.c","15550142"]');
    expect(canonicalInput('contact', ['a@b.c', ''])).toBe('["contact","a@b.c",""]');
    expect(canonicalInput('document', ['x1234567'])).toBe('["document","x1234567"]');
    expect(canonicalInput('file', ['ab'])).toBe('["file","ab"]');
  });
});
