import { describe, expect, it } from 'vitest';
import { base32Decode, codeAt, hotp, otpParamsOf, secondsLeft } from './otp';

// RFC 4226 / 6238 test secret "12345678901234567890".
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const params = (extra: Record<string, unknown> = {}) => {
  const p = otpParamsOf({ secret: SECRET, ...extra });
  if (!p) throw new Error('no params');
  return p;
};

const b32 = (text: string) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const byte of new TextEncoder().encode(text)) bits += byte.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += alphabet[Number.parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
};

describe('one-time codes', () => {
  it('decodes base32', () => {
    expect(new TextDecoder().decode(base32Decode(SECRET))).toBe('12345678901234567890');
    expect(() => base32Decode('1!')).toThrow();
  });

  it('matches the RFC 4226 counter vectors', async () => {
    const p = params();
    expect(await hotp(p, 0)).toBe('755224');
    expect(await hotp(p, 1)).toBe('287082');
    expect(await hotp(p, 9)).toBe('520489');
  });

  it('matches the RFC 6238 time vectors', async () => {
    expect(await codeAt(params({ digits: 8 }), 59_000)).toBe('94287082');
    expect(await codeAt(params({ digits: 8 }), 1_111_111_109_000)).toBe('07081804');
  });

  it('matches the RFC 6238 SHA-256 and SHA-512 vectors', async () => {
    const sha256 = params({ secret: b32('12345678901234567890123456789012'), algorithm: 'SHA256', digits: 8 });
    expect(await codeAt(sha256, 59_000)).toBe('46119246');
    expect(await codeAt(sha256, 1_111_111_109_000)).toBe('68084774');
    const key512 = '1234567890123456789012345678901234567890123456789012345678901234';
    const sha512 = params({ secret: b32(key512), algorithm: 'SHA512', digits: 8 });
    expect(await codeAt(sha512, 59_000)).toBe('90693936');
    expect(await codeAt(sha512, 1_111_111_109_000)).toBe('25091201');
  });

  it('shows the code of the stored counter for a counter code', async () => {
    expect(await codeAt(params({ type: 'hotp', counter: 1 }), Date.now())).toBe('287082');
  });

  it('counts the seconds left in the step', () => {
    expect(secondsLeft(59_000, 30)).toBe(1);
    expect(secondsLeft(60_000, 30)).toBe(30);
  });

  it('gives no parameters for a secret it cannot read', () => {
    expect(otpParamsOf({ secret: '!!!' })).toBeUndefined();
    expect(otpParamsOf(null)).toBeUndefined();
  });

  it('makes a Steam code SHA-1 and five characters whatever the item stores', async () => {
    const stored = params({ type: 'steam', algorithm: 'SHA512', digits: 8 });
    expect(stored).toMatchObject({ algorithm: 'SHA1', digits: 5 });
    expect(await codeAt(stored, 59_000)).toBe(await codeAt(params({ type: 'steam' }), 59_000));
    expect(await codeAt(stored, 59_000)).toHaveLength(5);
  });

  it('writes a Steam code in its alphabet', async () => {
    expect(await codeAt(params({ type: 'steam', digits: 5 }), 59_000)).toMatch(/^[2-9BCDFGHJKMNPQRTVWXY]{5}$/);
  });
});
