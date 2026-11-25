// The live code of a one-time-code item (RFC 4226 and 6238; Steam Guard's alphabet for `steam`).
// Pure and WebCrypto only; the secret is never logged or kept.

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEAM = '23456789BCDFGHJKMNPQRTVWXY';

export function base32Decode(text: string): Uint8Array {
  const clean = text.replace(/[\s=-]/g, '').toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index === -1) throw new Error('not base32');
    value = ((value << 5) | index) & 0xfffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

export interface OtpParams {
  secret: string;
  type: 'totp' | 'hotp' | 'steam';
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: number;
  period: number;
  counter: number;
}

const HASH = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' } as const;

/** The step a TOTP or Steam code is for at `nowMs`. */
export function stepAt(nowMs: number, period: number): number {
  return Math.floor(nowMs / 1000 / period);
}

/** Seconds left before the code for `nowMs` changes. */
export function secondsLeft(nowMs: number, period: number): number {
  return period - (Math.floor(nowMs / 1000) % period);
}

export async function hotp(params: OtpParams, counter: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(params.secret) as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: HASH[params.algorithm] },
    false,
    ['sign'],
  );
  const message = new ArrayBuffer(8);
  const view = new DataView(message);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  let number =
    ((mac[offset] ?? 0) & 0x7f) * 2 ** 24 +
    ((mac[offset + 1] ?? 0) << 16) +
    ((mac[offset + 2] ?? 0) << 8) +
    (mac[offset + 3] ?? 0);
  if (params.type === 'steam') {
    let code = '';
    for (let i = 0; i < params.digits; i += 1) {
      code += STEAM[number % STEAM.length];
      number = Math.floor(number / STEAM.length);
    }
    return code;
  }
  return String(number % 10 ** params.digits).padStart(params.digits, '0');
}

/** The code now (a counter code is the one for its stored counter). */
export function codeAt(params: OtpParams, nowMs: number): Promise<string> {
  return hotp(params, params.type === 'hotp' ? params.counter : stepAt(nowMs, params.period));
}

/** Reads an item's data into parameters; undefined when it has no usable secret. */
export function otpParamsOf(data: Record<string, unknown> | null | undefined): OtpParams | undefined {
  if (!data || typeof data['secret'] !== 'string') return undefined;
  const type = data['type'] === 'hotp' || data['type'] === 'steam' ? data['type'] : 'totp';
  // Steam Guard is SHA-1 and five characters whatever the item stores (the app's otp.dart).
  const algorithm =
    type !== 'steam' && (data['algorithm'] === 'SHA256' || data['algorithm'] === 'SHA512') ? data['algorithm'] : 'SHA1';
  const num = (key: string, fallback: number) => {
    const value = data[key];
    return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback;
  };
  try {
    base32Decode(data['secret']);
  } catch {
    return undefined;
  }
  return {
    secret: data['secret'],
    type,
    algorithm,
    digits: type === 'steam' ? 5 : Math.min(10, num('digits', 6)),
    period: num('period', 30),
    counter: typeof data['counter'] === 'number' ? data['counter'] : 0,
  };
}
