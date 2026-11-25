// The canonical inputs of the duplicate tags, exactly as docs/crypto.md ("Duplicate tags",
// "Normalisation") fixes them, so this browser, the Kemlock app and the server's optional matcher
// turn one item into one set of tags. Only the HMAC differs: here two items are compared by their
// canonical input, which never leaves the page, so no key is needed.
import { hostOfWebsite, isIpAddress, registrableDomain } from '@/lib/psl';

export type TagName =
  | 'cred'
  | 'account'
  | 'secret'
  | 'passkey'
  | 'card'
  | 'note'
  | 'key'
  | 'codes'
  | 'identity'
  | 'contact'
  | 'document'
  | 'file';

const WHITE_SPACE = /^\p{White_Space}+|\p{White_Space}+$/gu;

/** Trims by Unicode White_Space (not JavaScript's trim, which also eats U+FEFF). */
export function trimUnicode(text: string): string {
  return text.replace(WHITE_SPACE, '');
}

/**
 * Lower case by each code point's simple mapping (UnicodeData field 13): no SpecialCasing and no
 * final-sigma rule. JavaScript's `toLowerCase` applies both, so one code point at a time it is:
 * the only code point that then yields two is U+0130, whose simple mapping is `i`.
 */
export function lowerSimple(text: string): string {
  let out = '';
  for (const char of text) {
    const lower = char.toLowerCase();
    const first = lower.codePointAt(0);
    out += lower === char || first === undefined ? char : String.fromCodePoint(first);
  }
  return out;
}

export function nfc(text: string): string {
  return text.normalize('NFC');
}

/** trimmed of Unicode white space, NFC, lower case: usernames, names and email addresses. */
export function normaliseUsername(text: string): string {
  return lowerSimple(nfc(trimUnicode(text)));
}

/** The registrable domain of a website, or the whole host for an IP address. */
export function normaliseSite(uri: string): string {
  const host = hostOfWebsite(uri);
  return isIpAddress(host) ? host : registrableDomain(host);
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decodes RFC 4648 base32 (any case, spaces, dashes and padding accepted); null if not base32. */
export function decodeBase32(text: string): Uint8Array | null {
  const clean = text.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  if (clean === '') return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(out);
}

export function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32.charAt((value >> bits) & 31);
      value &= (1 << bits) - 1;
    }
  }
  if (bits > 0) out += BASE32.charAt((value << (5 - bits)) & 31);
  return out;
}

/** The secret of a code: from a base32 text or an `otpauth://` link, as upper-case base32. */
export function normaliseSecret(text: string): string | null {
  let secret = text.trim();
  if (/^otpauth:\/\//i.test(secret)) {
    try {
      secret = new URL(secret).searchParams.get('secret') ?? '';
    } catch {
      return null;
    }
  }
  const bytes = decodeBase32(secret);
  return bytes ? encodeBase32(bytes) : null;
}

/** A credential id as base64url without padding (standard base64 is accepted). */
export function normaliseCredentialId(text: string): string {
  return text.trim().replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** CRLF and lone CR become LF; spaces and tabs at the end of each line and blank lines at the end go. */
export function normaliseNote(text: string): string {
  const lines = nfc(text)
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.replace(/[ \t]+$/, ''));
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines.join('\n');
}

/** The card number's ASCII digits only. */
export function normaliseCardNumber(text: string): string {
  return text.replace(/[^0-9]/g, '');
}

/** `YYYY-MM`, or `""` when the expiry is unknown. */
export function normaliseExpiry(month: unknown, year: unknown): string {
  const m = typeof month === 'number' ? month : Number.parseInt(String(month ?? ''), 10);
  const y = typeof year === 'number' ? year : Number.parseInt(String(year ?? ''), 10);
  if (!Number.isInteger(m) || !Number.isInteger(y) || m < 1 || m > 12 || y < 1000) return '';
  return `${String(y).padStart(4, '0')}-${String(m).padStart(2, '0')}`;
}

/**
 * A key's or a certificate's fingerprint, as the Rust side reads one: an OpenSSH `SHA256:…` (the
 * prefix in capitals) as it is, or 40 or 64 hex digits (a PGP v4 or v6 fingerprint, a certificate's
 * SHA-1 or SHA-256 thumbprint) as upper case, without the spaces, the colons and a leading `0x`
 * (`AB:CD:…` and `abcd…` are one value). `""` for anything else, which makes no tag.
 */
export function normaliseFingerprint(text: string): string {
  const trimmed = text.trim();
  if (trimmed.startsWith('SHA256:')) return trimmed.length > 'SHA256:'.length ? trimmed : '';
  const squeezed = trimmed.replace(/[\s:]+/g, '').toUpperCase();
  const hex = squeezed.startsWith('0X') ? squeezed.slice(2) : squeezed;
  return /^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(hex) ? hex : '';
}

/** A contact's phone: its ASCII digits only, so `+1 (555) 0142` and `15550142` are one number. */
export function normalisePhone(text: string): string {
  return text.replace(/[^0-9]/g, '');
}

/** The fewest letters and digits an identity document's number needs to make a tag. */
const MIN_DOCUMENT_NUMBER = 4;

/**
 * An identity document's number: NFC, lower case, only its letters and digits. `""` below four of
 * them: a placeholder would match unrelated papers.
 */
export function normaliseDocumentNumber(text: string): string {
  const kept = lowerSimple(nfc(text)).replace(/[^\p{Alphabetic}\p{N}]/gu, '');
  return [...kept].length >= MIN_DOCUMENT_NUMBER ? kept : '';
}

/** A file's content hash: the SHA-256 of its plaintext as 64 hex digits in lower case, else `""`. */
export function normaliseContentHash(text: string): string {
  const trimmed = text.trim();
  return /^[0-9a-fA-F]{64}$/.test(trimmed) ? trimmed.toLowerCase() : '';
}

/** Backup codes: trimmed, duplicates dropped, sorted by code point. */
export function normaliseCodes(codes: string[]): string[] {
  const unique = new Set(codes.map(trimUnicode).filter((code) => code !== ''));
  return [...unique].sort((a, b) => {
    const x = [...a].map((c) => c.codePointAt(0) ?? 0);
    const y = [...b].map((c) => c.codePointAt(0) ?? 0);
    for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
      const diff = (x[i] as number) - (y[i] as number);
      if (diff !== 0) return diff;
    }
    return x.length - y.length;
  });
}

/**
 * The canonical input of a tag: the tag's name then its values, as a JSON array without
 * whitespace. `JSON.stringify` of an array of strings is RFC 8785 (JCS): it escapes only quotes,
 * backslashes and control characters, with the short forms and lower-case `\u00xx` JCS names.
 */
export function canonicalInput(name: TagName, values: string[]): string {
  return JSON.stringify([name, ...values]);
}
