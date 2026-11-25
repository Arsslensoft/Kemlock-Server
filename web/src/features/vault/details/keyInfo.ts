// What a detail page shows about the key items, worked out in the browser from the stored halves:
// an SSH key's OpenSSH line and SHA256 fingerprint, a PGP key's fingerprint and user ids, a
// certificate's subject, issuer, validity and fingerprint. Nothing here logs or keeps a key.
import { fromB64, pemBlocks, publicLength, toB64 } from '../forms/keyMaterial';

async function sha(name: 'SHA-1' | 'SHA-256', bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(name, bytes as Uint8Array<ArrayBuffer>));
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** `AB:CD:...` as certificate tools print a fingerprint. */
export const colonHex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');

function sshString(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const ascii = (text: string) => new TextEncoder().encode(text);

export interface SshInfo {
  /** `ssh-ed25519 AAAA...`, the line for authorized_keys. */
  line: string;
  /** `SHA256:...`, as `ssh-keygen -l` prints it. */
  fingerprint: string;
}

/** The OpenSSH line and fingerprint of an SPKI public key (Ed25519 or ECDSA P-256). */
export async function sshInfo(algorithm: string, spkiBase64: string): Promise<SshInfo | undefined> {
  try {
    const spki = fromB64(spkiBase64);
    let blob: Uint8Array;
    let name: string;
    if (algorithm === 'ed25519' && spki.length === 44) {
      name = 'ssh-ed25519';
      blob = join(sshString(ascii(name)), sshString(spki.subarray(12)));
    } else if (algorithm === 'ecdsa-p256' && spki.length === 91) {
      name = 'ecdsa-sha2-nistp256';
      blob = join(sshString(ascii(name)), sshString(ascii('nistp256')), sshString(spki.subarray(26)));
    } else return undefined;
    const digest = await sha('SHA-256', blob);
    return { line: `${name} ${toB64(blob)}`, fingerprint: `SHA256:${toB64(digest).replace(/=+$/, '')}` };
  } catch {
    return undefined;
  }
}

export interface PgpInfo {
  /** Upper-case hex, in groups of four. */
  fingerprint?: string;
  userIds: string[];
}

interface Packet {
  tag: number;
  body: Uint8Array;
}

function packets(b: Uint8Array): Packet[] {
  const out: Packet[] = [];
  let i = 0;
  while (i < b.length) {
    const head = b[i] ?? 0;
    if ((head & 0x80) === 0) break;
    let tag: number;
    let length: number;
    let at: number;
    if ((head & 0x40) !== 0) {
      tag = head & 0x3f;
      const l = b[i + 1] ?? 0;
      if (l < 192) {
        length = l;
        at = i + 2;
      } else if (l < 224) {
        length = ((l - 192) << 8) + (b[i + 2] ?? 0) + 192;
        at = i + 3;
      } else if (l === 255) {
        length = new DataView(b.buffer, b.byteOffset + i + 2, 4).getUint32(0);
        at = i + 6;
      } else break;
    } else {
      tag = (head >> 2) & 0xf;
      const size = [1, 2, 4][head & 3];
      if (size === undefined) break;
      length = 0;
      for (let k = 0; k < size; k += 1) length = length * 256 + (b[i + 1 + k] ?? 0);
      at = i + 1 + size;
    }
    if (at + length > b.length) break;
    out.push({ tag, body: b.subarray(at, at + length) });
    i = at + length;
  }
  return out;
}

/**
 * The fingerprint and user ids of a binary OpenPGP key (base64). A version 4 key hashes its
 * public part with SHA-1, a version 6 key with SHA-256. A secret key packet is cut down to its
 * public part with `publicLength`.
 */
export async function pgpInfo(base64: string): Promise<PgpInfo> {
  const userIds: string[] = [];
  let fingerprint: string | undefined;
  try {
    const all = packets(fromB64(base64));
    for (const packet of all) {
      if (packet.tag === 13) userIds.push(new TextDecoder().decode(packet.body));
    }
    const key = all.find((p) => p.tag === 6 || p.tag === 5);
    if (key) {
      const b = key.body;
      let pub: Uint8Array | undefined;
      if (key.tag === 6) pub = b;
      else if (b[0] === 4) {
        const n = publicLength(b[5] ?? 0, b, 6);
        pub = n === undefined ? undefined : b.subarray(0, 6 + n);
      } else if (b[0] === 6) {
        pub = b.subarray(0, 10 + new DataView(b.buffer, b.byteOffset + 6, 4).getUint32(0));
      }
      if (pub && pub[0] === 4) {
        fingerprint = hex(await sha('SHA-1', join(Uint8Array.of(0x99, pub.length >> 8, pub.length & 0xff), pub)));
      } else if (pub && pub[0] === 6) {
        const len = new Uint8Array(4);
        new DataView(len.buffer).setUint32(0, pub.length);
        fingerprint = hex(await sha('SHA-256', join(Uint8Array.of(0x9b), len, pub)));
      }
    }
  } catch {
    // An unreadable key shows no fingerprint.
  }
  return {
    userIds,
    ...(fingerprint ? { fingerprint: fingerprint.toUpperCase().replace(/(.{4})(?=.)/g, '$1 ') } : {}),
  };
}

/** ASCII armor of a binary key: 64-column base64 between its header and footer lines. */
export function armor(label: string, base64: string): string {
  const lines = base64.match(/.{1,64}/g) ?? [];
  return [`-----BEGIN ${label}-----`, '', ...lines, `-----END ${label}-----`, ''].join('\n');
}

// ---- certificates: a minimal DER reader ----

interface Tlv {
  tag: number;
  value: Uint8Array;
}

function read(b: Uint8Array, at: number): { tlv: Tlv; next: number } | undefined {
  const tag = b[at];
  let length = b[at + 1];
  if (tag === undefined || length === undefined) return undefined;
  let start = at + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4) return undefined;
    length = 0;
    for (let k = 0; k < n; k += 1) length = length * 256 + (b[at + 2 + k] ?? 0);
    start = at + 2 + n;
  }
  if (start + length > b.length) return undefined;
  return { tlv: { tag, value: b.subarray(start, start + length) }, next: start + length };
}

function children(value: Uint8Array): Tlv[] {
  const out: Tlv[] = [];
  let at = 0;
  while (at < value.length) {
    const r = read(value, at);
    if (!r) break;
    out.push(r.tlv);
    at = r.next;
  }
  return out;
}

const OIDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

function oid(value: Uint8Array): string {
  const parts: number[] = [];
  let n = 0;
  for (const byte of value) {
    n = n * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(n);
      n = 0;
    }
  }
  const first = parts.shift() ?? 0;
  return [first < 80 ? Math.floor(first / 40) : 2, first < 80 ? first % 40 : first - 80, ...parts].join('.');
}

function nameOf(seq: Tlv): string {
  const out: string[] = [];
  for (const set of children(seq.value)) {
    for (const pair of children(set.value)) {
      const [key, val] = children(pair.value);
      if (!key || !val) continue;
      const id = oid(key.value);
      const text = new TextDecoder(val.tag === 0x1e ? 'utf-16be' : 'utf-8').decode(val.value);
      out.push(`${OIDS[id] ?? id}=${text}`);
    }
  }
  return out.join(', ');
}

function timeOf(t: Tlv): Date | undefined {
  const s = new TextDecoder().decode(t.value);
  const re = t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/ : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/;
  const m = re.exec(s);
  if (!m) return undefined;
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)));
}

export interface CertInfo {
  subject: string;
  issuer: string;
  notBefore?: Date;
  notAfter?: Date;
  /** SHA-256 of the DER, as `AB:CD:...`. */
  fingerprint: string;
}

/** Subject, issuer, validity and SHA-256 fingerprint of a PEM certificate; undefined if unreadable. */
export async function certInfo(pem: string): Promise<CertInfo | undefined> {
  try {
    const block = pemBlocks(pem).find((b) => b.label === 'CERTIFICATE');
    if (!block) return undefined;
    const der = fromB64(block.body);
    const cert = read(der, 0)?.tlv;
    const tbs = cert ? children(cert.value)[0] : undefined;
    if (!tbs) return undefined;
    let fields = children(tbs.value);
    if (fields[0]?.tag === 0xa0) fields = fields.slice(1);
    // serial, signature algorithm, issuer, validity, subject
    const [, , issuer, validity, subject] = fields;
    if (!issuer || !validity || !subject) return undefined;
    const [from, to] = children(validity.value);
    const notBefore = from ? timeOf(from) : undefined;
    const notAfter = to ? timeOf(to) : undefined;
    return {
      subject: nameOf(subject),
      issuer: nameOf(issuer),
      ...(notBefore ? { notBefore } : {}),
      ...(notAfter ? { notAfter } : {}),
      fingerprint: colonHex(await sha('SHA-256', der)),
    };
  } catch {
    return undefined;
  }
}
