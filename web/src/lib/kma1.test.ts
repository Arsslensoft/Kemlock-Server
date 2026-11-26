import { createCipheriv, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Kma1Error, fileKeyBytes, fileKeyText, kma1Length, newAttachmentId, newFileKey, openKma1, sealKma1 } from './kma1';

const CHUNK = 65536;

/** The format written out a second way, with Node's own AES-GCM, so the two can disagree. */
function reference(key: Uint8Array, plain: Uint8Array, prefix: Uint8Array): Buffer {
  const chunks = Math.max(1, Math.ceil(plain.length / CHUNK));
  const parts: Buffer[] = [Buffer.from('KMA1'), Buffer.from(prefix)];
  for (let i = 0; i < chunks; i += 1) {
    const last = i === chunks - 1;
    const nonce = Buffer.alloc(12);
    nonce.set(prefix);
    nonce.writeUInt32BE(i, 8);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from([last ? 1 : 0]));
    const body = Buffer.concat([cipher.update(plain.subarray(i * CHUNK, last ? plain.length : (i + 1) * CHUNK)), cipher.final()]);
    parts.push(body, cipher.getAuthTag());
  }
  return Buffer.concat(parts);
}

const KEY = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const PREFIX = Uint8Array.from([9, 8, 7, 6, 5, 4, 3, 2]);

function bytes(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i * 31 + 7) % 251);
}

describe('kma1Length', () => {
  it('is the header, the plaintext and a tag for each chunk, with one chunk at least', () => {
    expect(kma1Length(0)).toBe(28);
    expect(kma1Length(1)).toBe(29);
    expect(kma1Length(CHUNK)).toBe(12 + CHUNK + 16);
    expect(kma1Length(CHUNK + 1)).toBe(12 + CHUNK + 1 + 32);
    expect(kma1Length(2 * CHUNK)).toBe(12 + 2 * CHUNK + 32);
  });
});

describe('sealKma1', () => {
  it('writes the format the Kemlock app reads, chunk for chunk', async () => {
    for (const size of [0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 17]) {
      const plain = bytes(size);
      const sealed = await sealKma1(KEY, plain, PREFIX);
      expect(sealed.length, `size ${size}`).toBe(kma1Length(size));
      expect(Buffer.from(sealed).equals(reference(KEY, plain, PREFIX)), `size ${size}`).toBe(true);
    }
  });

  it('starts with KMA1 and the nonce prefix', async () => {
    const sealed = await sealKma1(KEY, bytes(10), PREFIX);
    expect(new TextDecoder().decode(sealed.subarray(0, 4))).toBe('KMA1');
    expect([...sealed.subarray(4, 12)]).toEqual([...PREFIX]);
  });

  it('uses a fresh nonce prefix each time unless one is given', async () => {
    const one = await sealKma1(KEY, bytes(10));
    const two = await sealKma1(KEY, bytes(10));
    expect([...one.subarray(4, 12)]).not.toEqual([...two.subarray(4, 12)]);
  });

  it('refuses a key that is not 32 bytes and a prefix that is not 8', async () => {
    await expect(sealKma1(new Uint8Array(16), bytes(1))).rejects.toThrow(/32 bytes/);
    await expect(sealKma1(KEY, bytes(1), new Uint8Array(4))).rejects.toThrow(/8 bytes/);
  });
});

describe('file keys and ids', () => {
  it('makes 32-byte keys that read back from the text the body keeps', () => {
    const key = newFileKey();
    expect(key).toHaveLength(32);
    expect([...fileKeyBytes(fileKeyText(key))]).toEqual([...key]);
    expect(fileKeyText(KEY)).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });

  it('makes attachment ids of 16 random bytes in base64url', () => {
    const id = newAttachmentId();
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(newAttachmentId()).not.toBe(id);
  });
});

// The Kemlock app's own files, written when the format was added and never regenerated: the same
// bytes crates/kemlock-blob checks on the server side. What this writes must match them to the byte.
// They are read from the working directory (web/): under jsdom import.meta.url is not a file: URL.
const dir = resolve(process.cwd(), '..', 'crates', 'kemlock-blob', 'tests', 'fixtures');
const fixture = JSON.parse(readFileSync(resolve(dir, 'kma1.json'), 'utf8')) as {
  key: string;
  files: Array<{
    name: string;
    plain?: string;
    kma1?: string;
    plainLength?: number;
    plainSha256?: string;
    kma1File?: string;
    kma1Sha256?: string;
  }>;
};
const fromBase64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64'));
const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const appKey = fromBase64(fixture.key);
const twoChunks = new Uint8Array(readFileSync(resolve(dir, 'two-chunks.kma1')));
const twoChunksPlain = Uint8Array.from({ length: 65636 }, (_, i) => (i * 31 + 7) & 0xff);

describe("the app's KMA1 fixtures", () => {
  it('are written byte for byte by sealKma1, under each fixture\'s own nonce prefix', async () => {
    for (const name of ['empty', 'short']) {
      const entry = fixture.files.find((file) => file.name === name);
      const app = fromBase64(entry?.kma1 ?? '');
      const sealed = await sealKma1(appKey, fromBase64(entry?.plain ?? ''), app.subarray(4, 12));
      expect(Buffer.from(sealed).toString('base64'), name).toBe(entry?.kma1);
    }
  });

  it('are matched by the two-chunk file, built from its pattern, with its hash', async () => {
    const entry = fixture.files.find((file) => file.name === 'two chunks');
    expect(twoChunksPlain).toHaveLength(entry?.plainLength ?? 0);
    expect(sha256(twoChunksPlain)).toBe(entry?.plainSha256);
    expect(sha256(twoChunks)).toBe(entry?.kma1Sha256);
    const sealed = await sealKma1(appKey, twoChunksPlain, twoChunks.subarray(4, 12));
    expect(sealed).toHaveLength(twoChunks.length);
    expect(Buffer.from(sealed).equals(Buffer.from(twoChunks))).toBe(true);
  });

  it('are opened by openKma1, all three', async () => {
    const [empty, short] = ['empty', 'short'].map((name) => fixture.files.find((file) => file.name === name));
    expect(await openKma1(appKey, fromBase64(empty?.kma1 ?? ''))).toHaveLength(0);
    expect(new TextDecoder().decode(await openKma1(fixture.key, fromBase64(short?.kma1 ?? '')))).toBe(
      'Kemlock attachment fixture\n',
    );
    const plain = await openKma1(appKey, twoChunks);
    expect(sha256(plain)).toBe(fixture.files.find((file) => file.name === 'two chunks')?.plainSha256);
  });
});

describe('openKma1', () => {
  it('opens what sealKma1 sealed, for every size around a chunk', async () => {
    for (const size of [0, 1, 65535, 65536, 65537, 131072, 200000]) {
      const plain = bytes(size);
      const sealed = await sealKma1(KEY, plain, PREFIX);
      expect([...(await openKma1(KEY, sealed))], `size ${size}`).toEqual([...plain]);
    }
  });

  it('takes the key as text too, base64 or base64url', async () => {
    const sealed = await sealKma1(KEY, bytes(10), PREFIX);
    const text = fileKeyText(KEY);
    expect([...(await openKma1(text, sealed))]).toEqual([...bytes(10)]);
    expect([...(await openKma1(text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), sealed))]).toEqual([
      ...bytes(10),
    ]);
  });

  it('refuses another key, and returns no plaintext', async () => {
    const sealed = await sealKma1(KEY, bytes(100), PREFIX);
    await expect(openKma1(new Uint8Array(32).fill(9), sealed)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses a key that is not 32 bytes, or not base64', async () => {
    const sealed = await sealKma1(KEY, bytes(1), PREFIX);
    await expect(openKma1(new Uint8Array(16), sealed)).rejects.toMatchObject({ reason: 'key' });
    await expect(openKma1('not base64!', sealed)).rejects.toMatchObject({ reason: 'key' });
  });

  it('refuses a file cut at a chunk boundary, because the last chunk is marked in its associated data', async () => {
    const sealed = await sealKma1(KEY, bytes(CHUNK + 5), PREFIX);
    const cut = sealed.slice(0, 12 + CHUNK + 16);
    await expect(openKma1(KEY, cut)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses a cut that leaves part of a chunk, a changed byte, bytes added and chunks swapped', async () => {
    const sealed = await sealKma1(KEY, bytes(2 * CHUNK + 5), PREFIX);
    await expect(openKma1(KEY, sealed.slice(0, sealed.length - 3))).rejects.toBeInstanceOf(Kma1Error);
    const changed = sealed.slice();
    changed[100] = (changed[100] ?? 0) ^ 1;
    await expect(openKma1(KEY, changed)).rejects.toBeInstanceOf(Kma1Error);
    const longer = new Uint8Array(sealed.length + 1);
    longer.set(sealed);
    await expect(openKma1(KEY, longer)).rejects.toMatchObject({ reason: 'damaged' });
    const swapped = sealed.slice();
    const sealedChunk = CHUNK + 16;
    swapped.set(sealed.subarray(12 + sealedChunk, 12 + 2 * sealedChunk), 12);
    swapped.set(sealed.subarray(12, 12 + sealedChunk), 12 + sealedChunk);
    await expect(openKma1(KEY, swapped)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses what is not a KMA1 file', async () => {
    await expect(openKma1(KEY, new Uint8Array(40))).rejects.toMatchObject({ reason: 'shape' });
    await expect(openKma1(KEY, new Uint8Array(5))).rejects.toMatchObject({ reason: 'shape' });
  });
});
