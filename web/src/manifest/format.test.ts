// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  type Manifest,
  TOMBSTONE_HASH,
  ciphertextHash,
  decodeManifest,
  encodeManifest,
} from './format';

interface Vector {
  name: string;
  counter: number;
  owner: string;
  manifest: string;
  entries: Array<{
    item_id: string;
    revision: number;
    ciphertext: string | null;
    ciphertext_hash: string;
    deleted: boolean;
  }>;
}

const vectors = (
  JSON.parse(
    readFileSync(fileURLToPath(new URL('../../../test-vectors/manifest.json', import.meta.url)), 'utf8'),
  ) as { cases: Vector[] }
).cases;

const fromHex = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);

const uuid = (hex: string) =>
  `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const USER = 'user:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const HASH = 'ab'.repeat(32);

describe('the manifest codec, against test-vectors/manifest.json', () => {
  it.each(vectors.map((vector) => [vector.name, vector] as const))('reads and writes %s', async (_name, vector) => {
    const bytes = fromHex(vector.manifest);
    const read = decodeManifest(bytes);
    expect(read).not.toBeNull();
    expect(read?.counter).toBe(vector.counter);
    expect(read?.owner).toBe(`user:${uuid(vector.owner.slice(2))}`);
    expect(read?.entries).toEqual(
      vector.entries
        .map((entry) => ({
          id: uuid(entry.item_id),
          revision: entry.revision,
          hash: entry.ciphertext_hash,
          deleted: entry.deleted,
        }))
        .sort((a, b) => (a.id < b.id ? -1 : 1)),
    );
    // Written back, the bytes are the vector's exactly.
    expect(encodeManifest(read as Manifest)).toEqual(bytes);
    // And a live entry's hash is the SHA-256 of its ciphertext.
    for (const entry of vector.entries) {
      if (entry.ciphertext) expect(await ciphertextHash(fromHex(entry.ciphertext))).toBe(entry.ciphertext_hash);
    }
  });
});

describe('encodeManifest', () => {
  const manifest: Manifest = {
    owner: USER,
    counter: 9,
    entries: [
      { id: C, revision: 2, hash: HASH, deleted: false },
      { id: A, revision: 5, hash: TOMBSTONE_HASH, deleted: true },
      { id: B, revision: 1, hash: HASH, deleted: false },
    ],
  };

  it('sorts the entries by item id and round-trips', () => {
    const bytes = encodeManifest(manifest);
    expect(bytes).toHaveLength(48 + 3 * 57);
    expect(new TextDecoder().decode(bytes.subarray(0, 19))).toBe('kemlock/v1/manifest');
    expect(decodeManifest(bytes)).toEqual({
      ...manifest,
      entries: [manifest.entries[1], manifest.entries[2], manifest.entries[0]],
    });
  });

  it('writes a space as owner type 2', () => {
    const bytes = encodeManifest({ owner: `space:${A}`, counter: 1, entries: [] });
    expect(bytes[19]).toBe(2);
    expect(decodeManifest(bytes)?.owner).toBe(`space:${A}`);
  });

  it.each([
    ['an item twice', { ...manifest, entries: [...manifest.entries, manifest.entries[0] as never] }],
    ['a tombstone with a hash', { ...manifest, entries: [{ id: A, revision: 1, hash: HASH, deleted: true }] }],
    ['a short hash', { ...manifest, entries: [{ id: A, revision: 1, hash: 'ab', deleted: false }] }],
    ['a counter below zero', { ...manifest, counter: -1 }],
    ['a counter past 2^53', { ...manifest, counter: 2 ** 53 }],
    ['an owner that is not one', { ...manifest, owner: 'team:x' }],
    ['an id that is not a UUID', { ...manifest, entries: [{ id: 'nope', revision: 1, hash: HASH, deleted: false }] }],
  ])('refuses %s', (_name, bad) => {
    expect(() => encodeManifest(bad as Manifest)).toThrow();
  });
});

describe('decodeManifest', () => {
  const good = encodeManifest({
    owner: USER,
    counter: 1,
    entries: [
      { id: A, revision: 1, hash: HASH, deleted: false },
      { id: B, revision: 3, hash: TOMBSTONE_HASH, deleted: true },
    ],
  });

  const changed = (edit: (bytes: Uint8Array) => Uint8Array) => decodeManifest(edit(good.slice()));

  it('reads a good one', () => {
    expect(decodeManifest(good)?.entries).toHaveLength(2);
  });

  it.each([
    ['another label', (b: Uint8Array) => Object.assign(b, { 0: 0x58 })],
    ['an owner type that is not one', (b: Uint8Array) => Object.assign(b, { 19: 3 })],
    ['a count that does not match the length', (b: Uint8Array) => Object.assign(b, { 47: 3 })],
    ['a flag that is not 0 or 1', (b: Uint8Array) => Object.assign(b, { [48 + 56]: 2 })],
    ['a tombstone with a hash', (b: Uint8Array) => Object.assign(b, { [48 + 57 + 30]: 1 })],
    ['trailing bytes', (b: Uint8Array) => Uint8Array.from([...b, 0])],
    ['a missing byte', (b: Uint8Array) => b.subarray(0, b.length - 1)],
    ['too little for a header', (b: Uint8Array) => b.subarray(0, 20)],
    [
      'entries out of order',
      (b: Uint8Array) => {
        const out = b.slice();
        out.set(b.subarray(48 + 57, 48 + 114), 48);
        out.set(b.subarray(48, 48 + 57), 48 + 57);
        return out;
      },
    ],
    [
      'an item twice',
      (b: Uint8Array) => {
        const out = b.slice();
        out.set(b.subarray(48, 48 + 57), 48 + 57);
        return out;
      },
    ],
    ['a counter past 2^53', (b: Uint8Array) => Object.assign(b, { 36: 0x7f })],
  ])('refuses %s', (_name, edit) => {
    expect(changed(edit)).toBeNull();
  });
});
