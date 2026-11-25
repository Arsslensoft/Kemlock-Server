import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { Kma1Error, kma1Length, openKma1 } from './kma1';

// The files of the Kemlock app's test/fixtures/attachments, which pin the format: the same bytes
// the Rust side checks (crates/kemlock-blob/tests/fixtures).
const dir = new URL('../../../../../crates/kemlock-blob/tests/fixtures/', import.meta.url);
const fixture = JSON.parse(readFileSync(fileURLToPath(new URL('kma1.json', dir)), 'utf8')) as {
  key: string;
  files: Array<{ name: string; plain?: string; kma1?: string; plainLength?: number; plainSha256?: string }>;
};
const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const twoChunks = new Uint8Array(readFileSync(fileURLToPath(new URL('two-chunks.kma1', dir))));
const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');

describe('openKma1', () => {
  it("opens the app's empty and short files", async () => {
    const [empty, short] = fixture.files;
    expect(await openKma1(fixture.key, bytes(empty?.kma1 ?? ''))).toEqual(new Uint8Array());
    expect(new TextDecoder().decode(await openKma1(fixture.key, bytes(short?.kma1 ?? '')))).toBe(
      'Kemlock attachment fixture\n',
    );
  });

  it("opens the app's two-chunk file, every chunk in order", async () => {
    const plain = await openKma1(fixture.key, twoChunks);
    expect(plain).toHaveLength(65636);
    expect(plain.every((byte, i) => byte === ((i * 31 + 7) & 0xff))).toBe(true);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', plain as Uint8Array<ArrayBuffer>));
    expect(hex(digest)).toBe(fixture.files[2]?.plainSha256);
  });

  it('knows how long a file becomes', () => {
    expect(kma1Length(0)).toBe(28);
    expect(kma1Length(65536)).toBe(12 + 65536 + 16);
    expect(kma1Length(65636)).toBe(twoChunks.length);
  });

  it('refuses the wrong key, and returns nothing', async () => {
    const other = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
    await expect(openKma1(other, twoChunks)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses a changed byte', async () => {
    const changed = twoChunks.slice();
    changed[100] = (changed[100] ?? 0) ^ 1;
    await expect(openKma1(fixture.key, changed)).rejects.toBeInstanceOf(Kma1Error);
  });

  it('refuses a file cut at a chunk boundary, because the last chunk is marked', async () => {
    const cut = twoChunks.slice(0, 12 + 65536 + 16);
    await expect(openKma1(fixture.key, cut)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses a file with bytes added', async () => {
    const longer = new Uint8Array(twoChunks.length + 1);
    longer.set(twoChunks);
    await expect(openKma1(fixture.key, longer)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses reordered chunks', async () => {
    const [first, second] = [twoChunks.slice(12, 12 + 65552), twoChunks.slice(12 + 65552)];
    const swapped = new Uint8Array(twoChunks.length);
    swapped.set(twoChunks.slice(0, 12));
    swapped.set(second, 12);
    swapped.set(first, 12 + second.length);
    await expect(openKma1(fixture.key, swapped)).rejects.toMatchObject({ reason: 'damaged' });
  });

  it('refuses what is not a KMA1 file, and a key that is not 32 bytes', async () => {
    const notKma = twoChunks.slice();
    notKma[0] = 0x58;
    await expect(openKma1(fixture.key, notKma)).rejects.toMatchObject({ reason: 'shape' });
    await expect(openKma1(fixture.key, new Uint8Array(5))).rejects.toMatchObject({ reason: 'shape' });
    await expect(openKma1('AAAA', twoChunks)).rejects.toMatchObject({ reason: 'key' });
    await expect(openKma1('***', twoChunks)).rejects.toMatchObject({ reason: 'key' });
  });
});
