// @vitest-environment node
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { approvalPhrase, phraseFromDigest, phraseInput, words, WORD_COUNT } from './approvalPhrase';

// The vectors are the ones crates/kemlock-domain/src/unlock/phrase.rs tests, so the browser and
// the apps cannot disagree on what two devices show.
describe('the approval phrase', () => {
  it('uses EFF’s 7,776-word list', () => {
    expect(words()).toHaveLength(WORD_COUNT);
    expect(words()[0]).toBe('abacus');
    expect(words()[WORD_COUNT - 1]).toBe('zoom');
    expect(words()[415]).toBe('backed');
  });

  it('is the first word five times for an all-zero digest', () => {
    expect(phraseFromDigest(new Uint8Array(32))).toBe('abacus abacus abacus abacus abacus');
  });

  it('wraps 8191 into the list for an all-one digest', () => {
    expect(phraseFromDigest(new Uint8Array(32).fill(0xff))).toBe(
      'backed backed backed backed backed',
    );
  });

  it('reads groups most significant first', () => {
    const digest = new Uint8Array(32);
    digest[1] = 0x08;
    expect(phraseFromDigest(digest)).toBe('abdomen abacus abacus abacus abacus');
  });

  it('counts only the first 65 bits', () => {
    const a = new Uint8Array(32).fill(0x5a);
    const b = new Uint8Array(a);
    b[8] = (b[8] ?? 0) ^ 0x7f;
    b[20] = (b[20] ?? 0) ^ 0xff;
    expect(phraseFromDigest(a)).toBe(phraseFromDigest(b));
    a[8] = (a[8] ?? 0) ^ 0x80;
    expect(phraseFromDigest(a)).not.toBe(phraseFromDigest(b));
  });

  it('hashes the label and then the key', () => {
    expect(Array.from(phraseInput(new Uint8Array([1, 2])))).toEqual([
      ...new TextEncoder().encode('kemlock approval v1'),
      1,
      2,
    ]);
  });

  it('works out the phrase of a key the way the server’s Rust does', async () => {
    const key = new Uint8Array(1600).map((_, i) => (i * 7 + 3) % 256);
    const digest = createHash('sha256').update(phraseInput(key)).digest();
    expect(await approvalPhrase(key)).toBe(phraseFromDigest(new Uint8Array(digest)));
    expect((await approvalPhrase(key)).split(' ')).toHaveLength(5);
  });
});
