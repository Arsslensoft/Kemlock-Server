import { describe, expect, it } from 'vitest';
import { bytes, count, relative, span } from './format';

describe('format', () => {
  it('says how long ago in words', () => {
    expect(relative(1000 - 720, 1000)).toBe('12 minutes ago');
    expect(relative(1000 + 3 * 86_400, 1000)).toBe('in 3 days');
    expect(relative(null)).toBe('');
  });

  it('sizes, spans and counts', () => {
    expect(bytes(512)).toBe('512 B');
    expect(bytes(1_700_000_000)).toBe('1.6 GB');
    expect(span(41)).toBe('41 s');
    expect(span(47 * 60)).toBe('47 min');
    expect(count(5302)).toBe('5,302');
  });
});
