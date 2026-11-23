import { describe, expect, it } from 'vitest';
import { webAddress } from './web-address';

describe('webAddress', () => {
  it('passes an http or https address', () => {
    expect(webAddress('https://github.com/Arsslensoft/Kemlock-Server/tree/abc1234')).toBe(
      'https://github.com/Arsslensoft/Kemlock-Server/tree/abc1234',
    );
    expect(webAddress('http://git.lan/kemlock')).toBe('http://git.lan/kemlock');
  });

  it('refuses anything a link could run or that is not an address', () => {
    for (const raw of ['javascript:alert(1)', 'data:text/html,hi', 'ftp://git.example.org/x', '/relative', 'nope']) {
      expect(webAddress(raw), raw).toBeUndefined();
    }
  });

  it('has nothing for a missing address', () => {
    expect(webAddress(undefined)).toBeUndefined();
    expect(webAddress(null)).toBeUndefined();
    expect(webAddress('')).toBeUndefined();
  });
});
