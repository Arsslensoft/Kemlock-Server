import { describe, expect, it } from 'vitest';
import { hashLinkToPath } from './hashLinks';

describe('the links Bitwarden writes with the route in the hash', () => {
  it('become paths that keep the query', () => {
    expect(hashLinkToPath({ hash: '#/accept-organization/?organizationId=o&token=a.b-c' })).toBe(
      '/accept-organization?organizationId=o&token=a.b-c',
    );
    expect(hashLinkToPath({ hash: '#/accept-emergency?id=g&token=t' })).toBe('/accept-emergency?id=g&token=t');
    expect(hashLinkToPath({ hash: '#/finish-signup/?email=a%40b.c&token=t' })).toBe(
      '/finish-signup?email=a%40b.c&token=t',
    );
  });

  it('leave any other hash alone', () => {
    expect(hashLinkToPath({ hash: '' })).toBeUndefined();
    expect(hashLinkToPath({ hash: '#/vault' })).toBeUndefined();
    expect(hashLinkToPath({ hash: '#section' })).toBeUndefined();
    expect(hashLinkToPath({ hash: '#/accept-organization-x/?a=b' })).toBeUndefined();
  });
});
