import { describe, expect, it } from 'vitest';
import { sessionEndedTarget } from './sessionEnded';

const at = (pathname: string, search: unknown = {}, query = '') => ({
  pathname,
  href: `${pathname}${query}`,
  search,
});

describe('where a refused refresh sends the person', () => {
  it('to the sign-in, keeping the page they were on', () => {
    expect(sessionEndedTarget(at('/vault/abc', {}, '?x=1'))).toEqual({
      to: '/sign-in',
      search: { next: '/vault/abc?x=1' },
    });
    expect(sessionEndedTarget(at('/admin/users'))?.search.next).toBe('/admin/users');
  });

  it('from the unlock screen, keeping the page it was headed for', () => {
    expect(sessionEndedTarget(at('/unlock', { next: '/trash' }))?.search.next).toBe('/trash');
  });

  it('nowhere when the page needs no session', () => {
    for (const path of ['/sign-in', '/sign-in/password', '/about', '/setup', '/setup/two-step']) {
      expect(sessionEndedTarget(at(path))).toBeUndefined();
    }
  });
});
