// What happens in the page when the server refuses the refresh token: the session is over, and the
// person lands on the sign-in with the page they were on kept as `next`.

/** Pages that need no session, or are part of getting one: nothing to leave. */
const OPEN_PREFIXES = ['/sign-in', '/about', '/setup'];

/**
 * Where to send the person when the session ends under them, or nothing when they are already on a
 * page that needs none. From the unlock screen the page they were headed for (`next`) is kept, not
 * the unlock screen itself.
 */
export function sessionEndedTarget(location: {
  pathname: string;
  href: string;
  search: unknown;
}): { to: '/sign-in'; search: { next: string } } | undefined {
  const { pathname } = location;
  if (OPEN_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))) {
    return undefined;
  }
  if (pathname === '/unlock') {
    const next = (location.search as { next?: unknown } | undefined)?.next;
    return { to: '/sign-in', search: { next: typeof next === 'string' ? next : '/vault' } };
  }
  return { to: '/sign-in', search: { next: location.href } };
}
