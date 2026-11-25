import { QueryClient } from '@tanstack/react-query';
import { createMemoryHistory } from '@tanstack/react-router';
import { beforeEach, describe, expect, it } from 'vitest';
import { createAppRouter } from './router';
import { createSession } from './session';

const config = { setup: 'complete' };

/** A router over a memory history, with the session in the given state, at `entry`. */
async function visit(entry: string, status: 'signed-out' | 'locked' | 'unlocked', admin = false) {
  const session = createSession();
  if (status !== 'signed-out') {
    session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin });
    if (status === 'unlocked') session.unlocked();
  }
  const queryClient = new QueryClient();
  queryClient.setQueryData(['config'], config);
  const router = createAppRouter({ queryClient, session }, createMemoryHistory({ initialEntries: [entry] }));
  await router.load();
  const { pathname, search } = router.state.location;
  return { pathname, search: search as Record<string, unknown>, router };
}

beforeEach(() => undefined);

describe('sign-in screens once the vault is open', () => {
  it('lead on to the page asked for', async () => {
    for (const path of ['/sign-in', '/sign-in/password', '/sign-in/device', '/unlock']) {
      const at = await visit(`${path}?email=sam%40example.co&next=%2Fabout`, 'unlocked');
      expect(at.pathname, path).toBe('/about');
    }
  });

  it('do not follow a next that leaves this origin', async () => {
    for (const next of ['//evil.example', 'https://evil.example', '%2F%5Cevil']) {
      const at = await visit(`/sign-in/password?email=sam%40example.co&next=${encodeURIComponent(next)}`, 'unlocked');
      expect(at.pathname, next).toBe('/vault');
    }
  });

  it('send the spent single sign-on return to the vault', async () => {
    const at = await visit('/sign-in/sso?code=c&state=s', 'unlocked');
    expect(at.pathname).toBe('/vault');
  });
});
