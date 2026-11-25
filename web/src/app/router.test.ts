import { QueryClient } from '@tanstack/react-query';
import { createMemoryHistory } from '@tanstack/react-router';
import { describe, expect, it } from 'vitest';
import { createAppRouter } from './router';
import { createSession } from './session';

/** A router over a memory history, with the session in the given state, at `entry`. */
async function visit(
  entry: string,
  status: 'signed-out' | 'locked' | 'unlocked',
  admin = false,
  setup = 'complete',
) {
  const session = createSession();
  if (status !== 'signed-out') {
    session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin });
    if (status === 'unlocked') session.unlocked();
  }
  const queryClient = new QueryClient();
  queryClient.setQueryData(['config'], { setup });
  const router = createAppRouter({ queryClient, session }, createMemoryHistory({ initialEntries: [entry] }));
  await router.load();
  const { pathname, search } = router.state.location;
  return { pathname, search: search as Record<string, unknown>, router };
}

describe('sign-in screens once the vault is open', () => {
  it('lead on to the page asked for', async () => {
    for (const path of ['/sign-in', '/sign-in/password', '/sign-in/device', '/unlock']) {
      const at = await visit(`${path}?email=sam%40example.co&next=%2Fabout`, 'unlocked');
      expect(at.pathname, path).toBe('/about');
    }
  });

  it('do not follow a next that leaves this origin', async () => {
    for (const next of ['//evil.example', 'https://evil.example', '/\\evil']) {
      const at = await visit(`/sign-in/password?email=sam%40example.co&next=${encodeURIComponent(next)}`, 'unlocked');
      expect(at.pathname, next).toBe('/vault');
    }
  });

  it('send the spent single sign-on return to the vault', async () => {
    const at = await visit('/sign-in/sso?code=c&state=s', 'unlocked');
    expect(at.pathname).toBe('/vault');
  });
});

describe('a locked vault', () => {
  it('sends the index to the unlock screen, not the sign-in', async () => {
    expect((await visit('/', 'locked')).pathname).toBe('/unlock');
    expect((await visit('/', 'signed-out')).pathname).toBe('/sign-in');
  });

  it('keeps a locked person off the sign-in screen, and keeps the page they asked for', async () => {
    const at = await visit('/sign-in?next=%2Ftrash', 'locked');
    expect(at.pathname).toBe('/unlock');
    expect(at.search['next']).toBe('/trash');
  });

  it('sends a locked admin to unlock, not sign-in, for a setup step', async () => {
    const at = await visit('/setup/two-step', 'locked', true, 'pending');
    expect(at.pathname).toBe('/unlock');
    expect(at.search['next']).toBe('/setup/two-step');
    expect((await visit('/setup/server', 'signed-out', false, 'pending')).pathname).toBe('/sign-in');
  });
});

describe('a sign-in screen with no email', () => {
  it('goes back to the sign-in and keeps the page asked for', async () => {
    for (const path of ['/sign-in/password', '/sign-in/device']) {
      const at = await visit(`${path}?next=%2Ftrash`, 'signed-out');
      expect(at.pathname, path).toBe('/sign-in');
      expect(at.search['next'], path).toBe('/trash');
    }
  });
});

describe('the new item route', () => {
  it('opens the form of any kind named in its search', async () => {
    for (const kind of ['login', 'note', 'file', 'otp', 'backup-codes', 'passkey', 'card', 'identity', 'contact', 'certificate', 'ssh-key', 'pgp-key']) {
      const at = await visit(`/vault/new?kind=${kind}`, 'unlocked');
      expect(at.pathname, kind).toBe('/vault/new');
      expect(at.search['kind'], kind).toBe(kind);
    }
  });

  it('drops a kind it does not know, so the login form opens', async () => {
    const at = await visit('/vault/new?kind=spaceship', 'unlocked');
    expect(at.pathname).toBe('/vault/new');
    expect(at.search['kind']).toBeUndefined();
  });
});
