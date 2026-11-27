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
  // The search the route understood (validateSearch applied), which is what the pages read; location.search is
  // the address as typed.
  const { pathname } = router.state.location;
  const search = router.state.matches.at(-1)?.search ?? {};
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

describe('Profile', () => {
  it('opens for a person with the vault open', async () => {
    expect((await visit('/profile', 'unlocked')).pathname).toBe('/profile');
  });

  it('asks a locked vault to open first, and a signed-out person to sign in, keeping the page', async () => {
    const locked = await visit('/profile', 'locked');
    expect(locked.pathname).toBe('/unlock');
    expect(locked.search['next']).toBe('/profile');
    const out = await visit('/profile', 'signed-out');
    expect(out.pathname).toBe('/sign-in');
    expect(out.search['next']).toBe('/profile');
  });
});

describe('the link mailed to a new address', () => {
  it('needs no sign-in, and keeps the token it carries', async () => {
    for (const status of ['signed-out', 'locked', 'unlocked'] as const) {
      const at = await visit('/confirm-email?token=abc_DEF-123', status);
      expect(at.pathname, status).toBe('/confirm-email');
      expect(at.search['token'], status).toBe('abc_DEF-123');
    }
  });

  it('opens with no token too, to say the link is incomplete', async () => {
    const at = await visit('/confirm-email', 'signed-out');
    expect(at.pathname).toBe('/confirm-email');
    expect(at.search['token']).toBeUndefined();
  });
});

describe('the links of an invitation or a sign-up', () => {
  it('need no sign-in and keep their values in the fragment', async () => {
    for (const status of ['signed-out', 'locked', 'unlocked'] as const) {
      const org = await visit('/accept-organization#organizationId=o&organizationUserId=u&token=a.b', status);
      expect(org.pathname, status).toBe('/accept-organization');
      expect(org.router.state.location.hash, status).toContain('token=a.b');
      // The page reads the fragment itself; nothing of it is read as a search.
      expect(org.search['token'], status).toBeUndefined();
      const emergency = await visit('/accept-emergency#id=g&token=t', status);
      expect(emergency.pathname, status).toBe('/accept-emergency');
      expect(emergency.router.state.location.hash, status).toContain('id=g');
      const signup = await visit('/finish-signup#email=a%40b.c&token=t', status);
      expect(signup.pathname, status).toBe('/finish-signup');
      expect(signup.router.state.location.hash, status).toContain('email=a%40b.c');
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

  it('keeps the item a new one is filled from', async () => {
    const at = await visit('/vault/new?kind=card&copyOf=7b1c2d3e', 'unlocked');
    expect(at.search['kind']).toBe('card');
    expect(at.search['copyOf']).toBe('7b1c2d3e');
    const bare = await visit('/vault/new?copyOf=7b1c2d3e', 'unlocked');
    expect(bare.search['kind']).toBeUndefined();
    expect(bare.search['copyOf']).toBe('7b1c2d3e');
  });

  it('drops a kind it does not know, so the login form opens', async () => {
    const at = await visit('/vault/new?kind=spaceship', 'unlocked');
    expect(at.pathname).toBe('/vault/new');
    expect(at.search['kind']).toBeUndefined();
  });
});
