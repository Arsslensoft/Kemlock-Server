// The two page frames with the real router: the header's search, the New menu and the avatar menu,
// the sidebar and the admin console's. The screens inside are stand-ins; only the frames are under test.
import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider, createMemoryHistory } from '@tanstack/react-router';
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { vaultKey } from '@/features/vault/hooks';
import type { VaultItem } from '@/features/vault/vault';
import { I18nProvider } from '@/i18n';
import { createAppRouter } from './router';
import { queryClient, session } from './services';

vi.mock('@/features/vault/Main', () => ({ default: () => <p>The list</p> }));
vi.mock('@/features/vault/NewItem', () => ({ default: () => <p>The form</p> }));
vi.mock('@/features/account/Profile', () => ({ default: () => <p>The profile</p> }));
vi.mock('@/features/admin/Overview', () => ({ default: () => <p>The overview</p> }));
vi.mock('@/features/auth/Unlock', () => ({ default: () => <p>The unlock screen</p> }));
vi.mock('@/features/auth/SignInScreen', () => ({ default: () => <p>The sign-in screen</p> }));
// What the real actions do to the session, without the keys and the cache behind them.
vi.mock('./actions', async () => {
  const { session: current } = await import('./services');
  return {
    lockVault: vi.fn(async () => current.locked()),
    signOut: vi.fn(async () => current.end()),
  };
});

const item = (id: string, kind: string, data: Record<string, unknown> | null = { name: id }): VaultItem => ({
  id,
  owner: 'user:u1',
  kind,
  revision: 1,
  keyVersion: 1,
  data,
  sizes: { ciphertext: 1, itemKey: 1 },
});

const ITEMS = [
  item('a', 'login'),
  item('b', 'login'),
  item('c', 'login'),
  item('d', 'note'),
  item('e', 'otp'),
  item('f', 'otp'),
  // A kind from a newer app: in the total, in no type's count.
  item('g', 'hologram'),
  // In the Trash: in no count but Trash's.
  item('h', 'login', { name: 'h', trashedAt: 1 }),
];

const TYPE_LINKS = [
  ['All items', '7', '/vault'],
  ['Logins', '3', '/vault?kind=login'],
  ['Notes', '1', '/vault?kind=note'],
  ['Files', '0', '/vault?kind=file'],
  ['MFA codes', '2', '/vault?kind=otp'],
  ['Backup codes', '0', '/vault?kind=backup-codes'],
  ['Passkeys', '0', '/vault?kind=passkey'],
  ['Cards', '0', '/vault?kind=card'],
  ['Identities', '0', '/vault?kind=identity'],
  ['Contacts', '0', '/vault?kind=contact'],
  ['Certificates', '0', '/vault?kind=certificate'],
  ['SSH keys', '0', '/vault?kind=ssh-key'],
  ['PGP keys', '0', '/vault?kind=pgp-key'],
] as const;

const NEW_TYPES = [
  ['Login', 'login'],
  ['Note', 'note'],
  ['File', 'file'],
  ['MFA code', 'otp'],
  ['Backup codes', 'backup-codes'],
  ['Passkey', 'passkey'],
  ['Card', 'card'],
  ['Identity', 'identity'],
  ['Contact', 'contact'],
  ['Certificate', 'certificate'],
  ['SSH key', 'ssh-key'],
  ['PGP key', 'pgp-key'],
] as const;

function open(path: string, who: { admin?: boolean; name?: string | null } = {}) {
  session.signedIn({
    email: 'sam@example.org',
    name: who.name === undefined ? 'Sam Rivera' : who.name,
    userId: 'u1',
    deviceId: 'd1',
    admin: who.admin ?? false,
  });
  session.unlocked();
  queryClient.setQueryData(['config'], { setup: 'complete' });
  queryClient.setQueryData(['placement'], null);
  queryClient.setQueryData(vaultKey, ITEMS);
  const router = createAppRouter({ queryClient, session }, createMemoryHistory({ initialEntries: [path] }));
  render(
    <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </I18nProvider>,
  );
  return router;
}

beforeEach(() => {
  session.end();
  queryClient.clear();
});
afterEach(() => {
  session.end();
  queryClient.clear();
});

describe('the vault header', () => {
  it('searches "the vault", not logins and notes', async () => {
    open('/vault');
    expect(await screen.findByPlaceholderText('Search the vault')).toBeInTheDocument();
  });

  it('has no Account section in the sidebar, and none of its old links', async () => {
    open('/vault');
    const nav = await screen.findByRole('navigation', { name: 'Vault' });
    expect(within(nav).queryByRole('heading', { name: 'Account' })).toBeNull();
    for (const gone of ['Account security', 'Security', 'Devices & apps', 'About', 'Admin console', 'Sign out']) {
      expect(within(nav).queryByRole('link', { name: gone }), gone).toBeNull();
    }
    expect(within(nav).queryByRole('button', { name: /Lock the vault|Sign out/ })).toBeNull();
  });
});

describe('the sidebar', () => {
  it('lists All items and every type in the owner\'s order, each with its count and its list', async () => {
    open('/vault');
    const nav = await screen.findByRole('navigation', { name: 'Vault' });
    const links = within(nav).getAllByRole('link').slice(0, TYPE_LINKS.length);
    expect(links.map((link) => link.textContent)).toEqual(TYPE_LINKS.map(([label, count]) => `${label}${count}`));
    expect(links.map((link) => link.getAttribute('href'))).toEqual(TYPE_LINKS.map(([, , href]) => href));
  });

  it('counts the Trash on its own and leaves what it holds out of every other count', async () => {
    open('/vault');
    const nav = await screen.findByRole('navigation', { name: 'Vault' });
    expect(within(nav).getByRole('link', { name: 'Trash1' })).toHaveAttribute('href', '/trash');
    expect(within(nav).getByRole('link', { name: 'Logins3' })).toBeInTheDocument();
  });

  it('marks All items on the list, and the type on a type\'s list', async () => {
    const router = open('/vault');
    const nav = await screen.findByRole('navigation', { name: 'Vault' });
    expect(within(nav).getByRole('link', { name: 'All items7' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'MFA codes2' })).not.toHaveAttribute('aria-current');
    await router.navigate({ to: '/vault', search: { kind: 'otp', q: 'github' } });
    expect(await within(nav).findByRole('link', { name: 'MFA codes2' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', { name: 'All items7' })).not.toHaveAttribute('aria-current');
  });
});

describe('the New menu', () => {
  it('is a + button that opens a menu naming every type, in order, each one a creation form', async () => {
    open('/vault');
    const user = userEvent.setup();
    const button = await screen.findByRole('button', { name: 'New item' });
    expect(button).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('navigation', { name: 'New item' })).toBeNull();

    await user.click(button);
    expect(button).toHaveAttribute('aria-expanded', 'true');
    const menu = screen.getByRole('navigation', { name: 'New item' });
    const links = within(menu).getAllByRole('link');
    expect(links.map((link) => link.textContent)).toEqual(NEW_TYPES.map(([label]) => label));
    expect(links.map((link) => link.getAttribute('href'))).toEqual(
      NEW_TYPES.map(([, kind]) => `/vault/new?kind=${kind}`),
    );
  });

  it('opens that type\'s form and closes when a type is picked', async () => {
    const router = open('/vault');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'New item' }));
    await user.click(within(screen.getByRole('navigation', { name: 'New item' })).getByRole('link', { name: 'Card' }));
    expect(await screen.findByText('The form')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/vault/new');
    expect(router.state.location.search).toMatchObject({ kind: 'card' });
    expect(screen.queryByRole('navigation', { name: 'New item' })).toBeNull();
  });

  it('closes with Escape and gives the focus back to the button', async () => {
    open('/vault');
    const user = userEvent.setup();
    const button = await screen.findByRole('button', { name: 'New item' });
    await user.click(button);
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('navigation', { name: 'New item' })).toBeNull();
    expect(button).toHaveFocus();
  });
});

describe('the avatar menu', () => {
  it('shows who is signed in and, for a member, Profile to Sign out with no Admin console', async () => {
    open('/vault');
    const user = userEvent.setup();
    const avatar = await screen.findByRole('button', { name: 'Account menu for Sam Rivera' });
    expect(avatar).toHaveTextContent('SR');
    expect(avatar).toHaveAttribute('aria-haspopup', 'true');
    expect(avatar).toHaveAttribute('aria-expanded', 'false');

    await user.click(avatar);
    expect(avatar).toHaveAttribute('aria-expanded', 'true');
    const menu = screen.getByRole('navigation', { name: 'Account' });
    expect(screen.getByText('sam@example.org')).toBeInTheDocument();
    const entries = [...menu.querySelectorAll('a, button')].map((entry) => entry.textContent);
    expect(entries).toEqual(['Profile', 'Security', 'Devices & apps', 'About', 'Lock the vault', 'Sign out']);
    expect(within(menu).getByRole('link', { name: 'Profile' })).toHaveAttribute('href', '/profile');
    expect(within(menu).getByRole('link', { name: 'Security' })).toHaveAttribute('href', '/security');
    expect(within(menu).getByRole('link', { name: 'Devices & apps' })).toHaveAttribute('href', '/devices');
    expect(within(menu).getByRole('link', { name: 'About' })).toHaveAttribute('href', '/about');
  });

  it('adds the Admin console, with its tag, between Devices & apps and About for an admin', async () => {
    open('/vault', { admin: true });
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Account menu for Sam Rivera' }));
    const menu = screen.getByRole('navigation', { name: 'Account' });
    const entries = [...menu.querySelectorAll('a, button')].map((entry) => entry.textContent);
    expect(entries).toEqual([
      'Profile',
      'Security',
      'Devices & apps',
      'Admin consoleAdmin',
      'About',
      'Lock the vault',
      'Sign out',
    ]);
    expect(within(menu).getByRole('link', { name: /Admin console/ })).toHaveAttribute('href', '/admin');
  });

  it('names a person with no name by their address', async () => {
    open('/vault', { name: null });
    const avatar = await screen.findByRole('button', { name: 'Account menu for sam@example.org' });
    expect(avatar).toHaveTextContent('SE');
  });

  it('learns the name from the profile when sign-in gave only the address', async () => {
    queryClient.setQueryData(['profile'], { userId: 'u1', email: 'sam@example.org', name: 'Sam Rivera' });
    open('/vault', { name: null });
    const avatar = await screen.findByRole('button', { name: 'Account menu for Sam Rivera' });
    expect(avatar).toHaveTextContent('SR');
    expect(session.getState().name).toBe('Sam Rivera');
  });

  it('follows a rename', async () => {
    open('/vault');
    expect(await screen.findByRole('button', { name: 'Account menu for Sam Rivera' })).toBeInTheDocument();
    act(() => session.renamed('Alex Chen'));
    expect(await screen.findByRole('button', { name: 'Account menu for Alex Chen' })).toHaveTextContent('AC');
  });

  it('closes after a choice, with a click outside and with Escape', async () => {
    const router = open('/vault');
    const user = userEvent.setup();
    const avatar = await screen.findByRole('button', { name: 'Account menu for Sam Rivera' });

    await user.click(avatar);
    await user.click(screen.getByRole('link', { name: 'Profile' }));
    expect(await screen.findByText('The profile')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/profile');
    expect(screen.queryByRole('navigation', { name: 'Account' })).toBeNull();

    await user.click(avatar);
    expect(screen.getByRole('navigation', { name: 'Account' })).toBeInTheDocument();
    await user.click(document.body);
    expect(screen.queryByRole('navigation', { name: 'Account' })).toBeNull();

    await user.click(avatar);
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('navigation', { name: 'Account' })).toBeNull();
    expect(avatar).toHaveFocus();
  });

  it('marks Profile as the page being shown', async () => {
    open('/profile');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Account menu for Sam Rivera' }));
    expect(screen.getByRole('link', { name: 'Profile' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Security' })).not.toHaveAttribute('aria-current');
  });

  it('locks the vault and leads to the unlock screen', async () => {
    const router = open('/vault');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Account menu for Sam Rivera' }));
    await user.click(screen.getByRole('button', { name: 'Lock the vault' }));
    expect(await screen.findByText('The unlock screen')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/unlock');
    expect(session.getState().status).toBe('locked');
  });

  it('signs out and leads to the sign-in screen', async () => {
    const router = open('/vault');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Account menu for Sam Rivera' }));
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('The sign-in screen')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/sign-in');
    expect(session.getState().status).toBe('signed-out');
  });
});

describe('the admin console', () => {
  it('has its own avatar menu: My Vault, About, Sign out', async () => {
    open('/admin', { admin: true });
    const user = userEvent.setup();
    expect(await screen.findByText('The overview')).toBeInTheDocument();
    const avatar = screen.getByRole('button', { name: 'Account menu for Sam Rivera' });
    await user.click(avatar);
    const menu = screen.getByRole('navigation', { name: 'Account' });
    expect(screen.getByText('Admin · sam@example.org')).toBeInTheDocument();
    expect([...menu.querySelectorAll('a, button')].map((entry) => entry.textContent)).toEqual([
      'My Vault',
      'About',
      'Sign out',
    ]);
    expect(within(menu).getByRole('link', { name: 'My Vault' })).toHaveAttribute('href', '/vault');
  });

  it('no longer lists About in its sidebar, nor the old links in its header', async () => {
    open('/admin', { admin: true });
    const nav = await screen.findByRole('navigation', { name: 'Admin' });
    expect(within(nav).queryByRole('link', { name: 'About' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'About this server' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Open my vault' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Sign out of admin' })).toBeNull();
    expect(within(nav).getByRole('link', { name: 'Overview' })).toBeInTheDocument();
  });

  it('lists Custom fields under Settings, right after Server settings', async () => {
    open('/admin', { admin: true });
    const nav = await screen.findByRole('navigation', { name: 'Admin' });
    const names = within(nav)
      .getAllByRole('link')
      .map((link) => link.textContent ?? '');
    const settings = names.findIndex((name) => name.includes('Server settings'));
    expect(settings).toBeGreaterThan(-1);
    expect(names[settings + 1]).toContain('Custom fields');
    expect(within(nav).getByRole('link', { name: /Custom fields/ })).toHaveAttribute('href', '/admin/fields');
  });

  it('signs out from its menu', async () => {
    const router = open('/admin', { admin: true });
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Account menu for Sam Rivera' }));
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('The sign-in screen')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/sign-in');
  });
});
