import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from './vault';

const ME = '00000000-0000-4000-8000-0000000000aa';
const LOGIN = '00000000-0000-4000-8000-0000000000a1';
const CODE = '00000000-0000-4000-8000-0000000000a2';

const state = vi.hoisted(() => ({
  item: undefined as VaultItem | undefined,
  all: [] as VaultItem[],
  collections: [] as Array<{ spaceId: string; spaceName: string; collectionId: string; collectionName: string }>,
  adminFields: [] as Array<{ id: string; name: string; type: string; kinds: string | string[] }>,
  canWrite: (_item: VaultItem): boolean => true,
  trashing: false,
  trash: vi.fn(),
  restore: vi.fn(),
  link: vi.fn(),
  move: vi.fn(),
  navigate: vi.fn(),
  backToList: vi.fn(),
}));

vi.mock('@/app/services', () => ({
  api: { raw: vi.fn() },
  session: { getState: () => ({ userId: '00000000-0000-4000-8000-0000000000aa' }) },
}));
vi.mock('./backNav', () => ({ useBackToList: () => state.backToList }));
vi.mock('./hooks', () => ({
  useVaultItem: () => ({ item: state.item, isLoading: false }),
  useVault: () => ({ all: state.all }),
  useCanWrite: () => (item: VaultItem) => state.canWrite(item),
  useAdminFields: () => state.adminFields,
  itemFiles: { download: vi.fn() },
  useWritableCollections: () => ({ data: state.collections, isPending: false }),
  useVaultActions: () => ({
    trash: { mutate: state.trash, isPending: state.trashing, error: null },
    restore: { mutate: state.restore, isPending: false, error: null },
    link: { mutateAsync: state.link },
    move: { mutate: state.move, isPending: false, error: null },
  }),
}));
vi.mock('@tanstack/react-router', async () => {
  const { createElement } = await import('react');
  return {
    getRouteApi: () => ({ useParams: () => ({ itemId: state.item?.id ?? '' }) }),
    useNavigate: () => state.navigate,
    Link: ({
      to,
      params,
      children,
      className,
      onClick,
    }: {
      to: string;
      params?: { itemId: string };
      children: unknown;
      className?: string;
      onClick?: () => void;
    }) => createElement('a', { href: to.replace('$itemId', params?.itemId ?? ''), className, onClick }, children as never),
  };
});

import Item from './Item';

function make(kind: string, data: Record<string, unknown> | null, extra: Partial<VaultItem> = {}): VaultItem {
  return {
    id: LOGIN,
    owner: `user:${ME}`,
    kind,
    revision: 14,
    keyVersion: 3,
    data,
    sizes: { ciphertext: 1214, itemKey: 1648 },
    ...extra,
  };
}

const github = {
  name: 'GitHub',
  username: 'sam@example.org',
  password: 'hunter2',
  urls: ['https://github.com'],
  notes: 'Personal account.',
  updatedAt: Date.now() - 2 * 3600 * 1000,
  fields: [
    { name: 'Security question', value: 'blue', kind: 'hidden', adminField: 'q1' },
    { name: 'Recovery email', value: 'sam.backup@example.org', kind: 'text' },
  ],
};

function show(item: VaultItem, all: VaultItem[] = [item]) {
  state.item = item;
  state.all = all;
  renderWithIntl(<Item />);
}

const moreButton = () => screen.getByRole('button', { name: 'More actions for GitHub' });

beforeEach(() => {
  for (const fn of [state.trash, state.restore, state.link, state.move, state.navigate, state.backToList]) fn.mockReset();
  state.collections = [];
  state.adminFields = [];
  state.canWrite = () => true;
  state.trashing = false;
});

describe('the item page header', () => {
  it('has Edit as its only main button, and a ⋯ menu', () => {
    show(make('login', github));
    expect(screen.getByRole('link', { name: 'Edit' })).toHaveAttribute('href', `/vault/${LOGIN}/edit`);
    expect(screen.getByRole('heading', { level: 1, name: 'GitHub' })).toBeInTheDocument();
    // Everything else is behind the ⋯ button: no Trash or Websites button on the page.
    expect(screen.queryByRole('button', { name: 'Move to Trash' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Websites and rules' })).not.toBeInTheDocument();
    expect(moreButton()).toBeInTheDocument();
  });

  it('has no End-to-end encrypted card: the lock beside the title carries the text', () => {
    show(make('login', github));
    expect(screen.queryByRole('region', { name: 'End-to-end encrypted' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'End-to-end encrypted' })).not.toBeInTheDocument();
    const lock = screen.getByRole('button', { name: 'End-to-end encrypted' });
    expect(lock.closest('.title-row')).toContainElement(screen.getByRole('heading', { level: 1 }));
    expect(lock).toHaveAccessibleDescription(/Encrypted on the device that saved it/);
  });

  it('has no What the server holds card either', () => {
    show(make('login', github));
    expect(screen.queryByRole('region', { name: 'What the server holds' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('server-record')).not.toBeInTheDocument();
  });

  it('shows Restore, and no Edit, for an item in the Trash, with only the server record in the menu', async () => {
    show(make('login', { ...github, trashedAt: '2026-11-20T00:00:00.000Z' }));
    expect(screen.getByRole('button', { name: 'Restore' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Edit' })).not.toBeInTheDocument();
    await userEvent.setup().click(moreButton());
    expect(await screen.findAllByRole('menuitem')).toHaveLength(1);
    expect(screen.getByRole('menuitem', { name: 'What the server holds' })).toBeInTheDocument();
  });
});

describe('the ⋯ menu on the page', () => {
  it('offers websites and rules for a login only', async () => {
    const user = userEvent.setup();
    show(make('login', github));
    await user.click(moreButton());
    expect(await screen.findByRole('menuitem', { name: 'Websites and rules' })).toBeInTheDocument();
  });

  it('leaves websites out for other kinds, and offers no copy of a passkey', async () => {
    const user = userEvent.setup();
    show(make('passkey', { name: 'GitHub', rpId: 'github.com' }));
    expect(screen.queryByRole('link', { name: 'Edit' })).not.toBeInTheDocument();
    await user.click(moreButton());
    await screen.findByRole('menu');
    expect(screen.queryByRole('menuitem', { name: 'Websites and rules' })).not.toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Make a copy' })).not.toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: 'Move to a space' })).toBeInTheDocument();
  });

  it('opens the websites page', async () => {
    const user = userEvent.setup();
    show(make('login', github));
    await user.click(moreButton());
    await user.click(await screen.findByRole('menuitem', { name: 'Websites and rules' }));
    await waitFor(() => expect(state.navigate).toHaveBeenCalledWith({ to: '/vault/$itemId/websites', params: { itemId: LOGIN } }));
  });

  it('opens the create form for a copy', async () => {
    const user = userEvent.setup();
    show(make('login', github));
    await user.click(moreButton());
    await user.click(await screen.findByRole('menuitem', { name: 'Make a copy' }));
    await waitFor(() =>
      expect(state.navigate).toHaveBeenCalledWith({ to: '/vault/new', search: { kind: 'login', copyOf: LOGIN } }),
    );
  });

  it('moves the item to the Trash from the red entry, then goes back to the list', async () => {
    const user = userEvent.setup();
    const item = make('login', github);
    state.trash.mockImplementation((_item: VaultItem, options: { onSuccess: () => void }) => options.onSuccess());
    show(item);
    await user.click(moreButton());
    await user.click(await screen.findByRole('menuitem', { name: 'Move to Trash' }));
    await waitFor(() => expect(state.trash).toHaveBeenCalledWith(item, expect.objectContaining({ onSuccess: expect.any(Function) })));
    expect(state.backToList).toHaveBeenCalledOnce();
  });
});

describe('What the server holds, in a dialog', () => {
  it('opens from the menu with the record, and Close gives focus back to the ⋯ button', async () => {
    const user = userEvent.setup();
    show(make('login', github));
    await user.click(moreButton());
    await user.click(await screen.findByRole('menuitem', { name: 'What the server holds' }));
    const dialog = await screen.findByRole('dialog', { name: 'What the server holds' });
    expect(within(dialog).getByTestId('server-record')).toHaveTextContent('revision 14 · key version 3');
    expect(within(dialog).getByTestId('server-record')).toHaveTextContent('key 1648 B wrapped');
    expect(within(dialog).getByTestId('server-record')).toHaveTextContent('body AES-256-GCM, 1214 B');
    expect(within(dialog).getByTestId('server-record')).toHaveTextContent(`owner user:${ME}`);
    // The note sits in the dialog, with nothing of the item's own content.
    expect(dialog).toHaveTextContent('No name, address, password or note.');
    expect(dialog).not.toHaveTextContent('hunter2');

    await user.click(within(dialog).getAllByRole('button', { name: 'Close' })[1] as HTMLElement);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(moreButton()).toHaveFocus());
  });

  it('closes on Escape and gives focus back too', async () => {
    const user = userEvent.setup();
    show(make('login', github));
    await user.click(moreButton());
    await user.click(await screen.findByRole('menuitem', { name: 'What the server holds' }));
    await screen.findByRole('dialog');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(moreButton()).toHaveFocus());
  });
});

describe('the first section', () => {
  it('ends a login\'s Sign-in card with its custom fields, right after Website', () => {
    show(make('login', github));
    const card = screen.getByRole('region', { name: 'Sign-in' });
    const labels = Array.from(card.querySelectorAll('.lbl')).map((node) => node.textContent);
    expect(labels).toEqual(['Username', 'Password', 'Website', 'Security questionAdmin', 'Recovery email']);
  });

  it('masks a hidden field, with show and copy, and tags the admin\'s field', async () => {
    const user = userEvent.setup();
    show(make('login', github));
    const card = screen.getByRole('region', { name: 'Sign-in' });
    expect(within(card).queryByText('blue')).not.toBeInTheDocument();
    expect(within(card).getByText('Admin')).toBeInTheDocument();
    expect(within(card).getByText('sam.backup@example.org')).toBeInTheDocument();
    await user.click(within(card).getByRole('button', { name: 'Show the Security question' }));
    expect(within(card).getByText('blue')).toBeInTheDocument();
    expect(within(card).getByRole('button', { name: 'Copy the Security question' })).toBeInTheDocument();
  });

  it('puts them in the card of another kind too', () => {
    const fields = [{ name: 'Employee ID', value: '42', kind: 'text', adminField: 'e1' }];
    show(make('card', { name: 'Visa', number: '4111111111111111', fields }));
    const card = screen.getByRole('region', { name: 'Card' });
    expect(within(card).getByText('Employee ID')).toBeInTheDocument();
    expect(within(card).getByText('42')).toBeInTheDocument();
  });

  it('shows a note\'s text, its custom fields and its attachments', () => {
    show(
      make('note', {
        name: 'GitHub',
        text: 'Wi-Fi: hunter2',
        fields: [{ name: 'Room', value: '12', kind: 'text' }],
        attachments: [{ name: 'map.png', size: 1_500, type: 'image/png', key: 'k', kemlockFile: 'f1' }],
      }),
    );
    const text = screen.getByRole('region', { name: 'Text' });
    expect(text).toHaveTextContent('Wi-Fi: hunter2');
    expect(text).toHaveTextContent('Room');
    expect(screen.getByRole('region', { name: 'Attachments' })).toHaveTextContent('Image · 2 KB');
  });
});

describe('every kind renders', () => {
  const kinds: Array<[string, string, Record<string, unknown>]> = [
    ['login', 'Sign-in', github],
    ['note', 'Text', { name: 'GitHub', text: 'hello' }],
    ['file', 'File', { name: 'GitHub', file: { name: 'a.pdf', size: 10, key: 'k', kemlockFile: 'f' } }],
    ['otp', 'MFA code', { name: 'GitHub', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' }],
    ['backup-codes', 'Backup codes', { name: 'GitHub', codes: [{ code: 'aaaa' }] }],
    ['passkey', 'Passkey', { name: 'GitHub', rpId: 'github.com' }],
    ['card', 'Card', { name: 'GitHub', number: '4111111111111111' }],
    ['identity', 'Identity', { name: 'GitHub', givenName: 'Ada' }],
    ['contact', 'Contact', { name: 'GitHub', email: 'ada@example.org' }],
    ['certificate', 'Certificate', { name: 'GitHub', certificate: 'nope' }],
    ['ssh-key', 'SSH key', { name: 'GitHub', algorithm: 'ed25519' }],
    ['pgp-key', 'PGP key', { name: 'GitHub' }],
  ];
  it.each(kinds)('%s shows its card, the Linked items card and the menu', (kind, card, data) => {
    show(make(kind, data));
    expect(screen.getByRole('region', { name: card })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Linked items' })).toBeInTheDocument();
    expect(moreButton()).toBeInTheDocument();
  });
});

describe('the Linked items card on the page', () => {
  it('lists the linked items and links to them', () => {
    const login = make('login', { ...github, links: [{ id: CODE }] });
    const code = make('otp', { name: 'GitHub code', period: 30, links: [{ id: LOGIN }] }, { id: CODE });
    show(login, [login, code]);
    const card = screen.getByRole('region', { name: 'Linked items' });
    expect(within(card).getByRole('link', { name: /GitHub code/ })).toHaveAttribute('href', `/vault/${CODE}`);
  });

  it('writes the link through the batch of both items', async () => {
    const user = userEvent.setup();
    const login = make('login', github);
    const code = make('otp', { name: 'GitHub code' }, { id: CODE });
    state.link.mockResolvedValue(undefined);
    show(login, [login, code]);
    await user.click(screen.getByRole('button', { name: 'Link an item' }));
    await user.click(await screen.findByRole('button', { name: 'Link GitHub code' }));
    await waitFor(() => expect(state.link).toHaveBeenCalledWith({ a: login, b: code, linked: true }));
  });

  it('unlinks both ends', async () => {
    const user = userEvent.setup();
    const login = make('login', { ...github, links: [{ id: CODE }] });
    const code = make('otp', { name: 'GitHub code', links: [{ id: LOGIN }] }, { id: CODE });
    state.link.mockResolvedValue(undefined);
    show(login, [login, code]);
    await user.click(screen.getByRole('button', { name: 'Unlink GitHub code' }));
    await waitFor(() => expect(state.link).toHaveBeenCalledWith({ a: login, b: code, linked: false }));
  });
});

describe('an item that cannot be read', () => {
  it('says so, offers no Edit and no links to change, and has only What the server holds in its menu', async () => {
    show(make('login', null));
    expect(screen.getByText(/This app can't read this item/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Link an item' })).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'More actions for login' }));
    const entries = await screen.findAllByRole('menuitem');
    expect(entries.map((entry) => entry.textContent)).toEqual(['What the server holds']);
  });
});

describe('an item this person may only read', () => {
  beforeEach(() => {
    state.canWrite = () => false;
  });

  it('has no Edit, and a menu with a copy and the server record but no Move or Trash', async () => {
    show(make('login', github, { owner: 'space:00000000-0000-4000-8000-0000000000bb', collectionId: '00000000-0000-4000-8000-0000000000cc' }));
    expect(screen.queryByRole('link', { name: 'Edit' })).not.toBeInTheDocument();
    await userEvent.setup().click(moreButton());
    const entries = await screen.findAllByRole('menuitem');
    expect(entries.map((entry) => entry.textContent)).toEqual(['Make a copy', 'What the server holds']);
  });

  it('says it is read-only, and offers no way to link or unlink', () => {
    const login = make('login', { ...github, links: [{ id: CODE }] });
    const code = make('otp', { name: 'GitHub code', links: [{ id: LOGIN }] }, { id: CODE });
    show(login, [login, code]);
    expect(screen.getByText(/You can read this item but not change it/)).toBeInTheDocument();
    const card = screen.getByRole('region', { name: 'Linked items' });
    expect(within(card).getByRole('link', { name: /GitHub code/ })).toBeInTheDocument();
    expect(within(card).queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows no Restore for a read-only item in the Trash', () => {
    show(make('login', { ...github, trashedAt: '2026-11-20T00:00:00.000Z' }));
    expect(screen.queryByRole('button', { name: 'Restore' })).not.toBeInTheDocument();
  });

  it('says nothing about it for an item the person can change', () => {
    state.canWrite = () => true;
    show(make('login', github));
    expect(screen.queryByText(/You can read this item but not change it/)).not.toBeInTheDocument();
  });
});

describe('the websites', () => {
  it('lists the websites of a login wherever its body keeps them', () => {
    show(make('login', { name: 'GitHub', username: 'sam', uris: [{ uri: 'https://github.com' }, { uri: 'example.co', match: 1 }] }));
    const card = screen.getByRole('region', { name: 'Sign-in' });
    expect(within(card).getByRole('link', { name: 'github.com' })).toHaveAttribute('href', 'https://github.com');
    expect(within(card).getByText('example.co')).toBeInTheDocument();
  });

  it('gives an MFA code a Website row from its linked login, read-only, before its custom fields', () => {
    const login = make('login', { ...github, links: [{ id: CODE }] });
    const code = make(
      'otp',
      { name: 'GitHub code', links: [{ id: LOGIN }], fields: [{ name: 'Seat', value: '12', kind: 'text' }] },
      { id: CODE },
    );
    show(code, [login, code]);
    const card = screen.getByRole('region', { name: 'MFA code' });
    const labels = Array.from(card.querySelectorAll('.lbl')).map((node) => node.textContent);
    expect(labels.slice(-2)).toEqual(['Website', 'Seat']);
    expect(within(card).getByRole('link', { name: 'github.com' })).toBeInTheDocument();
    expect(card).toHaveTextContent('From the linked login GitHub. Change it there.');
  });

  it('gives backup codes their own websites, with no note about a login', () => {
    show(make('backup-codes', { name: 'Recovery', codes: [{ code: 'aaaa' }], urls: ['https://own.example'] }));
    const card = screen.getByRole('region', { name: 'Backup codes' });
    expect(within(card).getByRole('link', { name: 'own.example' })).toBeInTheDocument();
    expect(card).not.toHaveTextContent('From the linked login');
  });

  it('shows no Website row for a code with no websites and no login', () => {
    show(make('otp', { name: 'Code', secret: 'JBSWY3DPEHPK3PXP' }));
    expect(screen.queryByText('Website')).not.toBeInTheDocument();
  });
});

describe('the fields of the admin', () => {
  it('shows the name and type the admin has now, with the Admin tag', async () => {
    state.adminFields = [{ id: 'q1', name: 'Security prompt', type: 'hidden', kinds: 'all' }];
    show(make('login', github));
    const card = screen.getByRole('region', { name: 'Sign-in' });
    expect(within(card).getByText('Security prompt')).toBeInTheDocument();
    expect(within(card).queryByText('Security question')).not.toBeInTheDocument();
    await userEvent.setup().click(within(card).getByRole('button', { name: 'Show the Security prompt' }));
    expect(within(card).getByText('blue')).toBeInTheDocument();
  });
});

describe('moving to the Trash', () => {
  it('cannot be asked while it is already going', async () => {
    state.trashing = true;
    show(make('login', github));
    await userEvent.setup().click(moreButton());
    expect(await screen.findByRole('menuitem', { name: 'Move to Trash' })).toHaveAttribute('aria-disabled', 'true');
  });
});

describe('What the server holds for an item in a collection', () => {
  it('names the collection', async () => {
    const user = userEvent.setup();
    show(make('login', github, { owner: 'space:00000000-0000-4000-8000-0000000000bb', collectionId: '00000000-0000-4000-8000-0000000000cc' }));
    await user.click(moreButton());
    await user.click(await screen.findByRole('menuitem', { name: 'What the server holds' }));
    expect(await screen.findByTestId('server-record')).toHaveTextContent('collection 00000000-0000-4000-8000-0000000000cc');
  });
});
