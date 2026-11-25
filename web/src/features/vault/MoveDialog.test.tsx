import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from './vault';

const ME = '00000000-0000-4000-8000-0000000000aa';
const SPACE_A = '00000000-0000-4000-8000-0000000000b1';
const SPACE_B = '00000000-0000-4000-8000-0000000000b2';
const ENGINEERING = '00000000-0000-4000-8000-0000000000c1';
const SHARED = '00000000-0000-4000-8000-0000000000c2';
const LOGIN = '00000000-0000-4000-8000-0000000000a1';
const CODE = '00000000-0000-4000-8000-0000000000a2';
const MOVED = '00000000-0000-4000-8000-0000000000ee';

const state = vi.hoisted(() => ({
  all: [] as VaultItem[],
  collections: [] as Array<{ spaceId: string; spaceName: string; collectionId: string; collectionName: string }>,
  pending: false,
  error: null as unknown,
  move: vi.fn(),
  navigate: vi.fn(),
}));

vi.mock('@/app/services', () => ({
  session: { getState: () => ({ userId: '00000000-0000-4000-8000-0000000000aa' }) },
}));
vi.mock('@tanstack/react-router', () => ({ useNavigate: () => state.navigate }));
vi.mock('./hooks', () => ({
  useVault: () => ({ all: state.all }),
  useCanWrite: () => (item: VaultItem) => item.owner.startsWith('user:'),
  useWritableCollections: () => ({ data: state.collections, isPending: false }),
  useVaultActions: () => ({ move: { mutate: state.move, isPending: state.pending, error: state.error } }),
}));

import { MoveDialog } from './MoveDialog';

function make(kind: string, data: Record<string, unknown>, extra: Partial<VaultItem> = {}): VaultItem {
  return {
    id: LOGIN,
    owner: `user:${ME}`,
    kind,
    revision: 3,
    keyVersion: 1,
    data,
    sizes: { ciphertext: 1, itemKey: 1 },
    ...extra,
  };
}

function open(item: VaultItem, all: VaultItem[] = [item]) {
  state.all = all;
  const onClose = vi.fn();
  renderWithIntl(<MoveDialog item={item} name={String(item.data?.['name'] ?? '')} onClose={onClose} />);
  return onClose;
}

beforeEach(() => {
  state.move.mockReset();
  state.navigate.mockReset();
  state.pending = false;
  state.error = null;
  state.collections = [
    { spaceId: SPACE_A, spaceName: 'Example Co', collectionId: ENGINEERING, collectionName: 'Engineering' },
    { spaceId: SPACE_B, spaceName: 'Family', collectionId: SHARED, collectionName: 'Shared logins' },
  ];
});

const confirm = () => screen.getByRole('button', { name: 'Move' });

describe('Move to a space', () => {
  it('is a dialog that offers every collection the person can add to', () => {
    open(make('login', { name: 'GitHub' }));
    const dialog = screen.getByRole('dialog', { name: 'Move to a space' });
    expect(dialog).toHaveTextContent('Choose where GitHub should be kept.');
    const radios = within(dialog).getAllByRole('radio');
    expect(radios.map((radio) => radio.closest('label')?.textContent)).toEqual([
      expect.stringContaining('Example Co: Engineering'),
      expect.stringContaining('Family: Shared logins'),
    ]);
    // The account's own vault is where it is, so it is not offered.
    expect(within(dialog).queryByText('My vault')).not.toBeInTheDocument();
    expect(radios[0]).toBeChecked();
  });

  it('moves it to the first place, with the items that link to it, and goes to it', async () => {
    const login = make('login', { name: 'GitHub', links: [{ id: CODE }] });
    const code = make('otp', { name: 'GitHub code', links: [{ id: LOGIN }] }, { id: CODE });
    state.move.mockImplementation((_input: unknown, options: { onSuccess: (item: unknown) => void }) => options.onSuccess({ id: MOVED }));
    const onClose = open(login, [login, code]);
    await userEvent.setup().click(confirm());
    expect(state.move).toHaveBeenCalledWith(
      { item: login, target: { owner: `space:${SPACE_A}`, collectionId: ENGINEERING }, linked: [code] },
      expect.any(Object),
    );
    expect(onClose).toHaveBeenCalledOnce();
    expect(state.navigate).toHaveBeenCalledWith({ to: '/vault/$itemId', params: { itemId: MOVED }, replace: true });
  });

  it('moves it where the person chose', async () => {
    const login = make('login', { name: 'GitHub' });
    open(login);
    const user = userEvent.setup();
    await user.click(screen.getByRole('radio', { name: /Family: Shared logins/ }));
    await user.click(confirm());
    expect(state.move.mock.calls[0]?.[0]).toMatchObject({ target: { owner: `space:${SPACE_B}`, collectionId: SHARED } });
  });

  it('offers the account\'s own vault, and the other collections, for an item that is in a space', async () => {
    const inSpace = make('login', { name: 'Wiki' }, { owner: `space:${SPACE_A}`, collectionId: ENGINEERING });
    open(inSpace);
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getAllByRole('radio').map((radio) => radio.closest('label')?.textContent)).toEqual([
      expect.stringContaining('My vault'),
      expect.stringContaining('Family: Shared logins'),
    ]);
    await userEvent.setup().click(confirm());
    expect(state.move.mock.calls[0]?.[0]).toMatchObject({ target: { owner: `user:${ME}` } });
  });

  it('does not rewrite the items the person may not change', async () => {
    const login = make('login', { name: 'GitHub', links: [{ id: CODE }] });
    const readOnly = make('otp', { name: 'Shared code', links: [{ id: LOGIN }] }, { id: CODE, owner: `space:${SPACE_B}`, collectionId: SHARED });
    open(login, [login, readOnly]);
    await userEvent.setup().click(confirm());
    expect(state.move.mock.calls[0]?.[0]).toMatchObject({ linked: [] });
  });

  it('says a file cannot move, and offers no place', () => {
    open(make('file', { name: 'Lease', file: { name: 'a.pdf', size: 1, key: 'k', kemlockFile: 'f' } }));
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('This item holds a file.');
    expect(within(dialog).queryByRole('radio')).not.toBeInTheDocument();
    expect(confirm()).toBeDisabled();
  });

  it('says so when there is nowhere else to move it to', () => {
    state.collections = [];
    open(make('login', { name: 'GitHub' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('There is nowhere else to move this item to.');
    expect(confirm()).toBeDisabled();
  });

  it('shows why a move failed, and stays open', () => {
    state.error = new Error('refused');
    open(make('login', { name: 'GitHub' }));
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('cannot be closed or sent again while it is moving', () => {
    state.pending = true;
    open(make('login', { name: 'GitHub' }));
    expect(confirm()).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });

  it('closes with Cancel or Escape and moves nothing', async () => {
    const onClose = open(make('login', { name: 'GitHub' }));
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(2));
    expect(state.move).not.toHaveBeenCalled();
  });
});
