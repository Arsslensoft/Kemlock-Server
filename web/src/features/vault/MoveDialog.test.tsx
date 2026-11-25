import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { quotaError } from '@/test/fake-files';
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
  canWrite: (item: VaultItem) => item.owner.startsWith('user:'),
  move: vi.fn(),
  navigate: vi.fn(),
}));

vi.mock('@/app/services', () => ({
  session: { getState: () => ({ userId: '00000000-0000-4000-8000-0000000000aa' }) },
}));
vi.mock('@tanstack/react-router', () => ({ useNavigate: () => state.navigate }));
vi.mock('./hooks', () => ({
  useVault: () => ({ all: state.all }),
  useCanWrite: () => (item: VaultItem) => state.canWrite(item),
  useWritableCollections: () => ({ data: state.collections, isPending: false }),
  useVaultActions: () => ({ move: { mutateAsync: state.move, isPending: state.pending, error: state.error } }),
}));

import { MAX_RELINKS } from './move';
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
  state.move.mockResolvedValue({ id: MOVED });
  state.navigate.mockReset();
  state.navigate.mockResolvedValue(undefined);
  state.pending = false;
  state.error = null;
  state.canWrite = (item) => item.owner.startsWith('user:');
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

  it('moves it to the first place, with the items that link to it, then goes to it, then closes', async () => {
    const login = make('login', { name: 'GitHub', links: [{ id: CODE }] });
    const code = make('otp', { name: 'GitHub code', links: [{ id: LOGIN }] }, { id: CODE });
    const onClose = open(login, [login, code]);
    await userEvent.setup().click(confirm());
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(state.move).toHaveBeenCalledWith({
      item: login,
      target: { owner: `space:${SPACE_A}`, collectionId: ENGINEERING },
      linked: [code],
      writable: true,
    });
    expect(state.navigate).toHaveBeenCalledWith({ to: '/vault/$itemId', params: { itemId: MOVED }, replace: true });
    // The page it goes to comes first: closing first would leave the dialog's page for an id that is gone.
    expect(state.navigate.mock.invocationCallOrder[0]).toBeLessThan(onClose.mock.invocationCallOrder[0] ?? 0);
  });

  it('counts the code the importer linked to a login among the items to rewrite', async () => {
    const login = make('login', { name: 'GitHub' });
    const code = make('otp', { name: 'GitHub code', linkedLoginId: LOGIN }, { id: CODE });
    open(login, [login, code]);
    await userEvent.setup().click(confirm());
    await waitFor(() => expect(state.move).toHaveBeenCalled());
    expect(state.move.mock.calls[0]?.[0].linked).toEqual([code]);
  });

  it('moves it where the person chose', async () => {
    open(make('login', { name: 'GitHub' }));
    const user = userEvent.setup();
    await user.click(screen.getByRole('radio', { name: /Family: Shared logins/ }));
    await user.click(confirm());
    await waitFor(() => expect(state.move).toHaveBeenCalled());
    expect(state.move.mock.calls[0]?.[0]).toMatchObject({ target: { owner: `space:${SPACE_B}`, collectionId: SHARED } });
  });

  it("offers the account's own vault, and the other collections, for an item that is in a space", async () => {
    const inSpace = make('login', { name: 'Wiki' }, { owner: `space:${SPACE_A}`, collectionId: ENGINEERING });
    state.canWrite = () => true;
    open(inSpace);
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getAllByRole('radio').map((radio) => radio.closest('label')?.textContent)).toEqual([
      expect.stringContaining('My vault'),
      expect.stringContaining('Family: Shared logins'),
    ]);
    await userEvent.setup().click(confirm());
    await waitFor(() => expect(state.move).toHaveBeenCalled());
    expect(state.move.mock.calls[0]?.[0]).toMatchObject({ target: { owner: `user:${ME}` } });
  });

  it('does not rewrite the items the person may not change', async () => {
    const login = make('login', { name: 'GitHub', links: [{ id: CODE }] });
    const readOnly = make('otp', { name: 'Shared code', links: [{ id: LOGIN }] }, { id: CODE, owner: `space:${SPACE_B}`, collectionId: SHARED });
    open(login, [login, readOnly]);
    await userEvent.setup().click(confirm());
    await waitFor(() => expect(state.move).toHaveBeenCalled());
    expect(state.move.mock.calls[0]?.[0]).toMatchObject({ linked: [] });
  });

  it('stays open when the move fails, and shows why', async () => {
    const error = new Error('refused');
    state.move.mockRejectedValue(error);
    state.error = error;
    const onClose = open(make('login', { name: 'GitHub' }));
    await userEvent.setup().click(confirm());
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    await waitFor(() => expect(state.move).toHaveBeenCalled());
    expect(state.navigate).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});

describe('an item that holds a file', () => {
  const lease = () => make('file', { name: 'Lease', file: { name: 'a.pdf', size: 1, key: 'k', kemlockFile: 'f' } });

  it('can move: its file goes with it', async () => {
    open(lease());
    expect(screen.queryByText(/This item holds a file/)).not.toBeInTheDocument();
    expect(screen.getAllByRole('radio')).toHaveLength(2);
    expect(confirm()).toBeEnabled();
    await userEvent.setup().click(confirm());
    await waitFor(() => expect(state.move).toHaveBeenCalled());
  });

  it('says it is moving the files while it does, and cannot be sent again or closed', () => {
    state.pending = true;
    open(lease());
    expect(screen.getByRole('status')).toHaveTextContent('Moving files…');
    expect(confirm()).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });

  it('says nothing about files for an item with none', () => {
    state.pending = true;
    open(make('login', { name: 'GitHub' }));
    expect(screen.queryByText('Moving files…')).not.toBeInTheDocument();
  });

  it('says so when the files would take the person over their attachment space', () => {
    state.error = quotaError('storage-limit-exceeded');
    open(lease());
    expect(screen.getByRole('alert')).toHaveTextContent('These files would take you over your attachment space.');
  });

  it('says so when file storage is switched off', () => {
    state.error = quotaError('storage-disabled', 403);
    open(lease());
    expect(screen.getByRole('alert')).toHaveTextContent('file storage off');
  });
});

describe('what cannot move', () => {
  it('keeps a contact in the account\'s own vault: no space is offered, and it says why', () => {
    open(make('contact', { name: 'Ada' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).queryByRole('radio')).not.toBeInTheDocument();
    expect(dialog).toHaveTextContent('A contact stays in your own vault, so it can\'t move to a space.');
    expect(confirm()).toBeDisabled();
  });

  it('lets a contact that is in a space come home', async () => {
    state.canWrite = () => true;
    open(make('contact', { name: 'Ada' }, { owner: `space:${SPACE_A}`, collectionId: ENGINEERING }));
    expect(screen.getAllByRole('radio')).toHaveLength(1);
    expect(screen.getByRole('radio', { name: /My vault/ })).toBeChecked();
    await userEvent.setup().click(confirm());
    await waitFor(() => expect(state.move).toHaveBeenCalled());
  });

  it('refuses an item the person may only read, and says so', () => {
    state.canWrite = () => false;
    open(make('login', { name: 'Shared' }, { owner: `space:${SPACE_A}`, collectionId: ENGINEERING }));
    expect(screen.getByRole('dialog')).toHaveTextContent("You can read this item but not change it, so it can't be moved.");
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    expect(confirm()).toBeDisabled();
  });

  it('refuses an item in the Trash', () => {
    open(make('login', { name: 'Old', trashedAt: '2026-11-01T00:00:00.000Z' }));
    expect(screen.getByRole('dialog')).toHaveTextContent("This item can't be moved right now.");
    expect(confirm()).toBeDisabled();
  });

  it('refuses a move that would rewrite more links than one batch holds', () => {
    const login = make('login', { name: 'Hub' });
    const crowd = Array.from({ length: MAX_RELINKS + 1 }, (_, i) =>
      make('note', { name: `n${i}`, links: [{ id: LOGIN }] }, { id: `00000000-0000-4000-8000-${String(1000 + i).padStart(12, '0')}` }),
    );
    open(login, [login, ...crowd]);
    expect(screen.getByRole('dialog')).toHaveTextContent('Too many items link to this one');
    expect(confirm()).toBeDisabled();
  });

  it('says so when there is nowhere else to move it to', () => {
    state.collections = [];
    open(make('login', { name: 'GitHub' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('There is nowhere else to move this item to.');
    expect(confirm()).toBeDisabled();
  });

  it('cannot be closed while it is moving', () => {
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
