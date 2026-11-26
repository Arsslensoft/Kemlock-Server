import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NO_DEFINITIONS } from '@/api/customFields';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from './vault';

const ME = '00000000-0000-4000-8000-0000000000aa';
const SPACE = '00000000-0000-4000-8000-0000000000bb';
const COLLECTION = '00000000-0000-4000-8000-0000000000cc';
const SOURCE = '00000000-0000-4000-8000-0000000000a1';
const NEW_ID = '00000000-0000-4000-8000-0000000000e1';

const state = vi.hoisted(() => ({
  item: undefined as VaultItem | undefined,
  itemId: undefined as string | undefined,
  search: {} as { kind?: string; copyOf?: string },
  collections: [] as Array<{ spaceId: string; spaceName: string; collectionId: string; collectionName: string }>,
  save: vi.fn(),
  remove: vi.fn(),
  navigate: vi.fn(),
}));

vi.mock('@/app/services', () => ({
  session: { getState: () => ({ userId: '00000000-0000-4000-8000-0000000000aa' }) },
}));
vi.mock('./hooks', () => ({
  itemFiles: {},
  useVault: () => ({ active: [] }),
  useCanWrite: () => () => true,
  useCustomFieldDefinitions: () => NO_DEFINITIONS,
  useVaultItem: (id: string | undefined) => ({ item: id === undefined ? undefined : state.item, isLoading: false }),
  useWritableCollections: () => ({ data: state.collections, isPending: false }),
  useVaultActions: () => ({
    save: { mutateAsync: state.save },
    remove: { mutateAsync: state.remove },
  }),
}));
vi.mock('@tanstack/react-router', async () => {
  const { createElement } = await import('react');
  return {
    useNavigate: () => state.navigate,
    useParams: () => ({ itemId: state.itemId }),
    useSearch: () => state.search,
    useRouter: () => ({ history: { back: vi.fn() } }),
    useCanGoBack: () => false,
    Link: ({ to, children, className }: { to: string; children: unknown; className?: string }) =>
      createElement('a', { href: to, className }, children as never),
  };
});

import NewItem from './NewItem';

function source(kind: string, data: Record<string, unknown> | null, extra: Partial<VaultItem> = {}): VaultItem {
  return {
    id: SOURCE,
    owner: `user:${ME}`,
    kind,
    revision: 4,
    keyVersion: 1,
    data,
    sizes: { ciphertext: 1, itemKey: 1 },
    ...extra,
  };
}

// What a login form does not own, and an app that knows more keeps.
const extras = {
  fields: [{ name: 'Employee ID', value: '42', kind: 'text', adminField: 'f1' }],
  tags: ['work'],
  someKeyAnotherAppWrote: { nested: true },
};

beforeEach(() => {
  for (const fn of [state.save, state.remove, state.navigate]) fn.mockReset();
  // A save answers with the item it made, as the vault does.
  state.save.mockImplementation(async (input: { kind: string; owner: string; fields: Record<string, unknown> }) => ({
    id: NEW_ID,
    owner: input.owner,
    kind: input.kind,
    revision: 1,
    keyVersion: 1,
    data: input.fields,
    sizes: { ciphertext: 1, itemKey: 1 },
  }));
  state.item = undefined;
  state.itemId = undefined;
  state.search = {};
  state.collections = [];
});

async function save() {
  await userEvent.setup().click(screen.getByRole('button', { name: 'Save' }));
}

describe('Make a copy', () => {
  it('saves a copy of a login with its custom fields, tags and unknown keys, and its name unchanged', async () => {
    state.item = source('login', {
      id: SOURCE,
      name: 'GitHub',
      username: 'sam@example.org',
      password: 'hunter2',
      urls: ['https://github.com'],
      links: [{ id: '00000000-0000-4000-8000-0000000000a9' }],
      ...extras,
    });
    state.search = { kind: 'login', copyOf: SOURCE };
    renderWithIntl(<NewItem />);
    expect(screen.getByRole('heading', { name: 'New login' })).toBeInTheDocument();
    expect(screen.getByLabelText('Name', { exact: true })).toHaveValue('GitHub');
    await save();
    await waitFor(() => expect(state.save).toHaveBeenCalledOnce());
    const [input] = state.save.mock.calls[0] ?? [];
    // A new item, not a new revision of the old: nothing it is edited from.
    expect(input).toMatchObject({ kind: 'login', owner: `user:${ME}` });
    expect(input.existing).toBeUndefined();
    expect(input.fields).toMatchObject({ name: 'GitHub', username: 'sam@example.org', password: 'hunter2', ...extras });
    // And nothing that names the old item.
    expect(input.fields).not.toHaveProperty('id');
    expect(input.fields).not.toHaveProperty('links');
  });

  it('saves a copy of a card with them too', async () => {
    state.item = source('card', {
      name: 'Visa',
      number: '4111111111111111',
      brand: 'Visa',
      expMonth: 5,
      expYear: 2029,
      ...extras,
    });
    state.search = { kind: 'card', copyOf: SOURCE };
    renderWithIntl(<NewItem />);
    await save();
    await waitFor(() => expect(state.save).toHaveBeenCalledOnce());
    const [input] = state.save.mock.calls[0] ?? [];
    expect(input).toMatchObject({ kind: 'card', entry: true });
    expect(input.existing).toBeUndefined();
    expect(input.fields).toMatchObject({ name: 'Visa', number: '4111111111111111', expMonth: 5, expYear: 2029, ...extras });
  });

  it('lets what the person changed win over what the item held', async () => {
    state.item = source('login', { name: 'GitHub', username: 'sam', password: 'pw', urls: ['https://github.com'], notes: 'old', ...extras });
    state.search = { kind: 'login', copyOf: SOURCE };
    renderWithIntl(<NewItem />);
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Name', { exact: true }));
    await user.type(screen.getByLabelText('Name', { exact: true }), 'GitHub work');
    await user.clear(screen.getByLabelText('Notes'));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(state.save).toHaveBeenCalledOnce());
    const [input] = state.save.mock.calls[0] ?? [];
    expect(input.fields).toMatchObject({ name: 'GitHub work', ...extras });
    // A cleared note is not kept from the source.
    expect(input.fields['notes']).toBeUndefined();
  });

  it('goes where the source is, when this person may write there, until they choose', async () => {
    state.item = source('login', { name: 'VPN', username: 'ops', password: 'pw', urls: [] }, { owner: `space:${SPACE}`, collectionId: COLLECTION });
    state.search = { kind: 'login', copyOf: SOURCE };
    state.collections = [{ spaceId: SPACE, spaceName: 'Example Co', collectionId: COLLECTION, collectionName: 'Engineering' }];
    renderWithIntl(<NewItem />);
    expect(screen.getByLabelText('Save to')).toHaveValue(`${SPACE}/${COLLECTION}`);
    await save();
    await waitFor(() => expect(state.save).toHaveBeenCalledOnce());
    expect(state.save.mock.calls[0]?.[0]).toMatchObject({ owner: `space:${SPACE}`, collectionId: COLLECTION });
  });

  it("goes to the account's own vault when the person may not write where the source is", () => {
    state.item = source('login', { name: 'VPN', username: 'ops', password: 'pw', urls: [] }, { owner: `space:${SPACE}`, collectionId: COLLECTION });
    state.search = { kind: 'login', copyOf: SOURCE };
    state.collections = [{ spaceId: SPACE, spaceName: 'Example Co', collectionId: '00000000-0000-4000-8000-0000000000dd', collectionName: 'Other' }];
    renderWithIntl(<NewItem />);
    expect(screen.getByLabelText('Save to')).toHaveValue('');
  });

  it("lists a note's files to be sent again, and leaves the original's file names out of the first save", async () => {
    state.item = source('note', {
      name: 'Wi-Fi',
      text: 'hunter2',
      attachments: [
        { id: 'a1', name: 'map.png', size: 3, key: 'k1', addedAt: 1, kemlockFile: 'old-1' },
        { id: 'a2', name: 'pending.txt', size: 9, key: 'k2', addedAt: 2 },
      ],
    });
    state.search = { kind: 'note', copyOf: SOURCE };
    renderWithIntl(<NewItem />);
    expect(screen.getByText('map.png')).toBeInTheDocument();
    expect(screen.getByText('pending.txt')).toBeInTheDocument();
    await save();
    // The files go up from the original once the copy exists: a save never names a file the server lacks.
    await waitFor(() => expect(state.save).toHaveBeenCalled());
    const [first] = state.save.mock.calls[0] ?? [];
    expect(first.existing).toBeUndefined();
    const named = (first.fields['attachments'] ?? []) as Array<Record<string, unknown>>;
    expect(named.map((entry) => entry['kemlockFile'])).not.toContain('old-1');
  });

  it('is a plain new item without a source, saved as one', async () => {
    state.search = { kind: 'login' };
    renderWithIntl(<NewItem />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Name', { exact: true }), 'Fresh');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(state.save).toHaveBeenCalledOnce());
    expect(state.save.mock.calls[0]?.[0].fields).toMatchObject({ name: 'Fresh' });
  });

  it('does not copy an item that could not be read, and says why', () => {
    state.item = source('login', null);
    state.search = { kind: 'login', copyOf: SOURCE };
    renderWithIntl(<NewItem />);
    expect(screen.getByText(/This app can't read this item/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
  });

  it('does not copy a passkey or a file', () => {
    for (const kind of ['passkey', 'file']) {
      state.item = source(kind, { name: 'Thing' });
      state.search = { kind, copyOf: SOURCE };
      const { unmount } = renderWithIntl(<NewItem />);
      expect(screen.getByRole('heading', { name: 'Item not found' })).toBeInTheDocument();
      unmount();
    }
  });
});

describe('Edit', () => {
  it('refuses an item that could not be read, with the reason, and offers no form', () => {
    state.item = source('login', null);
    state.itemId = SOURCE;
    renderWithIntl(<NewItem />);
    expect(screen.getByText(/This app can't read this item/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
  });

  it('opens one that can be read, filled in, and saves it as the same item', async () => {
    state.item = source('login', { name: 'GitHub', username: 'sam', password: 'pw', urls: ['https://github.com'], ...extras });
    state.itemId = SOURCE;
    renderWithIntl(<NewItem />);
    expect(screen.getByLabelText('Name', { exact: true })).toHaveValue('GitHub');
    await save();
    await waitFor(() => expect(state.save).toHaveBeenCalledOnce());
    expect(state.save.mock.calls[0]?.[0]).toMatchObject({ existing: state.item });
  });
});
