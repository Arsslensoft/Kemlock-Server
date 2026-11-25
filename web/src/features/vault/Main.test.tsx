// The list pages: All items and one page per type.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SPACE, login, renderInRouter, vaultItem } from '@/test/tools-fixtures';
import { FAMILY_ID, VAULTS } from '@/test/vault-fixtures';
import { ItemListView, type ItemListProps } from './Main';
import { KIND_ORDER } from './kinds';
import { filterItems } from './listFilters';
import type { VaultItem } from './vault';

/** The row of the item with this name: the row's own name joins the cells, so find it by its text. */
function rowOf(name: string): HTMLElement {
  const row = screen.getAllByRole('row').find((candidate) => within(candidate).queryByText(name) !== null);
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

const items: VaultItem[] = [
  login('GitHub', 'sam@example.org', 'pw', ['https://github.com'], { updatedAt: Date.now() - 2 * 3600_000 }),
  login('Netflix', 'family', 'pw', ['netflix.com'], {}, { owner: SPACE }),
  vaultItem('note', { name: 'Wi-Fi at home', text: 'words' }),
  vaultItem('note', { name: 'Lease', text: 'x' }, { owner: SPACE }),
  vaultItem('otp', { name: 'GitHub code', secret: 'JBSWY3DPEHPK3PXP', label: 'sam@example.org', period: 30 }),
  vaultItem('backup-codes', { name: 'GitHub recovery codes', codes: [{ code: 'a' }, { code: 'b', used: true }] }),
  vaultItem('file', { name: 'Passport scan.jpg', file: { name: 'Passport scan.jpg', size: 1_100_000 } }),
];

/** The view of `all` filtered the way the page does it. */
function props(overrides: Partial<ItemListProps> & { kind?: string | undefined; vault?: string } = {}): ItemListProps {
  const { kind, vault = 'all' } = overrides;
  const filtered = filterItems(items, { kind, vault });
  return {
    kind,
    vault,
    onVault: vi.fn(),
    vaults: VAULTS,
    rows: filtered,
    total: filtered.length,
    hasItems: items.length > 0,
    page: 1,
    pages: 1,
    onKind: vi.fn(),
    onPage: vi.fn(),
    facts: new Map(),
    ...overrides,
  };
}

describe('All items', () => {
  it('has its title, the gray line, the round lock and a chip for All items and every type', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    expect(screen.getByRole('heading', { name: 'All items', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Everything in your vault and in the spaces you belong to.')).toBeInTheDocument();
    const chips = screen.getByRole('group', { name: 'Filter by type' });
    expect(within(chips).getAllByRole('button').map((chip) => chip.textContent)).toEqual([
      'All items',
      'Logins',
      'Notes',
      'Files',
      'MFA codes',
      'Backup codes',
      'Passkeys',
      'Cards',
      'Identities',
      'Contacts',
      'Certificates',
      'SSH keys',
      'PGP keys',
    ]);
    expect(within(chips).getByRole('button', { name: 'All items' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('has the End-to-end encrypted lock, with the lists\' tooltip', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    const lock = screen.getByRole('button', { name: 'End-to-end encrypted' });
    expect(lock).toHaveAccessibleDescription(/Every item is encrypted on your devices first, with ML-KEM-1024 and X25519, then AES-256-GCM/);
    expect(screen.getByRole('tooltip')).toHaveTextContent("The server keeps ciphertext only and can't open any of it.");
  });

  it('asks for a type when a chip is pressed', async () => {
    const onKind = vi.fn();
    await renderInRouter(<ItemListView {...props({ onKind })} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'MFA codes' }));
    await user.click(screen.getByRole('button', { name: 'Backup codes' }));
    await user.click(screen.getByRole('button', { name: 'Files' }));
    expect(onKind.mock.calls.map(([kind]) => kind)).toEqual(['otp', 'backup-codes', 'file']);
  });

  it('has the Type and Vault columns, and says which vault each item is in', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
      'Name',
      'Type',
      'Vault',
      'Details',
      'Updated',
      'Actions',
    ]);
    expect(within(rowOf('GitHub')).getByText('Personal')).toBeInTheDocument();
    expect(within(rowOf('GitHub')).getByText('Login')).toBeInTheDocument();
    expect(within(rowOf('Netflix')).getByText('Family')).toBeInTheDocument();
  });

  it('calls an MFA code an MFA code, and lists files', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    expect(within(rowOf('GitHub code')).getByText('MFA code')).toBeInTheDocument();
    expect(within(rowOf('Passport scan.jpg')).getByText('File')).toBeInTheDocument();
  });

  it('shows a details line that tells items apart, and never a secret', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    expect(within(rowOf('GitHub')).getByText('github.com')).toBeInTheDocument();
    expect(within(rowOf('GitHub code')).getByText('sam@example.org · every 30 s')).toBeInTheDocument();
    expect(within(rowOf('GitHub recovery codes')).getByText('2 codes, 1 unused')).toBeInTheDocument();
    expect(within(rowOf('Passport scan.jpg')).getByText('JPG · 1.1 MB')).toBeInTheDocument();
    expect(screen.queryByText(/JBSWY3DP/)).not.toBeInTheDocument();
  });

  it('has a copy button for a login\'s password and an MFA code, and for nothing else', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    expect(screen.getByRole('button', { name: 'Copy the GitHub password' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the code for GitHub code' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /^Copy/ })).toHaveLength(3);
  });

  it('says "Showing N of M" in the footer', async () => {
    await renderInRouter(<ItemListView {...props()} />);
    expect(screen.getByText('Showing 7 of 7')).toBeInTheDocument();
  });
});

describe('a page for one type', () => {
  it.each([
    ['login', 'Logins', 'Usernames and passwords for websites and apps.'],
    ['note', 'Notes', 'Free text, kept encrypted like everything else.'],
    ['file', 'Files', 'Documents, photos and other files, encrypted before upload.'],
    ['otp', 'MFA codes', 'Codes for two-step sign-in, made right here.'],
    ['backup-codes', 'Backup codes', 'One-time codes that get you in when you lose your second step.'],
    ['ssh-key', 'SSH keys', 'Keys for signing in to servers.'],
    ['pgp-key', 'PGP keys', 'Keys for encrypting and signing email and files.'],
  ])('%s has its own title and gray line', async (kind, title, subtitle) => {
    await renderInRouter(<ItemListView {...props({ kind })} />);
    expect(screen.getByRole('heading', { name: title, level: 1 })).toBeInTheDocument();
    expect(screen.getByText(subtitle)).toBeInTheDocument();
  });

  it('has no type chips, whichever the type', async () => {
    for (const kind of KIND_ORDER) {
      const { unmount } = await renderInRouter(<ItemListView {...props({ kind })} />);
      expect(screen.queryByRole('group', { name: 'Filter by type' }), kind).not.toBeInTheDocument();
      unmount();
    }
  });

  it('lists only that type, with the Vault filter still above it', async () => {
    await renderInRouter(<ItemListView {...props({ kind: 'note' })} />);
    expect(screen.getAllByRole('row')).toHaveLength(3);
    expect(rowOf('Wi-Fi at home')).toBeInTheDocument();
    expect(screen.queryByText('GitHub')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Vault' })).toBeInTheDocument();
    expect(screen.getByText('Showing 2 of 2')).toBeInTheDocument();
  });

  it('calls a type this app has no name for "Items"', async () => {
    await renderInRouter(<ItemListView {...props({ kind: 'hologram' })} />);
    expect(screen.getByRole('heading', { name: 'Items', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('No matches')).toBeInTheDocument();
  });
});

describe('the Vault filter', () => {
  it('offers All vaults, Personal and each space, and says which is chosen', async () => {
    await renderInRouter(<ItemListView {...props({ vault: FAMILY_ID })} />);
    const select = screen.getByRole('combobox', { name: 'Vault' });
    expect(within(select).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'All vaults',
      'Personal',
      'Family',
    ]);
    expect(select).toHaveValue(FAMILY_ID);
  });

  it('tells the page which vault was picked', async () => {
    const onVault = vi.fn();
    await renderInRouter(<ItemListView {...props({ onVault })} />);
    await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'Vault' }), 'Family');
    expect(onVault).toHaveBeenCalledWith(FAMILY_ID);
  });

  it('shows only that vault\'s items, and the footer says "Showing N in <vault>"', async () => {
    await renderInRouter(<ItemListView {...props({ vault: FAMILY_ID })} />);
    expect(rowOf('Netflix')).toBeInTheDocument();
    expect(rowOf('Lease')).toBeInTheDocument();
    expect(screen.queryByText('GitHub')).not.toBeInTheDocument();
    expect(screen.getByText('Showing 2 in Family')).toBeInTheDocument();
  });

  it('combines with the type: the notes of Family only', async () => {
    await renderInRouter(<ItemListView {...props({ kind: 'note', vault: FAMILY_ID })} />);
    expect(rowOf('Lease')).toBeInTheDocument();
    expect(screen.queryByText('Wi-Fi at home')).not.toBeInTheDocument();
    expect(screen.getByText('Showing 1 in Family')).toBeInTheDocument();
  });

  it('says no item fits when the type and the vault leave none, not that the vault is empty', async () => {
    await renderInRouter(<ItemListView {...props({ kind: 'otp', vault: FAMILY_ID })} />);
    expect(screen.getByText('No matches')).toBeInTheDocument();
    expect(screen.queryByText('Nothing here yet')).not.toBeInTheDocument();
  });
});

describe('an empty or loading vault', () => {
  it('offers the first item to an empty vault', async () => {
    await renderInRouter(<ItemListView {...props({ rows: [], total: 0, hasItems: false })} />);
    expect(screen.getByText('Nothing here yet')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'New item' })).toBeInTheDocument();
  });

  it('says it is opening the vault, and shows an error with a way to try again', async () => {
    const onRetry = vi.fn();
    await renderInRouter(<ItemListView {...props({ rows: [], total: 0, isLoading: true, error: new Error('boom'), onRetry })} />);
    expect(screen.getByRole('status')).toHaveTextContent('Opening your vault');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalled();
  });

  it('pages through a long list', async () => {
    const onPage = vi.fn();
    await renderInRouter(<ItemListView {...props({ page: 2, pages: 3, onPage })} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Previous' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(onPage.mock.calls.map(([page]) => page)).toEqual([1, 3]);
  });
});
