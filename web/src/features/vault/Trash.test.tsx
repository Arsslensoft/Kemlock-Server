import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SPACE, login, renderInRouter, vaultItem } from '@/test/tools-fixtures';
import { VAULTS } from '@/test/vault-fixtures';
import { TrashTable } from './Trash';

const trashedAt = new Date(Date.now() - 3 * 3600_000).toISOString();

const rows = [
  login('Old forum', 'sam', 'pw', ['forum.example'], { trashedAt }),
  vaultItem('otp', { name: 'Twitter', secret: 'JBSWY3DP', trashedAt }),
  vaultItem('ssh-key', { name: 'Deploy key 2024', trashedAt }, { owner: SPACE }),
  vaultItem('file', { name: 'Scan of lease', trashedAt }, { owner: SPACE }),
];

function rowOf(name: string): HTMLElement {
  const row = screen.getAllByRole('row').find((candidate) => within(candidate).queryByText(name) !== null);
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

describe('TrashTable', () => {
  it('has the Deleted from column, between the kind and when it was deleted', async () => {
    await renderInRouter(<TrashTable rows={rows} vaults={VAULTS} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
      'Name',
      'Kind',
      'Deleted from',
      'Deleted',
      'Gone for good',
      'Actions',
    ]);
  });

  it('says which vault each item was deleted from: Personal or the space\'s name', async () => {
    await renderInRouter(<TrashTable rows={rows} vaults={VAULTS} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(within(rowOf('Old forum')).getByText('Personal')).toBeInTheDocument();
    expect(within(rowOf('Twitter')).getByText('Personal')).toBeInTheDocument();
    expect(within(rowOf('Deploy key 2024')).getByText('Family')).toBeInTheDocument();
    expect(within(rowOf('Scan of lease')).getByText('Family')).toBeInTheDocument();
  });

  it('calls an MFA code an MFA code, and shows files and keys by their own kind', async () => {
    await renderInRouter(<TrashTable rows={rows} vaults={VAULTS} onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(within(rowOf('Twitter')).getByText('MFA code')).toBeInTheDocument();
    expect(within(rowOf('Deploy key 2024')).getByText('SSH key')).toBeInTheDocument();
    expect(within(rowOf('Scan of lease')).getByText('File')).toBeInTheDocument();
    expect(within(rowOf('Old forum')).getByText('Login')).toBeInTheDocument();
  });

  it('says when it was deleted and when it goes for good', async () => {
    await renderInRouter(<TrashTable rows={rows.slice(0, 1)} vaults={VAULTS} onRestore={vi.fn()} onDelete={vi.fn()} />);
    const row = rowOf('Old forum');
    expect(within(row).getByText('3 hours ago')).toBeInTheDocument();
    // 30 days on: a day and a month, such as "Dec 25".
    expect(within(row).getByText(/^[A-Z][a-z]{2} \d{1,2}$/)).toBeInTheDocument();
  });

  it('restores and deletes the item of the row it was pressed in', async () => {
    const onRestore = vi.fn();
    const onDelete = vi.fn();
    await renderInRouter(<TrashTable rows={rows} vaults={VAULTS} onRestore={onRestore} onDelete={onDelete} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Restore Twitter' }));
    await user.click(screen.getByRole('button', { name: 'Delete now: Deploy key 2024' }));
    expect(onRestore).toHaveBeenCalledWith(rows[1]);
    expect(onDelete).toHaveBeenCalledWith(rows[2]);
  });

  it('can hold Restore while one is being made', async () => {
    await renderInRouter(<TrashTable rows={rows} vaults={VAULTS} restoring onRestore={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Restore Twitter' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete now: Twitter' })).toBeEnabled();
  });
});
