// Duplicates over every item type: the chips, the reason of each kind, the Vault filter, and where a
// copy that sits in two vaults is kept.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import type { ItemData } from '@/features/vault/vault';
import { SPACE, login, renderInRouter, vaultItem } from '@/test/tools-fixtures';
import { FAMILY_ID, VAULTS } from '@/test/vault-fixtures';
import { type DuplicateGroup, findDuplicates } from './detect';
import { type DuplicateFilter, DuplicatesView, groupInVault } from './Duplicates';

const HASH = 'ab'.repeat(32);

/** Two copies of one kind, the first changed more recently. */
function pair(kind: string, a: ItemData, b: ItemData) {
  return [vaultItem(kind, { updatedAt: 2, ...a }), vaultItem(kind, { updatedAt: 1, ...b })];
}

/** One pair of copies of every kind, so a page can show them all. */
function everyKind(): DuplicateGroup[] {
  return findDuplicates([
    ...pair(
      'login',
      { name: 'GitHub', username: 'sam', password: 'pw', urls: ['github.com'] },
      { name: 'github.com', username: 'sam', password: 'pw', urls: ['gist.github.com'] },
    ),
    ...pair('note', { name: 'Wi-Fi', text: 'pw' }, { name: 'Home Wi-Fi', text: 'pw' }),
    ...pair(
      'file',
      { name: 'Lease.pdf', file: { name: 'Lease.pdf', size: 10, sha256: HASH } },
      { name: 'Lease copy.pdf', file: { name: 'Lease copy.pdf', size: 10, sha256: HASH.toUpperCase() } },
    ),
    ...pair('otp', { name: 'AWS', secret: 'JBSWY3DPEHPK3PXP' }, { name: 'Amazon', secret: 'jbsw y3dp ehpk 3pxp' }),
    ...pair(
      'backup-codes',
      { name: 'GH codes', codes: [{ code: 'a1' }, { code: 'b2', used: true }] },
      { name: 'GH backup', codes: [{ code: 'b2' }, { code: 'a1' }] },
    ),
    ...pair(
      'passkey',
      { name: 'Google', rpId: 'google.com', credentialId: 'abc123' },
      { name: 'google.com', rpId: 'Google.com', credentialId: 'abc123' },
    ),
    ...pair(
      'card',
      { name: 'Travel', number: '4111 1111 1111 1111', expMonth: 5, expYear: 2029 },
      { name: 'Mastercard', number: '4111111111111111', expMonth: '05', expYear: '2029' },
    ),
    ...pair(
      'identity',
      { name: 'Passport', documents: [{ number: 'X 1234-567' }] },
      { name: 'Passport details', documents: [{ number: 'x1234567' }] },
    ),
    ...pair(
      'contact',
      { name: 'Alex Chen', email: 'Alex@Example.org', phone: '+1 555 0142' },
      { name: 'Alex C.', email: 'alex@example.org', phone: '15550142' },
    ),
    ...pair(
      'certificate',
      { name: 'Workstation', fingerprint: HASH.toUpperCase().replace(/(..)(?=.)/g, '$1:') },
      { name: 'Client cert', fingerprint: HASH },
    ),
    ...pair(
      'ssh-key',
      { name: 'Router', fingerprint: 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8' },
      { name: 'Router key', fingerprint: 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8' },
    ),
    ...pair(
      'pgp-key',
      { name: 'Sam, work', fingerprint: '9F3A 77C1 0B2E 45D6 8A19 C0DE 12F4 5B6A 7788 9900' },
      { name: 'sam@example.co PGP', fingerprint: '9f3a77c10b2e45d68a19c0de12f45b6a77889900' },
    ),
  ]);
}

function View({
  groups,
  initial = 'all',
  vault = 'all',
  selectedId,
  onMerge = vi.fn(),
  onVault = vi.fn(),
}: {
  groups: DuplicateGroup[];
  initial?: DuplicateFilter;
  vault?: string;
  selectedId?: string | undefined;
  onMerge?: (group: DuplicateGroup, picks: unknown) => void;
  onVault?: (vault: string) => void;
}) {
  const [filter, setFilter] = useState<DuplicateFilter>(initial);
  const [chosen, setChosen] = useState(vault);
  return (
    <DuplicatesView
      groups={groups}
      total={groups.length * 2}
      filter={filter}
      onFilter={setFilter}
      vault={chosen}
      onVault={(next) => {
        setChosen(next);
        onVault(next);
      }}
      vaults={VAULTS}
      selectedId={selectedId}
      onSelect={vi.fn()}
      onMerge={onMerge}
      onDismiss={vi.fn()}
      onRecheck={vi.fn()}
    />
  );
}

/** A note in the person's vault and the same note in the Family space. */
function crossNotes(): DuplicateGroup[] {
  const mine = vaultItem('note', { name: 'Wi-Fi at home', text: 'pw', updatedAt: 2 });
  const family = vaultItem('note', { name: 'Home Wi-Fi', text: 'pw', updatedAt: 1 }, { owner: SPACE });
  return findDuplicates([mine, family]);
}

describe('groupInVault', () => {
  it('is true when any copy is in the vault the filter picks', () => {
    const [cross] = crossNotes();
    if (!cross) throw new Error('no group');
    expect(groupInVault(cross, 'all')).toBe(true);
    expect(groupInVault(cross, 'personal')).toBe(true);
    expect(groupInVault(cross, FAMILY_ID)).toBe(true);
    expect(groupInVault(cross, '00000000-0000-4000-8000-0000000000cc')).toBe(false);
  });
});

describe('the chips and the reason of every kind', () => {
  it('has a chip for every type, Files included, and for groups in two places', async () => {
    await renderInRouter(<View groups={everyKind()} />);
    const chips = screen.getByRole('group', { name: 'Kind of duplicate' });
    expect(within(chips).getAllByRole('button').map((chip) => chip.textContent)).toEqual([
      'All',
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
      'In two places',
    ]);
  });

  it('says why each kind matched, and finds each one by its own chip', async () => {
    await renderInRouter(<View groups={everyKind()} />);
    const user = userEvent.setup();
    const cases: Array<[string, string]> = [
      ['Logins', 'Same website, username and password'],
      ['Notes', 'Same note text'],
      ['Files', 'Same file contents'],
      ['MFA codes', 'Same code secret'],
      ['Backup codes', 'Same codes'],
      ['Passkeys', 'Same passkey'],
      ['Cards', 'Same card number and expiry'],
      ['Identities', 'Same document number'],
      ['Contacts', 'Same email and phone'],
      ['Certificates', 'Same certificate fingerprint'],
      ['SSH keys', 'Same key fingerprint'],
      ['PGP keys', 'Same key fingerprint'],
    ];
    for (const [chip, reason] of cases) {
      await user.click(screen.getByRole('button', { name: chip }));
      // Only that type's one group is listed, and it says why.
      const group = screen.getAllByRole('article');
      expect(group, chip).toHaveLength(1);
      expect(within(group[0] as HTMLElement).getByText(reason), chip).toBeInTheDocument();
    }
  });

  it('names a copy by its vault and the details of its kind', async () => {
    await renderInRouter(<View groups={everyKind()} initial="card" />);
    expect(screen.getAllByText(/Your vault · Ending 1111 · expires 05\/29/)).toHaveLength(2);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Backup codes' }));
    expect(screen.getAllByText(/Your vault · 2 codes, 1 unused/).length).toBeGreaterThan(0);
  });

  it('says when no group of the chosen type is left', async () => {
    const logins = everyKind().filter((group) => group.kind === 'login');
    await renderInRouter(<View groups={logins} initial="card" />);
    expect(screen.getByText('No duplicates of this type.')).toBeInTheDocument();
  });
});

describe('the Vault filter and where a copy is kept', () => {
  it('lists the vaults, and narrows to the groups with a copy in one', async () => {
    const groups = [...everyKind().filter((group) => group.kind === 'login'), ...crossNotes()];
    await renderInRouter(<View groups={groups} />);
    const user = userEvent.setup();
    const filter = screen.getByRole('combobox', { name: 'Vault' });
    expect(within(filter).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'All vaults',
      'Personal',
      'Family',
    ]);
    // The logins are in the person's vault only; the notes have a copy in Family.
    await user.selectOptions(filter, 'Family');
    expect(screen.queryByText('Same website, username and password')).not.toBeInTheDocument();
    expect(screen.getByText('Same note text')).toBeInTheDocument();
    await user.selectOptions(filter, 'Personal');
    expect(screen.getByText('Same website, username and password')).toBeInTheDocument();
    expect(screen.getByText('Same note text')).toBeInTheDocument();
  });

  it('asks where to keep a copy that sits in two vaults, and keeps it there', async () => {
    const onMerge = vi.fn();
    await renderInRouter(<View groups={crossNotes()} onMerge={onMerge} />);
    const user = userEvent.setup();
    const keepIn = screen.getByRole('group', { name: 'Keep it in' });
    const places = within(keepIn).getAllByRole('radio');
    expect(places.map((radio) => radio.closest('label')?.textContent)).toEqual(['Your vault', 'Family']);
    expect(places[0]).toBeChecked();
    await user.click(places[1] as HTMLElement);
    await user.click(screen.getByRole('button', { name: 'Merge' }));
    const [group, picks] = onMerge.mock.calls[0] as [DuplicateGroup, { keepId: string }];
    expect(picks.keepId).toBe(group.items.find((item) => item.owner === SPACE)?.id);
  });

  it('keeps a name from one vault while keeping the item in the other', async () => {
    const onMerge = vi.fn();
    await renderInRouter(<View groups={crossNotes()} onMerge={onMerge} />);
    const user = userEvent.setup();
    // Pick the Family copy's name, then keep the item in the person's vault.
    await user.click(within(screen.getByRole('group', { name: 'Name' })).getByRole('radio', { name: /Home Wi-Fi/ }));
    await user.click(within(screen.getByRole('group', { name: 'Keep it in' })).getByRole('radio', { name: 'Your vault' }));
    await user.click(screen.getByRole('button', { name: 'Merge' }));
    const [group, picks] = onMerge.mock.calls[0] as [DuplicateGroup, { keepId: string; nameFrom: string }];
    expect(picks.nameFrom).toBe(group.items.find((item) => item.owner === SPACE)?.id);
    expect(picks.keepId).toBe(group.items.find((item) => item.owner !== SPACE)?.id);
    expect(screen.getByText(/Keeps Home Wi-Fi\./)).toBeInTheDocument();
  });

  it('keeps a login as the design has it: one Keep pick, with each copy named by vault', async () => {
    const mine = login('Netflix', 'sam', 'pw', ['netflix.com'], { updatedAt: 2 });
    const family = login('Netflix', 'sam', 'pw', ['netflix.com'], { updatedAt: 1 }, { owner: SPACE });
    const groups = findDuplicates([mine, family]);
    await renderInRouter(<View groups={groups} />);
    const keep = screen.getByRole('group', { name: 'Keep' });
    expect(within(keep).getAllByRole('radio')).toHaveLength(2);
    expect(within(keep).getByText(/^Family · /)).toBeInTheDocument();
    expect(screen.queryByRole('group', { name: 'Keep it in' })).not.toBeInTheDocument();
  });

  it('says the linked items and custom fields are kept from every item', async () => {
    const a = vaultItem('note', { name: 'A', text: 'x', links: [{ id: '00000000-0000-4000-8000-0000000000e1' }] });
    const b = vaultItem('note', { name: 'B', text: 'x' });
    await renderInRouter(<View groups={findDuplicates([a, b])} />);
    expect(screen.getByText('Linked items and custom fields')).toBeInTheDocument();
    expect(screen.getByText('Kept from every item')).toBeInTheDocument();
  });

  it('does not offer a place to keep it when all copies are in one vault', async () => {
    const a = vaultItem('note', { name: 'A', text: 'x' });
    const b = vaultItem('note', { name: 'B', text: 'x' });
    await renderInRouter(<View groups={findDuplicates([a, b])} />);
    expect(screen.queryByRole('group', { name: 'Keep it in' })).not.toBeInTheDocument();
    expect(screen.queryByText('Linked items and custom fields')).not.toBeInTheDocument();
  });
});
