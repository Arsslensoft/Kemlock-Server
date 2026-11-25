// What the merge preview and the merge page say and ask: the fields the copies disagree on, what is
// the same, what the merge rewrites besides the copies, and who may merge.
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ItemData } from '@/features/vault/vault';
import { SPACE, renderInRouter, vaultItem } from '@/test/tools-fixtures';
import { VAULTS } from '@/test/vault-fixtures';
import { type DuplicateGroup, findDuplicates } from './detect';
import { MergeView } from './DuplicateMerge';
import { DuplicatesView } from './Duplicates';
import type { MergeContext } from './merge';

function cards(a: ItemData, b: ItemData, owner?: string) {
  const first = vaultItem('card', { name: 'Travel', number: '4111111111111111', updatedAt: 2, ...a });
  const second = vaultItem('card', { name: 'Visa', number: '4111111111111111', updatedAt: 1, ...b }, owner ? { owner } : {});
  return { first, second, group: findDuplicates([first, second])[0] as DuplicateGroup };
}

function View({
  group,
  context,
  onMerge = vi.fn(),
}: {
  group: DuplicateGroup;
  context?: MergeContext;
  onMerge?: (group: DuplicateGroup, picks: unknown) => void;
}) {
  return (
    <DuplicatesView
      groups={[group]}
      total={2}
      filter="all"
      onFilter={vi.fn()}
      onVault={vi.fn()}
      vaults={VAULTS}
      context={context}
      selectedId={group.id}
      onSelect={vi.fn()}
      onMerge={onMerge}
      onDismiss={vi.fn()}
      onRecheck={vi.fn()}
    />
  );
}

describe('the merge preview', () => {
  it('asks which value to keep where the copies hold different ones, and keeps the pick', async () => {
    const onMerge = vi.fn();
    const { first, second, group } = cards({ cardholder: 'Sam Rivera' }, { cardholder: 'S. Rivera' });
    await renderInRouter(<View group={group} onMerge={onMerge} />);
    const user = userEvent.setup();
    const holder = screen.getByRole('group', { name: 'Cardholder' });
    const options = within(holder).getAllByRole('radio');
    expect(options.map((radio) => radio.closest('label')?.textContent)).toEqual([
      expect.stringContaining('Sam Rivera'),
      expect.stringContaining('S. Rivera'),
    ]);
    // The kept item's own value is picked first.
    expect(options[0]).toBeChecked();
    await user.click(options[1] as HTMLElement);
    await user.click(screen.getByRole('button', { name: 'Merge' }));
    const [, picks] = onMerge.mock.calls[0] as [DuplicateGroup, { valuesFrom: Record<string, string> }];
    expect(picks.valuesFrom).toEqual({ cardholder: second.id });
    expect(first.id).not.toBe(second.id);
  });

  it('does not ask about a field they agree on, and says only what is the same', async () => {
    const { group } = cards({ cardholder: 'Sam', code: '123' }, { cardholder: 'Sam', code: '123' });
    await renderInRouter(<View group={group} />);
    expect(screen.queryByRole('group', { name: 'Cardholder' })).not.toBeInTheDocument();
    expect(screen.getByText('Card number, expiry and security code')).toBeInTheDocument();
    expect(screen.getByText('The same in both')).toBeInTheDocument();
  });

  it('does not call the security code the same when it differs', async () => {
    const { group } = cards({ code: '123' }, { code: '999' });
    await renderInRouter(<View group={group} />);
    expect(screen.getByRole('group', { name: 'Security code' })).toBeInTheDocument();
    expect(screen.getByText('Card number and expiry')).toBeInTheDocument();
    expect(screen.queryByText('Card number, expiry and security code')).not.toBeInTheDocument();
    // A secret is never shown.
    expect(screen.queryByText('123')).not.toBeInTheDocument();
    expect(screen.queryByText('999')).not.toBeInTheDocument();
  });

  it('says "in every item" for three copies', async () => {
    const items = [1, 2, 3].map((n) => vaultItem('note', { name: `N${n}`, text: 'same', updatedAt: n }));
    await renderInRouter(<View group={findDuplicates(items)[0] as DuplicateGroup} />);
    expect(screen.getByText('The same in every item')).toBeInTheDocument();
  });

  it('says how many linked items now point at the kept item', async () => {
    const { first, second, group } = cards({}, {});
    const third = vaultItem('login', { name: 'Bank', username: 'u', links: [{ id: second.id }] });
    await renderInRouter(<View group={group} context={{ all: [first, second, third] }} />);
    expect(screen.getByText('1 linked item now points to Travel.')).toBeInTheDocument();
  });

  it('says how many files are copied onto the kept note', async () => {
    const entry = { id: 'B', name: 'lease.pdf', size: 4, key: 'k', addedAt: 1, kemlockFile: 'fb' };
    const a = vaultItem('note', { name: 'Lease', text: 'x', updatedAt: 2 });
    const b = vaultItem('note', { name: 'Lease copy', text: 'x', updatedAt: 1, attachments: [entry] });
    await renderInRouter(<View group={findDuplicates([a, b])[0] as DuplicateGroup} context={{ all: [a, b] }} />);
    expect(screen.getByText('1 attachment is copied to Lease.')).toBeInTheDocument();
  });

  it('does not say either when nothing points at the kept item or needs copying', async () => {
    const { first, second, group } = cards({}, {});
    await renderInRouter(<View group={group} context={{ all: [first, second] }} />);
    expect(screen.queryByText(/now point/)).not.toBeInTheDocument();
    expect(screen.queryByText(/copied to/)).not.toBeInTheDocument();
  });
});

describe('who may merge', () => {
  const readOnlyFamily: MergeContext = { all: [], canWrite: (item) => item.owner !== SPACE };

  it('stops a merge that would change a copy the person may only read, and says which', async () => {
    const { group } = cards({}, {}, SPACE);
    await renderInRouter(<View group={group} context={readOnlyFamily} />);
    expect(screen.getByText(/You can only read Visa\. A merge changes every copy/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Merge' })).toBeDisabled();
  });

  it('leaves "Keep it in" off a vault the person may only read', async () => {
    const { group } = cards({}, {}, SPACE);
    await renderInRouter(<View group={group} context={readOnlyFamily} />);
    const keepIn = screen.getByRole('group', { name: 'Keep it in' });
    expect(within(keepIn).getByRole('radio', { name: /Family/ })).toBeDisabled();
    expect(within(keepIn).getByText('Read only')).toBeInTheDocument();
    expect(within(keepIn).getByRole('radio', { name: 'Your vault' })).toBeEnabled();
  });

  it('lets a merge go when every copy may be written', async () => {
    const onMerge = vi.fn();
    const { group } = cards({}, {}, SPACE);
    await renderInRouter(<View group={group} context={{ all: [], canWrite: () => true }} onMerge={onMerge} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Merge' }));
    expect(onMerge).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/You can only read/)).not.toBeInTheDocument();
  });
});

describe('the merge page', () => {
  it('has a row to pick each field the copies disagree on', async () => {
    const onMerge = vi.fn();
    const { second, group } = cards({ cardholder: 'Sam Rivera' }, { cardholder: 'S. Rivera' });
    await renderInRouter(
      <MergeView group={group} vaults={VAULTS} onMerge={onMerge} onDismiss={vi.fn()} onCancel={vi.fn()} />,
    );
    const user = userEvent.setup();
    const row = screen.getByRole('row', { name: /Cardholder/ });
    const radios = within(row).getAllByRole('radio');
    expect(radios).toHaveLength(2);
    await user.click(radios[1] as HTMLElement);
    await user.click(screen.getByRole('button', { name: 'Merge' }));
    const picks = onMerge.mock.calls[0]?.[0] as { valuesFrom: Record<string, string> };
    expect(picks.valuesFrom).toEqual({ cardholder: second.id });
  });

  it('has no row for a value only one copy holds: the other lacks it and takes it', async () => {
    const { group } = cards({ cardholder: 'Sam Rivera' }, { cardholder: 'S. Rivera', pin: '1234' });
    await renderInRouter(<MergeView group={group} vaults={VAULTS} onMerge={vi.fn()} onDismiss={vi.fn()} onCancel={vi.fn()} />);
    // The PIN is held by one copy only: the other has none and takes it, so it is no pick.
    expect(screen.queryByRole('row', { name: /PIN/ })).not.toBeInTheDocument();
  });

  it('stops a merge the person may not make, and says how many linked items now point at the kept one', async () => {
    const { first, second, group } = cards({}, {}, SPACE);
    const third = vaultItem('login', { name: 'Bank', username: 'u', links: [{ id: second.id }] });
    await renderInRouter(
      <MergeView
        group={group}
        vaults={VAULTS}
        context={{ all: [first, second, third], canWrite: (item) => item.owner !== SPACE }}
        onMerge={vi.fn()}
        onDismiss={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText(/You can only read Visa/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Merge' })).toBeDisabled();
    expect(screen.getByText('1 linked item now points to Travel.')).toBeInTheDocument();
  });
});
