import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { SPACE, login, renderInRouter, vaultItem } from '@/test/tools-fixtures';
import { type DuplicateGroup, findDuplicates } from './detect';
import { type DuplicateFilter, DuplicatesView, matchesFilter } from './Duplicates';
import { MergeView } from './DuplicateMerge';

function groups(): DuplicateGroup[] {
  const gh1 = login('GitHub', 'sam', 'pw', ['github.com'], { updatedAt: '2026-11-21T10:00:00Z', folder: 'Work' });
  const gh2 = login('github.com', 'sam', 'pw', ['gist.github.com'], { updatedAt: '2026-10-03T10:00:00Z' });
  const px1 = login('Proton Mail', 'sam', 'new', ['proton.me'], { updatedAt: '2026-11-20T10:00:00Z' });
  const px2 = login('proton.me', 'sam', 'old', ['account.proton.me'], { updatedAt: '2026-08-12T10:00:00Z' });
  const n1 = vaultItem('note', { name: 'Wi-Fi at home', text: 'pw' });
  const n2 = vaultItem('note', { name: 'Home Wi-Fi', text: 'pw' }, { owner: SPACE });
  return findDuplicates([gh1, gh2, px1, px2, n1, n2]);
}

function Harness({
  onMerge = vi.fn(),
  onDismiss = vi.fn(),
}: {
  onMerge?: (group: DuplicateGroup, picks: unknown) => void;
  onDismiss?: (group: DuplicateGroup) => void;
}) {
  // Built once: the fixtures number their items as they are made, so groups made again on every
  // render would carry new ids and lose the selection.
  const [all] = useState(groups);
  const [filter, setFilter] = useState<DuplicateFilter>('all');
  const [selected, setSelected] = useState<string | undefined>(all[0]?.id);
  return (
    <DuplicatesView
      groups={all}
      total={6}
      filter={filter}
      onFilter={setFilter}
      selectedId={selected}
      onSelect={setSelected}
      onMerge={onMerge}
      onDismiss={onDismiss}
      onRecheck={vi.fn()}
    />
  );
}

describe('DuplicatesView', () => {
  it('lists each group with why it matched, and counts them', async () => {
    await renderInRouter(<Harness />);
    expect(screen.getByRole('heading', { name: 'Duplicates', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/3 groups in your vault and spaces/)).toBeInTheDocument();
    expect(screen.getByText('Same website, username and password')).toBeInTheDocument();
    expect(screen.getByText('Same website and username, different passwords')).toBeInTheDocument();
    expect(screen.getByText('Same note text')).toBeInTheDocument();
  });

  it('says the server is not involved, and the switch to let it match is off and disabled', async () => {
    await renderInRouter(<Harness />);
    const toggle = screen.getByRole('switch', { name: 'Let the server match new items' });
    expect(toggle).toBeDisabled();
    expect(toggle).not.toBeChecked();
  });

  it('narrows by kind and to groups in two places', async () => {
    await renderInRouter(<Harness />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'In two places' }));
    expect(screen.getByText('Same note text')).toBeInTheDocument();
    expect(screen.queryByText('Same website and username, different passwords')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Logins' }));
    expect(screen.queryByText('Same note text')).not.toBeInTheDocument();
  });

  it('previews a group and merges with the picks', async () => {
    const onMerge = vi.fn();
    await renderInRouter(<Harness onMerge={onMerge} />);
    const user = userEvent.setup();
    // The first group is the GitHub pair: same password, so no password choice is offered.
    expect(screen.getByText(/Keeps GitHub\./)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Merge' }));
    expect(onMerge).toHaveBeenCalledTimes(1);
    const [group, picks] = onMerge.mock.calls[0] as [DuplicateGroup, { keepId: string; websites: string[] }];
    expect(group.items).toHaveLength(2);
    expect(picks.keepId).toBe(group.items[0]?.id);
    expect(picks.websites).toHaveLength(2);
  });

  it('offers a password choice only where the passwords differ', async () => {
    await renderInRouter(<Harness />);
    const user = userEvent.setup();
    expect(screen.queryByText('Password')).not.toBeInTheDocument();
    const reviews = screen.getAllByRole('button', { name: 'Review' });
    await user.click(reviews[1] as HTMLElement);
    expect(screen.getByText('Password')).toBeInTheDocument();
  });

  it('dismisses a group', async () => {
    const onDismiss = vi.fn();
    await renderInRouter(<Harness onDismiss={onDismiss} />);
    const user = userEvent.setup();
    await user.click(screen.getAllByRole('button', { name: 'Not duplicates' })[0] as HTMLElement);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('shows the toast with Undo', async () => {
    const onUndo = vi.fn();
    await renderInRouter(
      <DuplicatesView
        groups={[]}
        total={0}
        filter="all"
        onFilter={vi.fn()}
        selectedId={undefined}
        onSelect={vi.fn()}
        onMerge={vi.fn()}
        onDismiss={vi.fn()}
        onRecheck={vi.fn()}
        toast={{ id: 'dup.toast.merged', values: { kept: 'GitHub', trashed: 'github.com' }, onUndo }}
      />,
    );
    expect(screen.getByRole('status')).toHaveTextContent('Merged into GitHub. github.com is in the trash for 30 days.');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Undo' }));
    expect(onUndo).toHaveBeenCalled();
    expect(screen.getByText(/No duplicates left/)).toBeInTheDocument();
  });
});

describe('matchesFilter', () => {
  it('filters by kind and by place', () => {
    const [first] = groups();
    if (!first) throw new Error('no group');
    expect(matchesFilter(first, 'all')).toBe(true);
    expect(matchesFilter(first, 'login')).toBe(true);
    expect(matchesFilter(first, 'note')).toBe(false);
    expect(matchesFilter(first, 'places')).toBe(false);
  });
});

describe('MergeView', () => {
  const pair = findDuplicates([
    login('Proton Mail', 'sam', 'new-pass', ['proton.me'], { folder: 'Work', notes: 'Recovery', updatedAt: '2026-11-21T00:00:00Z' }),
    login('proton.me', 'sam', 'old-pass', ['account.proton.me', 'mail.proton.me'], {
      notes: 'Old account',
      passkeys: [{ credentialId: 'pk1', rpId: 'proton.me' }],
      updatedAt: '2026-08-12T00:00:00Z',
    }),
  ])[0] as DuplicateGroup;

  it('lets every field be chosen and shows the kept login as the choices change', async () => {
    const onMerge = vi.fn();
    await renderInRouter(
      <MergeView group={pair} onMerge={onMerge} onDismiss={vi.fn()} onCancel={vi.fn()} />,
    );
    const user = userEvent.setup();
    expect(screen.getByRole('heading', { name: 'Merge 2 items into one', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/1 other password joins its password history/)).toBeInTheDocument();

    // Keep the other login's password: the history now holds the first one, still one password.
    const passwordRadios = screen.getAllByRole('radio').filter((el) => (el as HTMLInputElement).name === 'm-passwordFrom');
    expect(passwordRadios).toHaveLength(2);
    await user.click(passwordRadios[1] as HTMLElement);
    expect(passwordRadios[1]).toBeChecked();

    // Untick a website: the kept login holds two.
    await user.click(screen.getByRole('checkbox', { name: /mail\.proton\.me/ }));
    expect(screen.getByText('Websites · 2')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Merge' }));
    const picks = onMerge.mock.calls[0]?.[0] as { passwordFrom: string; websites: string[]; passkeys: string[] };
    expect(picks.passwordFrom).toBe(pair.items[1]?.id);
    expect(picks.websites).toHaveLength(2);
    expect(picks.passkeys).toEqual(['pk1']);
  });

  it('names the item that goes to the trash and offers Undo once merged', async () => {
    await renderInRouter(
      <MergeView
        group={pair}
        onMerge={vi.fn()}
        onDismiss={vi.fn()}
        onCancel={vi.fn()}
        done={{ kept: 'Proton Mail', trashed: 'proton.me', onUndo: vi.fn() }}
      />,
    );
    expect(screen.getByText('proton.me, restorable for 30 days')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Merged into Proton Mail.');
    expect(screen.getByRole('button', { name: 'Merge' })).toBeDisabled();
  });
});
