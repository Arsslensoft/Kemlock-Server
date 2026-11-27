import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { NOW, SPACES, USERS, invite } from './fixtures';
import { PairView } from './Pair';
import { UsersView } from './Users';

const copy = vi.hoisted(() => vi.fn(async () => true));
vi.mock('@/lib/clipboard', () => ({ copyText: copy }));

beforeEach(() => copy.mockClear());

describe('what an administrator copies', () => {
  it('marks the pairing code secret, so the clipboard is cleared', async () => {
    renderWithIntl(
      <PairView
        state={{ code: { code: 'HXQ7-42MD-R9KT', expiresAt: NOW + 540 }, session: null }}
        compare={async () => ({ words: 'a-b-c-d-e-f', selfShort: '1', peerShort: '2' })}
        now={NOW}
        onNewCode={vi.fn()}
        onConnect={vi.fn()}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
        onNavigate={vi.fn()}
      />,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Copy the code' }));
    expect(copy).toHaveBeenCalledWith('HXQ7-42MD-R9KT', { secret: true });
  });

  it('marks the link of a new invitation secret, so the clipboard is cleared', async () => {
    renderWithIntl(
      <UsersView
        users={USERS}
        total={42}
        invites={[invite()]}
        spaces={SPACES}
        search=""
        now={NOW}
        onSearch={vi.fn()}
        onInvite={vi.fn()}
        onInviteAction={vi.fn()}
        onAction={vi.fn()}
        onChangeOwner={vi.fn()}
        issued={{ invite: invite(), link: 'https://vault.example.org/invite/abc', mailed: true }}
      />,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Copy the invitation link' }));
    expect(copy).toHaveBeenCalledWith('https://vault.example.org/invite/abc', { secret: true });
  });
});
