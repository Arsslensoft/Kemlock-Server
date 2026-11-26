import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { ADMIN_OVERVIEW, NOW, SPACES, USERS, invite } from './fixtures';
import { AttentionCard, attentionFrom } from './Overview';
import { type UsersViewProps, UsersView, isEmail } from './Users';

function view(props: Partial<UsersViewProps> = {}) {
  const handlers = {
    onSearch: vi.fn(),
    onInvite: vi.fn(),
    onInviteAction: vi.fn(),
    onAction: vi.fn(),
    onChangeOwner: vi.fn(),
  };
  renderWithIntl(
    <UsersView
      users={USERS}
      total={42}
      invites={[invite()]}
      spaces={SPACES}
      search=""
      now={NOW}
      {...handlers}
      {...props}
    />,
  );
  return handlers;
}

describe('UsersView', () => {
  it('lists the users with their two-step, devices and last sign-in', () => {
    view();
    expect(screen.getByText('42 in all, showing 4')).toBeInTheDocument();
    const riley = screen.getByRole('row', { name: /Riley Moss/ });
    expect(within(riley).getByText('None')).toBeInTheDocument();
    expect(within(riley).getByText('Kemlock and Bitwarden apps')).toBeInTheDocument();
    const sam = screen.getByRole('row', { name: /Sam Rivera/ });
    expect(within(sam).getByText('On')).toBeInTheDocument();
    expect(within(sam).getByText(/admin/)).toBeInTheDocument();
    expect(within(sam).getByText('4')).toBeInTheDocument();
    const ana = screen.getByRole('row', { name: /ana@example.co/ });
    expect(within(ana).getByText(/disabled/)).toBeInTheDocument();
    expect(within(ana).getByText('Never')).toBeInTheDocument();
    expect(within(ana).getByRole('button', { name: /Enable/ })).toBeInTheDocument();
    expect(within(ana).queryByRole('button', { name: /Sign out everywhere/ })).not.toBeInTheDocument();
  });

  it('offers to cancel the deletion of an account awaiting it, and nothing else but erasing', async () => {
    const waiting = { ...(USERS[1] as (typeof USERS)[number]), erasurePending: true };
    const { onAction } = view({ users: [waiting] });
    const row = screen.getByRole('row', { name: /Jordan Lee/ });
    expect(within(row).getByText(/awaiting deletion/)).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: /Sign out everywhere/ })).not.toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: /Disable/ })).not.toBeInTheDocument();
    await userEvent.setup().click(within(row).getByRole('button', { name: 'Cancel deletion: Jordan Lee' }));
    expect(onAction).toHaveBeenCalledWith('cancel-erasure', waiting);
  });

  it('does not offer to cancel a deletion that is not pending', () => {
    view();
    expect(screen.queryByRole('button', { name: /Cancel deletion/ })).not.toBeInTheDocument();
  });

  it('sends an action for the user on its row', async () => {
    const { onAction } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Sign out everywhere: Jordan Lee' }));
    expect(onAction).toHaveBeenCalledWith('sign-out', USERS[1]);
    await user.click(screen.getByRole('button', { name: 'Reset two-step: Jordan Lee' }));
    expect(onAction).toHaveBeenLastCalledWith('reset-two-step', USERS[1]);
    // Riley has no two-step method to reset.
    expect(screen.queryByRole('button', { name: 'Reset two-step: Riley Moss' })).not.toBeInTheDocument();
  });

  it('asks before erasing and only then acts', async () => {
    const { onAction } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Erase: Jordan Lee' }));
    expect(onAction).not.toHaveBeenCalled();
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Erase Jordan Lee?' })).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Erase' }));
    expect(onAction).toHaveBeenCalledWith('erase', USERS[1]);
  });

  it('takes an address with a non-ASCII domain, as the server does', async () => {
    const { onInvite } = view();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Email to invite'), 'ada@bücher.de');
    expect(screen.queryByText(/Type an email address/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Invite' }));
    expect(onInvite).toHaveBeenCalledWith('ada@bücher.de');
  });

  it('shows the email error as it is typed and keeps Invite off', async () => {
    const { onInvite } = view();
    const user = userEvent.setup();
    const invite = screen.getByRole('button', { name: 'Invite' });
    expect(invite).toBeDisabled();
    await user.type(screen.getByLabelText('Email to invite'), 'not-an-email');
    expect(screen.getByText(/Type an email address/)).toBeInTheDocument();
    expect(invite).toBeDisabled();
    expect(onInvite).not.toHaveBeenCalled();
  });

  it('checks the email before inviting', async () => {
    const { onInvite } = view();
    const user = userEvent.setup();
    const box = screen.getByLabelText('Email to invite');
    await user.type(box, 'not-an-email');
    expect(await screen.findByText(/Type an email address/)).toBeInTheDocument();
    expect(onInvite).not.toHaveBeenCalled();
    await user.clear(box);
    await user.type(box, 'new@example.co');
    await user.click(screen.getByRole('button', { name: 'Invite' }));
    expect(onInvite).toHaveBeenCalledWith('new@example.co');
    expect(box).toHaveValue('');
  });

  it('lists the waiting invitations and resends or revokes one', async () => {
    const pending = invite();
    const { onInviteAction } = view({ invites: [pending, invite({ id: 'i2', email: 'old@example.co', pending: false })] });
    expect(screen.getByText('Sent 1 time, expires in 5 days')).toBeInTheDocument();
    expect(screen.getByText('Expired')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Resend: new@example.co' }));
    expect(onInviteAction).toHaveBeenLastCalledWith('resend', pending);
    await user.click(screen.getByRole('button', { name: 'Revoke: new@example.co' }));
    expect(onInviteAction).toHaveBeenLastCalledWith('revoke', pending);
    expect(screen.queryByRole('button', { name: 'Resend: old@example.co' })).not.toBeInTheDocument();
  });

  it('shows the link of a new invitation, and says when the mail did not go out', () => {
    view({
      issued: { invite: invite(), link: 'https://vault.example.org/invite/abc', mailed: false },
    });
    expect(screen.getByText('https://vault.example.org/invite/abc')).toBeInTheDocument();
    // The copy button has its own live region, so there is more than one status on the page: the
    // notice is the one that holds the words.
    const notice = screen.getByText(/couldn't send the email/).closest('[role="status"]');
    expect(notice).toHaveClass('warn');
  });

  it('lists the spaces by id, with their owners, members and keys', () => {
    view();
    const first = screen.getByRole('row', { name: /s1aaaaaa/ });
    expect(within(first).getByText('sam@example.co')).toBeInTheDocument();
    expect(within(first).getByText('5 of 6 confirmed')).toBeInTheDocument();
    const second = screen.getByRole('row', { name: /s2bbbbbb/ });
    expect(within(second).getByText('Waiting to be replaced')).toBeInTheDocument();
  });

  it('changes a space owner to one of the active users', async () => {
    const { onChangeOwner } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Change owner of s1aaaaaa' }));
    await user.selectOptions(screen.getByLabelText('New owner of s1aaaaaa'), 'u1');
    await user.click(screen.getByRole('button', { name: 'Make owner' }));
    expect(onChangeOwner).toHaveBeenCalledWith(SPACES[0], 'u1');
  });

  it('offers more users when there are more', async () => {
    const onMore = vi.fn();
    view({ hasMore: true, onMore });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Show more' }));
    expect(onMore).toHaveBeenCalled();
  });
});

describe('the overview', () => {
  it('turns the counts into what needs a look', () => {
    expect(attentionFrom(ADMIN_OVERVIEW)).toEqual([
      { kind: 'overdue', count: 1 },
      { kind: 'requests', count: 2 },
      { kind: 'invited', count: 2 },
      { kind: 'disabled', count: 1 },
      { kind: 'mail', count: 1 },
    ]);
    expect(
      attentionFrom({ ...ADMIN_OVERVIEW, openRequests: 0, overdueRequests: 0, pendingInvites: 0, disabledUsers: 0, mailConfigured: true }),
    ).toEqual([]);
  });

  it('counts what needs a look, and says when the API is not there', () => {
    const { unmount } = renderWithIntl(
      <AttentionCard items={[{ kind: 'invited', count: 2 }, { kind: 'overdue', count: 1 }]} />,
    );
    expect(screen.getByText('2 invitations are still waiting')).toBeInTheDocument();
    expect(screen.getByText(/1 request is past its due date/)).toBeInTheDocument();
    unmount();
    renderWithIntl(<AttentionCard items={[]} unavailable />);
    expect(screen.getByText(/admin API didn't answer/)).toBeInTheDocument();
  });
});

describe('isEmail', () => {
  it('needs one @, text before it, a dot in the domain and no spaces', () => {
    expect(isEmail('new@example.co')).toBe(true);
    expect(isEmail('ada@bücher.de')).toBe(true);
    expect(isEmail('a@b@example.co')).toBe(false);
    expect(isEmail('@example.co')).toBe(false);
    expect(isEmail('ada@localhost')).toBe(false);
    expect(isEmail('a da@example.co')).toBe(false);
  });
});

describe('a request that fails', () => {
  it('keeps the invite address, the owner panel and the erase dialog open', async () => {
    const failing = vi.fn().mockResolvedValue(false);
    view({ onInvite: failing, onChangeOwner: failing, onAction: failing });
    const user = userEvent.setup();

    await user.type(screen.getByLabelText('Email to invite'), 'new@example.co');
    await user.click(screen.getByRole('button', { name: 'Invite' }));
    expect(failing).toHaveBeenCalledWith('new@example.co');
    expect(screen.getByLabelText('Email to invite')).toHaveValue('new@example.co');

    await user.click(screen.getByRole('button', { name: 'Change owner of s1aaaaaa' }));
    await user.click(screen.getByRole('button', { name: 'Make owner' }));
    expect(screen.getByRole('group', { name: /owner/i })).toBeInTheDocument();

    const row = screen.getByRole('row', { name: /Jordan Lee/ });
    await user.click(within(row).getByRole('button', { name: /Erase/ }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Erase/ }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});

describe('the Bitwarden invitation link', () => {
  const LINK = 'https://vault.example.org/#/accept-organization/?token=secret';

  it('is not offered where the console has no route for it', () => {
    view();
    expect(screen.queryByRole('button', { name: /invitation link/i })).not.toBeInTheDocument();
  });

  it('asks for the link of the account picked, and shows it once with its warning', async () => {
    const onInviteLink = vi.fn().mockResolvedValue(LINK);
    view({ onInviteLink });
    const user = userEvent.setup();
    await user.click(
      screen.getByRole('button', { name: 'Copy a Bitwarden invitation link for space s1aaaaaa' }),
    );
    await user.selectOptions(screen.getByLabelText('Invited member of space s1aaaaaa'), 'u1');
    expect(screen.queryByText(LINK)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Get the link' }));
    expect(onInviteLink).toHaveBeenCalledWith(SPACES[0], 'u1');
    expect(await screen.findByText(LINK)).toBeInTheDocument();
    expect(screen.getByText(/Whoever opens this link accepts the invitation for that account/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy invitation link' })).toBeInTheDocument();

    // Picking another account clears the link, so it is never taken for theirs.
    await user.selectOptions(screen.getByLabelText('Invited member of space s1aaaaaa'), 'u0');
    expect(screen.queryByText(LINK)).not.toBeInTheDocument();
  });

  it('shows no link when the request failed, and keeps the panel open', async () => {
    const onInviteLink = vi.fn().mockResolvedValue(undefined);
    view({ onInviteLink });
    const user = userEvent.setup();
    await user.click(
      screen.getByRole('button', { name: 'Copy a Bitwarden invitation link for space s2bbbbbb' }),
    );
    await user.click(screen.getByRole('button', { name: 'Get the link' }));
    expect(onInviteLink).toHaveBeenCalledWith(SPACES[1], expect.any(String));
    expect(screen.queryByText(/Whoever opens this link/)).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Bitwarden invitation link' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('group', { name: 'Bitwarden invitation link' })).not.toBeInTheDocument();
  });
});
