import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ProfileDto } from '@/api/profile';
import { renderWithIntl } from '@/test/render';
import { type ProfileViewProps, ProfileView } from './ProfileView';

const EMAIL = 'sam@example.org';

function view(over: Partial<ProfileViewProps> = {}, profile: Partial<ProfileDto> = {}) {
  const props: ProfileViewProps = {
    profile: {
      userId: 'u1',
      email: EMAIL,
      name: 'Sam Rivera',
      sso: false,
      hasPassword: true,
      compatible: false,
      pendingEmail: null,
      ...profile,
    },
    busy: false,
    actions: {
      saveIdentity: vi.fn(async () => true),
      cancelEmailChange: vi.fn(async () => true),
      changePassword: vi.fn(async () => true),
    },
    ...over,
  };
  renderWithIntl(<ProfileView {...props} />);
  return props;
}

const identity = () => screen.getByRole('region', { name: 'Name and email' });
const password = () => screen.getByRole('region', { name: 'Master password' });

describe('the name and email', () => {
  it('shows both, with what each is for, and nothing to save yet', () => {
    view();
    expect(screen.getByRole('heading', { level: 1, name: 'Profile' })).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toHaveValue('Sam Rivera');
    expect(screen.getByLabelText('Email')).toHaveValue(EMAIL);
    expect(screen.getByText('Shown to people you share spaces with.')).toBeInTheDocument();
    expect(screen.getByText(/A new address changes once you open the link we send to it/)).toBeInTheDocument();
    expect(within(identity()).getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('saves a new name alone, with no password asked', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Name'));
    await user.type(screen.getByLabelText('Name'), '  Alex Chen ');
    expect(within(identity()).queryByLabelText('Current master password')).toBeNull();
    await user.click(within(identity()).getByRole('button', { name: 'Save' }));
    expect(props.actions.saveIdentity).toHaveBeenCalledWith({ name: 'Alex Chen', password: '' });
  });

  it('asks the master password when the address changes, and sends nothing without it', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Email'));
    await user.type(screen.getByLabelText('Email'), 'New@Example.org');
    const save = within(identity()).getByRole('button', { name: 'Save' });
    expect(within(identity()).getByLabelText('Current master password')).toBeInTheDocument();
    expect(save).toBeDisabled();
    await user.type(within(identity()).getByLabelText('Current master password'), 'the current password');
    expect(save).toBeEnabled();
    await user.click(save);
    expect(props.actions.saveIdentity).toHaveBeenCalledWith({ email: 'New@Example.org', password: 'the current password' });
  });

  it('does not take a half-typed address', async () => {
    view();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Email'));
    await user.type(screen.getByLabelText('Email'), 'new@');
    await user.type(within(identity()).getByLabelText('Current master password'), 'pw');
    expect(screen.getByRole('alert')).toHaveTextContent('Type a full address');
    expect(screen.getByLabelText('Email')).toBeInvalid();
    expect(within(identity()).getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('sees the same address in another case as no change', async () => {
    view();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Email'));
    await user.type(screen.getByLabelText('Email'), ' SAM@example.org ');
    expect(within(identity()).queryByLabelText('Current master password')).toBeNull();
    expect(within(identity()).getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('saves the name and the address together', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Name'));
    await user.type(screen.getByLabelText('Name'), 'Alex');
    await user.clear(screen.getByLabelText('Email'));
    await user.type(screen.getByLabelText('Email'), 'alex@example.org');
    await user.type(within(identity()).getByLabelText('Current master password'), 'pw');
    await user.click(within(identity()).getByRole('button', { name: 'Save' }));
    expect(props.actions.saveIdentity).toHaveBeenCalledWith({ name: 'Alex', email: 'alex@example.org', password: 'pw' });
  });

  it('says a link was sent, and that a change of address waits for it, with a way to cancel', async () => {
    const props = view(
      { identityNotice: { kind: 'sent', email: 'new@example.org' } },
      { pendingEmail: 'new@example.org' },
    );
    expect(screen.getByText('We sent a link to new@example.org. Your address changes once you open it.')).toBeInTheDocument();
    expect(
      screen.getByText(`Waiting for the link sent to new@example.org. Your address stays ${EMAIL} until it is opened.`),
    ).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel the change' }));
    expect(props.actions.cancelEmailChange).toHaveBeenCalledOnce();
  });

  it('says what the last save did and what went wrong', () => {
    view({ identityNotice: { kind: 'saved' }, identityError: { id: 'profile.error.taken' } });
    expect(screen.getByText('Saved.')).toBeInTheDocument();
    expect(screen.getByText('Another account already uses that address.')).toBeInTheDocument();
  });

  it('shows the pending change only to someone who can still change the address', () => {
    view({}, { pendingEmail: 'new@example.org', sso: true });
    expect(screen.queryByRole('button', { name: 'Cancel the change' })).toBeNull();
  });
});

describe('an account an identity provider owns', () => {
  it('shows the name and the email locked, with the note, and nothing to save', () => {
    view({}, { sso: true });
    expect(screen.getByLabelText('Name')).toHaveAttribute('readonly');
    expect(screen.getByLabelText('Email')).toHaveAttribute('readonly');
    expect(screen.getByText(/they show here locked and change there/)).toBeInTheDocument();
    expect(screen.getAllByText('Comes from your identity provider. Change it there.')).toHaveLength(2);
    expect(within(identity()).queryByRole('button', { name: 'Save' })).toBeNull();
  });

  it('keeps the master password section', () => {
    view({}, { sso: true });
    expect(within(password()).getByLabelText('Current master password')).toBeInTheDocument();
    expect(within(password()).getByRole('button', { name: 'Change master password' })).toBeInTheDocument();
  });

  it('does not let typing in a locked box change anything', async () => {
    const props = view({}, { sso: true });
    await userEvent.setup().type(screen.getByLabelText('Name'), 'x');
    expect(screen.getByLabelText('Name')).toHaveValue('Sam Rivera');
    expect(props.actions.saveIdentity).not.toHaveBeenCalled();
  });
});

describe('an account shared with Bitwarden apps', () => {
  it('can rename itself but not change its address or its password here', () => {
    view({}, { compatible: true });
    expect(screen.getByLabelText('Name')).not.toHaveAttribute('readonly');
    expect(screen.getByLabelText('Email')).toHaveAttribute('readonly');
    expect(screen.getByText(/shared with Bitwarden apps, which hold its address/)).toBeInTheDocument();
    expect(within(password()).queryByLabelText('New master password')).toBeNull();
    expect(within(password()).getByText(/which hold its master password/)).toBeInTheDocument();
  });
});

describe('an account with no master password', () => {
  it('says so instead of asking for one, and keeps its address as it is', () => {
    view({}, { hasPassword: false });
    expect(screen.getByLabelText('Email')).toHaveAttribute('readonly');
    expect(within(password()).queryByLabelText('Current master password')).toBeNull();
    expect(within(password()).getByText(/no master password/)).toBeInTheDocument();
  });
});

describe('the master password', () => {
  const fill = async (user: ReturnType<typeof userEvent.setup>, current: string, next: string, again: string) => {
    await user.type(within(password()).getByLabelText('Current master password'), current);
    await user.type(within(password()).getByLabelText('New master password'), next);
    await user.type(within(password()).getByLabelText('Type it again'), again);
  };

  it('explains the three boxes, signs the other devices out by default and warns nobody can reset it', () => {
    view();
    expect(screen.getByText(/The server never sees either one/)).toBeInTheDocument();
    expect(screen.getByText('At least 12 characters. A long phrase is easier to remember.')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /Sign out my other devices/ })).toBeChecked();
    expect(screen.getByText('They ask for the new master password the next time they open.')).toBeInTheDocument();
    expect(screen.getByText('No one can reset it for you.')).toBeInTheDocument();
    expect(screen.getByText(/only your Recovery Kit or emergency access can get you back in/)).toBeInTheDocument();
  });

  it('puts the show and hide eye inside every password box', () => {
    view();
    const eyes = within(password()).getAllByRole('button', { name: 'Show the password' });
    expect(eyes).toHaveLength(3);
    for (const eye of eyes) expect(eye.closest('.pw')).not.toBeNull();
  });

  it('changes it, signing the other devices out, and empties the boxes once it is done', async () => {
    const props = view();
    const user = userEvent.setup();
    await fill(user, 'the current password', 'a brand new password', 'a brand new password');
    await user.click(within(password()).getByRole('button', { name: 'Change master password' }));
    expect(props.actions.changePassword).toHaveBeenCalledWith({
      current: 'the current password',
      next: 'a brand new password',
      signOutOthers: true,
    });
    expect(within(password()).getByLabelText('Current master password')).toHaveValue('');
    expect(within(password()).getByLabelText('New master password')).toHaveValue('');
    expect(within(password()).getByLabelText('Type it again')).toHaveValue('');
  });

  it('leaves the other devices signed in when the box is cleared', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: /Sign out my other devices/ }));
    await fill(user, 'the current password', 'a brand new password', 'a brand new password');
    await user.click(within(password()).getByRole('button', { name: 'Change master password' }));
    expect(props.actions.changePassword).toHaveBeenCalledWith(expect.objectContaining({ signOutOthers: false }));
  });

  it('refuses a short password, two that differ and the one it already is, and sends nothing', async () => {
    const props = view();
    const user = userEvent.setup();
    const submit = within(password()).getByRole('button', { name: 'Change master password' });
    await fill(user, 'the current password', 'short', 'short');
    await user.click(submit);
    expect(within(password()).getByRole('alert')).toHaveTextContent('at least 12 characters');

    await user.clear(within(password()).getByLabelText('New master password'));
    await user.clear(within(password()).getByLabelText('Type it again'));
    await user.type(within(password()).getByLabelText('New master password'), 'a brand new password');
    await user.type(within(password()).getByLabelText('Type it again'), 'a brand new passworX');
    await user.click(submit);
    expect(within(password()).getByRole('alert')).toHaveTextContent("The two passwords don't match");

    await user.clear(within(password()).getByLabelText('New master password'));
    await user.clear(within(password()).getByLabelText('Type it again'));
    await user.type(within(password()).getByLabelText('New master password'), 'the current password');
    await user.type(within(password()).getByLabelText('Type it again'), 'the current password');
    await user.click(submit);
    expect(within(password()).getByRole('alert')).toHaveTextContent('same as the current one');
    expect(props.actions.changePassword).not.toHaveBeenCalled();
  });

  it('keeps what was typed when the change failed, and says why', async () => {
    const props = view({ passwordError: { id: 'profile.error.wrong' } });
    vi.mocked(props.actions.changePassword).mockResolvedValue(false);
    const user = userEvent.setup();
    await fill(user, 'wrong one', 'a brand new password', 'a brand new password');
    await user.click(within(password()).getByRole('button', { name: 'Change master password' }));
    expect(within(password()).getByLabelText('Current master password')).toHaveValue('wrong one');
    expect(screen.getByText('That is not your current master password.')).toBeInTheDocument();
  });

  it('says when it is changed, and whether the other devices were signed out', () => {
    view({ passwordNotice: 'changedOthers' });
    expect(screen.getByText('Your master password is changed, and your other devices are signed out.')).toBeInTheDocument();
  });

  it('waits for the current password before it can be sent', () => {
    view();
    expect(within(password()).getByRole('button', { name: 'Change master password' })).toBeDisabled();
  });
});
