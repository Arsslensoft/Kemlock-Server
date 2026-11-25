// The Profile container: what it asks the server, what it does with the answers, and what it shows
// of them. The view's own behaviour is in ProfileView.test.tsx, the two changes in profileModel.test.ts.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import type { ProfileDto } from '@/api/profile';
import { I18nProvider } from '@/i18n';

const profileApi = vi.hoisted(() => ({
  get: vi.fn(),
  rename: vi.fn(),
  credentialsStart: vi.fn(),
  changePassword: vi.fn(),
  requestEmailChange: vi.fn(),
  cancelEmailChange: vi.fn(),
  confirmEmailChange: vi.fn(),
}));
const session = vi.hoisted(() => ({ renamed: vi.fn(), tokenStore: { set: vi.fn() } }));
const model = vi.hoisted(() => ({ changePassword: vi.fn(), requestEmailChange: vi.fn() }));
const steps = vi.hoisted(() => ({ proofRequest: vi.fn() }));

vi.mock('@/api/profile', () => ({ createProfileApi: () => profileApi }));
vi.mock('@/api/twoStep', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/twoStep')>()),
  createSecondStepsApi: () => steps,
}));
// No security key in the test browser: the card offers the code only.
vi.mock('./useKeyProof', () => ({ useKeyProof: () => undefined }));
vi.mock('@/app/services', () => ({ api: { prelogin: vi.fn(), opaqueStart: vi.fn() }, session }));
vi.mock('./profileModel', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./profileModel')>()),
  changePassword: model.changePassword,
  requestEmailChange: model.requestEmailChange,
}));

import Profile from './Profile';
import { WrongPasswordError } from './profileModel';

const PROFILE: ProfileDto = {
  userId: 'u1',
  email: 'sam@example.org',
  name: 'Sam Rivera',
  sso: false,
  hasPassword: true,
  compatible: false,
  pendingEmail: null,
  twoStep: false,
};

function open() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <I18nProvider>
      <QueryClientProvider client={client}>
        <Profile />
      </QueryClientProvider>
    </I18nProvider>,
  );
}

const identity = () => screen.getByRole('region', { name: 'Name and email' });
const password = () => screen.getByRole('region', { name: 'Master password' });

beforeEach(() => {
  for (const fn of [
    ...Object.values(profileApi),
    ...Object.values(model),
    ...Object.values(steps),
    session.renamed,
    session.tokenStore.set,
  ]) {
    fn.mockReset();
  }
  profileApi.get.mockResolvedValue(PROFILE);
});

describe('opening Profile', () => {
  it('shows the account the server describes', async () => {
    open();
    expect(await screen.findByLabelText('Name')).toHaveValue('Sam Rivera');
    expect(screen.getByLabelText('Email')).toHaveValue('sam@example.org');
    expect(profileApi.get).toHaveBeenCalledOnce();
  });

  it('says it is opening, then says when it could not and tries again on request', async () => {
    profileApi.get.mockRejectedValueOnce(new ApiError(500, undefined));
    open();
    expect(screen.getByRole('status')).toHaveTextContent('Opening your profile');
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Try again' }));
    expect(await screen.findByLabelText('Name')).toBeInTheDocument();
    expect(profileApi.get).toHaveBeenCalledTimes(2);
  });
});

describe('saving the name', () => {
  it('renames, shows it in the avatar through the session, and says so', async () => {
    profileApi.rename.mockResolvedValue({ ...PROFILE, name: 'Alex Chen' });
    open();
    const user = userEvent.setup();
    await user.clear(await screen.findByLabelText('Name'));
    await user.type(screen.getByLabelText('Name'), 'Alex Chen');
    await user.click(within(identity()).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
    expect(profileApi.rename).toHaveBeenCalledWith('Alex Chen');
    expect(session.renamed).toHaveBeenCalledWith('Alex Chen');
    expect(model.requestEmailChange).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Name')).toHaveValue('Alex Chen');
  });

  it('says why the server refused', async () => {
    profileApi.rename.mockRejectedValue(
      new ApiError(403, { type: 'urn:kemlock:problem:sso-managed', title: 'x', status: 403 } as never),
    );
    open();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Name'), 'x');
    await user.click(within(identity()).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Your identity provider owns your name and email/)).toBeInTheDocument();
    expect(session.renamed).not.toHaveBeenCalled();
  });
});

describe('changing the address', () => {
  it('asks for the link with the current password and reads the profile again', async () => {
    model.requestEmailChange.mockResolvedValue({ pendingEmail: 'new@example.org', expiresAt: '2026-11-26T10:00:00Z' });
    profileApi.get.mockResolvedValueOnce(PROFILE).mockResolvedValue({ ...PROFILE, pendingEmail: 'new@example.org' });
    open();
    const user = userEvent.setup();
    await user.clear(await screen.findByLabelText('Email'));
    await user.type(screen.getByLabelText('Email'), 'new@example.org');
    await user.type(within(identity()).getByLabelText('Current master password'), 'the current password');
    await user.click(within(identity()).getByRole('button', { name: 'Save' }));
    expect(
      await screen.findByText('We sent an email to new@example.org. Your address changes once you open the link in it.'),
    ).toBeInTheDocument();
    expect(model.requestEmailChange).toHaveBeenCalledWith(expect.anything(), {
      email: 'sam@example.org',
      newEmail: 'new@example.org',
      current: 'the current password',
    });
    expect(profileApi.rename).not.toHaveBeenCalled();
    // The address in force is still the old one, and the change is shown as waiting.
    await waitFor(() => expect(profileApi.get).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/Waiting for the link sent to new@example.org/)).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toHaveValue('sam@example.org');
  });

  it('says when the current password is wrong', async () => {
    model.requestEmailChange.mockRejectedValue(new WrongPasswordError());
    open();
    const user = userEvent.setup();
    await user.clear(await screen.findByLabelText('Email'));
    await user.type(screen.getByLabelText('Email'), 'new@example.org');
    await user.type(within(identity()).getByLabelText('Current master password'), 'nope');
    await user.click(within(identity()).getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('That is not your current master password.')).toBeInTheDocument();
  });

  it('cancels a change that waits and reads the profile again', async () => {
    profileApi.get.mockResolvedValueOnce({ ...PROFILE, pendingEmail: 'new@example.org' }).mockResolvedValue(PROFILE);
    profileApi.cancelEmailChange.mockResolvedValue(undefined);
    open();
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Cancel the change' }));
    expect(await screen.findByText('The change of address is cancelled.')).toBeInTheDocument();
    expect(profileApi.cancelEmailChange).toHaveBeenCalledOnce();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel the change' })).toBeNull());
  });
});

describe('changing the master password', () => {
  async function submit(user: ReturnType<typeof userEvent.setup>) {
    await user.type(await within(await screen.findByRole('region', { name: 'Master password' })).findByLabelText('Current master password'), 'the current password');
    await user.type(within(password()).getByLabelText('New master password'), 'a brand new password');
    await user.type(within(password()).getByLabelText('Type it again'), 'a brand new password');
    await user.click(within(password()).getByRole('button', { name: 'Change master password' }));
  }

  it('hands the model the address in force and what was typed, then says the other devices are signed out', async () => {
    model.changePassword.mockResolvedValue({ tokens: null });
    open();
    await submit(userEvent.setup());
    expect(
      await screen.findByText('Your master password is changed, and your other devices are signed out.'),
    ).toBeInTheDocument();
    expect(model.changePassword).toHaveBeenCalledWith(expect.anything(), {
      email: 'sam@example.org',
      current: 'the current password',
      next: 'a brand new password',
      signOutOthers: true,
    });
  });

  it('says a wrong current password is wrong and keeps the boxes filled', async () => {
    model.changePassword.mockRejectedValue(new WrongPasswordError());
    open();
    await submit(userEvent.setup());
    expect(await screen.findByText('That is not your current master password.')).toBeInTheDocument();
    expect(within(password()).getByLabelText('Current master password')).toHaveValue('the current password');
  });

  it('takes up the new tokens when the other devices were signed out, since the old ones ended with theirs', async () => {
    const tokens = {
      tokenType: 'DPoP',
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresIn: 900,
      refreshExpiresIn: 3600,
      userId: 'u1',
      deviceId: 'd1',
      admin: false,
    };
    model.changePassword.mockResolvedValue({ tokens });
    open();
    await submit(userEvent.setup());
    await screen.findByText('Your master password is changed, and your other devices are signed out.');
    expect(session.tokenStore.set).toHaveBeenCalledOnce();
    expect(session.tokenStore.set).toHaveBeenCalledWith(
      expect.objectContaining({ access: 'new-access', refresh: 'new-refresh' }),
    );
  });

  it('keeps the tokens it has when the server made no new ones', async () => {
    model.changePassword.mockResolvedValue({ tokens: null });
    open();
    await submit(userEvent.setup());
    await screen.findByText(/Your master password is changed/);
    expect(session.tokenStore.set).not.toHaveBeenCalled();
  });

  it('reads the profile again, so a change of address dropped with the old password stops showing', async () => {
    profileApi.get.mockResolvedValueOnce({ ...PROFILE, pendingEmail: 'new@example.org' }).mockResolvedValue(PROFILE);
    model.changePassword.mockResolvedValue({ tokens: null });
    open();
    expect(await screen.findByText(/Waiting for the link sent to new@example.org/)).toBeInTheDocument();
    await submit(userEvent.setup());
    await screen.findByText(/Your master password is changed/);
    await waitFor(() => expect(screen.queryByText(/Waiting for the link sent/)).toBeNull());
    expect(profileApi.get).toHaveBeenCalledTimes(2);
  });

  it('words a malformed request and a lost race here, in Profile's own words', async () => {
    model.changePassword.mockRejectedValueOnce(
      new ApiError(400, { type: 'urn:kemlock:problem:invalid-request', title: 'x', status: 400 } as never),
    );
    open();
    const user = userEvent.setup();
    await submit(user);
    expect(await screen.findByText(/That could not be saved/)).toBeInTheDocument();

    model.changePassword.mockRejectedValueOnce(
      new ApiError(409, { type: 'urn:kemlock:problem:account-changed', title: 'x', status: 409 } as never),
    );
    await user.click(within(password()).getByRole('button', { name: 'Change master password' }));
    expect(await screen.findByText(/Your account changed while this was being saved/)).toBeInTheDocument();
  });

  it('sends the second step\'s proof with the change when one is on, and mails a code on request', async () => {
    profileApi.get.mockResolvedValue({ ...PROFILE, twoStep: true });
    steps.proofRequest.mockResolvedValue(undefined);
    model.changePassword.mockResolvedValue({ tokens: null });
    open();
    const user = userEvent.setup();
    const region = within(await screen.findByRole('region', { name: 'Master password' }));
    await user.click(region.getByRole('button', { name: 'Email me a code' }));
    expect(steps.proofRequest).toHaveBeenCalledOnce();
    await user.type(region.getByLabelText('Current master password'), 'the current password');
    await user.type(region.getByLabelText('New master password'), 'a brand new password');
    await user.type(region.getByLabelText('Type it again'), 'a brand new password');
    await user.type(region.getByLabelText('Second-step code'), '123456');
    await user.click(region.getByRole('button', { name: 'Change master password' }));
    await screen.findByText(/Your master password is changed/);
    expect(model.changePassword).toHaveBeenCalledWith(expect.anything(), {
      email: 'sam@example.org',
      current: 'the current password',
      next: 'a brand new password',
      signOutOthers: true,
      proof: '123456',
    });
  });

  it('does not show a failed request for a mailed code, since another proof will do', async () => {
    profileApi.get.mockResolvedValue({ ...PROFILE, twoStep: true });
    steps.proofRequest.mockRejectedValue(new ApiError(409, undefined));
    open();
    const region = within(await screen.findByRole('region', { name: 'Master password' }));
    await userEvent.setup().click(region.getByRole('button', { name: 'Email me a code' }));
    expect(steps.proofRequest).toHaveBeenCalledOnce();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('says why a Bitwarden-shared account is refused', async () => {
    model.changePassword.mockRejectedValue(
      new ApiError(403, { type: 'urn:kemlock:problem:compatible-account', title: 'x', status: 403 } as never),
    );
    open();
    await submit(userEvent.setup());
    expect(await screen.findByText('This account is shared with Bitwarden apps. Change this in one of them.')).toBeInTheDocument();
  });
});
