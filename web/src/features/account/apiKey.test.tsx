import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { createApiKeyApi } from '@/api/apiKey';
import { ApiError } from '@/api/errors';
import { renderWithIntl } from '@/test/render';
import { ApiKeyCard, type ApiKeyProps } from './ApiKeyCard';

const ID = 'user.70000000-0000-4000-8000-000000000001';
const SECRET = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123';

function card(over: Partial<ApiKeyProps> = {}) {
  const props: ApiKeyProps = {
    info: { clientId: ID, set: true },
    secret: null,
    changed: null,
    busy: false,
    actions: {
      askProof: vi.fn(async () => true),
      reveal: vi.fn(async () => true),
      rotate: vi.fn(async () => true),
      hide: vi.fn(),
    },
    ...over,
  };
  renderWithIntl(<ApiKeyCard {...props} />);
  return props;
}

describe('ApiKeyCard', () => {
  it('shows the client id and keeps the secret hidden', () => {
    card();
    expect(screen.getByText(ID)).toBeInTheDocument();
    expect(screen.queryByTestId('api-secret')).toBeNull();
    expect(screen.getByText(/Kept hidden/)).toBeInTheDocument();
  });

  it('asks for the mailed proof and shows the secret only with it', async () => {
    const props = card();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Show the secret' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: 'Show the secret' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('The code from the email'), ' 123456 ');
    await user.click(confirm);
    expect(props.actions.reveal).toHaveBeenCalledWith('123456');
  });

  it('shows and copies the secret once the proof showed it, and hides it again', async () => {
    const props = card({ secret: SECRET });
    expect(screen.getByTestId('api-secret')).toHaveTextContent(SECRET);
    expect(screen.getByRole('button', { name: 'Copy the client secret' })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Hide' }));
    expect(props.actions.hide).toHaveBeenCalled();
  });

  it('replaces the secret only with a proof and says the old one is out', async () => {
    const props = card();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Make a new secret' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    expect(screen.getByText(/stops working until you give it the new one/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('The code from the email'), '654321');
    await user.click(screen.getByRole('button', { name: 'Replace the secret' }));
    expect(props.actions.rotate).toHaveBeenCalledWith('654321');
  });

  it('tells of the change after the key was made or replaced', () => {
    card({ secret: SECRET, changed: 'rotated' });
    expect(screen.getByText('The secret was replaced. The old secret no longer signs in.')).toBeInTheDocument();
  });

  it('offers to make the key when there is none', () => {
    card({ info: { clientId: ID, set: false } });
    expect(screen.getByRole('button', { name: 'Make the key' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Make a new secret' })).toBeNull();
  });

  it('says an account with no Bitwarden sign-in has no key', () => {
    card({ info: null });
    expect(screen.getByText(/has no API key/)).toBeInTheDocument();
    expect(screen.queryByText(ID)).toBeNull();
  });
});

describe('the API key calls', () => {
  it('reads the key without a secret and treats a 404 as no key', async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ clientId: ID, set: false })
      .mockRejectedValueOnce(new ApiError(404, undefined));
    const api = createApiKeyApi({ request, send: vi.fn() });
    expect(await api.show()).toEqual({ clientId: ID, set: false });
    expect(await api.show()).toBeNull();
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/account/api-key' });
  });

  it('sends the proof to show and to replace the secret', async () => {
    const request = vi.fn(async () => ({ clientId: ID, clientSecret: SECRET, revisionDate: '2026-11-28T10:00:00Z' }));
    const send = vi.fn(async () => undefined);
    const api = createApiKeyApi({ request, send } as never);
    await api.reveal('111111');
    expect(request).toHaveBeenLastCalledWith({
      method: 'POST',
      path: '/kem/v1/account/api-key',
      body: { proof: '111111' },
    });
    await api.rotate('222222');
    expect(request).toHaveBeenLastCalledWith({
      method: 'POST',
      path: '/kem/v1/account/api-key/rotate',
      body: { proof: '222222' },
    });
    await api.proofRequest();
    expect(send).toHaveBeenLastCalledWith({ method: 'POST', path: '/kem/v1/account/two-factor/proof' });
  });

  it('does not hide a failure that is not a 404', async () => {
    const request = vi.fn().mockRejectedValue(new ApiError(500, undefined));
    const api = createApiKeyApi({ request, send: vi.fn() });
    await expect(api.show()).rejects.toBeInstanceOf(ApiError);
  });
});
