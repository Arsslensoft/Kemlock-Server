import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { createEraseAccountApi } from '@/api/eraseAccount';
import { encodeB64 } from '@/lib/b64url';
import { renderWithIntl } from '@/test/render';
import { DeleteAccountCard, type DeleteAccountProps } from './DeleteAccountCard';
import { type DeleteDeps, confirmsEmail, deleteAccount } from './deleteAccountModel';
import { describeAccountError } from './errors';

const EMAIL = 'Sam@Example.org';

function card(over: Partial<DeleteAccountProps> = {}) {
  const props: DeleteAccountProps = {
    email: EMAIL,
    secondStep: false,
    busy: false,
    actions: {
      askProof: vi.fn(async () => true),
      erase: vi.fn(async () => true),
    },
    ...over,
  };
  renderWithIntl(<DeleteAccountCard {...props} />);
  return props;
}

describe('DeleteAccountCard', () => {
  it('opens the form and warns what goes, asking no mailed code when no second step is on', async () => {
    const props = card();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete my account' }));
    expect(props.actions.askProof).not.toHaveBeenCalled();
    expect(screen.getByText(/It cannot be undone/)).toBeInTheDocument();
    expect(screen.getByText(/only owner of a space/)).toBeInTheDocument();
    expect(screen.queryByLabelText('The code from the email')).toBeNull();
  });

  it('stays shut until the address and the password are typed', async () => {
    const props = card();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Delete my account' }));
    const confirm = screen.getByRole('button', { name: 'Delete the account for good' });
    await user.type(screen.getByLabelText('Your master password'), 'hunter2');
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(`Type ${EMAIL} to confirm`), 'someone@else.org');
    expect(confirm).toBeDisabled();
    await user.clear(screen.getByLabelText(`Type ${EMAIL} to confirm`));
    await user.type(screen.getByLabelText(`Type ${EMAIL} to confirm`), ' sam@example.ORG ');
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    expect(props.actions.erase).toHaveBeenCalledWith(' sam@example.ORG ', 'hunter2', undefined);
  });

  it('asks the mailed code beside the password when a second step is on', async () => {
    const props = card({ secondStep: true });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Delete my account' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: 'Delete the account for good' });
    await user.type(screen.getByLabelText(`Type ${EMAIL} to confirm`), EMAIL);
    await user.type(screen.getByLabelText('Your master password'), 'hunter2');
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('The code from the email'), '123456');
    await user.click(confirm);
    expect(props.actions.erase).toHaveBeenCalledWith(EMAIL, 'hunter2', '123456');
  });
});

function deps(over: Partial<DeleteDeps['api']> = {}) {
  const order: string[] = [];
  const erase = vi.fn(async () => {
    order.push('erase');
  });
  const signOut = vi.fn(async () => {
    order.push('signOut');
  });
  const wiring: DeleteDeps = {
    api: {
      erase,
      prelogin: vi.fn(async () => ({
        salt: encodeB64(new Uint8Array(16)),
        memoryKib: 1,
        iterations: 1,
        parallelism: 1,
      })) as never,
      opaqueStart: vi.fn(async () => ({ response: encodeB64(new Uint8Array(4)), loginState: 'state' })) as never,
      ...over,
    },
    crypto: {
      masterKey: vi.fn(async () => new Uint8Array(4)),
      opaqueLoginStart: vi.fn(async () => ({ request: new Uint8Array(4), state: new Uint8Array(4) })),
      opaqueLoginFinish: vi.fn(async () => ({
        finalization: new Uint8Array([1, 2, 3]),
        exportKey: new Uint8Array(4),
      })),
    } as never,
    signOut,
  };
  return { wiring, erase, signOut, order };
}

describe('deleting the account', () => {
  it('compares the typed address in any case and spacing', () => {
    expect(confirmsEmail(' sam@example.ORG', EMAIL)).toBe(true);
    expect(confirmsEmail('sam@example.com', EMAIL)).toBe(false);
    expect(confirmsEmail('', '')).toBe(false);
  });

  it('proves the password through OPAQUE, erases, and signs out only after the server said yes', async () => {
    const { wiring, erase, order } = deps();
    const done = await deleteAccount(wiring, {
      email: EMAIL,
      typed: 'sam@example.org',
      password: 'hunter2',
      secondStep: false,
    });
    expect(done).toBe(true);
    expect(erase).toHaveBeenCalledWith({ loginState: 'state', finalization: encodeB64(new Uint8Array([1, 2, 3])) }, undefined);
    expect(order).toEqual(['erase', 'signOut']);
  });

  it('sends the fresh proof beside the password when a second step is on', async () => {
    const { wiring, erase } = deps();
    await deleteAccount(wiring, {
      email: EMAIL,
      typed: EMAIL,
      password: 'hunter2',
      proof: ' 123456 ',
      secondStep: true,
    });
    expect(erase).toHaveBeenCalledWith(expect.objectContaining({ loginState: 'state' }), '123456');
  });

  it('does nothing without the address, the password or the proof, and stays signed in when refused', async () => {
    const { wiring, erase, signOut } = deps();
    const base = { email: EMAIL, typed: EMAIL, password: 'pw', secondStep: false };
    expect(await deleteAccount(wiring, { ...base, typed: 'x' })).toBe(false);
    expect(await deleteAccount(wiring, { ...base, password: '' })).toBe(false);
    expect(await deleteAccount(wiring, { ...base, secondStep: true, proof: ' ' })).toBe(false);
    expect(erase).not.toHaveBeenCalled();

    const refused = deps({ erase: vi.fn().mockRejectedValue(new ApiError(400, undefined)) });
    await expect(deleteAccount(refused.wiring, base)).rejects.toBeInstanceOf(ApiError);
    expect(refused.signOut).not.toHaveBeenCalled();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('sends DELETE /kem/v1/account with the password messages, and the proof only when given', async () => {
    const send = vi.fn(async () => undefined);
    const api = createEraseAccountApi({ send } as never);
    const password = { loginState: 's', finalization: 'f' };
    await api.erase(password);
    expect(send).toHaveBeenLastCalledWith({ method: 'DELETE', path: '/kem/v1/account', body: password });
    await api.erase(password, '123456');
    expect(send).toHaveBeenLastCalledWith({
      method: 'DELETE',
      path: '/kem/v1/account',
      body: { ...password, proof: '123456' },
    });
    await api.proofRequest();
    expect(send).toHaveBeenLastCalledWith({ method: 'POST', path: '/kem/v1/account/two-factor/proof' });
  });

  it('words the refusal for the only owner of a space', () => {
    const refusal = new ApiError(400, {
      type: 'urn:kemlock:problem:invalid',
      title: 'Invalid',
      status: 400,
      detail: 'the account is the only owner of a space with other members: hand it over or delete the space first',
    } as never);
    expect(describeAccountError(refusal)).toEqual({ id: 'security.delete.lastOwner' });
  });
});
