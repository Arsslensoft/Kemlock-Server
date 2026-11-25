import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { createEraseAccountApi } from '@/api/eraseAccount';
import { renderWithIntl } from '@/test/render';
import { DeleteAccountCard, type DeleteAccountProps } from './DeleteAccountCard';
import { confirmsEmail, deleteAccount } from './deleteAccountModel';
import { describeAccountError } from './errors';

const EMAIL = 'Sam@Example.org';

function card(over: Partial<DeleteAccountProps> = {}) {
  const props: DeleteAccountProps = {
    email: EMAIL,
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
  it('opens the form with a mailed proof and warns what goes', async () => {
    const props = card();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete my account' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    expect(screen.getByText(/It cannot be undone/)).toBeInTheDocument();
    expect(screen.getByText(/only owner of a space/)).toBeInTheDocument();
  });

  it('stays shut until the address and the code are typed', async () => {
    const props = card();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Delete my account' }));
    const confirm = screen.getByRole('button', { name: 'Delete the account for good' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('The code from the email'), '123456');
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(`Type ${EMAIL} to confirm`), 'someone@else.org');
    expect(confirm).toBeDisabled();
    await user.clear(screen.getByLabelText(`Type ${EMAIL} to confirm`));
    await user.type(screen.getByLabelText(`Type ${EMAIL} to confirm`), ' sam@example.ORG ');
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    expect(props.actions.erase).toHaveBeenCalledWith(' sam@example.ORG ', '123456');
  });
});

describe('deleting the account', () => {
  it('compares the typed address in any case and spacing', () => {
    expect(confirmsEmail(' sam@example.ORG', EMAIL)).toBe(true);
    expect(confirmsEmail('sam@example.com', EMAIL)).toBe(false);
    expect(confirmsEmail('', '')).toBe(false);
  });

  it('erases with the proof and signs out only after the server said yes', async () => {
    const order: string[] = [];
    const erase = vi.fn(async () => {
      order.push('erase');
    });
    const signOut = vi.fn(async () => {
      order.push('signOut');
    });
    const done = await deleteAccount({ api: { erase }, signOut }, { email: EMAIL, typed: 'sam@example.org', proof: ' 123456 ' });
    expect(done).toBe(true);
    expect(erase).toHaveBeenCalledWith('123456');
    expect(order).toEqual(['erase', 'signOut']);
  });

  it('does nothing without the address or the proof, and stays signed in when the server refuses', async () => {
    const erase = vi.fn(async () => undefined);
    const signOut = vi.fn(async () => undefined);
    expect(await deleteAccount({ api: { erase }, signOut }, { email: EMAIL, typed: 'x', proof: '1' })).toBe(false);
    expect(await deleteAccount({ api: { erase }, signOut }, { email: EMAIL, typed: EMAIL, proof: ' ' })).toBe(false);
    expect(erase).not.toHaveBeenCalled();

    const refused = vi.fn().mockRejectedValue(new ApiError(400, undefined));
    await expect(
      deleteAccount({ api: { erase: refused }, signOut }, { email: EMAIL, typed: EMAIL, proof: '1' }),
    ).rejects.toBeInstanceOf(ApiError);
    expect(signOut).not.toHaveBeenCalled();
  });

  it('sends DELETE /kem/v1/account with the proof', async () => {
    const send = vi.fn(async () => undefined);
    const api = createEraseAccountApi({ send } as never);
    await api.erase('123456');
    expect(send).toHaveBeenCalledWith({ method: 'DELETE', path: '/kem/v1/account', body: { proof: '123456' } });
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
