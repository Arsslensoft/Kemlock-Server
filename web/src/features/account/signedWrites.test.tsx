import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { createOwnerSigningApi } from '@/api/ownerSigning';
import { encodeB64 } from '@/lib/b64url';
import { renderWithIntl } from '@/test/render';
import { SignedWritesCard, type SignedWritesProps } from './SignedWritesCard';
import { type SignedWritesDeps, clearSignedWrites, ownVault, requireSignedWrites } from './signedWritesModel';

const USER = '11111111-1111-4111-8111-111111111111';

function card(over: Partial<SignedWritesProps> = {}) {
  const props: SignedWritesProps = {
    required: false,
    secondStep: false,
    busy: false,
    actions: {
      turnOn: vi.fn(async () => true),
      askProof: vi.fn(async () => true),
      turnOff: vi.fn(async () => true),
    },
    ...over,
  };
  renderWithIntl(<SignedWritesCard {...props} />);
  return props;
}

describe('SignedWritesCard', () => {
  it('turns it on with one press, and says what an unsigned device meets', async () => {
    const props = card();
    expect(screen.getByText(/A device that doesn't sign yet is refused/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Turn on' }));
    expect(props.actions.turnOn).toHaveBeenCalled();
  });

  it('shows nothing to press while it is read', () => {
    card({ required: undefined });
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('asks the password to turn it off, and no mailed code without a second step', async () => {
    const props = card({ required: true });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Turn off' }));
    expect(props.actions.askProof).not.toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: 'Turn off signed writes only' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('Your master password'), 'hunter2');
    await user.click(confirm);
    expect(props.actions.turnOff).toHaveBeenCalledWith('hunter2', undefined);
  });

  it('asks a fresh proof beside the password when a second step is on', async () => {
    const props = card({ required: true, secondStep: true });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Turn off' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    await user.type(screen.getByLabelText('Your master password'), 'hunter2');
    const confirm = screen.getByRole('button', { name: 'Turn off signed writes only' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('The code from the email'), ' 123456 ');
    await user.click(confirm);
    expect(props.actions.turnOff).toHaveBeenCalledWith('hunter2', '123456');
  });
});

function deps() {
  const api = {
    require: vi.fn(async () => undefined),
    clear: vi.fn(async () => undefined),
    prelogin: vi.fn(async () => ({
      salt: encodeB64(new Uint8Array(16)),
      memoryKib: 1,
      iterations: 1,
      parallelism: 1,
    })),
    opaqueStart: vi.fn(async () => ({ response: encodeB64(new Uint8Array(4)), loginState: 'state' })),
  };
  const wiring = {
    api,
    crypto: {
      masterKey: vi.fn(async () => new Uint8Array(4)),
      opaqueLoginStart: vi.fn(async () => ({ request: new Uint8Array(4), state: new Uint8Array(4) })),
      opaqueLoginFinish: vi.fn(async () => ({ finalization: new Uint8Array([1, 2, 3]), exportKey: new Uint8Array(4) })),
      release: vi.fn(async () => undefined),
    },
  } as unknown as SignedWritesDeps;
  return { api, wiring };
}

describe('turning signed writes on and off', () => {
  it('asks for the own vault', async () => {
    const { api, wiring } = deps();
    await requireSignedWrites(wiring, USER);
    expect(api.require).toHaveBeenCalledWith(`user:${USER}`);
    expect(ownVault(USER)).toBe(`user:${USER}`);
  });

  it('sends the password the worker made, and the proof when a second step is on', async () => {
    const { api, wiring } = deps();
    const input = { userId: USER, email: 'sam@example.org', password: 'hunter2', secondStep: false };
    expect(await clearSignedWrites(wiring, input)).toBe(true);
    expect(api.clear).toHaveBeenCalledWith(
      `user:${USER}`,
      { loginState: 'state', finalization: encodeB64(new Uint8Array([1, 2, 3])) },
      undefined,
    );
    expect(await clearSignedWrites(wiring, { ...input, secondStep: true, proof: ' 424242 ' })).toBe(true);
    expect(api.clear).toHaveBeenLastCalledWith(`user:${USER}`, expect.any(Object), '424242');
  });

  it('sends nothing without the password, or without the proof a second step asks', async () => {
    const { api, wiring } = deps();
    const input = { userId: USER, email: 'sam@example.org', password: 'hunter2', secondStep: true };
    expect(await clearSignedWrites(wiring, { ...input, password: '' })).toBe(false);
    expect(await clearSignedWrites(wiring, input)).toBe(false);
    expect(api.prelogin).not.toHaveBeenCalled();
    expect(api.clear).not.toHaveBeenCalled();
  });
});

describe('the owner signing api', () => {
  it('reads, sets and clears on the owner path', async () => {
    const request = vi.fn(async () => ({ required: true }));
    const send = vi.fn(async () => undefined);
    const owners = createOwnerSigningApi({ request, send } as never);
    expect(await owners.required('user:abc')).toBe(true);
    expect(request).toHaveBeenCalledWith({ method: 'GET', path: '/kem/v1/owners/user%3Aabc/signed-writes' });
    await owners.require('user:abc');
    expect(send).toHaveBeenCalledWith({ method: 'PUT', path: '/kem/v1/owners/user%3Aabc/signed-writes' });
    await owners.clear('user:abc', { loginState: 'a', finalization: 'b' }, '12');
    expect(send).toHaveBeenLastCalledWith({
      method: 'DELETE',
      path: '/kem/v1/owners/user%3Aabc/signed-writes',
      body: { loginState: 'a', finalization: 'b', proof: '12' },
    });
  });
});
