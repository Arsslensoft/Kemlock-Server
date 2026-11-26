import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { RotateKeysCard, type RotateKeysProps } from './RotateKeysCard';

const PIECES = [1, 2, 3].map((n) => `BMCKIT1-NEWKIT22-23${n}-${'ABCD'.repeat(13)}-WXYZ`);

function card(over: Partial<RotateKeysProps> = {}) {
  const props: RotateKeysProps = {
    impact: { contacts: [], passkeys: 0, emergency: 0, recovery: 0, hasKit: false, hasPassword: true },
    blocked: null,
    twoStep: false,
    busy: false,
    progress: null,
    done: null,
    actions: {
      start: vi.fn(async () => true),
      askProof: vi.fn(async () => true),
      readdPasskey: vi.fn(async () => true),
      dismiss: vi.fn(),
    },
    ...over,
  };
  renderWithIntl(<RotateKeysCard {...props} />);
  return props;
}

describe('RotateKeysCard', () => {
  it('explains what happens before it asks for anything', async () => {
    card({ impact: { contacts: [], passkeys: 2, emergency: 1, recovery: 0, hasKit: true, hasPassword: true } });
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    expect(screen.getByText(/deletes every copy of the old root key/)).toBeTruthy();
    expect(screen.getByText(/Every other device is signed out/)).toBeTruthy();
    expect(screen.getByText(/2 passkeys stop opening the vault/)).toBeTruthy();
    expect(screen.getByText(/1 emergency contact is kept only if you compare/)).toBeTruthy();
    expect(screen.getByText(/keep their own keys/)).toBeTruthy();
    expect(screen.getByLabelText(/Replace my Recovery Kit/)).toBeTruthy();
  });

  it('sends the password and the choice of a new kit, and closes when it is installed', async () => {
    const props = card();
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    await userEvent.type(screen.getByLabelText('Master password'), 'correct horse');
    await userEvent.click(screen.getByLabelText(/Make a new Recovery Kit/));
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys now' }));
    expect(props.actions.start).toHaveBeenCalledWith({ password: 'correct horse', makeKit: false, emergencyKeep: {} });
    expect(screen.queryByLabelText('Master password')).toBeNull();
  });

  it('keeps the form open when the rotation failed, so the password can be fixed', async () => {
    const props = card({
      actions: {
        start: vi.fn(async () => false),
        askProof: vi.fn(async () => true),
        readdPasskey: vi.fn(async () => true),
        dismiss: vi.fn(),
      },
    });
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    await userEvent.type(screen.getByLabelText('Master password'), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys now' }));
    expect(props.actions.start).toHaveBeenCalled();
    expect(screen.getByLabelText('Master password')).toBeTruthy();
  });

  it('keeps a contact only when their fingerprint was compared, and sends that very bundle', async () => {
    const contacts = [
      { id: 'g1', email: 'ann@example.org', bundle: 'QUJD', fingerprint: '11111 22222' },
      { id: 'g2', email: 'bo@example.org', bundle: 'REVG', fingerprint: '33333 44444' },
    ];
    const props = card({
      impact: { contacts, passkeys: 0, emergency: 2, recovery: 0, hasKit: false, hasPassword: true },
    });
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    expect(screen.getByTestId('contact-fingerprint-g1').textContent).toBe('11111 22222');
    await userEvent.type(screen.getByLabelText('Master password'), 'pw');
    await userEvent.click(screen.getByLabelText(/Keep ann@example.org/));
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys now' }));
    expect(props.actions.start).toHaveBeenCalledWith({
      password: 'pw',
      makeKit: true,
      emergencyKeep: { g1: 'QUJD' },
    });
  });

  it('cannot start without the password', async () => {
    card();
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    expect(screen.getByRole('button', { name: 'Rotate keys now' }).hasAttribute('disabled')).toBe(true);
  });

  it('says why an account in a space is not rotated here, and offers nothing', () => {
    card({ blocked: 'spaces' });
    expect(screen.getByText(/The web vault can't do that yet/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Rotate keys' })).toBeNull();
  });

  it('shows progress while it works', async () => {
    card({ progress: { phase: 'items', done: 3, total: 10 } });
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    expect(screen.getByRole('status').textContent).toContain('3 of 10');
  });

  it('shows the new Recovery Kit once, and what was removed', async () => {
    const props = card({
      done: {
        fingerprint: '11111 22222',
        kit: { kitId: 'NEWKIT22', pieces: PIECES },
        removed: { passkeys: [{ id: 'p1', credentialId: 'Y3JlZA' }], emergency: 0, recovery: 0 },
        passkeys: [{ id: 'p1', name: 'Work laptop' }],
      },
    });
    expect(screen.getByTestId('rotated')).toBeTruthy();
    expect(screen.getByText(/11111 22222/)).toBeTruthy();
    expect(screen.getByText(/1 passkey wrap/)).toBeTruthy();
    expect(screen.getByTestId('rotated-kit-piece-2')).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Add the unlock of Work laptop back' }));
    expect(props.actions.readdPasskey).toHaveBeenCalledWith('p1');
    expect(await screen.findByText('Opens the vault')).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'I have saved it' }));
    expect(props.actions.dismiss).toHaveBeenCalled();
  });

  it('asks for the second step beside the password when one is on', async () => {
    const props = card({ twoStep: true });
    await userEvent.click(screen.getByRole('button', { name: 'Rotate keys' }));
    expect(props.actions.askProof).toHaveBeenCalled();
  });
});
