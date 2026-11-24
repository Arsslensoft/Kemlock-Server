import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { RecoveryKitDto } from '@/api/recoveryKit';
import { renderWithIntl } from '@/test/render';
import { RecoveryKitCard, type RecoveryKitProps } from './RecoveryKitCard';

const KIT: RecoveryKitDto = {
  kitId: 'ABCDEFGH',
  threshold: 2,
  shares: 3,
  keyVersion: 1,
  createdAt: '2026-11-28T10:00:00Z',
  current: true,
  wrappedKey: 'AAAA',
};
const PIECES = [1, 2, 3].map((n) => `BMCKIT1-ABCDEFGH-23${n}-${'ABCD'.repeat(13)}-WXYZ`);
const CONFIRM = 'Type any one piece to show you kept it';

function card(over: Partial<RecoveryKitProps> = {}) {
  const props: RecoveryKitProps = {
    kit: null,
    making: null,
    busy: false,
    actions: {
      start: vi.fn(async () => undefined),
      cancel: vi.fn(),
      askProof: vi.fn(async () => true),
      confirm: vi.fn(async () => true),
      remove: vi.fn(async () => true),
    },
    ...over,
  };
  renderWithIntl(<RecoveryKitCard {...props} />);
  return props;
}

describe('RecoveryKitCard', () => {
  it('offers to make a kit when there is none, with no proof asked', async () => {
    const props = card();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Make a kit' }));
    expect(props.actions.start).toHaveBeenCalled();
    expect(props.actions.askProof).not.toHaveBeenCalled();
  });

  it('shows the 3 pieces, each with a QR code, and keeps the kit only after one is typed back', async () => {
    const props = card({ making: { pieces: PIECES, mismatch: false } });
    expect(screen.getAllByRole('img', { name: /QR code of piece/ })).toHaveLength(3);
    expect(screen.getByTestId('kit-piece-2')).toBeInTheDocument();
    const keep = screen.getByRole('button', { name: 'I kept them: turn the kit on' });
    expect(keep).toBeDisabled();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(CONFIRM), PIECES[1] as string);
    await user.click(keep);
    expect(props.actions.confirm).toHaveBeenCalledWith(PIECES[1], undefined);
  });

  it('says when the piece typed is not one of them', () => {
    card({ making: { pieces: PIECES, mismatch: true } });
    expect(screen.getByText(/not one of the pieces above/)).toBeInTheDocument();
  });

  it('asks for the mailed proof when it makes a new kit', async () => {
    const props = card({ kit: KIT });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Make a new kit' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    expect(props.actions.start).toHaveBeenCalled();
  });

  it('sends the proof with the confirmation of a kit that replaces another', async () => {
    const props = card({ kit: KIT, making: { pieces: PIECES, mismatch: false } });
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(CONFIRM), PIECES[0] as string);
    await user.type(screen.getByLabelText('The code from the email'), '123456');
    await user.click(screen.getByRole('button', { name: 'I kept them: replace the old kit' }));
    expect(props.actions.confirm).toHaveBeenCalledWith(PIECES[0], '123456');
  });

  it('removes the kit only with the proof', async () => {
    const props = card({ kit: KIT });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Remove' }));
    expect(props.actions.askProof).toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: 'Remove the kit' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('The code from the email'), '654321');
    await user.click(confirm);
    expect(props.actions.remove).toHaveBeenCalledWith('654321');
  });

  it('warns when the kit is for an older key', () => {
    card({ kit: { ...KIT, current: false } });
    expect(screen.getByText(/older key of your account/)).toBeInTheDocument();
  });
});

describe('RecoveryKitCard proof', () => {
  it('tells the person an authenticator code or the recovery code works when no mail comes', async () => {
    card({ kit: KIT });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Remove' }));
    expect(screen.getByText(/authenticator app or your recovery code works too/)).toBeInTheDocument();
  });
});
