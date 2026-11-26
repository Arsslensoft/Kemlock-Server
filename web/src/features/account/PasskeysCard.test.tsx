import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { PasskeysCard, type PasskeysCardProps } from './PasskeysCard';

function card(over: Partial<PasskeysCardProps> = {}) {
  const props: PasskeysCardProps = {
    passkeys: [],
    busy: false,
    onAskProof: vi.fn(),
    onAdd: vi.fn(async () => true),
    onRemove: vi.fn(),
    ...over,
  };
  renderWithIntl(<PasskeysCard {...props} />);
  return props;
}

describe('adding a passkey', () => {
  it('adds one at once when no second step is on', async () => {
    const props = card();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Add a passkey' }));
    expect(props.onAdd).toHaveBeenCalledWith();
    expect(props.onAskProof).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('The code from the email')).not.toBeInTheDocument();
  });

  it('asks for a fresh proof, mails one, and sends it when a second step is on', async () => {
    const props = card({ proofNeeded: true });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a passkey' }));
    expect(props.onAdd).not.toHaveBeenCalled();
    expect(props.onAskProof).toHaveBeenCalledTimes(1);
    const add = screen.getByRole('button', { name: 'Add a passkey' });
    expect(add).toBeDisabled();
    await user.type(screen.getByLabelText('The code from the email'), '731904');
    await user.click(screen.getByRole('button', { name: 'Add a passkey' }));
    expect(props.onAdd).toHaveBeenCalledWith('731904');
  });
});
