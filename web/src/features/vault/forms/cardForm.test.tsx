import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from '../vault';
import { CardForm, type CardValues, cardDefaults, cardFields } from './card';

function setup(initial = cardDefaults()) {
  const onSubmit = vi.fn();
  renderWithIntl(<CardForm initial={initial} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
  return { onSubmit, user: userEvent.setup({ delay: null }) };
}

const number = () => screen.getByLabelText('Card number') as HTMLInputElement;
const code = () => screen.getByLabelText('Security code') as HTMLInputElement;

describe('the card number', () => {
  it('shows the brand as a badge in the field as the number is typed, and groups the digits', async () => {
    const { user } = setup();
    expect(screen.getByText('Type the number on the card. The brand shows as you type.')).toBeInTheDocument();
    await user.type(number(), '4111111111111111');
    expect(number().value).toBe('4111 1111 1111 1111');
    expect(number().parentElement).toContainElement(screen.getByText('Visa'));
    expect(screen.getByText('Valid Visa number.')).toBeInTheDocument();
  });

  it('groups an American Express number as 4, 6 and 5, and names it', async () => {
    const { user } = setup();
    await user.type(number(), '378282246310005');
    expect(number().value).toBe('3782 822463 10005');
    expect(screen.getByText('American Express')).toBeInTheDocument();
    expect(screen.getByText('4 digits, on the front of the card.')).toBeInTheDocument();
  });

  it('accepts digits pasted with spaces and dashes', async () => {
    const { user } = setup();
    await user.click(number());
    await user.paste('5555-5555 5555-4444');
    expect(number().value).toBe('5555 5555 5555 4444');
    expect(screen.getByText('Mastercard')).toBeInTheDocument();
  });

  it('says when the number does not pass the card check, and refuses to save it', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Name'), 'Travel card');
    await user.type(number(), '4111111111111112');
    expect(await screen.findByRole('alert')).toHaveTextContent(/doesn't pass the card check/);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('says when there are too many digits for the brand', async () => {
    const { user } = setup();
    await user.type(number(), '3782822463100051');
    expect(await screen.findByText('Too many digits for American Express.')).toBeInTheDocument();
  });

  it('refuses a number of the wrong length for its brand', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Name'), 'Short');
    await user.type(number(), '411111111111');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('That is not a length this card number can have.')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('shows no badge for a brand it does not know, and takes the number once it passes the check', async () => {
    const { user } = setup();
    await user.type(number(), '000000000000');
    expect(screen.getByText(/The brand is not one Kemlock knows/)).toBeInTheDocument();
    expect(number().parentElement?.querySelector('.brand-badge')).toBeNull();
  });

  it('has no Brand box', () => {
    setup();
    expect(screen.queryByLabelText('Brand')).not.toBeInTheDocument();
  });
});

describe('the security code', () => {
  it('takes 3 or 4 digits before a brand is known, and only digits', async () => {
    const { user } = setup();
    expect(screen.getByText('3 or 4 digits.')).toBeInTheDocument();
    await user.type(code(), '12a3b4');
    expect(code().value).toBe('1234');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('is 3 digits for Visa, and 4 are wrong', async () => {
    const { user } = setup();
    await user.type(number(), '4111111111111111');
    expect(screen.getByText('3 digits, on the back of the card.')).toBeInTheDocument();
    await user.type(code(), '1234');
    expect(await screen.findByText('Visa uses 3 digits.')).toBeInTheDocument();
  });

  it('is 4 digits for American Express, and 3 are wrong once the box is left', async () => {
    const { user } = setup();
    await user.type(number(), '378282246310005');
    await user.type(code(), '123');
    await user.tab();
    expect(await screen.findByText('American Express uses 4 digits.')).toBeInTheDocument();
  });

  it('is checked against the brand when the card is saved', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Name'), 'Amex');
    await user.type(number(), '378282246310005');
    await user.type(code(), '123');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('American Express uses 4 digits.')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
    await user.type(code(), '4');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect((onSubmit.mock.calls[0]?.[0] as CardValues).code).toBe('1234');
  });
});

describe('the rest of the card', () => {
  it('has a PIN with the eye inside it, and no password box besides', () => {
    setup();
    const pin = screen.getByLabelText('PIN');
    expect(pin).toHaveAttribute('type', 'password');
    expect(pin.parentElement).toContainElement(screen.getByRole('button', { name: 'Show the password' }));
  });

  it('writes the brand its number names, and keeps the brand an item had when the number names none', () => {
    const visa = cardFields({ ...cardDefaults(), name: 'V', number: '4111 1111 1111 1111', brand: 'Other' });
    expect(visa['brand']).toBe('Visa');
    const unknown = cardFields({ ...cardDefaults(), name: 'U', number: '0000 0000 0000', brand: 'Store card' });
    expect(unknown['brand']).toBe('Store card');
    const existing: VaultItem = {
      id: 'c',
      owner: 'user:u',
      kind: 'card',
      revision: 2,
      keyVersion: 1,
      data: { name: 'Old', number: '4111111111111111', brand: 'Visa', expMonth: 5, expYear: 2029 },
      sizes: { ciphertext: 0, itemKey: 0 },
    };
    const values = cardDefaults(existing);
    expect(values.number).toBe('4111 1111 1111 1111');
    expect(cardFields(values, existing)).toMatchObject({ number: '4111111111111111', brand: 'Visa', expMonth: 5, expYear: 2029 });
  });
});
