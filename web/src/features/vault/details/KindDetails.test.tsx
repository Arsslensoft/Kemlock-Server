import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { copyText } from '@/lib/clipboard';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from '../vault';
import { KindDetails, groupDigits, maskedNumber } from './KindDetails';

vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn(() => Promise.resolve(true)) }));

function item(kind: string, data: Record<string, unknown>): VaultItem {
  return { id: 'i1', owner: 'user:u1', kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

describe('KindDetails', () => {
  it('shows a live one-time code and its countdown', async () => {
    renderWithIntl(
      <KindDetails
        item={item('otp', { issuer: 'GitHub', label: 'ada', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', type: 'totp' })}
      />,
    );
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('otp-code').textContent).toMatch(/^\d{3} \d{3}$/));
    expect(screen.getByRole('timer').textContent).toMatch(/\d+ s left/);
    expect(screen.getByRole('button', { name: 'Copy code' })).toBeInTheDocument();
  });

  it('strikes the used backup codes through and counts the rest', () => {
    renderWithIntl(
      <KindDetails
        item={item('backup-codes', {
          serviceName: 'Example',
          codes: [
            { code: 'aaaa-1111', used: true },
            { code: 'bbbb-2222', used: false },
          ],
        })}
      />,
    );
    expect(screen.getByText('aaaa-1111').tagName).toBe('S');
    expect(screen.getByText('bbbb-2222').tagName).toBe('LI');
    expect(screen.getByText('1 of 2 not used yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the codes not used yet' })).toBeInTheDocument();
  });

  it('masks the card number and codes until shown', async () => {
    renderWithIntl(
      <KindDetails
        item={item('card', { number: '4111111111111111', code: '123', brand: 'Visa', expMonth: 5, expYear: 2029 })}
      />,
    );
    expect(screen.queryByText('4111 1111 1111 1111')).not.toBeInTheDocument();
    expect(screen.getByText('•••• •••• •••• 1111')).toBeInTheDocument();
    expect(screen.getByText('05/2029')).toBeInTheDocument();
    expect(screen.queryByText('123')).not.toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Show card number' }));
    expect(screen.getByText('4111 1111 1111 1111')).toBeInTheDocument();
  });

  it('copies the card number as its digits, without the spaces', async () => {
    renderWithIntl(<KindDetails item={item('card', { number: '4111111111111111' })} />);
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Copy card number' }));
    expect(copyText).toHaveBeenCalledWith('4111111111111111', { secret: true });
  });

  it('shows an identity with its address', () => {
    renderWithIntl(
      <KindDetails
        item={item('identity', {
          givenName: 'Ada',
          familyName: 'Lovelace',
          email: 'ada@example.org',
          address: { lines: ['1 Main St'], city: 'London', country: 'UK' },
        })}
      />,
    );
    expect(screen.getByText('Ada Lovelace')).toBeInTheDocument();
    expect(screen.getByText('1 Main St')).toBeInTheDocument();
    expect(screen.getByText('ada@example.org')).toBeInTheDocument();
  });

  it('shows nothing for a login', () => {
    const { container } = renderWithIntl(<KindDetails item={item('login', {})} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('groups and masks digits', () => {
    expect(groupDigits('4111111111111111')).toBe('4111 1111 1111 1111');
    expect(maskedNumber('378282246310005')).toBe('•••• •••• •••0 005');
  });
});
