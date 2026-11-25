import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { copyText } from '@/lib/clipboard';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from '../vault';
import { toB64 } from '../forms/keyMaterial';
import { KindDetails, groupDigits, maskedNumber, sameFingerprint } from './KindDetails';

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
    expect(screen.getByRole('button', { name: 'Copy the code' })).toBeInTheDocument();
  });

  it('masks the backup codes, then strikes the used ones through and counts the rest', async () => {
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
    expect(screen.queryByText('bbbb-2222')).not.toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Show the codes' }));
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
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Show the card number' }));
    expect(screen.getByText('4111 1111 1111 1111')).toBeInTheDocument();
  });

  it('copies the card number as its digits, without the spaces', async () => {
    renderWithIntl(<KindDetails item={item('card', { number: '4111111111111111' })} />);
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Copy the card number' }));
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

  it('shows identity documents by their typed fields, the number masked and never the id', async () => {
    renderWithIntl(
      <KindDetails
        item={item('identity', {
          givenName: 'Ada',
          documents: [
            {
              id: 'doc-uuid-1',
              type: 'Passport',
              number: 'X1234567',
              issuingCountry: 'UK',
              issuingAuthority: 'HMPO',
              issuedOn: '2020-01-02',
              expiresOn: '2030-01-02',
            },
          ],
        })}
      />,
    );
    expect(screen.getByText('Passport')).toBeInTheDocument();
    expect(screen.getByText('HMPO')).toBeInTheDocument();
    expect(screen.getByText('2030-01-02')).toBeInTheDocument();
    expect(screen.queryByText('doc-uuid-1')).not.toBeInTheDocument();
    expect(screen.queryByText('X1234567')).not.toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Show the document number' }));
    expect(screen.getByText('X1234567')).toBeInTheDocument();
  });

  it('masks the private key of a certificate behind Show', async () => {
    renderWithIntl(<KindDetails item={item('certificate', { certificate: 'nope', private: 'MC4CAQAwBQYDK2VwBCIEIA==' })} />);
    expect(screen.queryByText('MC4CAQAwBQYDK2VwBCIEIA==')).not.toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Show the private key' }));
    expect(screen.getByText('MC4CAQAwBQYDK2VwBCIEIA==')).toBeInTheDocument();
  });

  it('shows the source, the checked addresses and whether the checked fingerprint matches', async () => {
    // A v4 RSA public key packet; its SHA-1 fingerprint is the one below.
    const body = Uint8Array.from([4, 0, 0, 0, 1, 1, 0, 8, 0xc3, 0, 8, 0x03]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', Uint8Array.from([0x99, 0, body.length, ...body])));
    const fingerprint = Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
    const contact = {
      name: 'Ada',
      public: toB64(Uint8Array.from([0xc6, body.length, ...body])),
      source: 'wkd',
      sourceEmail: 'ada@example.org',
      checkedAddresses: ['ada@example.org', 'ada@work.example'],
    };
    const { unmount } = renderWithIntl(
      <KindDetails item={item('contact', { ...contact, checkedFingerprint: fingerprint.toUpperCase() })} />,
    );
    expect(screen.getAllByText('ada@example.org').length).toBeGreaterThan(0);
    expect(screen.getByText('ada@work.example')).toBeInTheDocument();
    expect(await screen.findByText('It matches this key.')).toBeInTheDocument();
    unmount();
    renderWithIntl(<KindDetails item={item('contact', { ...contact, checkedFingerprint: 'AB'.repeat(20) })} />);
    expect(await screen.findByText(/does not match this key/)).toBeInTheDocument();
  });

  it('compares fingerprints without spaces, colons or case', () => {
    expect(sameFingerprint('AB CD:ef', 'abcdef')).toBe(true);
    expect(sameFingerprint('', '')).toBe(false);
    expect(sameFingerprint('ab', 'cd')).toBe(false);
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
