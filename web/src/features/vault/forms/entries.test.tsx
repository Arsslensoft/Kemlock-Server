import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from '../vault';
import { timeAgo } from '../kinds';
import { itemName } from '../vault';
import { BackupCodesForm, backupCodesDefaults, backupCodesFields, parseCodes } from './backupCodes';
import { CardForm, cardDefaults, cardFields, parseCardExpiry } from './card';
import { IdentityForm, identityDefaults, identityFields } from './identity';
import { OtpForm, otpDefaults, otpFields } from './otp';

function item(kind: string, data: Record<string, unknown>): VaultItem {
  return {
    id: 'i1',
    owner: 'user:u1',
    kind,
    revision: 3,
    keyVersion: 1,
    data,
    sizes: { ciphertext: 0, itemKey: 0 },
  };
}

describe('OtpForm', () => {
  it('wants a valid secret', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<OtpForm initial={otpDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Issuer'), 'GitHub');
    await user.type(screen.getByLabelText('Secret key'), 'not base32!');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/isn't a valid secret/, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('submits a code', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<OtpForm initial={otpDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Issuer'), 'GitHub');
    await user.type(screen.getByLabelText('Secret key'), 'jbsw y3dp ehpk 3pxp');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({ issuer: 'GitHub', type: 'totp', digits: '6', period: '30' });
  });

  it('writes the keys of OtpAccount.toJson', () => {
    const fields = otpFields({ ...otpDefaults(), issuer: 'GitHub', label: 'sam', secret: 'jbsw y3dp ehpk 3pxp' });
    expect(fields).toMatchObject({
      type: 'totp',
      issuer: 'GitHub',
      label: 'sam',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    });
    expect(fields['counter']).toBeUndefined();
    expect(typeof fields['addedAt']).toBe('number');
  });

  it('keeps the id and addedAt of an edited code, and a counter only for HOTP', () => {
    const existing = item('otp', { id: 'a1', addedAt: 5, issuer: 'X', label: '', secret: 'JBSWY3DP', type: 'hotp', counter: 4 });
    const values = otpDefaults(existing);
    expect(values.counter).toBe('4');
    const fields = otpFields({ ...values, counter: '9' }, existing);
    expect(fields['id']).toBeUndefined();
    expect(fields['addedAt']).toBeUndefined();
    expect(fields['counter']).toBe(9);
  });
});

describe('BackupCodesForm', () => {
  it('wants at least one code', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <BackupCodesForm initial={backupCodesDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Service'), 'GitHub');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/This is required/, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('writes {code, used} entries and keeps what the app wrote on known codes', () => {
    const existing = item('backup-codes', {
      id: 'b1',
      serviceName: 'GitHub',
      codes: [
        { code: 'aaaa-1111', used: true, usedAt: 99 },
        { code: 'bbbb-2222', used: false },
      ],
    });
    const values = { ...backupCodesDefaults(existing), codes: 'aaaa-1111\n\n cccc-3333 \n' };
    expect(parseCodes(values.codes)).toEqual(['aaaa-1111', 'cccc-3333']);
    expect(backupCodesFields(values, existing)['codes']).toEqual([
      { code: 'aaaa-1111', used: true, usedAt: 99 },
      { code: 'cccc-3333', used: false },
    ]);
  });
});

describe('CardForm', () => {
  it('reads expiry the way the app does', () => {
    expect(parseCardExpiry('05/29')).toEqual({ month: 5, year: 2029 });
    expect(parseCardExpiry('5/2029')).toEqual({ month: 5, year: 2029 });
    expect(parseCardExpiry('0529')).toEqual({ month: 5, year: 2029 });
    expect(parseCardExpiry('13/29')).toEqual({ year: 2029 });
    expect(parseCardExpiry('x')).toEqual({});
  });

  it('wants a number or a cardholder', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<CardForm initial={cardDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Everyday Visa');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/number or a cardholder/, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('writes digits only, expMonth and a four-digit expYear', () => {
    const fields = cardFields({
      ...cardDefaults(),
      name: 'Everyday Visa',
      number: '4111-1111 1111-1111',
      expiry: '05/29',
      code: '123',
    });
    expect(fields).toMatchObject({ name: 'Everyday Visa', number: '4111111111111111', expMonth: 5, expYear: 2029, code: '123' });
    expect(fields['cardholder']).toBeUndefined();
  });

  it('opens with the stored expiry', () => {
    const values = cardDefaults(item('card', { name: 'V', number: '4111', expMonth: 5, expYear: 2029 }));
    expect(values.expiry).toBe('05/2029');
  });
});

describe('IdentityForm', () => {
  it('wants a name and a valid email', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <IdentityForm initial={identityDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Email'), 'nope');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/This is required/, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('writes the address object only when it has something, and keeps documents', () => {
    const existing = item('identity', {
      id: 'd1',
      name: 'Sam',
      documents: [{ id: 'x', type: 'passport', number: 'P1' }],
      address: { city: 'Tunis', country: 'TN', extraKey: 1 },
    });
    const values = { ...identityDefaults(existing), line1: '1 Rue X', city: '' };
    const fields = identityFields(values, existing);
    expect(fields['address']).toEqual({ extraKey: 1, lines: ['1 Rue X'], country: 'TN' });
    expect('documents' in fields).toBe(false);
    expect(identityFields({ ...identityDefaults(), name: 'Blank' })['address']).toBeUndefined();
  });
});

describe('itemName', () => {
  it('names codes by issuer and account, and backup codes by service', () => {
    expect(itemName(item('otp', { issuer: 'GitHub', label: 'sam' }))).toBe('GitHub: sam');
    expect(itemName(item('backup-codes', { serviceName: 'Google' }))).toBe('Google');
    expect(itemName(item('card', {}))).toBe('card');
  });
});

describe('entry id', () => {
  it('does not set an entry id of its own; saveItem uses the item id', () => {
    expect(otpFields({ ...otpDefaults(), issuer: 'G', secret: 'JBSWY3DPEHPK3PXP' })['id']).toBeUndefined();
  });
});

describe('timeAgo', () => {
  it('reads epoch ms as well as legacy ISO strings', () => {
    const now = new Date('2026-11-24T12:00:00Z');
    expect(timeAgo(now.getTime() - 2 * 3600 * 1000, now)).toBe('2 hours ago');
    expect(timeAgo('2026-11-24T10:00:00Z', now)).toBe('2 hours ago');
  });
});
