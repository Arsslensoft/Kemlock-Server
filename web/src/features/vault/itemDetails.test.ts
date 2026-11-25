import { describe, expect, it } from 'vitest';
import { messages } from '@/i18n';
import { IntlMessageFormat } from 'intl-messageformat';
import { vaultItem } from '@/test/tools-fixtures';
import type { ItemData } from './vault';
import {
  type DetailPart,
  cardExpiry,
  commonName,
  detailParts,
  fileTypeName,
  formatSize,
  identityExpiryYear,
  shortFingerprint,
} from './itemDetails';

/** What the page prints for the parts: messages worded, text as it is, joined by a middle dot. */
function line(kind: string, data: ItemData | null, facts?: Parameters<typeof detailParts>[1]): string {
  return detailParts(vaultItem(kind, data), facts)
    .map((part: DetailPart) =>
      'text' in part ? part.text : String(new IntlMessageFormat(messages[part.id] as string, 'en').format(part.values)),
    )
    .join(' · ');
}

describe('the details of each kind', () => {
  it('are a login\'s websites, without www or the path', () => {
    expect(line('login', { name: 'x', urls: ['https://www.github.com/login', 'gist.github.com'] })).toBe('github.com, gist.github.com');
  });

  it('are "Secure note" for a note, and its attachments when it has some', () => {
    expect(line('note', { name: 'n', text: 'x' })).toBe('Secure note');
    expect(line('note', { name: 'n', attachments: [{}, {}] })).toBe('Secure note · 2 attachments');
    expect(line('note', { name: 'n', attachments: [{}] })).toBe('Secure note · 1 attachment');
  });

  it('are a file\'s type and size', () => {
    expect(line('file', { name: 'Lease', file: { name: 'Lease agreement.pdf', size: 2_400_000 } })).toBe('PDF · 2.4 MB');
    expect(line('file', { name: 'Scan', file: { name: 'Passport scan.jpg', size: 1_100_000 } })).toBe('JPEG image · 1.1 MB');
    expect(line('file', { name: 'Scan', file: { name: 'scan', type: 'image/jpeg', size: 860 } })).toBe('JPEG image · 860 B');
    expect(line('file', { name: 'x' })).toBe('Item');
  });

  it('are an MFA code\'s account and how often it changes, never its secret', () => {
    const text = line('otp', { name: 'GitHub code', secret: 'JBSWY3DPEHPK3PXP', label: 'sam@example.org', period: 30 });
    expect(text).toBe('sam@example.org · every 30 s');
    expect(text).not.toContain('JBSWY');
    expect(line('otp', { secret: 'JBSWY3DPEHPK3PXP', issuer: 'Okta', period: 60 })).toBe('Okta · every 60 s');
    expect(line('otp', { secret: 'JBSWY3DPEHPK3PXP', type: 'hotp', label: 'a' })).toBe('a');
  });

  it('are how many backup codes there are and how many are unused, never a code', () => {
    const text = line('backup-codes', { codes: [{ code: 'aaaa-1111', used: true }, { code: 'bbbb-2222' }, { code: 'cccc-3333' }] });
    expect(text).toBe('3 codes, 2 unused');
    expect(text).not.toContain('aaaa');
    expect(line('backup-codes', { codes: [{ code: 'z' }] })).toBe('1 code, 1 unused');
    expect(line('backup-codes', { codes: [] })).toBe('Item');
  });

  it('are a passkey\'s website', () => {
    expect(line('passkey', { name: 'p', rpId: 'accounts.google.com', credentialId: 'x' })).toBe('accounts.google.com');
  });

  it('are the last four digits of a card, its brand and its expiry, never the number', () => {
    const text = line('card', { name: 'c', brand: 'Visa', number: '4111 1111 1111 4821', expMonth: 8, expYear: 2028 });
    expect(text).toBe('Visa ending 4821 · expires 08/28');
    expect(text).not.toContain('4111');
    expect(line('card', { name: 'c', number: '5555444433330937', expMonth: '11', expYear: '2027' })).toBe(
      'ending 0937 · expires 11/27',
    );
    expect(line('card', { name: 'c' })).toBe('Item');
  });

  it('are the year the first of an identity\'s papers expires', () => {
    expect(line('identity', { name: 'i', documents: [{ expiresOn: '2031-04-01' }, { expiresOn: '2029-01-01' }] })).toBe('Expires 2029');
    expect(line('identity', { name: 'i' })).toBe('Item');
  });

  it('are a contact\'s phone and company, else their email', () => {
    expect(line('contact', { name: 'a', phone: '+1 555 0142', company: 'Example Co', email: 'a@b.c' })).toBe('+1 555 0142 · Example Co');
    expect(line('contact', { name: 'a', email: 'a@b.c' })).toBe('a@b.c');
  });

  it('are a key\'s algorithm and a short fingerprint, once the fingerprint is known', () => {
    const facts = { fingerprint: 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8', algorithm: 'ed25519' };
    expect(line('ssh-key', { name: 'k' }, facts)).toBe('ed25519 · SHA256:q38F…ZaS8');
    expect(line('ssh-key', { name: 'k' })).toBe('Item');
    expect(line('pgp-key', { name: 'k' }, { fingerprint: '9F3A 77C1 0B2E 45D6 8A19 C0DE', userId: 'Sam <sam@example.co>' })).toBe(
      'Sam <sam@example.co> · 9F3A…C0DE',
    );
  });

  it('are a certificate\'s common name only, and when it expires', () => {
    const notAfter = new Date('2027-02-02T00:00:00Z');
    expect(line('certificate', { name: 'c' }, { fingerprint: 'AB:CD', subject: 'CN=vpn.example.co', notAfter })).toBe(
      'vpn.example.co · expires 2 Feb 2027',
    );
    expect(
      line('certificate', { name: 'c' }, { fingerprint: 'AB:CD', subject: 'O=Example Co, CN=Workstation client, C=US', notAfter }),
    ).toBe('Workstation client · expires 2 Feb 2027');
  });

  it('are a PGP key\'s algorithm and subkeys, as "ed25519 · 3 subkeys"', () => {
    const base = { fingerprint: '9F3A 77C1', userId: 'Sam <sam@example.co>' };
    expect(line('pgp-key', { name: 'k' }, { ...base, algorithm: 'ed25519', subkeys: 3 })).toBe('ed25519 · 3 subkeys');
    expect(line('pgp-key', { name: 'k' }, { ...base, algorithm: 'RSA', subkeys: 1 })).toBe('RSA · 1 subkey');
    expect(line('pgp-key', { name: 'k' }, { ...base, algorithm: 'ed25519', subkeys: 0 })).toBe('ed25519 · no subkeys');
    expect(line('pgp-key', { name: 'k' }, { ...base, algorithm: 'ed25519' })).toBe('ed25519');
  });

  it('are nothing for an item that could not be opened, and "Item" for a kind with no line', () => {
    expect(detailParts(vaultItem('login', null))).toEqual([]);
    expect(line('hologram', { name: 'h' })).toBe('Item');
  });
});

describe('the pieces of a details line', () => {
  it('name a file as a person does: PDF, JPEG image, or the type it says', () => {
    expect(fileTypeName({ name: 'Lease agreement.pdf' })).toBe('PDF');
    expect(fileTypeName({ name: 'Passport scan.JPG' })).toBe('JPEG image');
    expect(fileTypeName({ name: 'photo.png' })).toBe('PNG image');
    expect(fileTypeName({ name: 'photo.tif' })).toBe('TIFF image');
    expect(fileTypeName({ name: 'backup.zip' })).toBe('ZIP');
    expect(fileTypeName({ name: 'scan', type: 'image/webp' })).toBe('WEBP image');
    expect(fileTypeName({ name: 'notes', type: 'application/pdf' })).toBe('PDF');
    expect(fileTypeName({ name: 'notes' })).toBe('');
  });

  it('take the common name out of a certificate\'s subject, or the whole subject without one', () => {
    expect(commonName('CN=vpn.example.co')).toBe('vpn.example.co');
    expect(commonName('C=US, O=Example Co, CN=Workstation client')).toBe('Workstation client');
    expect(commonName('O=Example Co')).toBe('O=Example Co');
  });

  it('shortens a fingerprint to its start and end', () => {
    expect(shortFingerprint('SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8')).toBe('SHA256:q38F…ZaS8');
    expect(shortFingerprint('9F3A 77C1 0B2E 45D6 8A19 C0DE')).toBe('9F3A…C0DE');
    expect(shortFingerprint('ABCD')).toBe('ABCD');
  });

  it('writes a size in the unit that reads best', () => {
    expect(formatSize(12)).toBe('12 B');
    expect(formatSize(860_000)).toBe('860 KB');
    expect(formatSize(2_400_000)).toBe('2.4 MB');
    expect(formatSize(1_100_000_000)).toBe('1.1 GB');
  });

  it('writes a card expiry as month and two-digit year, or nothing', () => {
    expect(cardExpiry({ expMonth: 8, expYear: 2028 })).toBe('08/28');
    expect(cardExpiry({ expMonth: '12', expYear: '2031' })).toBe('12/31');
    expect(cardExpiry({ expMonth: 13, expYear: 2031 })).toBe('');
    expect(cardExpiry({})).toBe('');
  });

  it('finds the first year an identity\'s papers expire', () => {
    expect(identityExpiryYear({ documents: [{ expiresOn: '2031-04-01' }, { expiresOn: '2029-01-01' }, { expiresOn: '' }] })).toBe('2029');
    expect(identityExpiryYear({ documents: 'nope' })).toBeUndefined();
  });
});
