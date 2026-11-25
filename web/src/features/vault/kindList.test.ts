import { describe, expect, it } from 'vitest';
import { messages } from '@/i18n';
import { kindSubtitle, listKind } from './kindList';
import { KIND_ORDER, kindLabel, kindPluralLabel } from './kinds';

describe('the item types the lists show', () => {
  it('are in the order the design fixes, and the stored id of an MFA code is otp', () => {
    expect([...KIND_ORDER]).toEqual([
      'login',
      'note',
      'file',
      'otp',
      'backup-codes',
      'passkey',
      'card',
      'identity',
      'contact',
      'certificate',
      'ssh-key',
      'pgp-key',
    ]);
  });

  it('have the plural labels of the design', () => {
    expect(KIND_ORDER.map((kind) => messages[kindPluralLabel(kind)])).toEqual([
      'Logins',
      'Notes',
      'Files',
      'MFA codes',
      'Backup codes',
      'Passkeys',
      'Cards',
      'Identities',
      'Contacts',
      'Certificates',
      'SSH keys',
      'PGP keys',
    ]);
  });

  it('have the singular labels of the design, "MFA code" and "File" included', () => {
    expect(KIND_ORDER.map((kind) => messages[kindLabel(kind)])).toEqual([
      'Login',
      'Note',
      'File',
      'MFA code',
      'Backup codes',
      'Passkey',
      'Card',
      'Identity',
      'Contact',
      'Certificate',
      'SSH key',
      'PGP key',
    ]);
  });

  it('have the gray line under their page title, and All items has its own', () => {
    expect(messages[kindSubtitle(undefined)]).toBe('Everything in your vault and in the spaces you belong to.');
    expect(messages[kindSubtitle('otp')]).toBe('Codes for two-step sign-in, made right here.');
    expect(messages[kindSubtitle('ssh-key')]).toBe('Keys for signing in to servers.');
    expect(messages[kindSubtitle('file')]).toBe('Documents, photos and other files, encrypted before upload.');
    for (const kind of KIND_ORDER) expect(messages[kindSubtitle(kind)], kind).toBeTruthy();
  });

  it('call a kind the app has no name for "Items", with the All items line', () => {
    expect(messages[kindPluralLabel('hologram')]).toBe('Items');
    expect(messages[kindLabel('hologram')]).toBe('Item');
    expect(kindSubtitle('hologram')).toBe(kindSubtitle(undefined));
  });
});

describe('the type a list route asks for', () => {
  it('is the kind id in `?kind=`, and All items for none, an empty one or "all"', () => {
    expect(listKind('otp')).toBe('otp');
    expect(listKind('backup-codes')).toBe('backup-codes');
    expect(listKind(undefined)).toBeUndefined();
    expect(listKind('')).toBeUndefined();
    expect(listKind('all')).toBeUndefined();
  });
});
