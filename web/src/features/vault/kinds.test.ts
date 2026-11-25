import { describe, expect, it } from 'vitest';
import { messages } from '@/i18n';
import {
  EDITABLE_KINDS,
  KIND_ORDER,
  SENDABLE_KIND_ORDER,
  isEditable,
  isKnownKind,
  kindIcon,
  kindLabel,
  kindPluralLabel,
} from './kinds';

describe('the kinds of item', () => {
  it('come in the owner order, with the file and the passkey', () => {
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

  it('are named in the singular and the plural, the MFA code included', () => {
    const names = KIND_ORDER.map((kind) => messages[kindLabel(kind)]);
    expect(names).toEqual([
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
    const plurals = KIND_ORDER.map((kind) => messages[kindPluralLabel(kind)]);
    expect(plurals).toEqual([
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

  it('keep the stored id otp for the MFA code', () => {
    expect(isKnownKind('otp')).toBe(true);
    expect(isKnownKind('mfa')).toBe(false);
  });

  it('have an icon each, and an unknown kind is an Item', () => {
    expect(new Set(KIND_ORDER.map((kind) => kindIcon(kind))).size).toBe(KIND_ORDER.length);
    expect(kindIcon('from-a-newer-app')).toBe('items');
    expect(kindLabel('from-a-newer-app')).toBe('kind.other');
    expect(kindPluralLabel('from-a-newer-app')).toBe('kind.other');
  });

  it('are editable except the passkey, which a website makes', () => {
    expect(isEditable('file')).toBe(true);
    expect(isEditable('contact')).toBe(true);
    expect(isEditable('passkey')).toBe(false);
    expect(isEditable('nope')).toBe(false);
    expect(EDITABLE_KINDS).toHaveLength(KIND_ORDER.length - 1);
  });

  it('can all be sent as an item except the file', () => {
    expect(SENDABLE_KIND_ORDER).not.toContain('file');
    expect(SENDABLE_KIND_ORDER).not.toContain('passkey');
    expect(SENDABLE_KIND_ORDER).toHaveLength(KIND_ORDER.length - 2);
  });
});
