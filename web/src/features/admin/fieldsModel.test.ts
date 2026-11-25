import { describe, expect, it } from 'vitest';
import type { CustomField } from '@/api/admin';
import {
  FIELD_KINDS,
  MAX_NAME_CHARS,
  appliesTo,
  checkDraft,
  cleanName,
  draftOf,
  isFieldKind,
} from './fieldsModel';

const FIELD: CustomField = { id: 'f1', name: 'Cost center', type: 'hidden', kinds: ['login', 'card'] };

describe('the item types a field can apply to', () => {
  it('are the ten that take custom fields, in the order the apps list them', () => {
    expect([...FIELD_KINDS]).toEqual([
      'login',
      'note',
      'otp',
      'backup-codes',
      'card',
      'identity',
      'contact',
      'certificate',
      'ssh-key',
      'pgp-key',
    ]);
  });

  it('leave out a file and a passkey, which take none', () => {
    expect(isFieldKind('file')).toBe(false);
    expect(isFieldKind('passkey')).toBe(false);
    expect(isFieldKind('otp')).toBe(true);
  });
});

describe('a field draft', () => {
  it('starts blank for a new field: text, on all types', () => {
    expect(draftOf()).toEqual({ name: '', type: 'text', scope: 'all', kinds: [] });
  });

  it('starts from the field being changed', () => {
    expect(draftOf(FIELD)).toEqual({ name: 'Cost center', type: 'hidden', scope: 'only', kinds: ['login', 'card'] });
    expect(draftOf({ ...FIELD, kinds: 'all' })).toMatchObject({ scope: 'all', kinds: [] });
  });

  it('drops a type the form does not know, such as one a newer server adds', () => {
    expect(draftOf({ ...FIELD, kinds: ['login', 'hologram'] }).kinds).toEqual(['login']);
  });
});

describe('a name', () => {
  it('is trimmed and its white space made single spaces, as the server keeps it', () => {
    expect(cleanName('  Employee \t  ID ')).toBe('Employee ID');
    expect(cleanName('   ')).toBe('');
  });
});

describe('checking a draft', () => {
  const draft = draftOf();

  it('sends the cleaned name, the type and all types', () => {
    expect(checkDraft({ ...draft, name: '  Employee   ID ', type: 'checkbox' })).toEqual({
      ok: true,
      input: { name: 'Employee ID', type: 'checkbox', kinds: 'all' },
    });
  });

  it('sends the ticked types in the apps order, whichever order they were ticked in', () => {
    expect(checkDraft({ ...draft, name: 'Pin', scope: 'only', kinds: ['pgp-key', 'card', 'login'] })).toEqual({
      ok: true,
      input: { name: 'Pin', type: 'text', kinds: ['login', 'card', 'pgp-key'] },
    });
  });

  it('refuses an empty name, a name over 64 characters and a control character in it', () => {
    const wrong = { ok: false, errors: { name: 'admin.fields.error.name' } };
    expect(checkDraft({ ...draft, name: '   ' })).toEqual(wrong);
    expect(checkDraft({ ...draft, name: 'x'.repeat(MAX_NAME_CHARS + 1) })).toEqual(wrong);
    expect(checkDraft({ ...draft, name: 'a\u0007b' })).toEqual(wrong);
  });

  it('counts characters, not bytes: 64 of them are fine', () => {
    expect(checkDraft({ ...draft, name: 'é'.repeat(MAX_NAME_CHARS) }).ok).toBe(true);
    expect(checkDraft({ ...draft, name: '😀'.repeat(MAX_NAME_CHARS) }).ok).toBe(true);
    expect(checkDraft({ ...draft, name: '😀'.repeat(MAX_NAME_CHARS + 1) }).ok).toBe(false);
  });

  it('wants at least one type when it is only some of them', () => {
    expect(checkDraft({ ...draft, name: 'Pin', scope: 'only', kinds: [] })).toEqual({
      ok: false,
      errors: { kinds: 'admin.fields.error.kinds' },
    });
    expect(checkDraft({ ...draft, name: '', scope: 'only', kinds: [] })).toEqual({
      ok: false,
      errors: { name: 'admin.fields.error.name', kinds: 'admin.fields.error.kinds' },
    });
    // Ticked types are ignored while the field is on all of them.
    expect(checkDraft({ ...draft, name: 'Pin', scope: 'all', kinds: ['card'] })).toMatchObject({
      ok: true,
      input: { kinds: 'all' },
    });
  });
});

describe('the On column', () => {
  it('says all types, or names the types in the plural', () => {
    expect(appliesTo({ kinds: 'all' })).toBe('all');
    expect(appliesTo(FIELD)).toEqual(['kind.plural.login', 'kind.plural.card']);
    expect(appliesTo({ kinds: ['otp', 'backup-codes', 'ssh-key'] })).toEqual([
      'kind.plural.otp',
      'kind.plural.backup-codes',
      'kind.plural.ssh-key',
    ]);
  });
});
