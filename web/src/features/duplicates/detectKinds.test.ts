// The duplicate rule of every item kind, and the reason a group of it gives.
import { describe, expect, it } from 'vitest';
import type { ItemData } from '@/features/vault/vault';
import { SPACE, vaultItem } from '@/test/tools-fixtures';
import { type DerivedFacts, WHY_LABEL, findDuplicates, tagsOf } from './detect';

const HASH = '0123456789abcdef'.repeat(4);

/** Two copies of one kind and what the one group of them says. */
function groupOf(kind: string, a: ItemData, b: ItemData, facts?: DerivedFacts) {
  const groups = findDuplicates([vaultItem(kind, a), vaultItem(kind, b)], facts);
  return groups.length === 1 ? groups[0] : undefined;
}

describe('MFA codes', () => {
  it('match on the secret however it is written', () => {
    const group = groupOf('otp', { secret: 'JBSWY3DPEHPK3PXP' }, { secret: 'jbsw y3dp ehpk 3pxp==' });
    expect(group?.why).toBe('secret');
  });

  it('do not match on different secrets, and a code with no secret is never a duplicate', () => {
    expect(groupOf('otp', { secret: 'JBSWY3DPEHPK3PXP' }, { secret: 'MFRGGZDFMZTWQ2LK' })).toBeUndefined();
    expect(groupOf('otp', { name: 'a' }, { name: 'a' })).toBeUndefined();
  });
});

describe('backup codes', () => {
  it('match on the same codes, in any order, used or not (the app keeps `{code, used}`)', () => {
    const group = groupOf(
      'backup-codes',
      { codes: [{ code: 'aaa-111' }, { code: 'bbb-222', used: true }] },
      { codes: [{ code: 'bbb-222' }, { code: 'aaa-111' }, { code: 'bbb-222' }] },
    );
    expect(group?.why).toBe('codes');
  });

  it('also read codes written as plain strings', () => {
    expect(groupOf('backup-codes', { codes: ['a', 'b'] }, { codes: [{ code: 'b' }, { code: 'a' }] })?.why).toBe('codes');
  });

  it('do not match when one code differs', () => {
    expect(groupOf('backup-codes', { codes: [{ code: 'a' }] }, { codes: [{ code: 'a' }, { code: 'b' }] })).toBeUndefined();
  });
});

describe('passkeys', () => {
  it('match on the website and the credential id', () => {
    const group = groupOf(
      'passkey',
      { rpId: 'accounts.google.com', credentialId: 'dGVzdA==' },
      { rpId: 'Accounts.Google.com', credentialId: 'dGVzdA' },
    );
    expect(group?.why).toBe('passkey');
  });

  it('are not copies on the same website with another credential', () => {
    expect(
      groupOf('passkey', { rpId: 'example.com', credentialId: 'AAAA' }, { rpId: 'example.com', credentialId: 'BBBB' }),
    ).toBeUndefined();
  });
});

describe('cards', () => {
  it('match on the number and the expiry', () => {
    const group = groupOf(
      'card',
      { number: '4111 1111 1111 1111', expMonth: 8, expYear: 2028 },
      { number: '4111-1111-1111-1111', expMonth: '08', expYear: '2028' },
    );
    expect(group?.why).toBe('card');
  });

  it('are not copies with another expiry', () => {
    expect(
      groupOf(
        'card',
        { number: '4111111111111111', expMonth: 8, expYear: 2028 },
        { number: '4111111111111111', expMonth: 9, expYear: 2028 },
      ),
    ).toBeUndefined();
  });
});

describe('identities', () => {
  it('match on a document number, however it is spaced', () => {
    const group = groupOf(
      'identity',
      { name: 'Passport', givenName: 'Sam', documents: [{ type: 'passport', number: 'X 1234-567' }] },
      { name: 'Passport details', givenName: 'Sam', documents: [{ type: 'passport', number: 'x1234567' }] },
    );
    expect(group?.why).toBe('document');
  });

  it('are not copies when two papers of one person have different numbers', () => {
    const passport = { givenName: 'Sam', familyName: 'Rivera', email: 'sam@example.org' };
    expect(
      groupOf(
        'identity',
        { ...passport, name: 'Passport', documents: [{ number: 'P1234567' }] },
        { ...passport, name: 'Driver license', documents: [{ number: 'D7654321' }] },
      ),
    ).toBeUndefined();
  });

  it('ignore a number too short to tell papers apart', () => {
    expect(
      groupOf('identity', { name: 'a', documents: [{ number: '12' }] }, { name: 'b', documents: [{ number: '12' }] }),
    ).toBeUndefined();
  });

  it('with no papers match on the person and the email', () => {
    const group = groupOf(
      'identity',
      { name: 'Sam', givenName: 'Sam', familyName: 'Rivera', email: 'SAM@example.org' },
      { name: 'Sam R', givenName: 'sam', familyName: 'rivera', email: 'sam@example.org' },
    );
    expect(group?.why).toBe('identity');
  });

  it('are never grouped by the title they were given', () => {
    expect(groupOf('identity', { name: 'Passport' }, { name: 'Passport' })).toBeUndefined();
  });
});

describe('contacts', () => {
  it('match on the email and the phone', () => {
    const group = groupOf(
      'contact',
      { name: 'Alex Chen', email: 'Alex.Chen@Example.org', phone: '+1 (555) 0142' },
      { name: 'Alex C.', email: 'alex.chen@example.org', phone: '1-555-0142' },
    );
    expect(group?.why).toBe('contact');
  });

  it('with an email only, or a phone only, say which', () => {
    expect(groupOf('contact', { email: 'a@b.c' }, { email: 'A@B.C' })?.why).toBe('contactEmail');
    expect(groupOf('contact', { phone: '555 0142' }, { phone: '5550142' })?.why).toBe('contactPhone');
  });

  it('are not copies with the same email and another phone', () => {
    expect(groupOf('contact', { email: 'a@b.c', phone: '111' }, { email: 'a@b.c', phone: '222' })).toBeUndefined();
  });

  it('read the email a key-only contact came from', () => {
    expect(groupOf('contact', { sourceEmail: 'a@b.c' }, { email: 'a@b.c' })?.why).toBe('contactEmail');
  });

  it('match on the PGP key they hold, as the Kemlock app does, whoever they are called', () => {
    const a = vaultItem('contact', { name: 'Alex', email: 'alex@work.example', public: 'AAAA' });
    const b = vaultItem('contact', { name: 'A. Chen', email: 'a.chen@home.example', public: 'AAAA' });
    const none = vaultItem('contact', { name: 'Blake', email: 'blake@home.example', public: 'BBBB' });
    const facts: DerivedFacts = new Map([
      [a.id, { fingerprint: '9F3A 77C1 0B2E 45D6 8A19 C0DE 12F4 5B6A 7788 9900' }],
      [b.id, { fingerprint: '9f3a77c10b2e45d68a19c0de12f45b6a77889900' }],
      [none.id, { fingerprint: '1111 2222' }],
    ]);
    expect(findDuplicates([a, b, none])).toEqual([]);
    const groups = findDuplicates([a, b, none], facts);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.why).toBe('key');
    expect(groups[0]?.items.map((item) => item.id).sort()).toEqual([a.id, b.id].sort());
  });

  it('give a contact with no key only its email and phone to go by', () => {
    const a = vaultItem('contact', { name: 'a', email: 'a@b.c' });
    expect(tagsOf(a, new Map([[a.id, { fingerprint: 'AB' }]])).map((tag) => tag.name)).toEqual(['contact']);
  });
});

describe('keys and certificates', () => {
  const FINGERPRINT = 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8';

  it('match SSH keys on a stored fingerprint, or one worked out in the browser', () => {
    expect(groupOf('ssh-key', { fingerprint: FINGERPRINT }, { fingerprint: FINGERPRINT })?.why).toBe('key');

    const a = vaultItem('ssh-key', { name: 'a' });
    const b = vaultItem('ssh-key', { name: 'b' });
    const facts: DerivedFacts = new Map([
      [a.id, { fingerprint: FINGERPRINT }],
      [b.id, { fingerprint: FINGERPRINT }],
    ]);
    expect(findDuplicates([a, b])).toEqual([]);
    expect(findDuplicates([a, b], facts)[0]?.why).toBe('key');
  });

  it('match PGP keys on the fingerprint, spaced or not', () => {
    const group = groupOf(
      'pgp-key',
      { fingerprint: '9F3A 77C1 0B2E 45D6 8A19 C0DE 12F4 5B6A 7788 9900' },
      { fingerprint: '9f3a77c10b2e45d68a19c0de12f45b6a77889900' },
    );
    expect(group?.why).toBe('key');
  });

  it('match certificates on the fingerprint with or without the colons, and say so', () => {
    const group = groupOf(
      'certificate',
      { fingerprint: HASH.toUpperCase().replace(/(..)(?=.)/g, '$1:') },
      { fingerprint: HASH },
    );
    expect(group?.why).toBe('certificate');
    expect(group?.kind).toBe('certificate');
  });

  it('keep SSH, PGP and certificates apart even when they share a value', () => {
    const groups = findDuplicates([
      vaultItem('ssh-key', { fingerprint: HASH }),
      vaultItem('pgp-key', { fingerprint: HASH }),
      vaultItem('certificate', { fingerprint: HASH }),
    ]);
    expect(groups).toEqual([]);
  });

  it('give a key with no fingerprint nothing to match on', () => {
    expect(groupOf('ssh-key', { name: 'a' }, { name: 'a' })).toBeUndefined();
    expect(tagsOf(vaultItem('certificate', { name: 'a' }))).toEqual([]);
  });
});

describe('files', () => {
  const entry = (sha256: string) => ({ id: 'x', name: 'Lease.pdf', size: 10, key: 'k', addedAt: 1, sha256 });

  it('match on the content hash their file entry holds, in either case', () => {
    const group = groupOf(
      'file',
      { name: 'Lease.pdf', file: entry(HASH) },
      { name: 'Lease (1).pdf', file: entry(HASH.toUpperCase()) },
    );
    expect(group?.why).toBe('file');
  });

  it('also read a hash kept on the item itself', () => {
    expect(groupOf('file', { name: 'a', sha256: HASH }, { name: 'b', file: entry(HASH) })?.why).toBe('file');
  });

  it('are not copies without a hash, or with another one', () => {
    // Two files of one name and size, each with a key of its own, say nothing about their contents.
    expect(
      groupOf('file', { name: 'a', file: { name: 'a.pdf', size: 10, key: 'k1' } }, { name: 'a', file: { name: 'a.pdf', size: 10, key: 'k2' } }),
    ).toBeUndefined();
    expect(groupOf('file', { name: 'a' }, { name: 'a' })).toBeUndefined();
    expect(groupOf('file', { file: entry(HASH) }, { file: entry('1'.repeat(64)) })).toBeUndefined();
    expect(groupOf('file', { file: entry('abc') }, { file: entry('abc') })).toBeUndefined();
  });
});

describe('across kinds and vaults', () => {
  it('never mixes two kinds even when a value is shared', () => {
    const groups = findDuplicates([vaultItem('note', { text: 'abcd1234' }), vaultItem('backup-codes', { codes: ['abcd1234'] })]);
    expect(groups).toEqual([]);
  });

  it('marks a group of any kind that sits in two vaults', () => {
    const mine = vaultItem('contact', { email: 'a@b.c' });
    const theirs = vaultItem('contact', { email: 'a@b.c' }, { owner: SPACE });
    const [group] = findDuplicates([mine, theirs]);
    expect(group?.crossOwner).toBe(true);
  });

  it('orders a group newest first, whether the app wrote a number or an older save a date', () => {
    const a = vaultItem('note', { text: 'x', updatedAt: Date.parse('2026-10-01T00:00:00Z') });
    const b = vaultItem('note', { text: 'x', updatedAt: '2026-11-01T00:00:00Z' });
    const c = vaultItem('note', { text: 'x', updatedAt: Date.parse('2026-09-01T00:00:00Z') });
    expect(findDuplicates([a, b, c])[0]?.items.map((item) => item.id)).toEqual([b.id, a.id, c.id]);
  });

  it('has a reason text for every reason', () => {
    for (const label of Object.values(WHY_LABEL)) expect(label).toMatch(/^dup\.why\./);
    expect(Object.keys(WHY_LABEL).sort()).toEqual(
      [
        'account',
        'card',
        'certificate',
        'codes',
        'contact',
        'contactEmail',
        'contactPhone',
        'cred',
        'document',
        'file',
        'identity',
        'key',
        'note',
        'passkey',
        'secret',
      ].sort(),
    );
  });
});
