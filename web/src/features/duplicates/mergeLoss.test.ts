// A merge loses nothing a copy held, whatever its kind: what the kept item lacks comes from the
// newest copy that has it, documents and used codes are joined, the fields the copies disagree on
// are a pick, and a note's files are copied onto the kept note.
import { describe, expect, it } from 'vitest';
import type { ItemData } from '@/features/vault/vault';
import { SPACE, login, vaultItem } from '@/test/tools-fixtures';
import { canWriteItem } from '@/features/vault/writeAccess';
import { type FileTransport, attachmentCopies, copyAttachments } from './attachmentCopy';
import { type DuplicateGroup, findDuplicates } from './detect';
import { applyCopies, defaultPicks, planMerge, resultName } from './merge';
import { chosenFrom, fieldConflicts, showValue } from './mergeFill';
import { sameLabel } from './sameLabel';

const NOW = new Date('2026-11-25T10:00:00Z');
const FINGERPRINT = 'SHA256:q38FRmSR0cmF/HngMtpw1AoIHLbKjnCck9Xp3KhZaS8';

/** Two copies of one kind, the first the newest. */
function two(kind: string, a: ItemData, b: ItemData) {
  return [vaultItem(kind, { updatedAt: 2, ...a }), vaultItem(kind, { updatedAt: 1, ...b })] as const;
}

describe('a value the kept item lacks', () => {
  it('comes from the copy that has it: the halves of a key and a certificate', () => {
    const [pub, full] = two(
      'ssh-key',
      { name: 'Router', fingerprint: FINGERPRINT, public: 'PUB' },
      { name: 'Router key', fingerprint: FINGERPRINT, public: 'PUB', private: 'PRIVATE', algorithm: 'ed25519' },
    );
    const plan = planMerge([pub, full], defaultPicks([pub, full]), NOW);
    expect(plan?.kept.id).toBe(pub.id);
    expect(plan?.fields['private']).toBe('PRIVATE');
    expect(plan?.fields['algorithm']).toBe('ed25519');
    // What the kept item had is untouched.
    expect('public' in (plan?.fields ?? {})).toBe(false);

    const [cert, withKey] = two(
      'certificate',
      { name: 'Client', fingerprint: FINGERPRINT, certificate: 'PEM' },
      { name: 'Client 2', fingerprint: FINGERPRINT, certificate: 'PEM', private: 'KEY' },
    );
    expect(planMerge([cert, withKey], defaultPicks([cert, withKey]), NOW)?.fields['private']).toBe('KEY');
  });

  it('brings a private key\'s protected flag with it, and a contact\'s key its source and checks', () => {
    const [bare, full] = two(
      'pgp-key',
      { name: 'a', fingerprint: FINGERPRINT, public: 'PUB' },
      { name: 'b', fingerprint: FINGERPRINT, public: 'PUB', private: 'SECRET', protected: true },
    );
    const keyPlan = planMerge([bare, full], defaultPicks([bare, full]), NOW);
    expect(keyPlan?.fields).toMatchObject({ private: 'SECRET', protected: true });

    const [manual, withKey] = two(
      'contact',
      { name: 'Alex', email: 'a@b.c', source: 'manual' },
      { name: 'Alex C.', email: 'a@b.c', public: 'PUB', source: 'paste', checkedFingerprint: 'AB' },
    );
    const contactPlan = planMerge([manual, withKey], defaultPicks([manual, withKey]), NOW);
    expect(contactPlan?.fields).toMatchObject({ public: 'PUB', checkedFingerprint: 'AB' });
    // The key brought its source along: the contact no longer says it has none.
    expect(contactPlan?.fields['source']).toBe('paste');
  });

  it('fills a contact\'s company, address and phone, a card\'s holder and code, a code\'s account', () => {
    const [bare, rich] = two('contact', { name: 'Alex', email: 'a@b.c' }, {
      name: 'Alex C.',
      email: 'a@b.c',
      company: 'Example Co',
      address: '1 High St',
      phone: '555 0142',
    });
    expect(planMerge([bare, rich], defaultPicks([bare, rich]), NOW)?.fields).toMatchObject({
      company: 'Example Co',
      address: '1 High St',
      phone: '555 0142',
    });

    const [card, holder] = two('card', { name: 'Travel', number: '4111111111111111' }, {
      name: 'Visa',
      number: '4111111111111111',
      cardholder: 'Sam Rivera',
      code: '123',
    });
    expect(planMerge([card, holder], defaultPicks([card, holder]), NOW)?.fields).toMatchObject({
      cardholder: 'Sam Rivera',
      code: '123',
    });

    const [code, labelled] = two('otp', { secret: 'JBSWY3DPEHPK3PXP' }, {
      secret: 'JBSWY3DPEHPK3PXP',
      label: 'sam@example.org',
      issuer: 'GitHub',
    });
    expect(planMerge([code, labelled], defaultPicks([code, labelled]), NOW)?.fields).toMatchObject({
      label: 'sam@example.org',
      issuer: 'GitHub',
    });
  });

  it('is taken from the newest copy that has it when two do', () => {
    const kept = vaultItem('contact', { name: 'a', email: 'a@b.c', updatedAt: 9 });
    const newer = vaultItem('contact', { name: 'b', email: 'a@b.c', company: 'New Co', updatedAt: 8 });
    const older = vaultItem('contact', { name: 'c', email: 'a@b.c', company: 'Old Co', updatedAt: 1 });
    expect(planMerge([kept, newer, older], defaultPicks([kept, newer, older]), NOW)?.fields['company']).toBe('New Co');
  });

  it('is recorded for Undo, so the kept item loses it again', () => {
    const [bare, rich] = two('contact', { name: 'a', email: 'a@b.c' }, { name: 'b', email: 'a@b.c', company: 'Example Co' });
    const plan = planMerge([bare, rich], defaultPicks([bare, rich]), NOW);
    expect(plan?.before['company']).toBeUndefined();
    expect('company' in (plan?.before ?? {})).toBe(true);
  });

  it('does not fill what a pick or a union settles: a login keeps its own password pick', () => {
    const a = login('A', 'sam', '', ['a.example'], { updatedAt: 2 });
    const b = login('B', 'sam', 'real-pass', ['a.example'], { updatedAt: 1 });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    // The default pick takes the first login that has a password.
    expect(plan?.fields['password']).toBe('real-pass');
  });
});

describe('the default picks', () => {
  it('take the first copy that has a folder or a note, so one that only a later copy held stays', () => {
    const a = vaultItem('note', { name: 'a', text: 'x', updatedAt: 2 });
    const b = vaultItem('note', { name: 'b', text: 'x', notes: 'Kept in the safe', folder: 'Home', updatedAt: 1 });
    const picks = defaultPicks([a, b]);
    expect(picks.keepId).toBe(a.id);
    expect(picks.notesFrom).toBe(b.id);
    expect(picks.folderFrom).toBe(b.id);
    const plan = planMerge([a, b], picks, NOW);
    expect(plan?.fields).toMatchObject({ notes: 'Kept in the safe', folder: 'Home' });
  });
});

describe('identity documents', () => {
  it('are joined by their number, however it is spaced', () => {
    const [kept, other] = two(
      'identity',
      { name: 'Passport', documents: [{ type: 'passport', number: 'X 1234-567', expiresOn: '2031-04-01' }] },
      {
        name: 'Passport details',
        documents: [
          { type: 'passport', number: 'x1234567' },
          { type: 'licence', number: 'D7654321', expiresOn: '2029-01-01' },
        ],
      },
    );
    const plan = planMerge([kept, other], defaultPicks([kept, other]), NOW);
    const documents = plan?.fields['documents'] as Array<{ number: string }>;
    expect(documents.map((doc) => doc.number)).toEqual(['X 1234-567', 'D7654321']);
  });

  it('are left alone when the kept identity holds them all', () => {
    const [kept, other] = two(
      'identity',
      { name: 'a', documents: [{ number: 'X1234567' }] },
      { name: 'b', documents: [{ number: 'x 1234567' }] },
    );
    expect('documents' in (planMerge([kept, other], defaultPicks([kept, other]), NOW)?.fields ?? {})).toBe(false);
  });
});

describe('the favourite mark', () => {
  it('is kept when any copy has it', () => {
    const [kept, starred] = two('note', { name: 'a', text: 'x' }, { name: 'b', text: 'x', favorite: true });
    expect(planMerge([kept, starred], defaultPicks([kept, starred]), NOW)?.fields['favorite']).toBe(true);
    const [entry, pinned] = two('card', { name: 'a', number: '4111111111111111' }, { name: 'b', number: '4111111111111111', pinned: true });
    expect(planMerge([entry, pinned], defaultPicks([entry, pinned]), NOW)?.fields['pinned']).toBe(true);
  });

  it('is not written again to an item that has it', () => {
    const [kept, starred] = two('note', { name: 'a', text: 'x', favorite: true }, { name: 'b', text: 'x', favorite: true });
    expect('favorite' in (planMerge([kept, starred], defaultPicks([kept, starred]), NOW)?.fields ?? {})).toBe(false);
  });
});

describe('backup codes', () => {
  it('stay used when any copy used them', () => {
    const [kept, other] = two(
      'backup-codes',
      { name: 'GitHub', codes: [{ code: 'aaaa-1111' }, { code: 'bbbb-2222' }, { code: 'cccc-3333', used: true }] },
      { name: 'GitHub 2', codes: [{ code: 'aaaa-1111', used: true }, { code: 'bbbb-2222' }, { code: 'cccc-3333' }] },
    );
    const plan = planMerge([kept, other], defaultPicks([kept, other]), NOW);
    expect(plan?.fields['codes']).toEqual([
      { code: 'aaaa-1111', used: true },
      { code: 'bbbb-2222' },
      { code: 'cccc-3333', used: true },
    ]);
  });

  it('keep a code written as plain text, and mark it used when another copy used it', () => {
    const [kept, other] = two(
      'backup-codes',
      { name: 'a', codes: ['one', 'two'] },
      { name: 'b', codes: [{ code: 'one', used: true }, { code: 'two' }] },
    );
    expect(planMerge([kept, other], defaultPicks([kept, other]), NOW)?.fields['codes']).toEqual([
      { code: 'one', used: true },
      'two',
    ]);
  });

  it('are left as they are when no copy used one the kept item did not', () => {
    const [kept, other] = two(
      'backup-codes',
      { name: 'a', codes: [{ code: 'one', used: true }, { code: 'two' }] },
      { name: 'b', codes: [{ code: 'one' }, { code: 'two' }] },
    );
    expect('codes' in (planMerge([kept, other], defaultPicks([kept, other]), NOW)?.fields ?? {})).toBe(false);
  });

  it('are undone with the rest: the kept item gets its own codes back', () => {
    const [kept, other] = two(
      'backup-codes',
      { name: 'a', codes: [{ code: 'one' }] },
      { name: 'b', codes: [{ code: 'one', used: true }] },
    );
    const plan = planMerge([kept, other], defaultPicks([kept, other]), NOW);
    expect(plan?.before['codes']).toEqual([{ code: 'one' }]);
  });
});

describe('the name of an unnamed item', () => {
  it('is written as its issuer and account when it is the name picked', () => {
    const [kept, labelled] = two('otp', { secret: 'JBSWY3DPEHPK3PXP' }, { secret: 'JBSWY3DPEHPK3PXP', issuer: 'GitHub', label: 'sam' });
    const plan = planMerge([kept, labelled], { ...defaultPicks([kept, labelled]), nameFrom: labelled.id }, NOW);
    expect(plan?.fields['name']).toBe('GitHub: sam');
    expect(plan && resultName(plan)).toBe('GitHub: sam');
  });

  it('is not made up for the kept item, nor from nothing', () => {
    const [kept, other] = two('otp', { secret: 'JBSWY3DPEHPK3PXP', issuer: 'GitHub' }, { secret: 'JBSWY3DPEHPK3PXP' });
    expect('name' in (planMerge([kept, other], defaultPicks([kept, other]), NOW)?.fields ?? {})).toBe(false);
    const named = planMerge([kept, other], { ...defaultPicks([kept, other]), nameFrom: other.id }, NOW);
    // The other has no name, no issuer and no account: its "name" would be its kind, so nothing is written.
    expect('name' in (named?.fields ?? {})).toBe(false);
  });
});

describe('fields the copies disagree on', () => {
  const [a, b] = two(
    'card',
    { name: 'Travel', number: '4111111111111111', cardholder: 'Sam Rivera', code: '123' },
    { name: 'Visa', number: '4111111111111111', cardholder: 'S. Rivera', code: '123' },
  );

  it('are listed, with the items that hold each value, and a field they agree on is not', () => {
    const conflicts = fieldConflicts([a, b]);
    expect(conflicts.map((conflict) => conflict.key)).toEqual(['cardholder']);
    expect(conflicts[0]?.options).toEqual([
      { value: 'Sam Rivera', from: [a.id] },
      { value: 'S. Rivera', from: [b.id] },
    ]);
  });

  it('keep the kept item\'s own value until the person picks another', () => {
    const [conflict] = fieldConflicts([a, b]);
    if (!conflict) throw new Error('no conflict');
    expect(chosenFrom(conflict, {}, a.id)).toBe(a.id);
    expect(planMerge([a, b], defaultPicks([a, b]), NOW)?.fields['cardholder']).toBeUndefined();
    const picks = { ...defaultPicks([a, b]), valuesFrom: { cardholder: b.id } };
    expect(chosenFrom(conflict, picks.valuesFrom, a.id)).toBe(b.id);
    expect(planMerge([a, b], picks, NOW)?.fields['cardholder']).toBe('S. Rivera');
  });

  it('are not a pick when only one copy holds a value: the other lacks it and takes it', () => {
    const [x, y] = two('card', { name: 'a', number: '4111111111111111' }, { name: 'b', number: '4111111111111111', cardholder: 'Sam' });
    expect(fieldConflicts([x, y])).toEqual([]);
  });

  it('show a secret as dots and a long text cut', () => {
    expect(showValue('private', 'a private key')).toMatch(/^•+$/);
    expect(showValue('code', '123')).toBe('••••••');
    expect(showValue('company', 'Example Co')).toBe('Example Co');
    expect(showValue('company', 'x'.repeat(80))).toHaveLength(58);
    expect(showValue('address', { lines: ['1 High St'], city: 'Springfield' })).toBe('1 High St, Springfield');
  });
});

describe('what is the same in every copy', () => {
  const group = (kind: string, a: ItemData, b: ItemData, facts?: Record<string, unknown>): DuplicateGroup => {
    const [first, second] = two(kind, a, b);
    const found = findDuplicates([first, second]);
    const one = found[0];
    if (!one) throw new Error(`no group of ${kind} ${JSON.stringify(facts ?? {})}`);
    return one;
  };

  it('says "Card number, expiry and security code" only when the security code is the same', () => {
    const same = group('card', { number: '4111111111111111', code: '123' }, { number: '4111111111111111', code: '123' });
    expect(sameLabel(same)).toBe('dup.same.cardFull');
    const differs = group('card', { number: '4111111111111111', code: '123' }, { number: '4111111111111111', code: '999' });
    expect(sameLabel(differs)).toBe('dup.same.card');
    const none = group('card', { number: '4111111111111111' }, { number: '4111111111111111' });
    expect(sameLabel(none)).toBe('dup.same.card');
  });

  it('says "Private key and fingerprint" and "Certificate and private key" the same way', () => {
    const key = group('ssh-key', { fingerprint: FINGERPRINT, private: 'K' }, { fingerprint: FINGERPRINT, private: 'K' });
    expect(sameLabel(key)).toBe('dup.same.sshFull');
    const other = group('ssh-key', { fingerprint: FINGERPRINT, private: 'K' }, { fingerprint: FINGERPRINT });
    expect(sameLabel(other)).toBe('dup.same.key');
    const hash = 'ab'.repeat(32);
    const cert = group('certificate', { fingerprint: hash, private: 'K' }, { fingerprint: hash, private: 'K' });
    expect(sameLabel(cert)).toBe('dup.same.certificateFull');
  });

  it('says the identity\'s name, number and dates only when the documents are equal', () => {
    const doc = { number: 'X1234567', expiresOn: '2031-04-01' };
    const same = group(
      'identity',
      { givenName: 'Sam', familyName: 'Rivera', documents: [doc] },
      { givenName: 'Sam', familyName: 'Rivera', documents: [doc] },
    );
    expect(sameLabel(same)).toBe('dup.same.identityFull');
    const later = group(
      'identity',
      { givenName: 'Sam', familyName: 'Rivera', documents: [doc] },
      { givenName: 'Sam', familyName: 'Rivera', documents: [{ ...doc, expiresOn: '2036-04-01' }] },
    );
    expect(sameLabel(later)).toBe('dup.same.document');
  });
});

describe('the files of a note', () => {
  const entry = (id: string, file: string) => ({ id, name: `${id}.pdf`, size: 4, key: `key-${id}`, addedAt: 1, kemlockFile: file });

  it('are the attachments the kept note lacks, each once, newest note first', () => {
    const kept = vaultItem('note', { name: 'a', text: 'x', updatedAt: 3, attachments: [entry('A', 'fa')] });
    const newer = vaultItem('note', { name: 'b', text: 'x', updatedAt: 2, attachments: [entry('A', 'fa2'), entry('B', 'fb')] });
    const older = vaultItem('note', { name: 'c', text: 'x', updatedAt: 1, attachments: [entry('B', 'fb2'), entry('C', 'fc'), { id: 'D', name: 'never uploaded' }] });
    const copies = attachmentCopies(kept, [newer, older]);
    expect(copies.map((copy) => [copy.from.id, copy.entry['id']])).toEqual([
      [newer.id, 'B'],
      [older.id, 'C'],
    ]);
    // The plan holds them for the merge to copy before it writes.
    expect(planMerge([kept, newer, older], defaultPicks([kept, newer, older]), NOW)?.copies).toHaveLength(2);
  });

  function transport(failAt?: 'upload' | 'download') {
    const calls: string[] = [];
    let counter = 0;
    const result: FileTransport = {
      download: (itemId, fileId) => {
        calls.push(`download ${itemId}/${fileId}`);
        return failAt === 'download' && calls.length > 2 ? Promise.reject(new Error('gone')) : Promise.resolve(new Uint8Array([1, 2, 3, 4]));
      },
      start: (itemId, size) => {
        counter += 1;
        calls.push(`start ${itemId} ${size}`);
        return Promise.resolve({ fileId: `new-${counter}` });
      },
      upload: (itemId, fileId) => {
        calls.push(`upload ${itemId}/${fileId}`);
        return failAt === 'upload' && fileId === 'new-2' ? Promise.reject(new Error('refused')) : Promise.resolve({});
      },
      remove: (itemId, fileId) => {
        calls.push(`remove ${itemId}/${fileId}`);
        return Promise.resolve();
      },
    };
    return { calls, result };
  }

  it('are copied under the kept note\'s id with the same entry and key, and the new file\'s id', async () => {
    const kept = vaultItem('note', { name: 'a', text: 'x', updatedAt: 3, attachments: [entry('A', 'fa')] });
    const other = vaultItem('note', { name: 'b', text: 'x', updatedAt: 2, attachments: [entry('B', 'fb')] });
    const plan = planMerge([kept, other], defaultPicks([kept, other]), NOW);
    if (!plan) throw new Error('no plan');
    const { calls, result } = transport();
    const copied = await copyAttachments(result, kept.id, plan.copies);
    expect(calls).toEqual([`download ${other.id}/fb`, `start ${kept.id} 4`, `upload ${kept.id}/new-1`]);
    expect(copied.files).toEqual(['new-1']);
    expect(copied.entries).toEqual([{ ...entry('B', 'fb'), kemlockFile: 'new-1' }]);

    // The kept note then names its own and the copy; Undo puts its own back.
    const written = applyCopies(plan, copied.entries);
    expect(written.fields['attachments']).toEqual([entry('A', 'fa'), { ...entry('B', 'fb'), kemlockFile: 'new-1' }]);
    expect(written.before['attachments']).toEqual([entry('A', 'fa')]);
  });

  it('are all removed again when one can\'t be copied, and the error stops the merge', async () => {
    const kept = vaultItem('note', { name: 'a', text: 'x', updatedAt: 3 });
    const other = vaultItem('note', { name: 'b', text: 'x', updatedAt: 2, attachments: [entry('B', 'fb'), entry('C', 'fc')] });
    const plan = planMerge([kept, other], defaultPicks([kept, other]), NOW);
    if (!plan) throw new Error('no plan');
    const { calls, result } = transport('upload');
    await expect(copyAttachments(result, kept.id, plan.copies)).rejects.toThrow('refused');
    expect(calls.filter((call) => call.startsWith('remove'))).toEqual([`remove ${kept.id}/new-1`, `remove ${kept.id}/new-2`]);
  });

  it('copy nothing for a note that has no files', async () => {
    const kept = vaultItem('note', { name: 'a', text: 'x' });
    const other = vaultItem('note', { name: 'b', text: 'x' });
    const plan = planMerge([kept, other], defaultPicks([kept, other]), NOW);
    expect(plan?.copies).toEqual([]);
    const { calls, result } = transport();
    expect(await copyAttachments(result, kept.id, plan?.copies ?? [])).toEqual({ entries: [], files: [] });
    expect(calls).toEqual([]);
    if (plan) expect(applyCopies(plan, [])).toBe(plan);
  });
});

describe('who may change an item', () => {
  const writable = [{ spaceId: '00000000-0000-4000-8000-0000000000bb', spaceName: 'Family', collectionId: 'c1', collectionName: 'Shared' }];

  it('is anyone for an item of their own vault', () => {
    expect(canWriteItem({ owner: 'user:00000000-0000-4000-8000-0000000000aa' }, [])).toBe(true);
  });

  it('is only a collection they may write, for an item of a space', () => {
    expect(canWriteItem({ owner: SPACE, collectionId: 'c1' }, writable)).toBe(true);
    expect(canWriteItem({ owner: SPACE, collectionId: 'c2' }, writable)).toBe(false);
    expect(canWriteItem({ owner: 'space:00000000-0000-4000-8000-0000000000cc', collectionId: 'c1' }, writable)).toBe(false);
    expect(canWriteItem({ owner: SPACE, collectionId: 'c1' }, [])).toBe(false);
  });

  it('is taken for true while the collections are not known', () => {
    expect(canWriteItem({ owner: SPACE, collectionId: 'c1' }, undefined)).toBe(true);
  });
});
