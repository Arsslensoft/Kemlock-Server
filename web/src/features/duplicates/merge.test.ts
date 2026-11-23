import { describe, expect, it } from 'vitest';
import type { VaultItem } from '@/features/vault/vault';
import { login, vaultItem } from '@/test/tools-fixtures';
import {
  allWebsites,
  defaultPicks,
  mergeWrites,
  planMerge,
  undoWrites,
  websiteKey,
} from './merge';

const NOW = new Date('2026-11-22T10:00:00Z');

function pair(): [VaultItem, VaultItem] {
  const a = login('Proton Mail', 'sam', 'new-pass', ['proton.me'], {
    folder: 'Work',
    notes: 'Recovery phrase is in the Family safe.',
    tags: ['mail'],
    updatedAt: '2026-11-21T00:00:00Z',
  });
  const b = login('proton.me', 'sam', 'old-pass', ['account.proton.me', 'mail.proton.me'], {
    notes: 'Old account',
    tags: ['work'],
    passkeys: [{ credentialId: 'pk1', rpId: 'proton.me' }],
    updatedAt: '2026-08-12T00:00:00Z',
  });
  return [a, b];
}

describe('defaultPicks', () => {
  it('takes every field from the first item and keeps every website and passkey', () => {
    const [a, b] = pair();
    const picks = defaultPicks([a, b]);
    expect(picks.keepId).toBe(a.id);
    expect(picks.nameFrom).toBe(a.id);
    expect(picks.websites).toEqual(allWebsites([a, b]).map(websiteKey));
    expect(picks.websites).toHaveLength(3);
    expect(picks.passkeys).toEqual(['pk1']);
  });
});

describe('planMerge', () => {
  it('keeps the first item, trashes the other and parks the other password in history', () => {
    const [a, b] = pair();
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect(plan).not.toBeNull();
    expect(plan?.kept.id).toBe(a.id);
    expect(plan?.trashed.map((i) => i.id)).toEqual([b.id]);
    expect(plan?.fields['name']).toBe('Proton Mail');
    expect(plan?.fields['password']).toBe('new-pass');
    expect(plan?.fields['passwordHistory']).toEqual([
      { password: 'old-pass', replacedAt: NOW.toISOString() },
    ]);
    expect(plan?.retired).toBe(1);
    expect(plan?.fields['websites']).toEqual(['proton.me', 'account.proton.me', 'mail.proton.me']);
    expect(plan?.fields['passkeys']).toEqual([{ credentialId: 'pk1', rpId: 'proton.me' }]);
    expect(plan?.fields['tags']).toEqual(['mail', 'work']);
    expect(plan?.fields['folder']).toBe('Work');
  });

  it('keeps the other password when picked, and drops an unticked website and passkey', () => {
    const [a, b] = pair();
    const picks = defaultPicks([a, b]);
    picks.passwordFrom = b.id;
    picks.websites = picks.websites.filter((k) => !k.startsWith('mail.proton.me'));
    picks.passkeys = [];
    const plan = planMerge([a, b], picks, NOW);
    expect(plan?.fields['password']).toBe('old-pass');
    expect(plan?.fields['passwordHistory']).toEqual([
      { password: 'new-pass', replacedAt: NOW.toISOString() },
    ]);
    expect(plan?.fields['websites']).toEqual(['proton.me', 'account.proton.me']);
    expect(plan?.fields['passkeys']).toBeUndefined();
  });

  it('can keep the second item: its name and notes win, the first is trashed', () => {
    const [a, b] = pair();
    const picks = { ...defaultPicks([a, b]), keepId: b.id, nameFrom: b.id, notesFrom: b.id, folderFrom: b.id };
    const plan = planMerge([a, b], picks, NOW);
    expect(plan?.kept.id).toBe(b.id);
    expect(plan?.trashed.map((i) => i.id)).toEqual([a.id]);
    expect(plan?.fields['notes']).toBe('Old account');
    expect(plan?.fields['folder']).toBeUndefined();
  });

  it('does not repeat a password the history already holds', () => {
    const [a, b] = pair();
    const withHistory = { ...a, data: { ...a.data, passwordHistory: [{ password: 'old-pass', replacedAt: 'x' }] } };
    const plan = planMerge([withHistory, b], defaultPicks([withHistory, b]), NOW);
    expect(plan?.retired).toBe(0);
    expect((plan?.fields['passwordHistory'] as unknown[]).length).toBe(1);
  });

  it('needs a kept item among at least two', () => {
    const [a] = pair();
    expect(planMerge([a], defaultPicks([a]), NOW)).toBeNull();
    expect(planMerge(pair(), { ...defaultPicks(pair()), keepId: 'nope' }, NOW)).toBeNull();
  });

  it('merges codes without login fields', () => {
    const a = vaultItem('otp', { name: 'AWS root', secret: 'JBSWY3DP' });
    const b = vaultItem('otp', { name: 'Amazon Web Services', secret: 'JBSWY3DP' });
    const plan = planMerge([a, b], { ...defaultPicks([a, b]), nameFrom: b.id }, NOW);
    expect(plan?.fields['name']).toBe('Amazon Web Services');
    expect(plan?.fields['password']).toBeUndefined();
    expect(plan?.kept.id).toBe(a.id);
  });
});

describe('mergeWrites and undoWrites', () => {
  it('writes the kept item and trashes the others, then reverses both', () => {
    const [a, b] = pair();
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    if (!plan) throw new Error('no plan');
    const writes = mergeWrites(plan, NOW);
    expect(writes).toHaveLength(2);
    expect(writes[0]?.existing?.id).toBe(a.id);
    expect(writes[1]?.fields).toEqual({ trashedAt: NOW.toISOString() });

    // The saved items have moved on one revision each.
    const saved = [
      { ...a, revision: a.revision + 1 },
      { ...b, revision: b.revision + 1 },
    ];
    const undo = undoWrites(plan, saved);
    expect(undo[0]?.fields).toEqual(plan.before);
    expect(undo[0]?.fields['notes']).toBe('Recovery phrase is in the Family safe.');
    // Fields the merge added, and a had not, are removed again.
    expect('passkeys' in (undo[0]?.fields ?? {})).toBe(true);
    expect(undo[0]?.fields['passkeys']).toBeUndefined();
    expect(undo[1]?.fields).toEqual({ trashedAt: undefined });
  });
});
