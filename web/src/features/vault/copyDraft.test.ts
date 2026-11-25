import { describe, expect, it } from 'vitest';
import { copyBase, copyFields, copySeed } from './copyDraft';
import type { VaultItem } from './vault';

const SOURCE: VaultItem = {
  id: '11111111-1111-4111-8111-111111111111',
  owner: 'user:u',
  kind: 'login',
  revision: 4,
  keyVersion: 1,
  collectionId: 'col',
  data: {
    id: '11111111-1111-4111-8111-111111111111',
    name: 'GitHub',
    username: 'sam@example.org',
    password: 'hunter2',
    urls: ['https://github.com'],
    uris: [{ uri: 'https://github.com', match: 1 }],
    favorite: true,
    notes: 'Personal',
    fields: [{ name: 'Recovery email', value: 'a@b.co', kind: 'text', vendor: 'kept' }],
    tags: ['work'],
    vendorKey: { from: 'another app' },
    links: [{ id: '22222222-2222-4222-8222-222222222222' }],
    linkedLoginId: '22222222-2222-4222-8222-222222222222',
    file: { id: 'f', name: 'x', kemlockFile: 'server-1' },
    attachments: [{ id: 'a', name: 'x', kemlockFile: 'server-2' }],
    passkeys: [{ credentialId: 'c' }],
    passwordHistory: [{ password: 'old', replacedAt: 'then' }],
    addedAt: 5,
    updatedAt: 9,
    trashedAt: '2026-11-01T00:00:00Z',
  },
  sizes: { ciphertext: 1, itemKey: 1 },
};

describe('a copy', () => {
  it('leaves behind what belongs to the original alone: its id, links, files, passkeys, history and dates', () => {
    const base = copyBase(SOURCE.data);
    for (const left of [
      'id',
      'links',
      'linkedLoginId',
      'file',
      'attachments',
      'passkeys',
      'passwordHistory',
      'addedAt',
      'updatedAt',
      'trashedAt',
    ]) {
      expect(left in base, left).toBe(false);
    }
  });

  it('keeps everything else, unknown keys included', () => {
    expect(copyBase(SOURCE.data)).toEqual({
      name: 'GitHub',
      username: 'sam@example.org',
      password: 'hunter2',
      urls: ['https://github.com'],
      uris: [{ uri: 'https://github.com', match: 1 }],
      favorite: true,
      notes: 'Personal',
      fields: [{ name: 'Recovery email', value: 'a@b.co', kind: 'text', vendor: 'kept' }],
      tags: ['work'],
      vendorKey: { from: 'another app' },
    });
    expect(copyBase(null)).toEqual({});
  });

  it('is an item whose body is the copy\'s, and does not change the original', () => {
    const seed = copySeed(SOURCE);
    expect(seed.kind).toBe('login');
    expect(seed.data).toEqual(copyBase(SOURCE.data));
    expect(SOURCE.data?.['links']).toBeDefined();
  });

  it('is saved with the original\'s body under what the form wrote, a cleared field staying cleared', () => {
    const fields = copyFields(copySeed(SOURCE), { name: 'GitHub (work)', notes: undefined, username: 'sam' });
    expect(fields).toMatchObject({ name: 'GitHub (work)', username: 'sam', vendorKey: { from: 'another app' }, tags: ['work'] });
    // `notes` is undefined, which saving removes: the form cleared it.
    expect('notes' in fields && fields['notes'] === undefined).toBe(true);
    expect(copyFields(undefined, { name: 'Plain' })).toEqual({ name: 'Plain' });
  });
});
