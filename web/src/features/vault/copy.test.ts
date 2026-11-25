import { describe, expect, it } from 'vitest';
import { canCopy, copyData, copyDraft } from './copy';
import type { VaultItem } from './vault';

function item(kind: string, data: Record<string, unknown> | null): VaultItem {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    owner: 'user:00000000-0000-4000-8000-0000000000aa',
    kind,
    revision: 14,
    keyVersion: 3,
    collectionId: '00000000-0000-4000-8000-0000000000cc',
    data,
    sizes: { ciphertext: 1214, itemKey: 1648 },
  };
}

describe('making a copy', () => {
  it('keeps what the person typed and drops what names the old item', () => {
    const original = {
      id: '00000000-0000-4000-8000-000000000001',
      name: 'GitHub',
      username: 'sam@example.org',
      password: 'pw',
      urls: ['https://github.com'],
      uris: [{ uri: 'https://github.com' }],
      fields: [{ name: 'Recovery email', value: 'x', kind: 'text' }],
      notes: 'Personal account.',
      favorite: true,
      links: [{ id: '00000000-0000-4000-8000-000000000002' }],
      linkedLoginId: '00000000-0000-4000-8000-000000000002',
      passkeys: [{ credentialId: 'c' }],
      passwordHistory: [{ password: 'old' }],
      attachments: [{ name: 'a.txt' }],
      file: { name: 'a.txt' },
      trashedAt: '2026-11-01T00:00:00.000Z',
      updatedAt: 1,
      createdAt: 2,
      addedAt: 3,
    };
    expect(copyData(original)).toEqual({
      name: 'GitHub',
      username: 'sam@example.org',
      password: 'pw',
      urls: ['https://github.com'],
      uris: [{ uri: 'https://github.com' }],
      fields: [{ name: 'Recovery email', value: 'x', kind: 'text' }],
      notes: 'Personal account.',
      favorite: true,
    });
    // The item it was made from is untouched.
    expect(original.links).toHaveLength(1);
  });

  it('makes a stand-in with no id, no revision and no collection', () => {
    const draft = copyDraft(item('login', { id: 'x', name: 'GitHub', links: [{ id: 'y' }] }));
    expect(draft).toMatchObject({ id: '', revision: 0, kind: 'login', data: { name: 'GitHub' } });
    expect(draft.data).not.toHaveProperty('id');
    expect(draft.data).not.toHaveProperty('links');
    expect(draft).not.toHaveProperty('collectionId');
  });

  it('is offered for what can be filled in again, not for a passkey, a file or an item that cannot be read', () => {
    expect(canCopy(item('login', {}))).toBe(true);
    expect(canCopy(item('contact', {}))).toBe(true);
    expect(canCopy(item('passkey', {}))).toBe(false);
    expect(canCopy(item('file', {}))).toBe(false);
    expect(canCopy(item('login', null))).toBe(false);
    expect(copyDraft(item('login', null)).data).toBeNull();
  });
});
