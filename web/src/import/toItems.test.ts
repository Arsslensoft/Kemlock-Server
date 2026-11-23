import { describe, expect, it } from 'vitest';
import type { BatchLogin, BatchMeta, ImportBatch } from './contract';
import { batchToItems } from './toItems';

const META: BatchMeta = {
  folder: null,
  spaces: [],
  favorite: false,
  created_ms: null,
  modified_ms: null,
  source_id: null,
  tags: [],
};

function batch(partial: Partial<ImportBatch>): ImportBatch {
  return {
    format: 'bitwarden-json',
    folders: [],
    spaces: [],
    logins: [],
    codes: [],
    notes: [],
    cards: [],
    identities: [],
    ssh_keys: [],
    files: [],
    skipped: [],
    ...partial,
  };
}

function login(over: Partial<BatchLogin>): BatchLogin {
  return {
    name: 'GitHub',
    uris: [],
    username: null,
    password: null,
    totp: null,
    notes: null,
    fields: [],
    previous_passwords: [],
    passkeys: [],
    meta: { ...META },
    ...over,
  };
}

function ids() {
  let n = 0;
  return () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`;
}

const NOW = new Date('2026-11-22T10:00:00Z');

describe('batchToItems', () => {
  it('turns a login into the item the app and the web vault both read', () => {
    const { items } = batchToItems(
      batch({
        folders: [{ name: 'Work', parent: null, path: 'Work' }],
        logins: [
          login({
            username: 'sam',
            password: 'pw',
            notes: 'note',
            uris: [
              { uri: 'https://github.com', match_rule: null },
              { uri: 'https://intranet.example.co/login', match_rule: 'starts-with' },
              { uri: '^x', match_rule: 'regular-expression' },
            ],
            previous_passwords: [{ password: 'old', until_ms: Date.UTC(2026, 7, 12) }],
            meta: { ...META, folder: 0, favorite: true, modified_ms: Date.UTC(2026, 10, 1), tags: ['dev'] },
          }),
        ],
      }),
      ids(),
      NOW,
    );
    expect(items).toHaveLength(1);
    const item = items[0];
    expect(item?.kind).toBe('login');
    expect(item?.data).toMatchObject({
      name: 'GitHub',
      username: 'sam',
      password: 'pw',
      notes: 'note',
      folder: 'Work',
      favorite: true,
      tags: ['dev'],
      updatedAt: '2026-11-01T00:00:00.000Z',
      uris: [{ uri: 'https://github.com' }, { uri: 'https://intranet.example.co/login', match: 2 }, { uri: '^x', match: 4 }],
      urls: ['https://github.com', 'https://intranet.example.co/login'],
      websites: ['github.com', 'intranet.example.co'],
      passwordHistory: [{ password: 'old', replacedAt: '2026-08-12T00:00:00.000Z' }],
    });
  });

  it('makes a login\'s TOTP a code of its own, linked to it', () => {
    const { items } = batchToItems(batch({ logins: [login({ username: 'sam', totp: 'JBSWY3DP' })] }), ids(), NOW);
    expect(items.map((i) => i.kind)).toEqual(['login', 'otp']);
    expect(items[1]?.data).toMatchObject({ secret: 'JBSWY3DP', linkedLoginId: items[0]?.id, label: 'sam' });
  });

  it('maps codes, notes, cards, identities and keys', () => {
    const { items } = batchToItems(
      batch({
        codes: [{ name: 'AWS', value: 'JBSWY3DP', notes: null, meta: { ...META } }],
        notes: [{ name: 'Wi-Fi', text: 'pw', fields: [{ name: 'a', value: 'b', kind: 'hidden' }], meta: { ...META } }],
        cards: [
          {
            name: 'Visa',
            cardholder: 'Ada',
            number: '4111111111111111',
            brand: 'Visa',
            exp_month: 5,
            exp_year: 2029,
            code: '123',
            pin: null,
            valid_from_month: null,
            valid_from_year: null,
            notes: null,
            fields: [],
            meta: { ...META },
          },
        ],
        identities: [
          {
            name: 'Home',
            title: null,
            given_name: 'Ada',
            middle_name: null,
            family_name: 'Lovelace',
            company: null,
            email: 'ada@example.org',
            phone: null,
            username: null,
            birth_date: null,
            address: { lines: ['1 Main St'], city: 'London', region: null, postal_code: null, country: 'UK' },
            documents: [],
            notes: null,
            fields: [],
            meta: { ...META },
          },
        ],
        ssh_keys: [
          { name: 'router', private_key: 'PEM', public_key: 'ssh-ed25519 AAA', fingerprint: 'SHA256:x', notes: null, fields: [], meta: { ...META } },
        ],
      }),
      ids(),
      NOW,
    );
    expect(items.map((i) => i.kind)).toEqual(['otp', 'note', 'card', 'identity', 'ssh-key']);
    expect(items[0]?.data).toMatchObject({ name: 'AWS', secret: 'JBSWY3DP' });
    expect(items[1]?.data).toMatchObject({ text: 'pw', fields: [{ name: 'a', value: 'b', kind: 'hidden' }] });
    expect(items[2]?.data).toMatchObject({ number: '4111111111111111', expMonth: 5, expYear: 2029, code: '123' });
    expect(items[2]?.data).not.toHaveProperty('pin');
    expect(items[3]?.data).toMatchObject({ firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.org' });
    expect(items[4]?.data).toMatchObject({ privateKey: 'PEM', fingerprint: 'SHA256:x' });
    // Every item has its own id.
    expect(new Set(items.map((i) => i.id)).size).toBe(5);
  });

  it('warns about files, skipped entries and shared vaults', () => {
    const { warnings } = batchToItems(
      batch({
        files: [{ name: 'a.txt', media_type: null, data: 'AA', owner: null }],
        skipped: [
          { name: 'x', reason: 'trashed', detail: null, count: 1 },
          { name: null, reason: 'over-limit', detail: null, count: 40 },
        ],
        spaces: [{ name: 'Team', kind: 'vault', source_id: null }],
      }),
    );
    expect(warnings).toEqual([
      { code: 'files', count: 1 },
      { code: 'skipped', count: 41 },
      { code: 'spaces', count: 1 },
    ]);
  });
});
