import { describe, expect, it } from 'vitest';
import {
  FIELD_SPECS,
  SENDABLE_KINDS,
  buildEnvelope,
  parseEnvelope,
  serializeEnvelope,
  shownFields,
} from './itemEnvelope';

describe('buildEnvelope', () => {
  it('sends only the fields of the kind, never ids, history or flags', () => {
    const envelope = buildEnvelope(
      {
        kind: 'login',
        data: {
          id: 'abc',
          name: 'GitHub',
          username: 'sam',
          password: 'hunter2',
          urls: ['https://github.com', 'https://gist.github.com'],
          notes: 'work',
          favorite: true,
          pinned: true,
          updatedAt: 1_700_000_000_000,
          history: [{ password: 'old' }],
          totp: 'JBSWY3DP',
        },
      },
      'GitHub',
    );
    expect(envelope).toEqual({
      kemlockSend: 1,
      kind: 'login',
      name: 'GitHub',
      fields: {
        username: 'sam',
        password: 'hunter2',
        urls: 'https://github.com\nhttps://gist.github.com',
        notes: 'work',
      },
    });
    expect(serializeEnvelope(envelope!)).not.toMatch(/old|JBSWY3DP|favorite|abc/);
  });

  it('writes a card expiry as MM/YYYY and leaves empty fields out', () => {
    const envelope = buildEnvelope(
      { kind: 'card', data: { number: '4111111111111111', expMonth: 5, expYear: 2029, pin: '', brand: '  ' } },
      'Visa',
    );
    expect(envelope?.fields).toEqual({ number: '4111111111111111', expiry: '05/2029' });
  });

  it('flattens an identity address and sends only the unused backup codes', () => {
    expect(
      buildEnvelope(
        { kind: 'identity', data: { givenName: 'Sam', address: { lines: ['1 Main St', 'Flat 2'], city: 'Tunis' } } },
        'Me',
      )?.fields,
    ).toEqual({ givenName: 'Sam', address: '1 Main St\nFlat 2', city: 'Tunis' });
    expect(
      buildEnvelope(
        {
          kind: 'backup-codes',
          data: { serviceName: 'Mail', codes: [{ code: 'a1', used: false }, { code: 'b2', used: true }, { code: 'c3' }] },
        },
        'Mail',
      )?.fields,
    ).toEqual({ serviceName: 'Mail', codes: 'a1\nc3' });
  });

  it('refuses a kind it cannot send and an item that did not open', () => {
    expect(buildEnvelope({ kind: 'passkey', data: { name: 'x' } }, 'x')).toBeNull();
    expect(buildEnvelope({ kind: 'note', data: null }, 'x')).toBeNull();
  });

  it('knows all ten kinds', () => {
    expect(SENDABLE_KINDS).toHaveLength(10);
    for (const kind of SENDABLE_KINDS) expect(FIELD_SPECS[kind].length).toBeGreaterThan(0);
  });
});

describe('parseEnvelope', () => {
  it('reads back what serializeEnvelope wrote, byte for byte', () => {
    const text = '{"kemlockSend":1,"kind":"note","name":"Wi-Fi","fields":{"text":"pw: 1234"}}';
    const parsed = parseEnvelope(text);
    expect(parsed).toEqual({ kemlockSend: 1, kind: 'note', name: 'Wi-Fi', fields: { text: 'pw: 1234' } });
    expect(serializeEnvelope(parsed!)).toBe(text);
  });

  it('answers null for plain text, other JSON, other versions and unknown kinds', () => {
    for (const text of [
      'just a note',
      '{"hello":1}',
      '[1]',
      '{"kemlockSend":2,"kind":"note","name":"n","fields":{}}',
      '{"kemlockSend":1,"kind":"spaceship","name":"n","fields":{}}',
      '{"kemlockSend":1,"kind":"note","name":5,"fields":{}}',
      '{"kemlockSend":1,"kind":"note","name":"n","fields":[]}',
      '{"kemlockSend":1,',
    ]) {
      expect(parseEnvelope(text), text).toBeNull();
    }
  });

  it('answers null for an envelope over 64 KiB or with more than 32 fields', () => {
    const big = JSON.stringify({ kemlockSend: 1, kind: 'note', name: 'n', fields: { text: 'x'.repeat(70_000) } });
    expect(parseEnvelope(big)).toBeNull();
    const many = Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, 'v']));
    expect(parseEnvelope(JSON.stringify({ kemlockSend: 1, kind: 'note', name: 'n', fields: many }))).toBeNull();
  });

  it('drops a key the kind does not define, so a crafted key never shows', () => {
    const parsed = parseEnvelope(
      JSON.stringify({
        kemlockSend: 1,
        kind: 'note',
        name: 'n',
        fields: { text: 'a', 'Kemlock: verify at evil.example': 'click here' },
      }),
    );
    expect(parsed?.fields).toEqual({ text: 'a' });
  });

  it('drops fields that are not text', () => {
    const parsed = parseEnvelope('{"kemlockSend":1,"kind":"note","name":"n","fields":{"text":"a","x":5,"y":""}}');
    expect(parsed?.fields).toEqual({ text: 'a' });
  });
});

describe('shownFields', () => {
  it('lists the fields of the kind in order with their secrecy', () => {
    const shown = shownFields({
      kemlockSend: 1,
      kind: 'card',
      name: 'Visa',
      fields: { code: '123', number: '4111', cardholder: 'Sam' },
    });
    expect(shown.map((f) => [f.key, f.secret])).toEqual([
      ['cardholder', false],
      ['number', true],
      ['code', true],
    ]);
  });
});
