// @vitest-environment node
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { encodeB64 } from '@/lib/b64url';
import { idBytes, keyWords, pairFingerprint, proquint, shortFingerprint } from './fingerprint';

interface PairingVectors {
  fingerprint: {
    initiator_identity_key: string;
    initiator_server_id: string;
    responder_identity_key: string;
    responder_server_id: string;
    words: string;
    words_swapped: string;
  };
  proquints: Array<{ value: number; word: string }>;
}

// test-vectors/federation-pairing.json is the file the Rust side is held to. It lives at the
// repository root, outside web/: a checkout of web/ alone (say, one mounted into a container) has
// no such file, and then the vector checks are skipped rather than the whole file failing to load.
const vectorFile = fileURLToPath(
  new URL('../../../../test-vectors/federation-pairing.json', import.meta.url),
);
const haveVectors = existsSync(vectorFile);
const vectors: PairingVectors = haveVectors
  ? (JSON.parse(readFileSync(vectorFile, 'utf8')) as PairingVectors)
  : {
      fingerprint: {
        initiator_identity_key: '',
        initiator_server_id: '',
        responder_identity_key: '',
        responder_server_id: '',
        words: '',
        words_swapped: '',
      },
      proquints: [],
    };

const b64 = (hex: string) => encodeB64(Uint8Array.from(hex.match(/../g) ?? [], (p) => Number.parseInt(p, 16)));

describe('proquint', () => {
  it('matches the published examples', () => {
    expect(proquint(0x7f00)).toBe('lusab');
    expect(proquint(0x0001)).toBe('babad');
    expect(proquint(0x3f54)).toBe('gutih');
  });

  it.skipIf(!haveVectors)('matches the vector file', () => {
    for (const { value, word } of vectors.proquints) expect(proquint(value)).toBe(word);
  });
});

describe.skipIf(!haveVectors)('pairFingerprint', () => {
  const initiator = {
    serverId: vectors.fingerprint.initiator_server_id,
    identityKey: b64(vectors.fingerprint.initiator_identity_key),
  };
  const responder = {
    serverId: vectors.fingerprint.responder_server_id,
    identityKey: b64(vectors.fingerprint.responder_identity_key),
  };

  it('gives the six words the Rust side gives', async () => {
    expect(await pairFingerprint(initiator, responder)).toBe(vectors.fingerprint.words);
  });

  it('gives the same words whichever server asks', async () => {
    expect(await pairFingerprint(responder, initiator)).toBe(vectors.fingerprint.words_swapped);
    expect(vectors.fingerprint.words_swapped).toBe(vectors.fingerprint.words);
  });

  it('changes when either key changes', async () => {
    const other = { ...responder, identityKey: encodeB64(new Uint8Array([1, 2, 3])) };
    expect(await pairFingerprint(initiator, other)).not.toBe(vectors.fingerprint.words);
  });
});

describe('the display-only forms of one key', () => {
  it('are stable, six words and four groups of hex', async () => {
    const key = encodeB64(new Uint8Array([9, 8, 7, 6, 5]));
    expect(await keyWords(key)).toMatch(/^([bdfghjklmnprstvz][aiou]){2}[bdfghjklmnprstvz](-([bdfghjklmnprstvz][aiou]){2}[bdfghjklmnprstvz]){5}$/);
    expect(await keyWords(key)).toBe(await keyWords(key));
    expect(await shortFingerprint(key)).toMatch(/^[0-9A-F]{4}( [0-9A-F]{4}){3}$/);
    expect(await keyWords(encodeB64(new Uint8Array([1])))).not.toBe(await keyWords(key));
  });

  it('reads a server id as hex, as a UUID or as base64url', () => {
    expect([...idBytes('01020304-0506-0708-090a-0b0c0d0e0f10')]).toEqual([...idBytes('0102030405060708090a0b0c0d0e0f10')]);
    expect([...idBytes('0102030405060708090a0b0c0d0e0f10')]).toHaveLength(16);
    expect([...idBytes('AQIDBAUGBwgJCgsMDQ4PEA')]).toEqual([...idBytes('0102030405060708090a0b0c0d0e0f10')]);
  });
});
