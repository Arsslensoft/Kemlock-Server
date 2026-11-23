import { afterEach, describe, expect, it, vi } from 'vitest';
import { encodeB64 } from './b64url';
import {
  PasskeyError,
  assertWithPasskey,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeCredential,
  passkeysAvailable,
} from './passkey';

const buffer = (...values: number[]) => new Uint8Array(values).buffer;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('decodeRequestOptions', () => {
  it('turns the challenge and each credential id into bytes and keeps the rest', () => {
    const decoded = decodeRequestOptions({
      challenge: encodeB64(new Uint8Array([1, 2, 3])),
      rpId: 'vault.example.org',
      userVerification: 'required',
      timeout: 60000,
      allowCredentials: [{ type: 'public-key', id: encodeB64(new Uint8Array([9, 8])), transports: ['usb'] }],
    });
    expect([...new Uint8Array(decoded.challenge as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect(decoded.rpId).toBe('vault.example.org');
    expect(decoded.userVerification).toBe('required');
    const [entry] = decoded.allowCredentials ?? [];
    expect([...new Uint8Array(entry?.id as ArrayBuffer)]).toEqual([9, 8]);
    expect(entry?.transports).toEqual(['usb']);
  });

  it('reads options wrapped as { publicKey }, and a list with no credentials', () => {
    const decoded = decodeRequestOptions({ publicKey: { challenge: encodeB64(new Uint8Array([7])) } });
    expect([...new Uint8Array(decoded.challenge as ArrayBuffer)]).toEqual([7]);
    expect(decoded.allowCredentials).toEqual([]);
  });

  it('refuses options without a challenge', () => {
    expect(() => decodeRequestOptions({ rpId: 'x' })).toThrow(PasskeyError);
  });
});

describe('encodeCredential', () => {
  it('writes every buffer as base64url, and leaves out an absent user handle', () => {
    const json = encodeCredential({
      id: 'abc',
      rawId: buffer(1, 2),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        authenticatorData: buffer(3),
        clientDataJSON: buffer(4, 5),
        signature: buffer(6),
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential);
    expect(json).toEqual({
      id: 'abc',
      rawId: encodeB64(new Uint8Array([1, 2])),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        authenticatorData: encodeB64(new Uint8Array([3])),
        clientDataJSON: encodeB64(new Uint8Array([4, 5])),
        signature: encodeB64(new Uint8Array([6])),
      },
      clientExtensionResults: {},
    });
  });
});

describe('assertWithPasskey', () => {
  const options = { challenge: encodeB64(new Uint8Array([1])) };

  it('is not available without WebAuthn, and says so', async () => {
    vi.stubGlobal('PublicKeyCredential', undefined);
    expect(passkeysAvailable()).toBe(false);
    await expect(assertWithPasskey(options)).rejects.toMatchObject({ reason: 'unavailable' });
  });

  it('asks the browser with the decoded options and returns the credential as JSON', async () => {
    const get = vi.fn(async () => ({
      id: 'cred',
      rawId: buffer(1),
      type: 'public-key',
      response: { authenticatorData: buffer(2), clientDataJSON: buffer(3), signature: buffer(4), userHandle: buffer(5) },
      getClientExtensionResults: () => ({}),
    }));
    vi.stubGlobal('PublicKeyCredential', class {});
    vi.stubGlobal('navigator', { credentials: { get } });
    const json = await assertWithPasskey(options);
    expect(get).toHaveBeenCalledTimes(1);
    const call = get.mock.calls[0] as unknown as [{ publicKey: PublicKeyCredentialRequestOptions }];
    expect([...new Uint8Array(call[0].publicKey.challenge as ArrayBuffer)]).toEqual([1]);
    expect(json).toMatchObject({ id: 'cred', response: { userHandle: encodeB64(new Uint8Array([5])) } });
  });

  it('reads a closed prompt and no answer as cancelled', async () => {
    vi.stubGlobal('PublicKeyCredential', class {});
    const refuse = vi.fn(async () => {
      throw new DOMException('closed', 'NotAllowedError');
    });
    vi.stubGlobal('navigator', { credentials: { get: refuse } });
    await expect(assertWithPasskey(options)).rejects.toMatchObject({ reason: 'cancelled' });
    vi.stubGlobal('navigator', { credentials: { get: vi.fn(async () => null) } });
    await expect(assertWithPasskey(options)).rejects.toMatchObject({ reason: 'cancelled' });
  });
});

describe('decodeCreationOptions', () => {
  it('turns the challenge, the user id and each excluded id into bytes, wrapped or not', () => {
    const publicKey = {
      challenge: encodeB64(new Uint8Array([1, 2])),
      rp: { id: 'vault.example.org', name: 'Kemlock' },
      user: { id: encodeB64(new Uint8Array([5, 6, 7])), name: 'sam@example.co', displayName: 'Sam' },
      excludeCredentials: [{ type: 'public-key', id: encodeB64(new Uint8Array([9])) }],
    };
    for (const options of [publicKey, { publicKey }]) {
      const decoded = decodeCreationOptions(options);
      expect([...new Uint8Array(decoded.challenge as ArrayBuffer)]).toEqual([1, 2]);
      expect([...new Uint8Array(decoded.user.id as ArrayBuffer)]).toEqual([5, 6, 7]);
      expect(decoded.user.name).toBe('sam@example.co');
      expect([...new Uint8Array(decoded.excludeCredentials?.[0]?.id as ArrayBuffer)]).toEqual([9]);
    }
  });

  it('refuses options with no user', () => {
    expect(() => decodeCreationOptions({ challenge: encodeB64(new Uint8Array([1])) })).toThrow(PasskeyError);
  });
});
