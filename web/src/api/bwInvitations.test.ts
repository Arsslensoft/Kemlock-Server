import { afterEach, describe, expect, it, vi } from 'vitest';
import { bwInvitations, kdfOf } from './bwInvitations';

const fetched = vi.fn();

function reply(status: number, body?: unknown, headers: Record<string, string> = {}) {
  fetched.mockResolvedValueOnce(
    new Response(body === undefined ? null : JSON.stringify(body), { status, headers }),
  );
}

afterEach(() => {
  fetched.mockReset();
  vi.unstubAllGlobals();
});

function stub() {
  vi.stubGlobal('fetch', fetched);
}

describe('the KDF a prelogin names', () => {
  it('is read in either spelling, with the Argon2id settings only when they are there', () => {
    expect(kdfOf({ kdf: 0, kdfIterations: 600000 })).toEqual({ type: 0, iterations: 600000 });
    expect(kdfOf({ Kdf: 1, KdfIterations: 3, KdfMemory: 64, KdfParallelism: 4 })).toEqual({
      type: 1,
      iterations: 3,
      memory: 64,
      parallelism: 4,
    });
    expect(kdfOf({ kdf: 1, kdfIterations: 3 })).toBeUndefined();
    expect(kdfOf({ kdf: 7, kdfIterations: 3 })).toBeUndefined();
    expect(kdfOf({ kdf: 0, kdfIterations: '600000' })).toBeUndefined();
    expect(kdfOf({})).toBeUndefined();
  });
});

describe('asking for the KDF', () => {
  it('posts the address and nothing else, with no credentials', async () => {
    stub();
    reply(200, { kdf: 0, kdfIterations: 600000 });
    expect(await bwInvitations.prelogin('bob@example.org')).toEqual({ type: 0, iterations: 600000 });
    const [path, init] = fetched.mock.calls[0] ?? [];
    expect(path).toBe('/identity/accounts/prelogin');
    expect(JSON.parse(init.body)).toEqual({ email: 'bob@example.org' });
    expect(init.credentials).toBe('omit');
    expect(init.headers).not.toHaveProperty('authorization');
  });

  it('is undefined when the server is out of reach or answers badly', async () => {
    stub();
    fetched.mockRejectedValueOnce(new Error('offline'));
    expect(await bwInvitations.prelogin('bob@example.org')).toBeUndefined();
    reply(500);
    expect(await bwInvitations.prelogin('bob@example.org')).toBeUndefined();
    reply(200, { nonsense: true });
    expect(await bwInvitations.prelogin('bob@example.org')).toBeUndefined();
  });
});

describe('accepting with the master password hash', () => {
  it('posts the token and the hash, with no Authorization header and no password', async () => {
    stub();
    reply(200);
    expect(await bwInvitations.acceptOrganization('org 1', 'user/1', 'tok.en', 'aGFzaA==')).toEqual({ ok: true });
    const [path, init] = fetched.mock.calls[0] ?? [];
    expect(path).toBe('/api/organizations/org%201/users/user%2F1/accept');
    expect(JSON.parse(init.body)).toEqual({ token: 'tok.en', masterPasswordHash: 'aGFzaA==' });
    expect(Object.keys(init.headers).map((key) => key.toLowerCase())).not.toContain('authorization');
    expect(init.credentials).toBe('omit');
  });

  it('is the same for an emergency contact', async () => {
    stub();
    reply(204);
    await bwInvitations.acceptEmergency('grant-1', 'tok.en', 'aGFzaA==');
    expect(fetched.mock.calls[0]?.[0]).toBe('/api/emergency-access/grant-1/accept');
  });

  it('says a 400 with the bad-login text is the password, which a wrong one and an unknown account share', async () => {
    stub();
    reply(400, { message: 'Username or password is incorrect. Try again' });
    expect(await bwInvitations.acceptOrganization('o', 'u', 't', 'h')).toEqual({
      ok: false,
      reason: 'password',
      message: 'Username or password is incorrect. Try again',
    });
  });

  it('shows any other 400 as a refusal with the server’s message, not as a wrong password', async () => {
    stub();
    for (const message of ['User already accepted the invitation', 'Invalid token', 'User not valid', 'Account is disabled']) {
      reply(400, { message });
      expect(await bwInvitations.acceptOrganization('o', 'u', 't', 'h')).toEqual({ ok: false, reason: 'other', message });
    }
  });

  it('says a 429 is a limit, with the wait the server gives', async () => {
    stub();
    reply(429, undefined, { 'Retry-After': '90' });
    expect(await bwInvitations.acceptEmergency('g', 't', 'h')).toEqual({
      ok: false,
      reason: 'limited',
      message: '',
      retryAfter: 90,
    });
    reply(429);
    expect(await bwInvitations.acceptEmergency('g', 't', 'h')).toMatchObject({ reason: 'limited' });
  });

  it('says anything else, or no answer, is some other trouble', async () => {
    stub();
    reply(500, { message: 'gone' });
    expect(await bwInvitations.acceptOrganization('o', 'u', 't', 'h')).toMatchObject({ reason: 'other', message: 'gone' });
    fetched.mockRejectedValueOnce(new Error('offline'));
    expect(await bwInvitations.acceptOrganization('o', 'u', 't', 'h')).toEqual({
      ok: false,
      reason: 'other',
      message: '',
    });
  });
});
