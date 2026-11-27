import { describe, expect, it } from 'vitest';
import { type AdminTransport, createAdminApi, isCopyFromAnotherServer } from './admin';
import { ApiError } from './errors';
import type { FeatureCall } from './client';

// The admin calls added with the passkey step-up, the push relay, account erasure and the
// migration's running and done states (crates/kemlock-api-admin).
function transport(answers: Record<string, unknown>) {
  const calls: FeatureCall[] = [];
  const answer = async (call: FeatureCall) => {
    calls.push(call);
    return answers[`${call.method} ${call.path}`];
  };
  const api: AdminTransport = {
    request: (call) => answer(call) as never,
    send: async (call) => {
      await answer(call);
    },
    raw: async () => new Response(),
  };
  return { calls, admin: createAdminApi(api) };
}

const BASE = '/admin/v1';

describe('the passkey step-up', () => {
  it('asks for options, then trades the credential and the sealed challenge for a token', async () => {
    const { admin, calls } = transport({
      [`POST ${BASE}/step-up/passkey/options`]: { options: { challenge: 'Y2g' }, challenge: 'sealed' },
      [`POST ${BASE}/step-up/passkey/finish`]: { token: 'T', expiresAt: 99 },
    });
    expect(await admin.stepUpPasskeyOptions()).toEqual({ options: { challenge: 'Y2g' }, challenge: 'sealed' });
    expect(await admin.stepUpPasskeyFinish('sealed', { id: 'cred' })).toEqual({ token: 'T', expiresAt: 99 });
    expect(calls[1]?.body).toEqual({ challenge: 'sealed', credential: { id: 'cred' } });
  });
});

describe('cancelling an erasure', () => {
  it('posts to the account with the step-up token', async () => {
    const { admin, calls } = transport({});
    await admin.cancelErasure('u1', 'tok');
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: `${BASE}/users/u1/cancel-erasure`,
      headers: { 'Step-Up-Token': 'tok' },
    });
  });
});

describe('the push relay', () => {
  it('reads where it stands, and turns it on and off with the token', async () => {
    const off = {
      enabled: false,
      installationId: null,
      relayUrl: 'https://push.example',
      apnsConfigured: false,
      apnsSandbox: false,
      unifiedPush: true,
    };
    const on = { ...off, enabled: true, installationId: 'inst' };
    const { admin, calls } = transport({
      [`GET ${BASE}/push-relay`]: off,
      [`POST ${BASE}/push-relay/enable`]: on,
      [`POST ${BASE}/push-relay/disable`]: off,
    });
    expect(await admin.pushRelay()).toEqual(off);
    expect(await admin.enablePushRelay('tok')).toEqual(on);
    expect(await admin.disablePushRelay('tok')).toEqual(off);
    expect(calls[1]?.headers).toEqual({ 'Step-Up-Token': 'tok' });
    expect(calls[2]?.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });
});

describe('the migration status', () => {
  it('reads the running stage and the done report as the server says them', async () => {
    const running = {
      state: 'running',
      source: '/srv/vw',
      plan: '1 user',
      error: null,
      at: 10,
      startedBy: 'u0',
      stage: 'writing items',
      report: null,
      finishedAt: null,
      applies: true,
    };
    const done = { ...running, state: 'done', stage: null, report: '1 user written', finishedAt: 20 };
    const { admin } = transport({ [`GET ${BASE}/migration`]: running });
    expect(await admin.migration()).toMatchObject({ state: 'running', stage: 'writing items' });
    const finished = transport({ [`GET ${BASE}/migration`]: done });
    expect(await finished.admin.migration()).toMatchObject({ state: 'done', report: '1 user written', finishedAt: 20 });
  });
});

describe('the custom fields', () => {
  it('reads the fields and the switch as the server sends them', async () => {
    const answer = {
      fields: [
        { id: 'f1', name: 'Employee ID', type: 'text', kinds: 'all' },
        { id: 'f2', name: 'Cost center', type: 'hidden', kinds: ['login', 'card'] },
      ],
      allowOwn: false,
    };
    const { admin, calls } = transport({ [`GET ${BASE}/custom-fields`]: answer });
    expect(await admin.customFields()).toEqual(answer);
    expect(calls[0]).toMatchObject({ method: 'GET', path: `${BASE}/custom-fields` });
  });

  it('adds, changes and deletes a field with the step-up token', async () => {
    const field = { id: 'f1', name: 'Employee ID', type: 'text', kinds: 'all' };
    const { admin, calls } = transport({
      [`POST ${BASE}/custom-fields`]: field,
      [`PUT ${BASE}/custom-fields/f1`]: { ...field, name: 'Staff number' },
    });
    const input = { name: 'Employee ID', type: 'text', kinds: 'all' } as const;
    expect(await admin.addCustomField(input, 'tok')).toEqual(field);
    expect(await admin.updateCustomField('f1', { ...input, name: 'Staff number' }, 'tok')).toMatchObject({
      name: 'Staff number',
    });
    await admin.deleteCustomField('f1', 'tok');
    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      `POST ${BASE}/custom-fields`,
      `PUT ${BASE}/custom-fields/f1`,
      `DELETE ${BASE}/custom-fields/f1`,
    ]);
    expect(calls[0]?.body).toEqual(input);
    for (const call of calls) expect(call.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });

  it('turns people adding their own fields off and on', async () => {
    const { admin, calls } = transport({ [`PUT ${BASE}/custom-fields/allow-own`]: { allowOwn: false } });
    expect(await admin.allowOwnFields(false, 'tok')).toEqual({ allowOwn: false });
    expect(calls[0]).toMatchObject({
      method: 'PUT',
      path: `${BASE}/custom-fields/allow-own`,
      body: { allow: false },
      headers: { 'Step-Up-Token': 'tok' },
    });
  });
});

describe('the Bitwarden invitation link', () => {
  it('reads the link of one member with the step-up token', async () => {
    const answer = { link: 'https://vault.example.org/#/accept-organization/?token=t', expiresAt: 1_800_000_000 };
    const { admin, calls } = transport({ [`GET ${BASE}/spaces/s1/members/u1/invite-link`]: answer });
    expect(await admin.spaceInviteLink('s1', 'u1', 'tok')).toEqual(answer);
    expect(calls[0]).toMatchObject({
      method: 'GET',
      path: `${BASE}/spaces/s1/members/u1/invite-link`,
      headers: { 'Step-Up-Token': 'tok' },
    });
  });
});

describe('changing the owner of a space', () => {
  it('passes on whether the change was only queued, as the chained space answers it', async () => {
    const queued = { id: 's1', owners: [], ownerChangeQueued: true };
    const { admin, calls } = transport({ [`PUT ${BASE}/spaces/s1/owner`]: queued });
    const answer = await admin.changeOwner('s1', { newOwner: 'u2' }, 'tok');
    expect(answer.ownerChangeQueued).toBe(true);
    expect(calls[0]?.body).toEqual({ newOwner: 'u2' });
  });
});

describe('the federation writes that need a step-up token', () => {
  it('send the token on promote, demotion and the rotation of this server’s identity', async () => {
    const { admin, calls } = transport({
      [`POST ${BASE}/federation/vaults/o1/promote`]: { record: 'r' },
      [`POST ${BASE}/federation/vaults/o1/demotion`]: {},
      [`POST ${BASE}/federation/self/identity-rotation`]: { identityKey: 'k' },
    });
    await admin.promote('o1', { homeIsDown: true }, 'tok');
    await admin.acceptDemotion('o1', 'tok');
    await admin.rotateIdentity('tok');
    for (const call of calls) expect(call.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });

  it('send none when they are given none, which the server answers with 403 step-up-required', async () => {
    const { admin, calls } = transport({ [`POST ${BASE}/federation/vaults/o1/promote`]: { record: 'r' } });
    await admin.promote('o1', { homeIsDown: false });
    expect(calls[0]?.headers).toBeUndefined();
  });
});

describe('held peer key rotations', () => {
  it('are listed with the peer, when they were held and the new key’s fingerprint', async () => {
    const { admin } = transport({
      [`GET ${BASE}/federation/rotations`]: [{ peer: 'p1', heldAt: 5, fingerprint: 'ab12' }],
    });
    expect(await admin.rotations()).toEqual([{ peerId: 'p1', heldAt: 5, fingerprint: 'ab12' }]);
  });

  it('are accepted or refused with the step-up token, naming the fingerprint', async () => {
    const { admin, calls } = transport({ [`POST ${BASE}/federation/peers/p1/rotation?fingerprint=ab12`]: {} });
    await admin.acceptRotation('p1', 'tok', 'ab12');
    await admin.refuseRotation('p1', 'tok', 'ab12');
    expect(calls.map((call) => [call.method, call.path])).toEqual([
      ['POST', `${BASE}/federation/peers/p1/rotation?fingerprint=ab12`],
      ['DELETE', `${BASE}/federation/peers/p1/rotation?fingerprint=ab12`],
    ]);
    for (const call of calls) expect(call.headers).toEqual({ 'Step-Up-Token': 'tok' });
  });

  it('name no fingerprint when none is given', async () => {
    const { admin, calls } = transport({});
    await admin.acceptRotation('p1', 'tok');
    expect(calls[0]?.path).toBe(`${BASE}/federation/peers/p1/rotation`);
  });
});

describe('accepting an offer', () => {
  it('is plain, or asks to move the vault’s home here with ?rehome=true', async () => {
    const { admin, calls } = transport({});
    await admin.federate('o1', 'tok');
    await admin.federate('o1', 'tok', true);
    expect(calls.map((call) => call.path)).toEqual([
      `${BASE}/federation/offers/o1/accept`,
      `${BASE}/federation/offers/o1/accept?rehome=true`,
    ]);
  });

  it('is told apart when the plain accept is refused because the account is a copy', () => {
    const problem = (slug: string, status: number) =>
      new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: slug, status } as never);
    expect(isCopyFromAnotherServer(problem('account-is-a-copy', 409))).toBe(true);
    expect(isCopyFromAnotherServer(problem('account-is-a-copy', 403))).toBe(false);
    expect(isCopyFromAnotherServer(problem('something-else', 409))).toBe(false);
    expect(isCopyFromAnotherServer(new Error('copy'))).toBe(false);
  });
});
