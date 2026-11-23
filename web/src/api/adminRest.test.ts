import { describe, expect, it } from 'vitest';
import { type AdminTransport, createAdminApi } from './admin';
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
    const off = { enabled: false, installationId: null, relayUrl: 'https://push.example' };
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
