import { IntlMessageFormat } from 'intl-messageformat';
import { describe, expect, it } from 'vitest';
import { type MessageId, type Values, messages } from '@/i18n';
import { actionMessage, eventText, format } from './eventText';

function t(id: MessageId, values?: Values): string {
  return String(new IntlMessageFormat(messages[id] as string, 'en').format(values));
}

function words(action: string, target: string | null = null): string {
  return format(eventText({ action, target }).words, t);
}

// Every action code the server writes to the event log (`action:` and `.record("…")` in crates/).
// A code added there and not here is still worded, from its parts, but not as well.
const SERVER_ACTIONS = [
  'account.api_key_created', 'account.api_key_rotated', 'account.api_key_viewed',
  'account.erase_scheduled', 'account.erased', 'account.export', 'account.keys_enrolled',
  'account.recovery_kit_created', 'account.recovery_kit_regenerated', 'account.recovery_kit_removed',
  'account.sso_created', 'account.two_step_added', 'account.two_step_removed',
  'account.name_changed', 'account.password_changed', 'account.email_change_requested',
  'account.email_changed',
  'admin.custom_field.create', 'admin.custom_field.update', 'admin.custom_field.delete',
  'admin.custom_field.allow_own',
  'device.untrust',
  'admin.compliance.log', 'admin.compliance.update', 'admin.events.export', 'admin.invite.create',
  'admin.invite.resend', 'admin.invite.revoke', 'admin.migration.start', 'admin.push-relay.disable',
  'admin.push-relay.enable', 'admin.reset', 'admin.settings.update', 'admin.space.change_owner',
  'admin.sso.domain_add', 'admin.sso.domain_remove', 'admin.sso.domain_verify', 'admin.sso.update',
  'admin.user.cancel_erasure', 'admin.user.delete', 'admin.user.disable', 'admin.user.enable',
  'admin.user.reset_two_step', 'admin.user.sign_out',
  'attachment.delete', 'attachment.upload',
  'auth.bitwarden_enrol', 'auth.device_approval', 'auth.device_key', 'auth.passkey_sign_in',
  'auth.refresh_disabled', 'auth.refresh_key_mismatch', 'auth.refresh_reuse',
  'auth.refresh_stamp_changed', 'auth.sign_in', 'auth.sso_logout', 'auth.sso_sign_in',
  'auth.two_step_recovered',
  'dedup.matching-off', 'dedup.matching-on',
  'device.approval_approved', 'device.approval_denied', 'device.sign_out',
  'emergency.accept', 'emergency.approve', 'emergency.approve_due', 'emergency.confirm',
  'emergency.initiate', 'emergency.invite', 'emergency.reject', 'emergency.release',
  'emergency.revoke',
  'federation.erasure_forwarded', 'federation.vault_erased', 'federation.waiting_cancelled',
  'federation.waiting_resumed',
  'incident.export',
  'item.batch', 'item.delete', 'item.put',
  'passkey.delete', 'passkey.register', 'passkey.wrap',
  'send.create', 'send.delete', 'send.update', 'send.upload',
  'space.chain.append', 'space.chain.pending.drop', 'space.collection.create',
  'space.collection.delete', 'space.collection.edit', 'space.create', 'space.grant',
  'space.grant.revoke', 'space.group.create', 'space.group.delete', 'space.group.edit',
  'space.keys.replace', 'space.member.accept', 'space.member.confirm', 'space.member.invite',
  'space.member.remove', 'space.member.restore', 'space.member.revoke', 'space.member.role',
  'space.member.sso-invite', 'space.policies.update', 'space.recovery.enrol', 'space.recovery.read',
  'space.recovery.withdraw',
];

// The `EventType` numbers Vaultwarden 1.37 doesn't comment out (src/db/models/event.rs).
const VAULTWARDEN_TYPES = [
  1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1010,
  1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115,
  1116, 1117, 1133,
  1300, 1301, 1302, 1400, 1401, 1402,
  1500, 1501, 1502, 1503, 1504, 1505, 1506, 1507, 1508, 1511, 1512, 1513, 1514, 1515, 1516, 1519,
  1520, 1521, 1522,
  1600, 1601, 1602, 1700,
];

describe('eventText', () => {
  it('has a message for every action the server writes', () => {
    expect(SERVER_ACTIONS.filter((action) => actionMessage(action) === undefined)).toEqual([]);
  });

  it('words the codes the console showed raw', () => {
    expect(words('auth.passkey_sign_in')).toBe('Signed in with a passkey');
    expect(words('passkey.register')).toBe('Added a passkey');
    expect(words('auth.sign_in')).toBe('Signed in');
    expect(words('account.two_step_added')).toBe('Added a two-step login method');
  });

  it('keeps the target of an ordinary event', () => {
    expect(eventText({ action: 'passkey.register', target: 'c691' }).target).toBe('c691');
  });

  it("doesn't take an object's own property names for actions", () => {
    expect(actionMessage('toString')).toBeUndefined();
    expect(words('constructor')).toBe('Other: constructor');
  });

  it('reads a code it has no message for out of its parts', () => {
    expect(words('space.member.kick')).toBe('Spaces: member kick');
    expect(words('auth.magic_link')).toBe('Sign-ins: magic link');
    expect(words('passkey.rename')).toBe('Passkeys: rename');
    expect(words('backup.drill-done')).toBe('Other: drill done');
    expect(words('heartbeat')).toBe('Other: heartbeat');
  });

  it('reads out only letters and digits of an unknown code, and cuts a long one short', () => {
    expect(words('space.<img src=x onerror=alert(1)>')).toBe('Spaces: imgsrcxonerroralert1');
    expect(words('x.{what}')).toBe('Other: what');
    expect(words('<script>')).toBe('Other: script');
    expect(words('...')).toBe('Other: ?');
    expect(words(`item.${'a'.repeat(500)}`)).toBe(`Items: ${'a'.repeat(60)}…`);
  });

  describe('of a Bitwarden-API event', () => {
    const bw = (target: string | null) => eventText({ action: 'bw.event', target });

    it('words every type Vaultwarden has by its own message', () => {
      for (const type of VAULTWARDEN_TYPES) {
        const text = format(bw(JSON.stringify({ type })).words, t);
        expect(text, String(type)).not.toMatch(/event \d+/);
        expect(text, String(type)).toMatch(/ \(Bitwarden API\)$/);
      }
    });

    it('tells a two-step recovery from a failed sign-in', () => {
      expect(format(bw('{"type":1004}').words, t)).toBe('Signed in with a two-step recovery code (Bitwarden API)');
      expect(format(bw('{"type":1005}').words, t)).toBe('Failed to sign in (Bitwarden API)');
    });

    const CIPHER = '265920f3-088e-47d9-bd7b-dfc31cd17f1a';
    const MEMBER = 'c6911909-41c7-4909-9986-51a49aa5000b';
    const ORG = 'dd99347a-052a-44a5-9441-517e4aefd8a9';

    it('shows what the event was about instead of its JSON', () => {
      expect(bw(JSON.stringify({ type: 1107, cipherId: CIPHER, organizationId: ORG })).target).toBe(CIPHER);
      expect(bw(JSON.stringify({ type: 1501, organizationUserId: MEMBER, organizationId: ORG })).target).toBe(
        MEMBER,
      );
      expect(bw(JSON.stringify({ type: 1602, organizationId: ORG })).target).toBe(ORG);
      expect(bw('{"type":1000,"organizationId":null}').target).toBeNull();
    });

    it('shows only a UUID out of the target, never other text in it', () => {
      const hostile = '<img src=x onerror=alert(1)>';
      expect(bw(JSON.stringify({ type: 1107, cipherId: hostile })).target).toBeNull();
      expect(bw(JSON.stringify({ type: 1107, cipherId: hostile, organizationId: ORG })).target).toBe(ORG);
      expect(bw(JSON.stringify({ type: 1107, cipherId: `${CIPHER}<script>` })).target).toBeNull();
      expect(bw(JSON.stringify({ type: 1107, cipherId: { toString: CIPHER } })).target).toBeNull();
      expect(bw('{"type":1107,"__proto__":{"cipherId":"x"}}').target).toBeNull();
    });

    it('words a type Vaultwarden adds later by its hundred', () => {
      expect(format(bw('{"type":1118}').words, t)).toBe('Item event 1118 (Bitwarden API)');
      expect(format(bw('{"type":1609}').words, t)).toBe('Organization event 1609 (Bitwarden API)');
      expect(format(bw('{"type":2100}').words, t)).toBe('Event 2100 (Bitwarden API)');
    });

    it('still has words when the target is missing or not what it should be', () => {
      for (const target of [null, '', 'not json', '[]', '{"type":"1000"}', '{"type":1.5}']) {
        expect(format(bw(target).words, t), String(target)).toBe('An event from the Bitwarden API');
        expect(bw(target).target).toBeNull();
      }
    });
  });
});
