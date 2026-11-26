// How the admin console words an event of the log. Every row gets words: an action code has its
// message, a Bitwarden-API event (`bw.event`) is worded by the Vaultwarden event type in its
// target, and a code this build doesn't know yet is read out from its parts.
import type { AdminEvent } from '@/api/admin';
import type { MessageId, Values } from '@/i18n';

// Every action code the server writes to the event log. The keys are written as template literals
// so the message-id check in i18n.test.ts, which reads quoted strings, doesn't take an action code
// such as `item.put` for a message id.
const ACTIONS: Record<string, MessageId> = {
  // Items and their files
  [`item.put`]: 'admin.events.action.itemPut',
  [`item.delete`]: 'admin.events.action.itemDelete',
  [`item.batch`]: 'admin.events.action.itemBatch',
  [`attachment.upload`]: 'admin.events.action.attachmentUpload',
  [`attachment.delete`]: 'admin.events.action.attachmentDelete',
  [`dedup.matching-on`]: 'admin.events.action.dedupOn',
  [`dedup.matching-off`]: 'admin.events.action.dedupOff',
  // Sign-ins and sessions
  [`auth.sign_in`]: 'admin.events.action.signIn',
  [`auth.passkey_sign_in`]: 'admin.events.action.signInPasskey',
  [`auth.sso_sign_in`]: 'admin.events.action.signInSso',
  [`auth.sso_logout`]: 'admin.events.action.signOutSso',
  [`auth.device_approval`]: 'admin.events.action.signInApproved',
  [`auth.device_key`]: 'admin.events.action.signInDeviceKey',
  [`auth.two_step_recovered`]: 'admin.events.action.twoStepRecovered',
  [`auth.bitwarden_enrol`]: 'admin.events.action.bitwardenEnrol',
  [`auth.refresh_reuse`]: 'admin.events.action.refreshReuse',
  [`auth.refresh_key_mismatch`]: 'admin.events.action.refreshKeyMismatch',
  [`auth.refresh_disabled`]: 'admin.events.action.refreshDisabled',
  [`auth.refresh_stamp_changed`]: 'admin.events.action.refreshStampChanged',
  // Passkeys
  [`passkey.register`]: 'admin.events.action.passkeyRegister',
  [`passkey.delete`]: 'admin.events.action.passkeyDelete',
  [`passkey.wrap`]: 'admin.events.action.passkeyWrap',
  // Accounts
  [`account.export`]: 'admin.events.action.accountExport',
  [`account.erase_scheduled`]: 'admin.events.action.accountEraseScheduled',
  [`account.erased`]: 'admin.events.action.accountErased',
  [`account.keys_enrolled`]: 'admin.events.action.keysEnrolled',
  [`account.api_key_created`]: 'admin.events.action.apiKeyCreated',
  [`account.api_key_viewed`]: 'admin.events.action.apiKeyViewed',
  [`account.api_key_rotated`]: 'admin.events.action.apiKeyRotated',
  [`account.recovery_kit_created`]: 'admin.events.action.recoveryKitCreated',
  [`account.recovery_kit_regenerated`]: 'admin.events.action.recoveryKitRegenerated',
  [`account.recovery_kit_removed`]: 'admin.events.action.recoveryKitRemoved',
  [`account.sso_created`]: 'admin.events.action.ssoJoined',
  [`account.two_step_added`]: 'admin.events.action.twoStepAdded',
  [`account.two_step_removed`]: 'admin.events.action.twoStepRemoved',
  [`account.name_changed`]: 'admin.events.action.nameChanged',
  [`account.password_changed`]: 'admin.events.action.passwordChanged',
  [`account.email_change_requested`]: 'admin.events.action.emailChangeRequested',
  [`account.email_changed`]: 'admin.events.action.emailChanged',
  [`incident.export`]: 'admin.events.action.incidentExport',
  // Devices
  [`device.approval_approved`]: 'admin.events.action.deviceApproved',
  [`device.approval_denied`]: 'admin.events.action.deviceDenied',
  [`device.sign_out`]: 'admin.events.action.deviceSignOut',
  [`device.untrust`]: 'admin.events.action.deviceUntrust',
  // Sends
  [`send.create`]: 'admin.events.action.sendCreate',
  [`send.update`]: 'admin.events.action.sendUpdate',
  [`send.upload`]: 'admin.events.action.sendUpload',
  [`send.delete`]: 'admin.events.action.sendDelete',
  // Spaces
  [`space.create`]: 'admin.events.action.spaceCreate',
  [`space.member.invite`]: 'admin.events.action.spaceInvite',
  [`space.member.sso-invite`]: 'admin.events.action.spaceSsoInvite',
  [`space.member.accept`]: 'admin.events.action.spaceAccept',
  [`space.member.confirm`]: 'admin.events.action.spaceConfirm',
  [`space.member.role`]: 'admin.events.action.spaceRole',
  [`space.member.revoke`]: 'admin.events.action.spaceRevoke',
  [`space.member.restore`]: 'admin.events.action.spaceRestore',
  [`space.member.remove`]: 'admin.events.action.spaceRemove',
  [`space.collection.create`]: 'admin.events.action.collectionCreate',
  [`space.collection.edit`]: 'admin.events.action.collectionEdit',
  [`space.collection.delete`]: 'admin.events.action.collectionDelete',
  [`space.grant`]: 'admin.events.action.spaceGrant',
  [`space.grant.revoke`]: 'admin.events.action.spaceGrantRevoke',
  [`space.group.create`]: 'admin.events.action.groupCreate',
  [`space.group.edit`]: 'admin.events.action.groupEdit',
  [`space.group.delete`]: 'admin.events.action.groupDelete',
  [`space.policies.update`]: 'admin.events.action.spacePolicies',
  [`space.keys.replace`]: 'admin.events.action.spaceKeys',
  [`space.recovery.enrol`]: 'admin.events.action.spaceRecoveryEnrol',
  [`space.recovery.withdraw`]: 'admin.events.action.spaceRecoveryWithdraw',
  [`space.recovery.read`]: 'admin.events.action.spaceRecoveryRead',
  [`space.chain.append`]: 'admin.events.action.chainAppend',
  [`space.chain.pending.drop`]: 'admin.events.action.chainDrop',
  // Emergency access
  [`emergency.invite`]: 'admin.events.action.emergencyInvite',
  [`emergency.accept`]: 'admin.events.action.emergencyAccept',
  [`emergency.confirm`]: 'admin.events.action.emergencyConfirm',
  [`emergency.initiate`]: 'admin.events.action.emergencyInitiate',
  [`emergency.approve`]: 'admin.events.action.emergencyApprove',
  [`emergency.approve_due`]: 'admin.events.action.emergencyApproveDue',
  [`emergency.reject`]: 'admin.events.action.emergencyReject',
  [`emergency.revoke`]: 'admin.events.action.emergencyRevoke',
  [`emergency.release`]: 'admin.events.action.emergencyRelease',
  // Federation
  [`federation.erasure_forwarded`]: 'admin.events.action.federationErasureForwarded',
  [`federation.vault_erased`]: 'admin.events.action.federationVaultErased',
  [`federation.waiting_resumed`]: 'admin.events.action.federationResumed',
  [`federation.waiting_cancelled`]: 'admin.events.action.federationCancelled',
  // Admin console
  [`admin.user.disable`]: 'admin.events.action.userDisabled',
  [`admin.user.enable`]: 'admin.events.action.userEnabled',
  [`admin.user.delete`]: 'admin.events.action.userErased',
  [`admin.user.sign_out`]: 'admin.events.action.userSignOut',
  [`admin.user.reset_two_step`]: 'admin.events.action.userResetTwoStep',
  [`admin.user.cancel_erasure`]: 'admin.events.action.userCancelErasure',
  [`admin.invite.create`]: 'admin.events.action.inviteCreate',
  [`admin.invite.resend`]: 'admin.events.action.inviteResend',
  [`admin.invite.revoke`]: 'admin.events.action.inviteRevoke',
  [`admin.space.change_owner`]: 'admin.events.action.spaceChangeOwner',
  [`admin.settings.update`]: 'admin.events.action.settingsUpdate',
  [`admin.sso.update`]: 'admin.events.action.ssoUpdate',
  [`admin.sso.domain_add`]: 'admin.events.action.ssoDomainAdd',
  [`admin.sso.domain_verify`]: 'admin.events.action.ssoDomainVerify',
  [`admin.sso.domain_remove`]: 'admin.events.action.ssoDomainRemove',
  [`admin.custom_field.create`]: 'admin.events.action.fieldCreate',
  [`admin.custom_field.update`]: 'admin.events.action.fieldUpdate',
  [`admin.custom_field.delete`]: 'admin.events.action.fieldDelete',
  [`admin.custom_field.allow_own`]: 'admin.events.action.fieldAllowOwn',
  [`admin.compliance.log`]: 'admin.events.action.complianceLog',
  [`admin.compliance.update`]: 'admin.events.action.complianceUpdate',
  [`admin.push-relay.enable`]: 'admin.events.action.pushRelayOn',
  [`admin.push-relay.disable`]: 'admin.events.action.pushRelayOff',
  [`admin.migration.start`]: 'admin.events.action.migrationStart',
  [`admin.events.export`]: 'admin.events.action.eventsExport',
  [`admin.reset`]: 'admin.events.action.adminReset',
};

/** The action code of an event that a Bitwarden-API client or route made. */
const BW_EVENT = `bw.event`;

// Vaultwarden's `EventType` numbers (src/db/models/event.rs), the ones it doesn't comment out.
const BW_TYPES: Record<number, MessageId> = {
  1000: 'admin.events.bw.userLoggedIn',
  1001: 'admin.events.bw.userChangedPassword',
  1002: 'admin.events.bw.userUpdated2fa',
  1003: 'admin.events.bw.userDisabled2fa',
  1004: 'admin.events.bw.userRecovered2fa',
  1005: 'admin.events.bw.userFailedLogIn',
  1006: 'admin.events.bw.userFailedLogIn2fa',
  1007: 'admin.events.bw.userExportedVault',
  1010: 'admin.events.bw.userRequestedDeviceApproval',
  1100: 'admin.events.bw.cipherCreated',
  1101: 'admin.events.bw.cipherUpdated',
  1102: 'admin.events.bw.cipherDeleted',
  1103: 'admin.events.bw.cipherAttachmentCreated',
  1104: 'admin.events.bw.cipherAttachmentDeleted',
  1105: 'admin.events.bw.cipherShared',
  1106: 'admin.events.bw.cipherUpdatedCollections',
  1107: 'admin.events.bw.cipherViewed',
  1108: 'admin.events.bw.cipherShowedPassword',
  1109: 'admin.events.bw.cipherShowedHiddenField',
  1110: 'admin.events.bw.cipherShowedCardCode',
  1111: 'admin.events.bw.cipherCopiedPassword',
  1112: 'admin.events.bw.cipherCopiedHiddenField',
  1113: 'admin.events.bw.cipherCopiedCardCode',
  1114: 'admin.events.bw.cipherAutofilled',
  1115: 'admin.events.bw.cipherSoftDeleted',
  1116: 'admin.events.bw.cipherRestored',
  1117: 'admin.events.bw.cipherShowedCardNumber',
  1133: 'admin.events.bw.cipherHttpAuthReleased',
  1300: 'admin.events.bw.collectionCreated',
  1301: 'admin.events.bw.collectionUpdated',
  1302: 'admin.events.bw.collectionDeleted',
  1400: 'admin.events.bw.groupCreated',
  1401: 'admin.events.bw.groupUpdated',
  1402: 'admin.events.bw.groupDeleted',
  1500: 'admin.events.bw.memberInvited',
  1501: 'admin.events.bw.memberConfirmed',
  1502: 'admin.events.bw.memberUpdated',
  1503: 'admin.events.bw.memberRemoved',
  1504: 'admin.events.bw.memberUpdatedGroups',
  1505: 'admin.events.bw.memberUnlinkedSso',
  1506: 'admin.events.bw.memberResetPasswordEnroll',
  1507: 'admin.events.bw.memberResetPasswordWithdraw',
  1508: 'admin.events.bw.memberAdminResetPassword',
  1511: 'admin.events.bw.memberRevoked',
  1512: 'admin.events.bw.memberRestored',
  1513: 'admin.events.bw.memberApprovedAuthRequest',
  1514: 'admin.events.bw.memberRejectedAuthRequest',
  1515: 'admin.events.bw.memberDeleted',
  1516: 'admin.events.bw.memberLeft',
  1519: 'admin.events.bw.memberAdminResetTwoFactor',
  1520: 'admin.events.bw.memberRevokedTwoFactor',
  1521: 'admin.events.bw.memberRevokedSingleOrg',
  1522: 'admin.events.bw.memberBannerClicked',
  1600: 'admin.events.bw.organizationUpdated',
  1601: 'admin.events.bw.organizationPurgedVault',
  1602: 'admin.events.bw.organizationExportedVault',
  1700: 'admin.events.bw.policyUpdated',
};

/** A type Vaultwarden doesn't list yet, worded by its hundred, as Bitwarden groups them. */
function bwRange(type: number): MessageId {
  if (type >= 1000 && type < 1100) return 'admin.events.bw.range.user';
  if (type >= 1100 && type < 1200) return 'admin.events.bw.range.cipher';
  if (type >= 1300 && type < 1400) return 'admin.events.bw.range.collection';
  if (type >= 1400 && type < 1500) return 'admin.events.bw.range.group';
  if (type >= 1500 && type < 1600) return 'admin.events.bw.range.member';
  if (type >= 1600 && type < 1700) return 'admin.events.bw.range.organization';
  if (type >= 1700 && type < 1800) return 'admin.events.bw.range.policy';
  return 'admin.events.bw.range.other';
}

/** The target's column that names what a Bitwarden event is about, by the type's hundred. */
function bwSourceKey(type: number): string | undefined {
  if (type >= 1100 && type < 1200) return 'cipherId';
  if (type >= 1300 && type < 1400) return 'collectionId';
  if (type >= 1400 && type < 1500) return 'groupId';
  if (type >= 1500 && type < 1600) return 'organizationUserId';
  if (type >= 1700 && type < 1800) return 'policyId';
  return undefined;
}

// The areas of an action code's first part, for a code this build doesn't word yet.
const AREAS: Record<string, MessageId> = {
  auth: 'admin.events.kind.signIn',
  item: 'admin.events.kind.item',
  space: 'admin.events.kind.space',
  send: 'admin.events.kind.send',
  device: 'admin.events.kind.device',
  account: 'admin.events.kind.account',
  admin: 'admin.events.kind.admin',
  federation: 'admin.events.kind.federation',
  passkey: 'admin.events.area.passkey',
  emergency: 'admin.events.area.emergency',
  attachment: 'admin.events.area.attachment',
  dedup: 'admin.events.area.dedup',
  incident: 'admin.events.area.incident',
  bw: 'admin.events.area.bitwarden',
};

function own<V>(record: Record<string, V>, key: string | number): V | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

/** The message that words an action code, or nothing for a code this build doesn't know. */
export function actionMessage(action: string): MessageId | undefined {
  return own(ACTIONS, action);
}

/** A message and its values, to hand to `t`; a value may itself be a message, formatted first. */
export interface Words {
  id: MessageId;
  values?: Record<string, string | number | Words>;
}

export interface EventText {
  words: Words;
  /** What the event was about, as an id or address to show beside the words; null for nothing. */
  target: string | null;
}

/** `bw.event`'s target: the JSON of Vaultwarden's event columns. */
function bwText(target: string | null): EventText {
  let parsed: Record<string, unknown> = {};
  try {
    const value: unknown = target === null ? null : JSON.parse(target);
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      parsed = value as Record<string, unknown>;
    }
  } catch {
    // Not JSON: worded as a Bitwarden event of no known type.
  }
  const type = typeof parsed.type === 'number' && Number.isInteger(parsed.type) ? parsed.type : null;
  if (type === null) {
    return { words: { id: 'admin.events.bw.unknown' }, target: null };
  }
  const known = own(BW_TYPES, type);
  // A string, so ICU doesn't group the digits (1,118).
  const what: Words = known ? { id: known } : { id: bwRange(type), values: { type: String(type) } };
  const key = bwSourceKey(type);
  const source = key === undefined ? undefined : parsed[key];
  const about = uuidOrNull(source) ?? uuidOrNull(parsed.organizationId);
  return { words: { id: 'admin.events.bw', values: { what } }, target: about };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * An id out of a `bw.event` target, only if it is a UUID. The server stores only UUIDs there, but
 * the target is JSON that Bitwarden clients' reports feed, so nothing else in it is shown.
 */
function uuidOrNull(value: unknown): string | null {
  return typeof value === 'string' && UUID.test(value) ? value : null;
}

/** The longest read-out of a code this build doesn't word. */
const MAX_WHAT = 60;

/**
 * Reads a code such as `space.member.kick` out as its area and the rest in words. Only letters and
 * digits are kept, the separators become spaces, and the read-out is cut short: a code is the
 * server's, but it is shown as text, so nothing in it may read as markup or run on.
 */
function unknownText(action: string): Words {
  const code = action.replace(/[^A-Za-z0-9._-]/g, '');
  const dot = code.indexOf('.');
  const head = dot < 0 ? '' : code.slice(0, dot);
  const rest = dot < 0 ? code : code.slice(dot + 1);
  const words = rest.replace(/[._-]+/g, ' ').trim() || code.replace(/[._-]+/g, ' ').trim();
  const what = words.length > MAX_WHAT ? `${words.slice(0, MAX_WHAT)}…` : words || '?';
  const area = own(AREAS, head);
  return { id: 'admin.events.other', values: { area: { id: area ?? 'admin.events.area.other' }, what } };
}

/** The words for an event of the log, and what it was about. */
export function eventText(event: Pick<AdminEvent, 'action' | 'target'>): EventText {
  if (event.action === BW_EVENT) return bwText(event.target);
  const id = actionMessage(event.action);
  if (id) return { words: { id }, target: event.target };
  return { words: unknownText(event.action), target: event.target };
}

/** Formats words with `t`, the messages among the values first. */
export function format(words: Words, t: (id: MessageId, values?: Values) => string): string {
  if (!words.values) return t(words.id);
  const values: Values = {};
  for (const [name, value] of Object.entries(words.values)) {
    values[name] = typeof value === 'object' ? format(value, t) : value;
  }
  return t(words.id, values);
}
