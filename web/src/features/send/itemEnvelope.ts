// An item Send: a Send of kind text whose text is a versioned JSON envelope built in the browser
// from one vault item. The wire stays what every Send is (a text Send, kind 0 to a Bitwarden
// client, which just shows the JSON), so the server and its routes know nothing about it.
// Documented in docs/crypto.md, "Sending an item".
//
//   {"kemlockSend":1,"kind":"card","name":"Visa","fields":{"number":"4111...","expiry":"05/2029"}}
//
// Only the fields the person's item holds for its kind go in: never ids, history, favorite,
// pinned, timestamps, or any key this table does not name.
import type { MessageId } from '@/i18n';
import type { SendableKind } from '@/features/vault/kinds';

export const ENVELOPE_VERSION = 1;
/** A larger envelope, or one with more fields, is shown as plain text. */
export const MAX_ENVELOPE_CHARS = 64 * 1024;
export const MAX_ENVELOPE_FIELDS = 32;

export interface ItemEnvelope {
  kemlockSend: typeof ENVELOPE_VERSION;
  kind: SendableKind;
  name: string;
  /** Field key to its text; fields with no value are left out. */
  fields: Record<string, string>;
}

export interface FieldSpec {
  key: string;
  label: MessageId;
  /** Shown masked, with a Show button. */
  secret?: boolean;
  /** Shown over several lines. */
  multiline?: boolean;
}

const f = (key: string, label: MessageId, extra: { secret?: boolean; multiline?: boolean } = {}): FieldSpec => ({
  key,
  label,
  ...extra,
});

const NOTE = f('note', 'sendItem.field.note', { multiline: true });

/** The fields each kind sends, in the order they are shown. */
export const FIELD_SPECS: Record<SendableKind, FieldSpec[]> = {
  login: [
    f('username', 'sendItem.field.username'),
    f('password', 'sendItem.field.password', { secret: true }),
    f('urls', 'sendItem.field.urls', { multiline: true }),
    f('notes', 'sendItem.field.note', { multiline: true }),
  ],
  note: [f('text', 'sendItem.field.text', { multiline: true })],
  card: [
    f('cardholder', 'sendItem.field.cardholder'),
    f('number', 'sendItem.field.number', { secret: true }),
    f('brand', 'sendItem.field.brand'),
    f('expiry', 'sendItem.field.expiry'),
    f('code', 'sendItem.field.securityCode', { secret: true }),
    f('pin', 'sendItem.field.pin', { secret: true }),
    NOTE,
  ],
  identity: [
    f('title', 'sendItem.field.title'),
    f('givenName', 'sendItem.field.givenName'),
    f('middleName', 'sendItem.field.middleName'),
    f('familyName', 'sendItem.field.familyName'),
    f('company', 'sendItem.field.company'),
    f('email', 'sendItem.field.email'),
    f('phone', 'sendItem.field.phone'),
    f('username', 'sendItem.field.username'),
    f('birthDate', 'sendItem.field.birthDate'),
    f('address', 'sendItem.field.address', { multiline: true }),
    f('city', 'sendItem.field.city'),
    f('region', 'sendItem.field.region'),
    f('postalCode', 'sendItem.field.postalCode'),
    f('country', 'sendItem.field.country'),
    NOTE,
  ],
  otp: [
    f('type', 'sendItem.field.type'),
    f('issuer', 'sendItem.field.issuer'),
    f('label', 'sendItem.field.account'),
    f('secret', 'sendItem.field.secret', { secret: true }),
    f('algorithm', 'sendItem.field.algorithm'),
    f('digits', 'sendItem.field.digits'),
    f('period', 'sendItem.field.period'),
    f('counter', 'sendItem.field.counter'),
    NOTE,
  ],
  'backup-codes': [
    f('serviceName', 'sendItem.field.service'),
    f('codes', 'sendItem.field.codes', { secret: true, multiline: true }),
    NOTE,
  ],
  'ssh-key': [
    f('algorithm', 'sendItem.field.algorithm'),
    f('public', 'sendItem.field.publicKey', { multiline: true }),
    f('private', 'sendItem.field.privateKey', { secret: true, multiline: true }),
    NOTE,
  ],
  'pgp-key': [
    f('public', 'sendItem.field.publicKey', { multiline: true }),
    f('private', 'sendItem.field.privateKey', { secret: true, multiline: true }),
    NOTE,
  ],
  certificate: [
    f('algorithm', 'sendItem.field.algorithm'),
    f('certificate', 'sendItem.field.certificate', { multiline: true }),
    f('private', 'sendItem.field.privateKey', { secret: true, multiline: true }),
    NOTE,
  ],
  contact: [f('public', 'sendItem.field.publicKey', { multiline: true }), NOTE],
};

export const SENDABLE_KINDS = Object.keys(FIELD_SPECS) as SendableKind[];

export function isSendableKind(kind: string): kind is SendableKind {
  return (SENDABLE_KINDS as string[]).includes(kind);
}

/** The slice of a vault item the envelope is built from. */
export interface SendableItem {
  kind: string;
  data: Record<string, unknown> | null;
}

function text(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string').join('\n');
  return '';
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** The text of one field of an item; `expiry`, `address` and `codes` are made from several keys. */
function read(kind: SendableKind, data: Record<string, unknown>, key: string): string {
  if (kind === 'card' && key === 'expiry') {
    const { expMonth, expYear } = data;
    if (typeof expMonth !== 'number' || typeof expYear !== 'number') return '';
    return `${String(expMonth).padStart(2, '0')}/${expYear}`;
  }
  if (kind === 'identity') {
    const address = record(data['address']);
    if (key === 'address') return text(address['lines']);
    if (['city', 'region', 'postalCode', 'country'].includes(key)) return text(address[key]);
  }
  if (kind === 'backup-codes' && key === 'codes') {
    const list = Array.isArray(data['codes']) ? data['codes'] : [];
    // A code already used is no use to the person it is sent to.
    return list
      .map(record)
      .filter((entry) => typeof entry['code'] === 'string' && entry['used'] !== true)
      .map((entry) => entry['code'] as string)
      .join('\n');
  }
  return text(data[key]);
}

/** The envelope for an item, or null for a kind that cannot be sent or an item that did not open. */
export function buildEnvelope(item: SendableItem, name: string): ItemEnvelope | null {
  if (!isSendableKind(item.kind) || item.data === null) return null;
  const fields: Record<string, string> = {};
  for (const spec of FIELD_SPECS[item.kind]) {
    const value = read(item.kind, item.data, spec.key);
    if (value.trim() !== '') fields[spec.key] = value;
  }
  return { kemlockSend: ENVELOPE_VERSION, kind: item.kind, name, fields };
}

/** The Send's text: compact JSON, keys in the order above. */
export function serializeEnvelope(envelope: ItemEnvelope): string {
  return JSON.stringify({
    kemlockSend: envelope.kemlockSend,
    kind: envelope.kind,
    name: envelope.name,
    fields: envelope.fields,
  });
}

/**
 * Reads a Send's text as an envelope. Null for anything else (plain text, other JSON, a newer
 * version, a kind this page does not know), so the page falls back to showing the text.
 */
export function parseEnvelope(raw: string): ItemEnvelope | null {
  if (raw.length > MAX_ENVELOPE_CHARS || !raw.trimStart().startsWith('{')) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  const top = record(value);
  if (top['kemlockSend'] !== ENVELOPE_VERSION) return null;
  const kind = top['kind'];
  if (typeof kind !== 'string' || !isSendableKind(kind) || typeof top['name'] !== 'string') return null;
  if (typeof top['fields'] !== 'object' || top['fields'] === null || Array.isArray(top['fields'])) return null;
  if (Object.keys(top['fields'] as object).length > MAX_ENVELOPE_FIELDS) return null;
  const fields: Record<string, string> = {};
  // Only the keys the kind defines are kept: nothing else is shown, so a crafted key can't pose as a label.
  const known = FIELD_SPECS[kind].map((spec) => spec.key);
  for (const [key, entry] of Object.entries(top['fields'] as Record<string, unknown>)) {
    if (known.includes(key) && typeof entry === 'string' && entry !== '') fields[key] = entry;
  }
  return { kemlockSend: ENVELOPE_VERSION, kind, name: top['name'], fields };
}

export interface ShownField {
  key: string;
  label: MessageId;
  value: string;
  secret: boolean;
  multiline: boolean;
}

/** The fields to show, in the order of the kind. */
export function shownFields(envelope: ItemEnvelope): ShownField[] {
  const known = FIELD_SPECS[envelope.kind];
  const out: ShownField[] = [];
  for (const spec of known) {
    const value = envelope.fields[spec.key];
    if (value === undefined) continue;
    out.push({
      key: spec.key,
      label: spec.label,
      value,
      secret: spec.secret === true,
      multiline: spec.multiline === true,
    });
  }
  return out;
}
