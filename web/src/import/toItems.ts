// An import batch as Kemlock items: the plaintext JSON each one is sealed from. Field names follow
// the Kemlock app's own models (mobile/test/fixtures: a login has `uris` with Bitwarden's rule
// numbers and `websites`, a card has `expMonth`/`expYear`, a code has `secret`) and the web vault's
// existing login and note (`urls`, `text`).
import type { ItemData } from '@/features/vault/vault';
import { writeWebsites, type WebsiteRule } from '@/features/vault/websites';
import type {
  BatchField,
  BatchMeta,
  ImportBatch,
  UriMatchName,
} from './contract';

export interface NewItem {
  id: string;
  kind: string;
  data: ItemData;
}

export interface Conversion {
  items: NewItem[];
  /** Things a person should know before importing: files left behind, entries skipped. */
  warnings: Array<{ code: 'files' | 'skipped' | 'spaces'; count: number }>;
}

const MATCH: Record<UriMatchName, WebsiteRule['match']> = {
  'base-domain': 'domain',
  host: 'host',
  'starts-with': 'startsWith',
  exact: 'exact',
  'regular-expression': 'regex',
  never: 'never',
};

function iso(ms: number | null | undefined): string | undefined {
  return typeof ms === 'number' ? new Date(ms).toISOString() : undefined;
}

/** Fields every kind carries: folder, favourite, dates, tags. Absent values are left out. */
function common(batch: ImportBatch, meta: BatchMeta, now: Date): ItemData {
  const out: ItemData = { updatedAt: iso(meta.modified_ms) ?? now.toISOString() };
  const folder = meta.folder === null ? undefined : batch.folders[meta.folder]?.path;
  if (folder) out['folder'] = folder;
  if (meta.favorite) out['favorite'] = true;
  const created = iso(meta.created_ms);
  if (created) out['createdAt'] = created;
  if (meta.tags.length > 0) out['tags'] = meta.tags;
  return out;
}

function fieldsOf(fields: BatchField[]): ItemData {
  return fields.length > 0 ? { fields: fields.map((f) => ({ name: f.name, value: f.value, kind: f.kind })) } : {};
}

function put(out: ItemData, key: string, value: string | number | null | undefined): void {
  if (value !== null && value !== undefined && value !== '') out[key] = value;
}

/** Converts a batch. `newId` makes each item's id; `now` stamps what the source didn't date. */
export function batchToItems(
  batch: ImportBatch,
  newId: () => string = () => globalThis.crypto.randomUUID(),
  now: Date = new Date(),
): Conversion {
  const items: NewItem[] = [];

  for (const login of batch.logins) {
    const id = newId();
    const rules: WebsiteRule[] = login.uris.map((u) => ({
      uri: u.uri,
      match: u.match_rule ? MATCH[u.match_rule] : 'default',
    }));
    const data: ItemData = { ...common(batch, login.meta, now), name: login.name };
    put(data, 'username', login.username);
    put(data, 'password', login.password);
    put(data, 'notes', login.notes);
    Object.assign(data, writeWebsites(rules), fieldsOf(login.fields));
    if (login.previous_passwords.length > 0) {
      data['passwordHistory'] = login.previous_passwords.map((p) => ({
        password: p.password,
        replacedAt: new Date(p.until_ms).toISOString(),
      }));
    }
    if (login.passkeys.length > 0) {
      data['passkeys'] = login.passkeys.map((p) => ({
        credentialId: p.credential_id,
        rpId: p.rp_id,
        rpName: p.rp_name ?? undefined,
        userHandle: p.user_handle,
        userName: p.user_name,
        userDisplayName: p.user_display_name ?? undefined,
        privateKey: p.private_key,
        algorithm: p.algorithm,
      }));
    }
    items.push({ id, kind: 'login', data });
    // A login's TOTP becomes a code of its own, linked to it.
    if (login.totp) {
      items.push({
        id: newId(),
        kind: 'otp',
        data: {
          ...common(batch, login.meta, now),
          name: login.name,
          secret: login.totp,
          linkedLoginId: id,
          ...(login.username ? { label: login.username } : {}),
        },
      });
    }
  }

  for (const code of batch.codes) {
    const data: ItemData = { ...common(batch, code.meta, now), name: code.name, secret: code.value };
    put(data, 'notes', code.notes);
    items.push({ id: newId(), kind: 'otp', data });
  }

  for (const note of batch.notes) {
    const data: ItemData = { ...common(batch, note.meta, now), name: note.name, text: note.text ?? '' };
    Object.assign(data, fieldsOf(note.fields));
    items.push({ id: newId(), kind: 'note', data });
  }

  for (const card of batch.cards) {
    const data: ItemData = { ...common(batch, card.meta, now), name: card.name };
    put(data, 'cardholder', card.cardholder);
    put(data, 'number', card.number);
    put(data, 'brand', card.brand);
    put(data, 'expMonth', card.exp_month);
    put(data, 'expYear', card.exp_year);
    put(data, 'code', card.code);
    put(data, 'pin', card.pin);
    put(data, 'validFromMonth', card.valid_from_month);
    put(data, 'validFromYear', card.valid_from_year);
    put(data, 'notes', card.notes);
    Object.assign(data, fieldsOf(card.fields));
    items.push({ id: newId(), kind: 'card', data });
  }

  for (const person of batch.identities) {
    const data: ItemData = { ...common(batch, person.meta, now), name: person.name };
    put(data, 'title', person.title);
    put(data, 'firstName', person.given_name);
    put(data, 'middleName', person.middle_name);
    put(data, 'lastName', person.family_name);
    put(data, 'company', person.company);
    put(data, 'email', person.email);
    put(data, 'phone', person.phone);
    put(data, 'username', person.username);
    put(data, 'birthDate', person.birth_date);
    put(data, 'notes', person.notes);
    if (person.address) {
      data['address'] = {
        lines: person.address.lines,
        city: person.address.city ?? undefined,
        region: person.address.region ?? undefined,
        postalCode: person.address.postal_code ?? undefined,
        country: person.address.country ?? undefined,
      };
    }
    if (person.documents.length > 0) {
      data['documents'] = person.documents.map((d) => ({
        kind: d.kind,
        number: d.number ?? undefined,
        issuingCountry: d.issuing_country ?? undefined,
        issuingAuthority: d.issuing_authority ?? undefined,
        issuedOn: d.issued_on ?? undefined,
        expiresOn: d.expires_on ?? undefined,
      }));
    }
    Object.assign(data, fieldsOf(person.fields));
    items.push({ id: newId(), kind: 'identity', data });
  }

  for (const key of batch.ssh_keys) {
    const data: ItemData = { ...common(batch, key.meta, now), name: key.name, privateKey: key.private_key };
    put(data, 'publicKey', key.public_key);
    put(data, 'fingerprint', key.fingerprint);
    put(data, 'notes', key.notes);
    Object.assign(data, fieldsOf(key.fields));
    items.push({ id: newId(), kind: 'ssh-key', data });
  }

  const warnings: Conversion['warnings'] = [];
  if (batch.files.length > 0) warnings.push({ code: 'files', count: batch.files.length });
  const skipped = batch.skipped.reduce((sum, s) => sum + Math.max(1, s.count), 0);
  if (skipped > 0) warnings.push({ code: 'skipped', count: skipped });
  if (batch.spaces.length > 0) warnings.push({ code: 'spaces', count: batch.spaces.length });
  return { items, warnings };
}
