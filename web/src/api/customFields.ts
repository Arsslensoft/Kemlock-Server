// The custom fields an admin offers (`GET /kem/v1/custom-fields`). Names and types are not secret,
// so every signed-in client reads them in the clear; a person's values live in the sealed item
// bodies. The answer is one object, `{ fields: [{ id, name, type, kinds }], allowOwn }`: `type` is
// `text`, `hidden` or `checkbox`, and `kinds` is the word `all` or a list of item kinds from login,
// note, otp, backup-codes, card, identity, contact, certificate, ssh-key and pgp-key. A file and a
// passkey take no custom fields.
import type { Api } from './client';
import { ApiError } from './errors';

export type CustomFieldType = 'text' | 'hidden' | 'checkbox';

export interface AdminFieldDef {
  id: string;
  name: string;
  type: CustomFieldType;
  /** The kinds of item the field is offered on, or `all`. */
  kinds: string[] | 'all';
}

export interface CustomFieldDefinitions {
  fields: AdminFieldDef[];
  /** Whether people may add fields of their own. Off only when an admin turned it off. */
  allowOwn: boolean;
}

/** What a server that has no custom fields (or an older one) means: none, and people may add their own. */
export const NO_DEFINITIONS: CustomFieldDefinitions = { fields: [], allowOwn: true };

const TYPES: readonly string[] = ['text', 'hidden', 'checkbox'];

function readField(raw: unknown): AdminFieldDef | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const entry = raw as Record<string, unknown>;
  const { id, name, type, kinds } = entry;
  if (typeof id !== 'string' || id === '' || typeof name !== 'string' || name.trim() === '') return undefined;
  if (typeof type !== 'string' || !TYPES.includes(type)) return undefined;
  const list =
    kinds === 'all'
      ? 'all'
      : Array.isArray(kinds)
        ? kinds.filter((kind): kind is string => typeof kind === 'string')
        : undefined;
  if (list === undefined) return undefined;
  return { id, name: name.trim(), type: type as CustomFieldType, kinds: list };
}

/**
 * Reads the answer: an object with `fields` and `allowOwn`. A field it can't read is left out,
 * never an error, and an answer that isn't that object means no admin fields.
 */
export function readDefinitions(raw: unknown): CustomFieldDefinitions {
  const body = typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
  const list = Array.isArray(body['fields']) ? (body['fields'] as unknown[]) : [];
  const own = body['allowOwn'];
  return {
    fields: list.map(readField).filter((field): field is AdminFieldDef => field !== undefined),
    allowOwn: typeof own === 'boolean' ? own : true,
  };
}

/** The kinds that take no custom fields, whatever an admin's field says. */
const NO_FIELDS = ['file', 'passkey'];

/** Whether the admin offers this field on items of `kind`: it names the kind, or says all. */
export function appliesTo(field: AdminFieldDef, kind: string): boolean {
  if (NO_FIELDS.includes(kind)) return false;
  return field.kinds === 'all' || field.kinds.includes(kind);
}

export interface CustomFieldsApi {
  list(): Promise<CustomFieldDefinitions>;
}

export function createCustomFieldsApi(api: Pick<Api, 'request'>): CustomFieldsApi {
  return {
    list: async () => {
      try {
        return readDefinitions(await api.request<unknown>({ method: 'GET', path: '/kem/v1/custom-fields' }));
      } catch (error) {
        // A server without the route has no admin fields: people still add their own.
        if (error instanceof ApiError && error.status === 404) return NO_DEFINITIONS;
        throw error;
      }
    },
  };
}
