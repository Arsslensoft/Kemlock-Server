// The custom fields an admin offers (`GET /kem/v1/custom-fields`). Names and types are not secret,
// so every signed-in client reads them in the clear; a person's values live in the sealed item
// bodies. The answer is `{ fields: [{ id, name, type, kinds }], allowOwn }`: `type` is `text`,
// `hidden` or `checkbox`, and `kinds` is the word `all` or a list of item kinds such as `login`.
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
 * Reads the answer, leniently: a field it can't read is left out, never an error. A bare list is
 * taken as the fields with people allowed to add their own.
 */
export function readDefinitions(raw: unknown): CustomFieldDefinitions {
  const list = Array.isArray(raw)
    ? raw
    : typeof raw === 'object' && raw !== null && Array.isArray((raw as { fields?: unknown }).fields)
      ? (raw as { fields: unknown[] }).fields
      : [];
  const own = typeof raw === 'object' && raw !== null ? (raw as { allowOwn?: unknown }).allowOwn : undefined;
  return {
    fields: list.map(readField).filter((field): field is AdminFieldDef => field !== undefined),
    allowOwn: typeof own === 'boolean' ? own : true,
  };
}

/** Whether the admin offers this field on items of `kind`. */
export function appliesTo(field: AdminFieldDef, kind: string): boolean {
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
