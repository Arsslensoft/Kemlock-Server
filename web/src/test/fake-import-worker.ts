// A stand-in for the import worker, with the same message contract (src/import/contract.ts) and
// none of the WebAssembly. It reads two toy formats well enough to drive the screen and the client:
//
//   - a Bitwarden-style JSON ({"items":[{"type":1,"name":…,"login":{…}}]}); with
//     "passwordProtected": true it asks for the password "swordfish" and refuses any other;
//   - a CSV with a header holding `login_uri`, `login_username` and `login_password`.
//
// An export is a JSON document with a `fakeEncrypted` marker: readable, so a test can check what
// went in. Nothing here is cryptography.
import type { ImportWorkerPort } from '@/import/client';
import type {
  BatchLogin,
  ExportFormat,
  ExportItem,
  ImportBatch,
  ImportErrorCode,
  ImportFormat,
  ImportRequest,
  ImportResponse,
} from '@/import/contract';

export const FAKE_EXPORT_PASSWORD = 'swordfish';

const META = {
  folder: null,
  spaces: [],
  favorite: false,
  created_ms: null,
  modified_ms: null,
  source_id: null,
  tags: [],
};

class FakeError extends Error {
  constructor(readonly code: ImportErrorCode) {
    super(code);
  }
}

function textOf(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function emptyBatch(format: ImportFormat): ImportBatch {
  return {
    format,
    folders: [],
    spaces: [],
    logins: [],
    codes: [],
    notes: [],
    cards: [],
    identities: [],
    ssh_keys: [],
    files: [],
    skipped: [],
  };
}

function detect(bytes: Uint8Array): { format: ImportFormat; encrypted: boolean } {
  const text = textOf(bytes).trim();
  if (text.startsWith('{')) {
    try {
      const root = JSON.parse(text) as Record<string, unknown>;
      if (root['passwordProtected'] === true) return { format: 'bitwarden-json', encrypted: true };
      if (Array.isArray(root['items'])) return { format: 'bitwarden-json', encrypted: false };
    } catch {
      throw new FakeError('malformed');
    }
    throw new FakeError('unsupported');
  }
  const header = text.split(/\r?\n/)[0] ?? '';
  if (header.includes('login_uri')) return { format: 'bitwarden-csv', encrypted: false };
  throw new FakeError('unsupported');
}

function login(name: string, uri: string, username: string, password: string): BatchLogin {
  return {
    name,
    uris: uri === '' ? [] : [{ uri, match_rule: null }],
    username: username === '' ? null : username,
    password: password === '' ? null : password,
    totp: null,
    notes: null,
    fields: [],
    previous_passwords: [],
    passkeys: [],
    meta: { ...META },
  };
}

function parse(bytes: Uint8Array, format: ImportFormat | undefined, password: string | undefined): ImportBatch {
  const found = detect(bytes);
  const use = format ?? found.format;
  const text = textOf(bytes);
  if (found.encrypted) {
    if (password === undefined || password === '') throw new FakeError('password-required');
    if (password !== FAKE_EXPORT_PASSWORD) throw new FakeError('bad-password');
  }
  const batch = emptyBatch(use);
  if (use === 'bitwarden-json') {
    const root = JSON.parse(text) as { items?: Array<Record<string, unknown>> };
    for (const entry of root.items ?? []) {
      const inner = (entry['login'] ?? {}) as { username?: string; password?: string; uris?: Array<{ uri?: string }> };
      if (entry['type'] === 1) {
        batch.logins.push(
          login(String(entry['name'] ?? ''), inner.uris?.[0]?.uri ?? '', inner.username ?? '', inner.password ?? ''),
        );
      } else {
        batch.skipped.push({ name: String(entry['name'] ?? ''), reason: 'unsupported-kind', detail: null, count: 1 });
      }
    }
  } else {
    const [header, ...rows] = text.trim().split(/\r?\n/);
    const columns = (header ?? '').split(',');
    const at = (row: string[], name: string) => row[columns.indexOf(name)] ?? '';
    for (const line of rows) {
      const row = line.split(',');
      batch.logins.push(login(at(row, 'name'), at(row, 'login_uri'), at(row, 'login_username'), at(row, 'login_password')));
    }
  }
  if (batch.logins.length === 0 && batch.skipped.length === 0) throw new FakeError('empty');
  return batch;
}

function exportEncrypted(format: Exclude<ExportFormat, 'csv'>, items: ExportItem[], password: string) {
  if (password === '') throw new FakeError('password-required');
  const document = JSON.stringify({ fakeEncrypted: true, format, items });
  return {
    bytes: new TextEncoder().encode(document),
    filename: format === 'kemlock-json' ? 'kemlock-export.json' : 'bitwarden-export.json',
    mime: 'application/json',
  };
}

/** A port whose messages are answered on the next microtask, like a real worker's would be. */
export function createFakeImportWorker(): ImportWorkerPort & { posted: ImportRequest[] } {
  const listeners: Array<(event: { data: unknown }) => void> = [];
  const posted: ImportRequest[] = [];
  const reply = (response: ImportResponse) => queueMicrotask(() => listeners.forEach((l) => l({ data: response })));
  return {
    posted,
    postMessage(message) {
      posted.push(message);
      const { id } = message;
      try {
        if (message.op === 'detect') {
          reply({ id, kind: 'result', result: detect(message.args[0] as Uint8Array) });
        } else if (message.op === 'parse') {
          const [bytes, format, password] = message.args as [Uint8Array, ImportFormat | undefined, string | undefined];
          reply({ id, kind: 'progress', done: 0, total: 1 });
          reply({ id, kind: 'result', result: parse(bytes, format, password) });
        } else {
          const [format, items, password] = message.args as [Exclude<ExportFormat, 'csv'>, ExportItem[], string];
          reply({ id, kind: 'result', result: exportEncrypted(format, items, password) });
        }
      } catch (error) {
        const code = error instanceof FakeError ? error.code : 'malformed';
        reply({ id, kind: 'error', code });
      }
    },
    addEventListener(type: string, listener: (event: never) => void) {
      if (type === 'message') listeners.push(listener as (event: { data: unknown }) => void);
    },
    terminate() {
      listeners.length = 0;
    },
  };
}
