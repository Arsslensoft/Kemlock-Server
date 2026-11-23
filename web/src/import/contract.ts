// The contract between the page and the import worker. Everything that crosses is a plain object,
// a string, a number or a Uint8Array (transferred, so a large file is not copied).
//
// The worker is `kemlock-import` compiled to WebAssembly (crates/kemlock-import: pure Rust, bytes in
// and an `ImportBatch` out) behind a small wasm-bindgen wrapper crate, crates/kemlock-import-wasm.
// What it exports is written next to each operation below and collected in `WASM_EXPORTS`; the
// worker is src/import/worker.ts. The batch crosses as the crate's own serde JSON: snake_case field
// names, kebab-case enum values, file bytes as standard base64.

/** `kemlock_import::Format`, serialised kebab-case. */
export type ImportFormat =
  | 'chrome-csv'
  | 'safari-csv'
  | 'firefox-csv'
  | 'bitwarden-json'
  | 'bitwarden-csv'
  | 'last-pass-csv'
  | 'one-password-pux'
  | 'one-password-csv'
  | 'dashlane-zip'
  | 'dashlane-csv'
  | 'nord-pass-csv'
  | 'keeper-json'
  | 'proton-pass-json'
  | 'proton-pass-zip'
  | 'proton-pass-pgp'
  | 'kdbx'
  | 'enpass-json'
  | 'robo-form-csv';

/** The formats an export can be written in. CSV is written by the page, the others by the worker. */
export type ExportFormat = 'kemlock-json' | 'bitwarden-json' | 'csv';

// ---- The batch, as the crate serialises it ------------------------------------------------------

export type UriMatchName =
  | 'base-domain'
  | 'host'
  | 'starts-with'
  | 'exact'
  | 'regular-expression'
  | 'never';

export interface BatchMeta {
  folder: number | null;
  spaces: number[];
  favorite: boolean;
  created_ms: number | null;
  modified_ms: number | null;
  source_id: string | null;
  tags: string[];
}

export interface BatchField {
  name: string;
  value: string;
  kind: 'text' | 'hidden' | 'boolean' | 'linked';
}

export interface BatchPasskey {
  credential_id: string;
  rp_id: string;
  rp_name: string | null;
  user_handle: string;
  user_name: string;
  user_display_name: string | null;
  private_key: string;
  algorithm: number;
  created_ms: number | null;
}

export interface BatchLogin {
  name: string;
  uris: Array<{ uri: string; match_rule: UriMatchName | null }>;
  username: string | null;
  password: string | null;
  totp: string | null;
  notes: string | null;
  fields: BatchField[];
  previous_passwords: Array<{ password: string; until_ms: number }>;
  passkeys: BatchPasskey[];
  meta: BatchMeta;
}

export interface BatchCode {
  name: string;
  value: string;
  notes: string | null;
  meta: BatchMeta;
}

export interface BatchNote {
  name: string;
  text: string | null;
  fields: BatchField[];
  meta: BatchMeta;
}

export interface BatchCard {
  name: string;
  cardholder: string | null;
  number: string | null;
  brand: string | null;
  exp_month: number | null;
  exp_year: number | null;
  code: string | null;
  pin: string | null;
  valid_from_month: number | null;
  valid_from_year: number | null;
  notes: string | null;
  fields: BatchField[];
  meta: BatchMeta;
}

export interface BatchIdentity {
  name: string;
  title: string | null;
  given_name: string | null;
  middle_name: string | null;
  family_name: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  username: string | null;
  birth_date: string | null;
  address: {
    lines: string[];
    city: string | null;
    region: string | null;
    postal_code: string | null;
    country: string | null;
  } | null;
  documents: Array<{
    kind: string;
    number: string | null;
    issuing_country: string | null;
    issuing_authority: string | null;
    issued_on: string | null;
    expires_on: string | null;
  }>;
  notes: string | null;
  fields: BatchField[];
  meta: BatchMeta;
}

export interface BatchSshKey {
  name: string;
  private_key: string;
  public_key: string | null;
  fingerprint: string | null;
  notes: string | null;
  fields: BatchField[];
  meta: BatchMeta;
}

export type SkipReasonName =
  | 'trashed'
  | 'unsupported-kind'
  | 'unsupported-passkey'
  | 'bad-key'
  | 'malformed'
  | 'over-limit'
  | 'file-over-limit'
  | 'other';

export interface BatchSkipped {
  name: string | null;
  reason: SkipReasonName;
  detail: string | null;
  count: number;
}

export interface ImportBatch {
  format: ImportFormat;
  folders: Array<{ name: string; parent: number | null; path: string }>;
  spaces: Array<{ name: string; kind: 'vault' | 'collection' | 'shared-folder'; source_id: string | null }>;
  logins: BatchLogin[];
  codes: BatchCode[];
  notes: BatchNote[];
  cards: BatchCard[];
  identities: BatchIdentity[];
  ssh_keys: BatchSshKey[];
  /** Files from the export. This build does not upload them; the count is shown as a warning. */
  files: Array<{ name: string; media_type: string | null; data: string; owner: { kind: string; index: number } | null }>;
  skipped: BatchSkipped[];
}

// ---- Errors -------------------------------------------------------------------------------------

/**
 * `kemlock_import::ImportError`, by variant (kebab-case), plus `unavailable` when the WebAssembly
 * module or the worker could not start and `cancelled` when the page gave up on the request.
 */
export type ImportErrorCode =
  | 'too-large'
  | 'limit-exceeded'
  | 'unsupported'
  | 'empty'
  | 'malformed'
  | 'password-required'
  | 'bad-password'
  | 'kdf-out-of-bounds'
  | 'account-restricted'
  | 'unsupported-encryption'
  | 'unavailable'
  | 'cancelled';

export class ImportWorkerError extends Error {
  readonly code: ImportErrorCode;

  constructor(code: ImportErrorCode) {
    super(code);
    this.name = 'ImportWorkerError';
    this.code = code;
  }
}

// ---- Operations ---------------------------------------------------------------------------------

export interface DetectResult {
  format: ImportFormat;
  /** Whether opening it takes a password (and, for KDBX, offers a key file). */
  encrypted: boolean;
}

/** One opened item handed to an export: what the page holds after decrypting the vault. */
export interface ExportItem {
  id: string;
  kind: string;
  /** The item's plaintext JSON object. */
  data: Record<string, unknown>;
}

export interface ExportResult {
  bytes: Uint8Array;
  filename: string;
  mime: string;
}

export interface ImportOps {
  /**
   * Which format these bytes are, without decrypting.
   * wasm: `detect(bytes: Uint8Array): string`, the JSON `{"format": "...", "encrypted": true}`,
   * throwing the `ImportError` variant name; calls `kemlock_import::detect` with default `Limits`.
   */
  detect: { args: [bytes: Uint8Array]; result: DetectResult };
  /**
   * Reads the file into a batch. `format` is omitted to detect it.
   * wasm: `parse(bytes: Uint8Array, format: string | undefined, password: string | undefined,
   * keyFile: Uint8Array | undefined): string` returning `serde_json::to_string(&ImportBatch)`;
   * calls `kemlock_import::parse` with `ImportOptions`.
   */
  parse: {
    args: [
      bytes: Uint8Array,
      format?: ImportFormat,
      password?: string,
      keyFile?: Uint8Array,
    ];
    result: ImportBatch;
  };
  /**
   * Writes a password-encrypted export.
   * wasm: `exportEncrypted(format: 'kemlock-json' | 'bitwarden-json', itemsJson: string,
   * password: string): Uint8Array`, written by `kemlock_import::bitwarden_export`: Bitwarden's
   * password-protected JSON, and the same file with a `kemlock` member that holds every item as
   * Kemlock stores it. The worker names the file and gives its media type.
   */
  exportEncrypted: {
    args: [format: Exclude<ExportFormat, 'csv'>, items: ExportItem[], password: string];
    result: ExportResult;
  };
}

export type OpName = keyof ImportOps;

export interface ImportRequest<Op extends OpName = OpName> {
  id: number;
  op: Op;
  args: ImportOps[Op]['args'];
}

/** What the worker posts back: progress while it works, then one result or one error. */
export type ImportResponse =
  | { id: number; kind: 'progress'; done: number; total: number }
  | { id: number; kind: 'result'; result: unknown }
  | { id: number; kind: 'error'; code: ImportErrorCode };

/** What the wasm wrapper crate must export, in one place, for whoever writes it. */
export const WASM_EXPORTS = [
  'detect(bytes: Uint8Array): string',
  'parse(bytes: Uint8Array, format?: string, password?: string, keyFile?: Uint8Array): string',
  "exportEncrypted(format: 'kemlock-json' | 'bitwarden-json', itemsJson: string, password: string): Uint8Array",
] as const;
