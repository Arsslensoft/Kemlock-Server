// Import & export (canvas: ImportExport). Files are read and written in this browser: an imported
// file is parsed by the import worker (kemlock-import as WebAssembly), its items are sealed here and
// then synced; nothing of it is uploaded in the clear.
import { useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { readBytes } from '@/lib/files';
import { api, queryClient, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { PasswordInput } from '@/ui/PasswordInput';
import '@/styles/tools.css';
import { useVault, vaultKey } from '@/features/vault/hooks';
import { type VaultItem, vaultStore } from '@/features/vault/vault';
import { type ImportClient, importClient } from '@/import/client';
import {
  type DetectResult,
  type ExportFormat,
  type ImportBatch,
  type ImportErrorCode,
  type ImportFormat,
  ImportWorkerError,
} from '@/import/contract';
import { download, exportFilename, exportItemsOf, toCsv } from '@/import/exporter';
import { importItems } from '@/import/importItems';
import { type Conversion, batchToItems } from '@/import/toItems';

export type SourceId = 'auto' | ImportFormat;

export const SOURCES: Array<{ id: SourceId; label: MessageId }> = [
  { id: 'auto', label: 'ie.source.auto' },
  { id: 'bitwarden-json', label: 'ie.source.bitwarden-json' },
  { id: 'bitwarden-csv', label: 'ie.source.bitwarden-csv' },
  { id: 'one-password-pux', label: 'ie.source.one-password-pux' },
  { id: 'one-password-csv', label: 'ie.source.one-password-csv' },
  { id: 'kdbx', label: 'ie.source.kdbx' },
  { id: 'chrome-csv', label: 'ie.source.chrome-csv' },
  { id: 'firefox-csv', label: 'ie.source.firefox-csv' },
  { id: 'safari-csv', label: 'ie.source.safari-csv' },
  { id: 'last-pass-csv', label: 'ie.source.last-pass-csv' },
  { id: 'dashlane-zip', label: 'ie.source.dashlane-zip' },
  { id: 'nord-pass-csv', label: 'ie.source.nord-pass-csv' },
  { id: 'keeper-json', label: 'ie.source.keeper-json' },
  { id: 'proton-pass-json', label: 'ie.source.proton-pass-json' },
  { id: 'proton-pass-zip', label: 'ie.source.proton-pass-zip' },
  { id: 'proton-pass-pgp', label: 'ie.source.proton-pass-pgp' },
  { id: 'enpass-json', label: 'ie.source.enpass-json' },
  { id: 'robo-form-csv', label: 'ie.source.robo-form-csv' },
];

const ERROR_MESSAGES: Record<ImportErrorCode, MessageId> = {
  'too-large': 'ie.error.tooLarge',
  'limit-exceeded': 'ie.error.limit',
  unsupported: 'ie.error.unsupported',
  empty: 'ie.error.empty',
  malformed: 'ie.error.malformed',
  'password-required': 'ie.error.passwordRequired',
  'bad-password': 'ie.error.badPassword',
  'kdf-out-of-bounds': 'ie.error.kdf',
  'account-restricted': 'ie.error.accountRestricted',
  'unsupported-encryption': 'ie.error.encryption',
  unavailable: 'ie.error.unavailable',
  cancelled: 'ie.error.cancelled',
};

export function importErrorId(error: unknown): MessageId {
  if (error instanceof ImportWorkerError) return ERROR_MESSAGES[error.code];
  return describeError(error).id;
}

/** A place items can be imported into or exported from. */
export interface Scope {
  /** `me` or a space id. */
  id: string;
  label: string;
  /** `user:<uuid>` or `space:<uuid>`: the owner string items carry. */
  owner: string;
  count: number;
  /** A space whose policy turns exports off. */
  exportsOff?: boolean;
}

export interface ImportState {
  fileName?: string | undefined;
  detected?: DetectResult | undefined;
  /** The batch's counts, once the file is read. */
  preview?: { count: number; warnings: Conversion['warnings'] } | undefined;
  busy?: 'detecting' | 'reading' | 'importing' | undefined;
  progress?: { done: number; total: number } | undefined;
  imported?: number | undefined;
  error?: MessageId | undefined;
}

export interface ExportState {
  busy?: boolean | undefined;
  done?: string | undefined;
  error?: MessageId | undefined;
}

const EXPORT_FORMATS: Array<{ id: ExportFormat; title: MessageId; hint: MessageId }> = [
  { id: 'kemlock-json', title: 'ie.export.kemlock', hint: 'ie.export.kemlockHint' },
  { id: 'bitwarden-json', title: 'ie.export.bitwarden', hint: 'ie.export.bitwardenHint' },
  { id: 'csv', title: 'ie.export.csv', hint: 'ie.export.csvHint' },
];

export function ImportExportView({
  scopes,
  state,
  exportState,
  onFile,
  onRead,
  onImport,
  onExport,
}: {
  scopes: Scope[];
  state: ImportState;
  exportState: ExportState;
  onFile: (file: File, source: SourceId) => void;
  onRead: (options: { source: SourceId; password: string }) => void;
  onImport: (scopeId: string) => void;
  onExport: (options: { format: ExportFormat; scopeIds: string[]; password: string }) => void;
}) {
  const t = useT();
  const [source, setSource] = useState<SourceId>('auto');
  const [password, setPassword] = useState('');
  const [target, setTarget] = useState(scopes[0]?.id ?? 'me');
  const [format, setFormat] = useState<ExportFormat>('kemlock-json');
  const [included, setIncluded] = useState<string[]>(scopes.filter((s) => !s.exportsOff).map((s) => s.id));
  const [exportPassword, setExportPassword] = useState('');
  const exportReady =
    included.length > 0 && (format === 'csv' || exportPassword.length >= 8) && !exportState.busy;
  const preview = state.preview;
  const asked = state.detected?.encrypted === true;

  return (
    <>
      <div>
        <h1 className="page-title">{t('ie.title')}</h1>
        <p className="lede">{t('ie.lede')}</p>
      </div>

      <div className="two-col">
        <section className="card pad" aria-labelledby="h-imp">
          <h2 id="h-imp">{t('ie.import')}</h2>
          <div className="stack">
            <div className="field">
              <label htmlFor="i-from">{t('ie.from')}</label>
              <select id="i-from" value={source} onChange={(e) => setSource(e.target.value as SourceId)}>
                {SOURCES.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {t(entry.label)}
                  </option>
                ))}
              </select>
            </div>

            <label
              htmlFor="i-file"
              className="dropzone"
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => {
                event.preventDefault();
                const dropped = event.dataTransfer.files[0];
                if (dropped) onFile(dropped, source);
              }}
            >
              <Icon name="transfer" />
              <span>{t('ie.drop')}</span>
              <span className="hint">
                {state.fileName
                  ? state.detected
                    ? t('ie.detected', {
                        name: state.fileName,
                        format: t(`ie.source.${state.detected.format}` as MessageId),
                      })
                    : state.fileName
                  : t('ie.dropHint')}
              </span>
            </label>
            <input
              id="i-file"
              type="file"
              className="sr"
              onChange={(event) => {
                const chosen = event.target.files?.[0];
                if (chosen) onFile(chosen, source);
              }}
            />

            <div className="field">
              <label htmlFor="i-pw">{t('ie.password')}</label>
              <PasswordInput
                id="i-pw"
                autoComplete="off"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <span className="hint">{asked ? t('ie.passwordNeeded') : t('ie.passwordHint')}</span>
            </div>

            {state.error ? (
              <Notice tone="error" live>
                <p>{t(state.error)}</p>
              </Notice>
            ) : null}

            {preview ? (
              <div className="stack" role="status">
                <p>{t('ie.preview', { count: preview.count })}</p>
                {preview.warnings.map((warning) => (
                  <Notice tone="warn" key={warning.code}>
                    <p>{t(`ie.warning.${warning.code}` as MessageId, { count: warning.count })}</p>
                  </Notice>
                ))}
                <div className="field">
                  <label htmlFor="i-to">{t('ie.into')}</label>
                  <select id="i-to" value={target} onChange={(e) => setTarget(e.target.value)}>
                    {scopes.map((scope) => (
                      <option key={scope.id} value={scope.id}>
                        {scope.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            ) : null}

            {state.busy === 'importing' && state.progress ? (
              <p role="status" className="hint">
                {t('ie.progress', { done: state.progress.done, total: state.progress.total })}
              </p>
            ) : null}
            {state.imported !== undefined ? (
              <Notice>
                <p>{t('ie.imported', { count: state.imported })}</p>
              </Notice>
            ) : null}

            <div className="actions">
              {preview ? (
                <Button
                  variant="primary"
                  isDisabled={state.busy !== undefined || preview.count === 0 || state.imported !== undefined}
                  onPress={() => onImport(target)}
                >
                  {t('ie.importCount', { count: preview.count })}
                </Button>
              ) : (
                <Button
                  variant="primary"
                  isDisabled={state.busy !== undefined || state.detected === undefined}
                  onPress={() => onRead({ source, password })}
                >
                  {state.busy === 'reading' ? t('ie.reading') : t('ie.read')}
                </Button>
              )}
            </div>
          </div>
        </section>

        <section className="card pad" aria-labelledby="h-exp">
          <h2 id="h-exp">{t('ie.export')}</h2>
          <div className="stack">
            <fieldset className="pick">
              <legend className="sr">{t('ie.format')}</legend>
              {EXPORT_FORMATS.map((entry) => (
                <label className="pick-opt" key={entry.id}>
                  <input
                    type="radio"
                    name="fmt"
                    checked={format === entry.id}
                    onChange={() => setFormat(entry.id)}
                  />
                  <span>
                    <span>{t(entry.title)}</span>
                    <span className="hint">{t(entry.hint)}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            <fieldset className="pick">
              <legend>{t('ie.include')}</legend>
              {scopes.map((scope) => (
                <div className="check-row" key={scope.id}>
                  <input
                    id={`e-${scope.id}`}
                    type="checkbox"
                    checked={included.includes(scope.id) && !scope.exportsOff}
                    disabled={scope.exportsOff}
                    onChange={() =>
                      setIncluded(
                        included.includes(scope.id)
                          ? included.filter((id) => id !== scope.id)
                          : [...included, scope.id],
                      )
                    }
                  />
                  <label htmlFor={`e-${scope.id}`}>
                    {scope.exportsOff
                      ? t('ie.policyOff', { name: scope.label })
                      : t('ie.scopeCount', { name: scope.label, count: scope.count })}
                  </label>
                </div>
              ))}
            </fieldset>
            {format !== 'csv' ? (
              <div className="field">
                <label htmlFor="e-pw">{t('ie.newPassword')}</label>
                <PasswordInput
                  id="e-pw"
                  autoComplete="new-password"
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                />
                <span className="hint">{t('ie.newPasswordHint')}</span>
              </div>
            ) : (
              <Notice tone="warn">
                <p>{t('ie.csvWarning')}</p>
              </Notice>
            )}
            {exportState.error ? (
              <Notice tone="error" live>
                <p>{t(exportState.error)}</p>
              </Notice>
            ) : null}
            {exportState.done ? (
              <Notice>
                <p role="status">{t('ie.exported', { name: exportState.done })}</p>
              </Notice>
            ) : null}
            <div className="actions">
              <Button
                variant="primary"
                isDisabled={!exportReady}
                onPress={() => onExport({ format, scopeIds: included, password: exportPassword })}
              >
                {t('ie.exportButton')}
              </Button>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}

/** What the screen does with a client and a vault: kept apart from React so a test drives it. */
export interface ImportFlowDeps {
  client: ImportClient;
  items: () => VaultItem[];
  scopes: Scope[];
  importInto: (conversion: Conversion, owner: string, onProgress: (done: number, total: number) => void) => Promise<number>;
  now?: () => Date;
  /** Hands a file to the browser; a test passes its own. */
  save?: typeof download;
}

export function ImportExportScreen({ deps }: { deps: ImportFlowDeps }) {
  const [state, setState] = useState<ImportState>({});
  const [exportState, setExportState] = useState<ExportState>({});
  const [file, setFile] = useState<{ bytes: Uint8Array; detected: DetectResult } | undefined>(undefined);
  const [conversion, setConversion] = useState<Conversion | undefined>(undefined);

  async function onFile(chosen: File): Promise<void> {
    setConversion(undefined);
    setFile(undefined);
    setState({ fileName: chosen.name, busy: 'detecting' });
    try {
      const bytes = await readBytes(chosen);
      const detected = await deps.client.detect(bytes);
      setFile({ bytes, detected });
      setState({ fileName: chosen.name, detected });
    } catch (error) {
      setState({ fileName: chosen.name, error: importErrorId(error) });
    }
  }

  async function onRead(options: { source: SourceId; password: string }): Promise<void> {
    if (!file) return;
    setState((s) => ({ ...s, busy: 'reading', error: undefined }));
    try {
      const batch: ImportBatch = await deps.client.parse(file.bytes, {
        format: options.source === 'auto' ? file.detected.format : options.source,
        ...(options.password === '' ? {} : { password: options.password }),
      });
      const made = batchToItems(batch);
      setConversion(made);
      setState((s) => ({ ...s, busy: undefined, preview: { count: made.items.length, warnings: made.warnings } }));
    } catch (error) {
      setState((s) => ({ ...s, busy: undefined, error: importErrorId(error) }));
    }
  }

  async function onImport(scopeId: string): Promise<void> {
    const scope = deps.scopes.find((s) => s.id === scopeId);
    if (!conversion || !scope) return;
    setState((s) => ({ ...s, busy: 'importing', error: undefined, progress: { done: 0, total: conversion.items.length } }));
    try {
      const imported = await deps.importInto(conversion, scope.owner, (done, total) =>
        setState((s) => ({ ...s, progress: { done, total } })),
      );
      setState((s) => ({ ...s, busy: undefined, imported, progress: undefined }));
    } catch (error) {
      setState((s) => ({ ...s, busy: undefined, error: importErrorId(error), progress: undefined }));
    }
  }

  async function onExport(options: { format: ExportFormat; scopeIds: string[]; password: string }): Promise<void> {
    setExportState({ busy: true });
    try {
      const owners = new Set(
        deps.scopes.filter((s) => options.scopeIds.includes(s.id) && !s.exportsOff).map((s) => s.owner),
      );
      const now = (deps.now ?? (() => new Date()))();
      const items = deps.items().filter((item) => owners.has(item.owner));
      if (options.format === 'csv') {
        const { csv } = toCsv(items);
        const name = exportFilename('kemlock-export', 'csv', now);
        (deps.save ?? download)(csv, name, 'text/csv');
        setExportState({ done: name });
        return;
      }
      const result = await deps.client.exportEncrypted(
        options.format,
        exportItemsOf(items, owners),
        options.password,
      );
      (deps.save ?? download)(result.bytes, result.filename, result.mime);
      setExportState({ done: result.filename });
    } catch (error) {
      setExportState({ error: importErrorId(error) });
    }
  }

  return (
    <ImportExportView
      scopes={deps.scopes}
      state={state}
      exportState={exportState}
      onFile={(chosen) => void onFile(chosen)}
      onRead={(options) => void onRead(options)}
      onImport={(scopeId) => void onImport(scopeId)}
      onExport={(options) => void onExport(options)}
    />
  );
}

/**
 * Runs an import and publishes the vault however it ends: items saved before a failure are in the
 * store already, and would not be listed until the next sync if only a success published them.
 */
export async function importThenPublish(
  run: () => Promise<{ imported: number }>,
  publish: () => void,
): Promise<number> {
  try {
    return (await run()).imported;
  } finally {
    publish();
  }
}

export default function ImportExport() {
  const t = useT();
  const { active, isLoading } = useVault();
  if (isLoading) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  const owner = `user:${session.getState().userId ?? ''}`;
  const mine = active.filter((item) => item.owner === owner);
  const scopes: Scope[] = [{ id: 'me', label: t('ie.myVault'), owner, count: mine.length }];
  const deps: ImportFlowDeps = {
    client: importClient,
    items: () => active,
    scopes,
    importInto: (conversion, into, onProgress) =>
      importThenPublish(
        () => importItems({ api, crypto: vaultCrypto }, vaultStore, conversion.items, into, onProgress),
        () => queryClient.setQueryData(vaultKey, vaultStore.snapshot()),
      ),
  };
  return <ImportExportScreen deps={deps} />;
}
