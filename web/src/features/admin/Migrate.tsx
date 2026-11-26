import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import type { MigrationStartRequest, MigrationStatus } from '@/api/admin';
import { configQuery, hostOf } from '@/app/services';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { relative } from './format';
import { useReauth } from './reauth';
import { ErrorNotice, Loading, PageHead, TextBox } from './ui';

const MAX_SOURCE_LENGTH = 1024;
/** A control character: C0, DEL and C1, as Rust's `char::is_control` counts them. */
const isControl = (c: string): boolean => c.charCodeAt(0) < 32 || (c.charCodeAt(0) >= 127 && c.charCodeAt(0) < 160);

/**
 * The error a typed source earns, or undefined. This is the server's own rule (plausible text:
 * not blank, at most 1024 characters, no control characters); whether the file exists in the
 * import folder is the server's to say. A database URL is never taken here, so it is told so before
 * anything is sent. An empty one has no error, it only keeps Check off.
 */
export function checkSource(value: string): MessageId | undefined {
  if (value.trim() === '') return undefined;
  if (value.includes('://')) return 'admin.migrate.error.url';
  return new TextEncoder().encode(value).length > MAX_SOURCE_LENGTH || [...value].some(isControl) ? 'admin.migrate.error.source' : undefined;
}

export type MigrateStep = 1 | 2 | 3 | 4;

/**
 * Where the person is: find the data, check it, copy it, switch the address. The server reads and
 * plans (step 2), copies in the background while it `running` (step 3) and says what it wrote when
 * it is `done` (step 4).
 */
export function stepOf(status: MigrationStatus | undefined): MigrateStep {
  switch (status?.state) {
    case 'planned':
      return 2;
    case 'running':
      return 3;
    case 'done':
      return 4;
    default:
      return 1;
  }
}

const STEPS: Array<[MigrateStep, MessageId]> = [
  [1, 'admin.migrate.step1'],
  [2, 'admin.migrate.step2'],
  [3, 'admin.migrate.step3'],
  [4, 'admin.migrate.step4'],
];

export interface MigrateViewProps {
  host: string;
  status?: MigrationStatus | undefined;
  starting?: boolean;
  error?: unknown;
  /** Reads the data and plans a move. */
  onStart: (request: MigrationStartRequest) => void;
  /** Seconds, for "read 3 minutes ago"; injectable for tests. */
  now?: number;
}

export function MigrateView({ host, status, starting, error, onStart, now }: MigrateViewProps) {
  const t = useT();
  const [from, setFrom] = useState(status?.source ?? '');
  const [files, setFiles] = useState('');
  const step = stepOf(status);
  const ready = from.trim() !== '' && checkSource(from) === undefined && checkSource(files) === undefined;
  return (
    <>
      <PageHead title={t('admin.migrate')} lede={t('admin.migrate.lede')} />
      <ol className="adm-steps" aria-label={t('admin.migrate.steps')}>
        {STEPS.map(([n, label]) => (
          <li key={n} aria-current={n === step ? 'step' : undefined}>
            <span className="b" aria-hidden="true">
              {n}
            </span>
            {t(label)}
          </li>
        ))}
      </ol>
      {error ? <ErrorNotice error={error} /> : null}
      {status?.state === 'failed' ? (
        <Notice tone="error" live>
          <p>
            {t('admin.migrate.failed', { error: status.error ?? '' })}
            {status.finishedAt !== null ? ` ${t('admin.migrate.failedAt', { when: relative(status.finishedAt, now) })}` : ''}
          </p>
        </Notice>
      ) : null}

      <div className="adm-split">
        <div className="adm-col">
          <section className="card" aria-labelledby="h-src">
            <div className="adm-head">
              <h2 id="h-src">{t('admin.migrate.source')}</h2>
            </div>
            <form
              className="adm-pad"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                if (!ready) return;
                const request: MigrationStartRequest = { from: from.trim() };
                if (files.trim() !== '') request.files = files.trim();
                onStart(request);
              }}
            >
              <TextBox
                label={t('admin.migrate.from')}
                mono
                value={from}
                onChange={setFrom}
                placeholder="db.sqlite3"
                hint={t('admin.migrate.pathHint')}
                error={checkSource(from)}
                required
              />
              <TextBox
                label={t('admin.migrate.files')}
                mono
                value={files}
                onChange={setFiles}
                placeholder="files"
                hint={t('admin.migrate.filesHint')}
                error={checkSource(files)}
              />
              <div className="actions">
                <Button type="submit" variant="primary" isDisabled={starting || !ready}>
                  {t('admin.migrate.check')}
                </Button>
              </div>
            </form>
          </section>

          {status?.state === 'running' ? (
            <section className="card" aria-labelledby="h-run">
              <div className="adm-head">
                <h2 id="h-run">{t('admin.migrate.running')}</h2>
                {status.at !== null ? (
                  <span className="hint">{t('admin.migrate.startedAt', { when: relative(status.at, now) })}</span>
                ) : null}
              </div>
              <div className="adm-pad" role="status">
                <p>{status.stage ?? t('admin.migrate.stageUnknown')}</p>
                <p className="mono">{status.source}</p>
                {status.plan ? <pre className="mono adm-plan">{status.plan}</pre> : null}
                <p className="hint">{t('admin.migrate.runningHint')}</p>
              </div>
            </section>
          ) : null}

          {status?.state === 'done' ? (
            <section className="card" aria-labelledby="h-done">
              <div className="adm-head">
                <h2 id="h-done">{t('admin.migrate.done')}</h2>
                {status.finishedAt !== null ? (
                  <span className="hint">{t('admin.migrate.finishedAt', { when: relative(status.finishedAt, now) })}</span>
                ) : null}
              </div>
              <div className="adm-pad">
                <p className="mono">{status.source}</p>
                <pre className="mono adm-plan">{status.report ?? ''}</pre>
                {status.plan ? (
                  <details>
                    <summary>{t('admin.migrate.planWas')}</summary>
                    <pre className="mono adm-plan">{status.plan}</pre>
                  </details>
                ) : null}
              </div>
            </section>
          ) : null}

          {status?.state === 'planned' ? (
            <section className="card" aria-labelledby="h-plan">
              <div className="adm-head">
                <h2 id="h-plan">{t('admin.migrate.plan')}</h2>
                {status.at !== null ? (
                  <span className="hint">{t('admin.migrate.read', { when: relative(status.at, now) })}</span>
                ) : null}
              </div>
              <div className="adm-pad">
                <p className="mono">{status.source}</p>
                <pre className="mono adm-plan">{status.plan ?? ''}</pre>
                {status.applies ? null : (
                  <Notice tone="info">
                    <p>{t('admin.migrate.readOnly')}</p>
                  </Notice>
                )}
              </div>
            </section>
          ) : null}
        </div>

        <div className="adm-col">
          <section className="card" aria-labelledby="h-switch">
            <div className="adm-head">
              <h2 id="h-switch">{t('admin.migrate.switch')}</h2>
            </div>
            <div className="adm-pad">
              <p>{t('admin.migrate.switchBody', { host })}</p>
              <p className="hint">{t('admin.migrate.switchBack')}</p>
            </div>
          </section>

          <section className="card" aria-labelledby="h-keep">
            <div className="adm-head">
              <h2 id="h-keep">{t('admin.migrate.keep')}</h2>
            </div>
            <p className="hint adm-pad">{t('admin.migrate.keepBody')}</p>
          </section>
        </div>
      </div>
    </>
  );
}

export default function Migrate() {
  const queryClient = useQueryClient();
  const { data: config } = useQuery(configQuery);
  const { guard, dialog } = useReauth(admin);
  const status = useQuery({
    queryKey: ['admin', 'migration'],
    queryFn: () => admin.migration(),
    // A move runs in the background on the server: follow it until it is done or has failed.
    refetchInterval: (query) => (query.state.data?.state === 'running' ? 3_000 : false),
  });
  const start = useMutation({
    mutationFn: (request: MigrationStartRequest) => guard((token) => admin.startMigration(request, token)),
    onSuccess: (result) => queryClient.setQueryData(['admin', 'migration'], result),
    // A failed read is recorded by the server too, so the status shows it.
    onError: () => queryClient.invalidateQueries({ queryKey: ['admin', 'migration'] }),
  });
  if (status.isPending) return <Loading />;
  return (
    <>
      <MigrateView
        host={hostOf(config?.domain)}
        status={status.data}
        starting={start.isPending}
        error={start.error ?? status.error}
        onStart={(request) => start.mutate(request)}
      />
      {dialog}
    </>
  );
}
