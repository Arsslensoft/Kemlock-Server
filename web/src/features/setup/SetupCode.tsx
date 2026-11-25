import { zodResolver } from '@hookform/resolvers/zod';
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { api } from '@/app/services';
import { type MessageId, useRich, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { type SetupCodeValues, normaliseSetupCode, setupCodeSchema } from '@/lib/schemas';
import { AuthPage } from '@/ui/AuthPage';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Field } from '@/ui/fields';
import { Notice } from '@/ui/Notice';
import { SetupSteps } from '@/ui/SetupSteps';
import { LOG_SOURCES } from './logSources';
import { setupMemory } from './memory';

/** The code box and Continue. Takes no router or network, so it is easy to test. */
export function SetupCodeForm({
  onSubmit,
  error,
  pending,
  secureContext,
}: {
  onSubmit: (code: string) => void;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
  pending?: boolean;
  /** False on plain HTTP away from localhost: setup is refused there. */
  secureContext: boolean;
}) {
  const t = useT();
  const { control, handleSubmit } = useForm<SetupCodeValues>({
    resolver: zodResolver(setupCodeSchema),
    defaultValues: { code: '' },
  });
  return (
    <form
      className="stack"
      noValidate
      onSubmit={handleSubmit((values) => onSubmit(normaliseSetupCode(values.code)))}
    >
      <Field
        control={control}
        name="code"
        label={t('setup.code.label')}
        hint={t('setup.code.hint')}
        code
        autoComplete="one-time-code"
        autoFocus
      />
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <Button type="submit" variant="primary" size="large" block isDisabled={pending || !secureContext}>
        {t('action.continue')}
      </Button>
    </form>
  );
}

function CommandLine({ command, label }: { command: string; label: string }) {
  return (
    <div className="cmd">
      {/* Focusable so the keyboard can scroll it when it overflows. */}
      <code tabIndex={0}>{command}</code>
      <CopyButton value={command} label={label} />
    </div>
  );
}

/** A collapsed panel: the sample log line, then one entry per way of running the server. */
export function WhereToFind() {
  const t = useT();
  return (
    <details className="where">
      <summary>{t('setup.code.find')}</summary>
      <div className="stack">
        <p className="pre">{t('setup.code.sample')}</p>
        <ul className="stack" aria-label={t('setup.code.elsewhere')}>
          {LOG_SOURCES.map((source) => {
            const target = t(source.target);
            return (
              <li key={source.id} className="stack">
                <b>{target}</b>
                {source.command ? (
                  <CommandLine command={source.command} label={t('setup.code.copyNamed', { target })} />
                ) : null}
                {source.alpine ? (
                  <>
                    <span className="hint">{t('setup.code.alpine')}</span>
                    <CommandLine command={source.alpine} label={t('setup.code.copyNamed', { target: `${target} (Alpine)` })} />
                  </>
                ) : null}
                {source.where ? <span>{t(source.where)}</span> : null}
              </li>
            );
          })}
        </ul>
      </div>
    </details>
  );
}

export default function SetupCode() {
  const t = useT();
  const rich = useRich();
  const navigate = useNavigate();
  const [error, setError] = useState<ReturnType<typeof describeError>>();
  const [pending, setPending] = useState(false);
  const secureContext = window.isSecureContext;

  async function verify(code: string) {
    setPending(true);
    setError(undefined);
    try {
      const { grant } = await api.setupVerify(code);
      setupMemory.set({ grant });
      await navigate({ to: '/setup/admin' });
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthPage badge="setup" width={560}>
      <SetupSteps current={1} />
      <div>
        <h1>{t('setup.code.title')}</h1>
        <p className="lede">{t('setup.code.lede')}</p>
      </div>

      {secureContext ? null : (
        <Notice tone="warn" live>
          <p>{rich('setup.code.insecure')}</p>
        </Notice>
      )}

      <WhereToFind />

      <SetupCodeForm
        onSubmit={(code) => void verify(code)}
        error={error}
        pending={pending}
        secureContext={secureContext}
      />

      <Notice icon="key">
        <p>{rich('setup.code.note1')}</p>
        <p>{rich('setup.code.note2')}</p>
      </Notice>
    </AuthPage>
  );
}
