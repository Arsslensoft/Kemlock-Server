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
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { SetupSteps } from '@/ui/SetupSteps';
import { setupMemory } from './memory';

const LOG_COMMAND = 'docker logs kemlock | grep "setup code"';

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
    <AuthPage
      badge="setup"
      width={560}
      footnote={
        <p className="footnote">
          <Icon name="lock" />
          <span>{rich('setup.code.https')}</span>
        </p>
      }
    >
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

      <section className="stack" aria-labelledby="h-find">
        <h2 id="h-find">
          {t('setup.code.find')}
        </h2>
        <div className="cmd">
          {/* Focusable so the keyboard can scroll it when it overflows. */}
          <code tabIndex={0}>{LOG_COMMAND}</code>
          <CopyButton value={LOG_COMMAND} label={t('setup.code.copyCommand')} big />
        </div>
        <p className="pre">{t('setup.code.sample')}</p>
        <ul className="stack" aria-label={t('setup.code.elsewhere')}>
          <li>
            <b>Unraid</b> {t('setup.code.unraid')}
          </li>
          <li>
            <b>TrueNAS</b> {t('setup.code.truenas')}
          </li>
          <li>
            <b>Compose</b> <span className="mono">docker compose logs kemlock</span>
          </li>
        </ul>
      </section>

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
