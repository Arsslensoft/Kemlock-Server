import { useQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { Radio, RadioGroup } from 'react-aria-components';
import { api, session } from '@/app/services';
import { useRich, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { AuthPage } from '@/ui/AuthPage';
import { CodeForm } from '@/ui/CodeForm';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { QrCode } from '@/ui/QrCode';
import { SetupSteps } from '@/ui/SetupSteps';
import { setupMemory } from './memory';

/** `KQ7M4XZP...` -> `KQ7M 4XZP ...`, which is easier to type from a screen. */
export function groupSecret(secret: string): string {
  return secret.replace(/\s+/g, '').replace(/(.{4})/g, '$1 ').trim();
}

export type TwoStepWay = 'totp' | 'key';

/** The two ways to a second step, as cards. Takes no router or network. */
export function TwoStepChoice({ value, onChange }: { value: TwoStepWay; onChange: (way: TwoStepWay) => void }) {
  const t = useT();
  return (
    <RadioGroup
      aria-label={t('setup.twoStep.way')}
      value={value}
      onChange={(way) => onChange(way as TwoStepWay)}
      className="opts"
    >
      <div className="grid">
        <Radio value="totp" className="opt">
          <span className="box">
            <Icon name="check" />
          </span>
          <span>
            <span className="t">{t('setup.twoStep.app')}</span>
            <span className="hint">{t('setup.twoStep.appHint')}</span>
          </span>
        </Radio>
        <Radio value="key" className="opt">
          <span className="box">
            <Icon name="check" />
          </span>
          <span>
            <span className="t">{t('setup.twoStep.key')}</span>
            <span className="hint">{t('setup.twoStep.keyHint')}</span>
          </span>
        </Radio>
      </div>
    </RadioGroup>
  );
}

export default function SetupTwoStep() {
  const t = useT();
  const rich = useRich();
  const navigate = useNavigate();
  const email = session.getState().email ?? setupMemory.get().adminEmail ?? '';
  const name = session.getState().name ?? setupMemory.get().adminName ?? email;
  const enrol = useQuery({
    queryKey: ['setup', 'totp-enrol'],
    queryFn: () => api.totpEnrol(),
    // Asking again would replace the secret the person just scanned.
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const [way, setWay] = useState<TwoStepWay>('totp');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeError>>();

  async function confirm(code: string) {
    setPending(true);
    setError(undefined);
    try {
      await api.totpConfirm(code);
      setupMemory.set({ twoStep: 'totp' });
      await navigate({ to: '/setup/server' });
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthPage badge="setup" width={600}>
      <SetupSteps current={2} />
      <p className="notice" role="status">
        <span className="tag ok" aria-hidden="true">
          1
        </span>
        <span>{rich('setup.twoStep.made', { name })}</span>
      </p>
      <div>
        <h1>{t('setup.twoStep.title')}</h1>
        <p className="lede">{t('setup.twoStep.lede')}</p>
      </div>

      <TwoStepChoice value={way} onChange={setWay} />

      {enrol.isError ? (
        <Notice tone="error" live>
          <p>{t(describeError(enrol.error).id)}</p>
        </Notice>
      ) : null}

      {way !== 'totp' ? null : enrol.data ? (
        <section className="scan" aria-labelledby="h-scan">
          <h2 id="h-scan" className="sr">
            {t('setup.twoStep.scanTitle')}
          </h2>
          <QrCode text={enrol.data.uri} label={t('setup.twoStep.qr', { host: window.location.host, email })} />
          <ol>
            <li>{rich('setup.twoStep.scan', { host: window.location.host, email })}</li>
            <li className="stack">
              {t('setup.twoStep.typeKey')}
              <span className="cmd">
                <code tabIndex={0}>{groupSecret(enrol.data.secret)}</code>
                <CopyButton value={enrol.data.secret} label={t('setup.twoStep.copyKey')} big />
              </span>
            </li>
            <li>{t('setup.twoStep.typeCode')}</li>
          </ol>
        </section>
      ) : (
        <p role="status" className="muted">
          {t('state.loading')}
        </p>
      )}

      <p className="hint">{t('setup.twoStep.keepApp')}</p>

      <CodeForm
        label={t('setup.twoStep.codeLabel')}
        submitLabel={t('setup.twoStep.submit')}
        onSubmit={(code) => void confirm(code)}
        pending={pending || !enrol.data}
        error={error}
      />
    </AuthPage>
  );
}
