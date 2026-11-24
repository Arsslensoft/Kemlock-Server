import { useQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { Radio, RadioGroup } from 'react-aria-components';
import { createPasskeysApi, createSecurityKeyApi } from '@/api/passkeys';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { useRich, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { PasskeyError, passkeysAvailable } from '@/lib/webauthn';
import { Button } from '@/ui/Button';
import { AuthPage } from '@/ui/AuthPage';
import { CodeForm } from '@/ui/CodeForm';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { QrCode } from '@/ui/QrCode';
import { SetupSteps } from '@/ui/SetupSteps';
import { setupMemory } from './memory';
import { confirmAuthenticatorApp, confirmSecurityKey } from './twoStepSetup';

const passkeysApi = createPasskeysApi(api);
const keysApi = createSecurityKeyApi(api);

/** The words for a passkey that was not made; anything else is described as everywhere else. */
function describePasskeyError(error: unknown): ReturnType<typeof describeError> {
  if (error instanceof PasskeyError) {
    return { id: error.reason === 'cancelled' ? 'security.passkeys.cancelled' : 'security.passkeys.unavailable' };
  }
  return describeError(error);
}

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
  const [way, setWay] = useState<TwoStepWay>('totp');
  const enrol = useQuery({
    queryKey: ['setup', 'totp-enrol'],
    queryFn: () => api.totpEnrol(),
    // Asking again would replace the secret the person just scanned.
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
    // A security key is the second step instead: an enrolled secret nobody scans would only get in the way.
    enabled: way === 'totp',
  });
  const [pending, setPending] = useState(false);
  const [warned, setWarned] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeError>>();

  const deps = {
    passkeys: { passkeys: passkeysApi, crypto: vaultCrypto },
    keys: { keys: keysApi },
    totpConfirm: (code: string) => api.totpConfirm(code),
    name: t('security.passkeys.defaultName'),
  };

  async function addKey() {
    setPending(true);
    setError(undefined);
    try {
      await confirmSecurityKey(deps);
      await navigate({ to: '/setup/server' });
    } catch (caught) {
      setError(describePasskeyError(caught));
    } finally {
      setPending(false);
    }
  }

  async function confirm(code: string) {
    setPending(true);
    setError(undefined);
    try {
      const { passkeyFailed } = await confirmAuthenticatorApp(deps, code);
      // Say so before moving on: the app is confirmed, but the passkey they ticked was not made.
      if (passkeyFailed) setWarned(true);
      else await navigate({ to: '/setup/server' });
    } catch (caught) {
      setError(describePasskeyError(caught));
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

      {way === 'totp' && enrol.isError ? (
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

      {warned ? (
        <>
          <Notice tone="error" live>
            <p>{t('setup.twoStep.passkeyFailed')}</p>
          </Notice>
          <Button variant="primary" size="large" block onPress={() => void navigate({ to: '/setup/server' })}>
            {t('action.continue')}
          </Button>
        </>
      ) : way === 'totp' ? (
        <>
          <p className="hint">{t('setup.twoStep.keepApp')}</p>
          <CodeForm
            label={t('setup.twoStep.codeLabel')}
            submitLabel={t('setup.twoStep.submit')}
            onSubmit={(code) => void confirm(code)}
            pending={pending || !enrol.data}
            error={error}
          />
        </>
      ) : (
        <section className="stack" aria-labelledby="h-key">
          <h2 id="h-key" className="sr">
            {t('setup.twoStep.key')}
          </h2>
          <p>{t('setup.twoStep.keyPrompt')}</p>
          {passkeysAvailable() ? null : (
            <Notice tone="error">
              <p>{t('security.passkeys.unavailable')}</p>
            </Notice>
          )}
          {error ? (
            <Notice tone="error" live>
              <p>{t(error.id, error.values)}</p>
            </Notice>
          ) : null}
          <Button
            variant="primary"
            size="large"
            block
            isDisabled={pending || !passkeysAvailable()}
            onPress={() => void addKey()}
          >
            {t('setup.twoStep.keyAdd')}
          </Button>
        </section>
      )}
    </AuthPage>
  );
}
