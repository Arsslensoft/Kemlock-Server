import { Link, getRouteApi, useRouter } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { thisDevice } from '@/lib/device';
import { AuthPage } from '@/ui/AuthPage';
import { CodeForm } from '@/ui/CodeForm';
import { Notice } from '@/ui/Notice';
import { PasswordForm } from './PasswordForm';
import { afterSignIn } from './afterSignIn';
import { type SignInStatus, createSignIn } from './signIn';

const route = getRouteApi('/sign-in/password');

export default function Password() {
  const t = useT();
  const router = useRouter();
  const { email = '', next } = route.useSearch();
  const signIn = useMemo(
    () => createSignIn({ api, crypto: vaultCrypto, session, device: thisDevice }),
    [],
  );
  useEffect(() => () => signIn.abandon(), [signIn]);
  const [step, setStep] = useState<'password' | 'code'>('password');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeError>>();

  async function run(attempt: () => Promise<SignInStatus>) {
    setPending(true);
    setError(undefined);
    try {
      const result = await attempt();
      if (result.status === 'second-step') setStep('code');
      else await afterSignIn(router, result, next);
    } catch (caught) {
      const described = describeError(caught);
      // A challenge that has expired or been used can't be retried: start again.
      if (step === 'code' && described.id === 'error.credentials') setStep('password');
      setError(described);
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthPage>
      <div>
        <h1>{t(step === 'password' ? 'password.title' : 'password.codeTitle')}</h1>
        <p className="lede">
          {email} <Link to="/sign-in">{t('password.notYou')}</Link>
        </p>
      </div>
      {step === 'password' ? (
        <>
          <PasswordForm
            submitLabel={t('password.submit')}
            pending={pending}
            error={error}
            onSubmit={(password) => void run(() => signIn.password(email, password))}
          />
          <p className="hint">{t('password.note')}</p>
          <p className="hint">
            <Link to="/sign-in/device" search={{ email, next }}>
              {t('signIn.approve')}
            </Link>
          </p>
        </>
      ) : (
        <>
          <Notice icon="shield">
            <p>{t('password.codeNote')}</p>
          </Notice>
          <CodeForm
            label={t('password.codeLabel')}
            submitLabel={t('password.codeSubmit')}
            pending={pending}
            error={error}
            onSubmit={(code) => void run(() => signIn.secondStep(code))}
          />
        </>
      )}
    </AuthPage>
  );
}
