import { Link, getRouteApi, useRouter } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';
import { createSecurityKeyStepApi } from '@/api/passkeys';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { useT } from '@/i18n';
import { thisDevice } from '@/lib/device';
import { AuthPage } from '@/ui/AuthPage';
import { PasswordForm } from './PasswordForm';
import { SecondStep } from './SecondStep';
import { afterSignIn } from './afterSignIn';
import { describeSignInError, secondStepIsOver } from './describeSignIn';
import { type SignInStatus, createSignIn } from './signIn';

const route = getRouteApi('/sign-in/password');
const securityKey = createSecurityKeyStepApi(api);

export default function Password() {
  const t = useT();
  const router = useRouter();
  const { email = '', next } = route.useSearch();
  const signIn = useMemo(
    () => createSignIn({ api, securityKey, crypto: vaultCrypto, session, device: thisDevice }),
    [],
  );
  useEffect(() => () => signIn.abandon(), [signIn]);
  const [step, setStep] = useState<'password' | 'code'>('password');
  // What the account asks for as its second step: a code, a security key, or either.
  const [methods, setMethods] = useState<string[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeSignInError>>();

  async function run(attempt: () => Promise<SignInStatus>) {
    setPending(true);
    setError(undefined);
    try {
      const result = await attempt();
      if (result.status === 'second-step') {
        setMethods(result.methods);
        setStep('code');
      } else await afterSignIn(router, result, next);
    } catch (caught) {
      const described = describeSignInError(caught);
      // A challenge that has expired or been used can't be retried: start again.
      if (step === 'code' && secondStepIsOver(caught, described)) setStep('password');
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
        <SecondStep
          methods={methods}
          source="password"
          pending={pending}
          error={error}
          onCode={(code) => void run(() => signIn.secondStep(code))}
          onSecurityKey={() => void run(() => signIn.securityKey())}
        />
      )}
    </AuthPage>
  );
}
