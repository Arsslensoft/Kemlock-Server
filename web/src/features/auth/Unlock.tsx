import { Link, getRouteApi, useNavigate, useRouter } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';
import { signOut } from '@/app/actions';
import { api, session } from '@/app/services';
import { useSessionState } from '@/app/session';
import { vaultCrypto } from '@/crypto-port';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { thisDevice } from '@/lib/device';
import { AuthPage } from '@/ui/AuthPage';
import { CodeForm } from '@/ui/CodeForm';
import { Icon, type IconName } from '@/ui/Icon';
import { afterSignIn } from './afterSignIn';
import { PasswordForm } from './PasswordForm';
import { type SignInStatus, createSignIn } from './signIn';

const route = getRouteApi('/unlock');

/** One of the other ways to open the vault; with no `onPress` it is drawn but off. */
export function Way({
  icon,
  title,
  hint,
  onPress,
}: {
  icon: IconName;
  title: string;
  hint: string;
  onPress?: () => void;
}) {
  return (
    <button type="button" className="way" disabled={!onPress} onClick={onPress}>
      <span className="ic" aria-hidden="true">
        <Icon name={icon} />
      </span>
      <span>
        <span className="t">{title}</span>
        <span className="d">{hint}</span>
      </span>
    </button>
  );
}

/**
 * The keys are gone (a lock, or this tab was reloaded with tokens kept) but the account is still
 * known: the master password opens the vault again by signing in once more, because OPAQUE's
 * export key only comes out of a sign-in.
 */
export default function Unlock() {
  const t = useT();
  const router = useRouter();
  const navigate = useNavigate();
  const { next } = route.useSearch();
  const state = useSessionState(session);
  const email = state.email ?? '';
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
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthPage width={560}>
      <div>
        <h1>{t('unlock.title')}</h1>
        <p className="lede">{t('unlock.lede', { email })}</p>
      </div>
      {step === 'password' ? (
        <section className="stack" aria-labelledby="h-pw">
          <h2 id="h-pw">{t('unlock.password')}</h2>
          <PasswordForm
            submitLabel={t('unlock.submit')}
            pending={pending}
            error={error}
            onSubmit={(password) => void run(() => signIn.password(email, password))}
          />
        </section>
      ) : (
        <CodeForm
          label={t('password.codeLabel')}
          submitLabel={t('password.codeSubmit')}
          pending={pending}
          error={error}
          onSubmit={(code) => void run(() => signIn.secondStep(code))}
        />
      )}
      <div className="stack">
        <h2 className="hint">{t('unlock.other')}</h2>
        <Way
          icon="device"
          title={t('unlock.approve')}
          hint={t('unlock.approveHint')}
          onPress={() => void navigate({ to: '/sign-in/device', search: { email, next } })}
        />
        <Way icon="key" title={t('unlock.kit')} hint={t('unlock.kitHint')} />
      </div>
      <p className="hint">
        <Link
          to="/sign-in"
          onClick={(event) => {
            event.preventDefault();
            void signOut().then(() => navigate({ to: '/sign-in' }));
          }}
        >
          {t('unlock.notYou')}
        </Link>
      </p>
    </AuthPage>
  );
}
