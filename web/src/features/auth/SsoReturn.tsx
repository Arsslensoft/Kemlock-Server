import { Link, getRouteApi, useNavigate, useRouter } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { createDevicesApi } from '@/api/devices';
import { createKeysApi } from '@/api/keys';
import { createSecurityKeyStepApi } from '@/api/passkeys';
import { createSsoApi } from '@/api/sso';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { useT } from '@/i18n';
import { thisDevice } from '@/lib/device';
import { AuthPage } from '@/ui/AuthPage';
import { Notice } from '@/ui/Notice';
import { afterSignIn } from './afterSignIn';
import { describeSignInError } from './describeSignIn';
import { enrolNewAccountKeys } from './enrolKeys';
import { SecondStep } from './SecondStep';
import { type SsoDeps, type SsoOutcome, completeSso, secondSsoKeyStep, secondSsoStep } from './ssoFlow';
import { unlockWithTrustedDevice } from './trustedDevice';

const route = getRouteApi('/sign-in/sso');
const sso = createSsoApi(api);
const keys = createKeysApi(api);
const devices = createDevicesApi(api);
const securityKey = createSecurityKeyStepApi(api);

function deps(): SsoDeps {
  return { sso, api, securityKey, session, device: thisDevice, origin: location.origin };
}

/** A code is good once and React may run an effect twice: one trip to `finish` per code. */
const finishing = new Map<string, Promise<SsoOutcome>>();

/**
 * Where the provider sends the browser back to: the one-time code trades for tokens, then the
 * vault opens with no master password: a new account makes its keys here and keeps this browser's
 * copy of the root key; an account this browser already trusts opens with that copy; any other
 * browser asks an open device to approve it. SSO itself holds no vault key.
 */
export default function SsoReturn() {
  const t = useT();
  const navigate = useNavigate();
  const router = useRouter();
  const { code, state, error: refused } = route.useSearch();
  const [outcome, setOutcome] = useState<SsoOutcome | 'working' | 'refused'>(
    refused ? 'refused' : 'working',
  );
  const [error, setError] = useState<ReturnType<typeof describeSignInError>>();
  const [pending, setPending] = useState(false);

  async function proceed(result: SsoOutcome) {
    if (result.status === 'new-account') {
      // No keys yet: this device makes them, keeps its copy of the root key, and the vault opens.
      await enrolNewAccountKeys({ keys, crypto: vaultCrypto, session });
      await afterSignIn(router, { status: 'signed-in', admin: result.admin }, result.next);
    } else if (result.status === 'signed-in') {
      const opened = await unlockWithTrustedDevice({ devices, api, crypto: vaultCrypto, session });
      if (opened) {
        await afterSignIn(router, { status: 'signed-in', admin: result.admin }, result.next);
      } else {
        // Not a browser this account trusts: another open device approves it.
        await navigate({ to: '/sign-in/device', search: { email: result.email, next: result.next } });
      }
    } else {
      setOutcome(result);
    }
  }

  /** A second step, with a code or a key. A failure leaves the step open to try again. */
  function runStep(attempt: Promise<SsoOutcome>) {
    setPending(true);
    setError(undefined);
    attempt
      .then(proceed)
      .catch((caught: unknown) => setError(describeSignInError(caught)))
      .finally(() => setPending(false));
  }

  function fail(caught: unknown) {
    setError(describeSignInError(caught));
    setOutcome({ status: 'lost' });
  }

  useEffect(() => {
    if (refused) return;
    if (!code || !state) {
      setOutcome({ status: 'lost' });
      return;
    }
    let attempt = finishing.get(code);
    if (!attempt) {
      attempt = completeSso(deps(), { code, state });
      finishing.set(code, attempt);
    }
    attempt.then(proceed).catch(fail);
    // `proceed` and `fail` only read the router and state setters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code, state, refused]);

  const email = typeof outcome === 'object' && 'email' in outcome ? outcome.email : '';
  const second = typeof outcome === 'object' && outcome.status === 'second-step';

  return (
    <AuthPage>
      <div>
        <h1>{t(second ? 'sso.codeTitle' : 'sso.title')}</h1>
      </div>
      {outcome === 'working' || (typeof outcome === 'object' && outcome.status === 'new-account') ? (
        <p role="status" className="muted">
          {t('sso.working')}
        </p>
      ) : null}
      {outcome === 'refused' ? (
        <Notice tone="error" live>
          <p>{t('sso.refused')}</p>
        </Notice>
      ) : null}
      {typeof outcome === 'object' && outcome.status === 'lost' ? (
        <Notice tone="error" live>
          <p>{error ? t(error.id, error.values) : t('sso.lost')}</p>
        </Notice>
      ) : null}
      {typeof outcome === 'object' && outcome.status === 'second-step' ? (
        <SecondStep
          methods={outcome.methods}
          source="sso"
          pending={pending}
          error={error}
          onCode={(value) => void runStep(secondSsoStep(deps(), email, value))}
          onSecurityKey={() => void runStep(secondSsoKeyStep(deps(), email))}
        />
      ) : null}
      {outcome !== 'working' && !second && !(typeof outcome === 'object' && outcome.status === 'new-account') ? (
        <p className="hint">
          <Link to="/sign-in">{t('sso.back')}</Link>
        </p>
      ) : null}
    </AuthPage>
  );
}
