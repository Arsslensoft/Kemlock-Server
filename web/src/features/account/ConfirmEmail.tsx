import { Link, getRouteApi } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { isApiError } from '@/api/errors';
import { createProfileApi } from '@/api/profile';
import { signOut } from '@/app/actions';
import { api, session } from '@/app/services';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { AuthPage } from '@/ui/AuthPage';
import { buttonClass } from '@/ui/Button';
import { Notice } from '@/ui/Notice';

const route = getRouteApi('/confirm-email');
const profileApi = createProfileApi(api);

type Outcome =
  | { status: 'working' }
  | { status: 'done'; email: string }
  | { status: 'invalid' }
  | { status: 'taken' }
  | { status: 'failed'; message: ReturnType<typeof describeError> };

/**
 * Where the link mailed to a new address lands (`/confirm-email?token=…`). The token is the proof,
 * so nothing is asked: the page spends it once and says what happened. The server ends every
 * session of the account when the address changes, so this browser forgets its own too, and the
 * person signs in again with the new address.
 */
export default function ConfirmEmail() {
  const t = useT();
  const { token } = route.useSearch();
  const [outcome, setOutcome] = useState<Outcome>(token ? { status: 'working' } : { status: 'invalid' });
  // A token works once, and React may run an effect twice: one trip to the server per page.
  const asked = useRef(false);

  useEffect(() => {
    if (!token || asked.current) return;
    asked.current = true;
    profileApi
      .confirmEmailChange(token)
      .then(async ({ email }) => {
        // Only a tab that still holds a session has anything to forget.
        if (session.getState().status !== 'signed-out') await signOut();
        setOutcome({ status: 'done', email });
      })
      .catch((error: unknown) => {
        if (isApiError(error, 'email-change-invalid')) setOutcome({ status: 'invalid' });
        else if (isApiError(error, 'email-taken')) setOutcome({ status: 'taken' });
        else setOutcome({ status: 'failed', message: describeError(error) });
      });
  }, [token]);

  return (
    <AuthPage>
      <div>
        <h1>{t('confirmEmail.title')}</h1>
      </div>
      {outcome.status === 'working' ? (
        <p role="status" className="muted">
          {t('confirmEmail.working')}
        </p>
      ) : null}
      {outcome.status === 'done' ? (
        <>
          <Notice icon="check" live>
            <p>{t('confirmEmail.done', { email: outcome.email })}</p>
          </Notice>
          <Link to="/sign-in" className={buttonClass({ variant: 'primary' })}>
            {t('confirmEmail.signIn')}
          </Link>
        </>
      ) : null}
      {outcome.status === 'invalid' ? (
        <Notice tone="error" live>
          <p>{t(token ? 'confirmEmail.invalid' : 'confirmEmail.missing')}</p>
        </Notice>
      ) : null}
      {outcome.status === 'taken' ? (
        <Notice tone="error" live>
          <p>{t('confirmEmail.taken')}</p>
        </Notice>
      ) : null}
      {outcome.status === 'failed' ? (
        <Notice tone="error" live>
          <p>{t(outcome.message.id, outcome.message.values)}</p>
        </Notice>
      ) : null}
    </AuthPage>
  );
}
