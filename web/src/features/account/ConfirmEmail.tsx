import { Link, getRouteApi } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';
import { isApiError } from '@/api/errors';
import { createProfileApi } from '@/api/profile';
import { signOut } from '@/app/actions';
import { api, session } from '@/app/services';
import { scrubAddress } from '@/features/invitations/linkParams';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { AuthPage } from '@/ui/AuthPage';
import { Button, buttonClass } from '@/ui/Button';
import { Notice } from '@/ui/Notice';

const route = getRouteApi('/confirm-email');
const profileApi = createProfileApi(api);

type Outcome =
  | { status: 'ready' }
  | { status: 'working' }
  | { status: 'done'; email: string }
  | { status: 'invalid' }
  | { status: 'taken' }
  | { status: 'failed'; message: ReturnType<typeof describeError> };

/**
 * Where the link mailed to a new address lands (`/confirm-email?token=…`). The token is the proof,
 * but it is spent only when the person presses the button: a mail scanner that opens the link and
 * runs its script must not change the address. The token is taken out of the address as the page
 * opens. The server ends every session of the account when the address changes, so this browser
 * forgets its own too, and the person signs in again with the new address.
 */
export default function ConfirmEmail() {
  const t = useT();
  // Held in the page's memory: the address is cleaned below, so a reload or the history has no token.
  const { token } = route.useSearch();
  const [held] = useState(token);
  const [outcome, setOutcome] = useState<Outcome>(held ? { status: 'ready' } : { status: 'invalid' });
  // A token works once: one trip to the server per page, whatever is pressed.
  const asked = useRef(false);

  useEffect(() => {
    if (window.location.search || window.location.hash) scrubAddress();
  }, []);

  function confirm() {
    if (!held || asked.current) return;
    asked.current = true;
    setOutcome({ status: 'working' });
    profileApi
      .confirmEmailChange(held)
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
  }

  return (
    <AuthPage>
      <div>
        <h1>{t('confirmEmail.title')}</h1>
      </div>
      {outcome.status === 'ready' || outcome.status === 'working' ? (
        <>
          <p>{t('confirmEmail.ask')}</p>
          <Button variant="primary" isDisabled={outcome.status === 'working'} onPress={confirm}>
            {t('confirmEmail.confirm')}
          </Button>
        </>
      ) : null}
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
          <p>{t(held ? 'confirmEmail.invalid' : 'confirmEmail.missing')}</p>
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
