import type { ReactNode } from 'react';
import { type MessageId, useT } from '@/i18n';
import { AuthPage } from '@/ui/AuthPage';
import { Notice } from '@/ui/Notice';
import type { Outcome } from './useAcceptOnce';

/** What an invitation link's page says: working, done, or why not. `done` is the sentence for success. */
export function InvitationLanding({
  title,
  done,
  outcome,
}: {
  title: MessageId;
  done: ReactNode;
  outcome: Outcome;
}) {
  const t = useT();
  return (
    <AuthPage>
      <div>
        <h1>{t(title)}</h1>
      </div>
      {outcome.status === 'working' ? (
        <p role="status" className="muted">
          {t('invitation.working')}
        </p>
      ) : null}
      {outcome.status === 'done' ? (
        <Notice icon="check" live>
          <p>{done}</p>
        </Notice>
      ) : null}
      {outcome.status === 'incomplete' ? (
        <Notice tone="error" live>
          <p>{t('invitation.incomplete')}</p>
        </Notice>
      ) : null}
      {outcome.status === 'refused' ? (
        <Notice tone="error" live>
          <p>{t('invitation.refused')}</p>
          {outcome.message ? <p className="muted">{outcome.message}</p> : null}
        </Notice>
      ) : null}
    </AuthPage>
  );
}
