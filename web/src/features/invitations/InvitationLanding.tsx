import type { ReactNode } from 'react';
import { type MessageId, useT } from '@/i18n';
import { AuthPage } from '@/ui/AuthPage';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import type { Outcome } from './useAcceptOnce';

/** One line of who an invitation is from and to: a label and what the link says. */
export interface Fact {
  label: MessageId;
  value: string;
}

/**
 * What an invitation link's page says: who it is from, a button to accept, then working, done, or why
 * not. `done` is the sentence for success. Nothing is accepted until the button is pressed.
 */
export function InvitationLanding({
  title,
  done,
  outcome,
  facts,
  acceptLabel,
  onAccept,
}: {
  title: MessageId;
  done: ReactNode;
  outcome: Outcome;
  facts: Fact[];
  acceptLabel: MessageId;
  onAccept: () => void;
}) {
  const t = useT();
  return (
    <AuthPage>
      <div>
        <h1>{t(title)}</h1>
      </div>
      {outcome.status === 'ready' || outcome.status === 'working' ? (
        <>
          <dl>
            {facts.map((fact) => (
              <div key={fact.label}>
                <dt className="muted">{t(fact.label)}</dt>
                <dd>{fact.value}</dd>
              </div>
            ))}
          </dl>
          <p className="muted">{t('invitation.unchecked')}</p>
          <Button variant="primary" isDisabled={outcome.status === 'working'} onPress={onAccept}>
            {t(acceptLabel)}
          </Button>
        </>
      ) : null}
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
