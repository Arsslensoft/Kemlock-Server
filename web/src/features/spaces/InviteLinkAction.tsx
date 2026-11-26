import { useState } from 'react';
import { isApiError } from '@/api/errors';
import { type MessageId, useT } from '@/i18n';
import { copyText } from '@/lib/clipboard';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { describeAccountError } from '../account/errors';

type State =
  | { kind: 'idle' }
  | { kind: 'pending' }
  /** The link is on the clipboard. */
  | { kind: 'copied' }
  /** The browser refused the clipboard: the link is shown to copy by hand. */
  | { kind: 'manual'; link: string }
  | { kind: 'failed'; id: MessageId; values?: Record<string, string | number> | undefined };

/** What a refusal says: the server's three answers have words of their own. */
function describeLinkError(error: unknown): { id: MessageId; values?: Record<string, string | number> | undefined } {
  if (isApiError(error)) {
    if (error.status === 404) return { id: 'space.inviteLink.noInvitation' };
    if (error.status === 403) return { id: 'space.inviteLink.forbidden' };
    if (error.status === 409) return { id: 'space.inviteLink.accepted' };
  }
  return describeAccountError(error);
}

/**
 * "Copy invitation link", for an invited member of a Bitwarden organization, shown to its owners
 * and admins. The link accepts the invitation for the account whoever opens it, so it is fetched
 * only when asked for, copied as a secret, and never kept in the page once copied.
 */
export function InviteLinkAction({
  name,
  fetchLink,
}: {
  /** The member's name, for the button's label. */
  name: string;
  /** Asks the server for the link. */
  fetchLink: () => Promise<string>;
}) {
  const t = useT();
  const [state, setState] = useState<State>({ kind: 'idle' });

  async function copy(): Promise<void> {
    setState({ kind: 'pending' });
    try {
      const link = await fetchLink();
      const copied = await copyText(link, { secret: true });
      setState(copied ? { kind: 'copied' } : { kind: 'manual', link });
    } catch (error) {
      setState({ kind: 'failed', ...describeLinkError(error) });
    }
  }

  return (
    <>
      <Button
        size="small"
        aria-label={t('space.inviteLink.copyFor', { name })}
        isDisabled={state.kind === 'pending'}
        onPress={() => void copy()}
      >
        {t('space.inviteLink.copy')}
      </Button>
      {state.kind === 'copied' ? (
        <p className="hint" role="status">
          {t('space.inviteLink.copied')}
        </p>
      ) : null}
      {state.kind === 'manual' ? (
        <div role="status">
          <p className="hint">{t('space.inviteLink.manual')}</p>
          <div className="with-action">
            <span className="mono">{state.link}</span>
            <CopyButton value={state.link} label={t('space.inviteLink.copy')} secret />
          </div>
        </div>
      ) : null}
      {state.kind === 'failed' ? (
        <p className="hint" role="alert">
          {t(state.id, state.values)}
        </p>
      ) : null}
    </>
  );
}
