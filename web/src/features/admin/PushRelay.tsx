// The push relay panel (`/admin/v1/push-relay`): whether this server has registered with Kemlock's
// push relay, so pushes to the mobile apps go out, with the relay's address and this server's id
// there. Turning it on registers the server; turning it off erases the installation at the relay
// and here. Both are writes, so both ask for a step-up check.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import type { PushRelay } from '@/api/admin';
import { isApiError } from '@/api/errors';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { useReauth } from './reauth';
import { ErrorNotice } from './ui';

export function PushRelayCard({
  relay,
  unavailable,
  busy,
  error,
  onEnable,
  onDisable,
}: {
  relay?: PushRelay | undefined;
  /** This server has no relay to turn on or off (the server answers 409). */
  unavailable?: boolean | undefined;
  busy?: boolean | undefined;
  error?: unknown;
  onEnable: () => void;
  onDisable: () => void;
}) {
  const t = useT();
  const [confirm, setConfirm] = useState(false);
  return (
    <section className="card" aria-labelledby="h-push">
      <div className="card-head">
        <h2 id="h-push">{t('admin.push.title')}</h2>
        {relay ? (
          <span className={relay.enabled ? 'tag ok' : 'tag mute'}>
            {relay.enabled ? t('admin.push.on') : t('admin.push.off')}
          </span>
        ) : null}
      </div>
      <div className="adm-pad stack">
        <p className="hint">{t('admin.push.lede')}</p>
        {unavailable ? (
          <p>{t('admin.push.unavailable')}</p>
        ) : relay ? (
          <>
            <dl className="kv">
              <div className="row">
                <dt className="grow">{t('admin.push.relay')}</dt>
                <dd className="mono">{relay.relayUrl}</dd>
              </div>
              {relay.enabled ? (
                <div className="row">
                  <dt className="grow">{t('admin.push.installation')}</dt>
                  <dd className="mono">{relay.installationId ?? '—'}</dd>
                </div>
              ) : null}
            </dl>
            <p className="hint">{relay.enabled ? t('admin.push.onBody') : t('admin.push.offBody')}</p>
            <div className="actions">
              {relay.enabled ? (
                <Button variant="danger" isDisabled={busy} onPress={() => setConfirm(true)}>
                  {t('admin.push.disable')}
                </Button>
              ) : (
                <Button variant="primary" isDisabled={busy} onPress={onEnable}>
                  {t('admin.push.enable')}
                </Button>
              )}
            </div>
          </>
        ) : (
          <p role="status">{t('state.loading')}</p>
        )}
        {error ? <ErrorNotice error={error} /> : null}
      </div>
      <ConfirmDialog
        isOpen={confirm}
        onOpenChange={setConfirm}
        title={t('admin.push.disable.title')}
        confirmLabel={t('admin.push.disable')}
        onConfirm={() => {
          setConfirm(false);
          onDisable();
        }}
      >
        <Notice tone="warn">
          <p>{t('admin.push.disable.body')}</p>
        </Notice>
      </ConfirmDialog>
    </section>
  );
}

export function PushRelayPanel() {
  const queryClient = useQueryClient();
  const { guard, dialog } = useReauth(admin);
  const relay = useQuery({
    queryKey: ['admin', 'push-relay'],
    queryFn: () => admin.pushRelay(),
    retry: false,
  });
  const done = (result: PushRelay) => queryClient.setQueryData(['admin', 'push-relay'], result);
  const enable = useMutation({
    mutationFn: () => guard((token) => admin.enablePushRelay(token)),
    onSuccess: done,
  });
  const disable = useMutation({
    mutationFn: () => guard((token) => admin.disablePushRelay(token)),
    onSuccess: done,
  });
  // A server with no relay answers 409: say so, instead of showing it as a failure.
  const unavailable = isApiError(relay.error) && relay.error.status === 409;
  return (
    <>
      <PushRelayCard
        relay={relay.data}
        unavailable={unavailable}
        busy={enable.isPending || disable.isPending}
        error={enable.error ?? disable.error ?? (unavailable ? undefined : relay.error)}
        onEnable={() => enable.mutate()}
        onDisable={() => disable.mutate()}
      />
      {dialog}
    </>
  );
}
