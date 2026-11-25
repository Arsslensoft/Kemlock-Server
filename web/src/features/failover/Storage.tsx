// "Where your vault is stored" (canvas: Failover): each vault's home and replicas in order, the
// changes waiting for a server that is down, and what each app is using right now.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import type { Placement, PlacementServer } from '@/api/placement';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import '@/styles/tools.css';
import { timeAgo } from '@/features/vault/kinds';
import { placementApi, placementQuery } from './queries';

function statusOf(server: PlacementServer): { label: MessageId; tone: 'on' | 'off' | 'idle' } {
  if (server.status === 'offline') return { label: 'failover.status.offline', tone: 'off' };
  if (server.status === 'unknown') return { label: 'failover.status.unknown', tone: 'idle' };
  if (server.status === 'degraded') return { label: 'failover.status.degraded', tone: 'off' };
  if (server.status === 'key-mismatch') return { label: 'failover.status.keyMismatch', tone: 'off' };
  return server.inUse
    ? { label: 'failover.status.inUse', tone: 'on' }
    : { label: 'failover.status.online', tone: 'idle' };
}

export function StorageView({
  placement,
  onCancelPending,
  onResume,
  cancelling,
  error,
}: {
  placement: Placement | null | undefined;
  onCancelPending: (vault: string, change: string) => void;
  /** Takes back a cancel for a server whose changes are being withheld. */
  onResume?: (vault: string, server: string) => void;
  cancelling?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
}) {
  const t = useT();
  return (
    <>
      <div>
        <h1 className="page-title">{t('failover.title')}</h1>
        <p className="lede">{t('failover.lede')}</p>
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      {!placement || placement.vaults.length === 0 ? (
        <section className="card pad">
          <h2>{t('failover.single.title')}</h2>
          <p>{t('failover.single.body')}</p>
        </section>
      ) : (
        <div className="two-col">
          <section id="where" className="card pad" aria-labelledby="h-where">
            <h2 id="h-where">{t('failover.where')}</h2>
            <p className="hint">{t('failover.whereBody')}</p>
            {placement.vaults.map((vault) => (
              <div key={vault.id}>
                <h3 className="group-title">{vault.name}</h3>
                <ol className="servers" aria-label={t('failover.serversOf', { name: vault.name })}>
                  {vault.servers.map((server, index) => {
                    const status = statusOf(server);
                    return (
                      <li key={server.id}>
                        <span
                          className={server.role === 'home' ? 'order home' : 'order'}
                          aria-label={server.role === 'home' ? t('failover.home') : t('failover.replica', { n: index })}
                        >
                          {server.role === 'home' ? 'H' : index}
                        </span>
                        <span className="grow">
                          <span>{server.name}</span>
                          <span className="hint">
                            {[server.place ?? '', server.role === 'home' ? '' : t('failover.replicaWord')]
                              .filter((part) => part !== '')
                              .join(' · ')}
                          </span>
                        </span>
                        <span className={`state ${status.tone}`}>
                          {t(status.label)}
                          {server.status === 'offline' && server.offlineSince
                            ? ` · ${timeAgo(server.offlineSince)}`
                            : ''}
                          {server.status === 'degraded' && server.lastSeen
                            ? ` · ${t('failover.lastSeen', { when: timeAgo(server.lastSeen) })}`
                            : ''}
                        </span>
                      </li>
                    );
                  })}
                </ol>
                {vault.pending ? (
                  <div className="waiting" role="group" aria-label={t('failover.waiting')}>
                    <strong>{t('failover.waiting')}</strong>
                    <span>
                      {vault.pending.summary}
                      {vault.pending.askedAt
                        ? ` ${t('failover.oldest', { when: timeAgo(vault.pending.askedAt) })}`
                        : ''}
                    </span>
                    <Button
                      size="small"
                      // Only a server that is down has changes queued for it that may be dropped.
                      isDisabled={cancelling || !vault.servers.some((server) => server.status === 'offline')}
                      onPress={() => onCancelPending(vault.id, vault.pending?.id ?? '')}
                    >
                      {t('failover.cancelChange')}
                    </Button>
                  </div>
                ) : null}
                {vault.servers
                  .filter((server) => server.withheld)
                  .map((server) => (
                    <div
                      key={server.id}
                      className="waiting"
                      role="group"
                      aria-label={t('failover.withheldFor', { name: server.name })}
                    >
                      <strong>{t('failover.withheldFor', { name: server.name })}</strong>
                      <span>{t('failover.withheldBody')}</span>
                      <Button size="small" isDisabled={cancelling} onPress={() => onResume?.(vault.id, server.id)}>
                        {t('failover.resume')}
                      </Button>
                    </div>
                  ))}
              </div>
            ))}
            <Link to="/security">{t('failover.seeSecurity')}</Link>
          </section>

          <section className="card pad" aria-labelledby="h-apps">
            <h2 id="h-apps">{t('failover.apps.title')}</h2>
            <p className="hint">{t('failover.apps.body')}</p>
            <ul className="apps">
              {placement.apps.map((app) => (
                <li key={app.name}>
                  <span>{app.name}</span>
                  <span className="hint">
                    {app.localCopy
                      ? t('failover.apps.local', { address: app.address ?? '' })
                      : app.since
                        ? t('failover.apps.since', { server: app.server, when: timeAgo(app.since) })
                        : app.server}
                  </span>
                </li>
              ))}
            </ul>
            <Link to="/devices">{t('failover.apps.all')}</Link>
          </section>
        </div>
      )}
    </>
  );
}

export default function Storage() {
  const t = useT();
  const client = useQueryClient();
  const { data, isLoading, error } = useQuery(placementQuery);
  const cancel = useMutation({
    mutationFn: ({ vault, change }: { vault: string; change: string }) =>
      placementApi.cancelPending(vault, change),
    onSuccess: () => client.invalidateQueries({ queryKey: placementQuery.queryKey }),
  });
  const resume = useMutation({
    mutationFn: ({ vault, server }: { vault: string; server: string }) =>
      placementApi.resumePending(vault, server),
    onSuccess: () => client.invalidateQueries({ queryKey: placementQuery.queryKey }),
  });
  if (isLoading) {
    return (
      <p className="empty" role="status">
        {t('state.loading')}
      </p>
    );
  }
  const failure = cancel.error ?? resume.error ?? error;
  return (
    <StorageView
      placement={data}
      cancelling={cancel.isPending || resume.isPending}
      error={failure ? describeError(failure) : undefined}
      onCancelPending={(vault, change) => cancel.mutate({ vault, change })}
      onResume={(vault, server) => resume.mutate({ vault, server })}
    />
  );
}
