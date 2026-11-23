import { useQuery } from '@tanstack/react-query';
import { configQuery, hostOf } from '@/app/services';
import type { AdminOverview } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Icon } from '@/ui/Icon';
import { admin } from './client';
import { count } from './format';
import { PushRelayPanel } from './PushRelay';
import '@/styles/admin.css';

export type AttentionKind = 'invited' | 'disabled' | 'overdue' | 'requests' | 'mail';

export interface Attention {
  kind: AttentionKind;
  count: number;
}

const ATTENTION: Record<AttentionKind, MessageId> = {
  invited: 'admin.attention.invited',
  disabled: 'admin.attention.disabled',
  overdue: 'admin.attention.overdue',
  requests: 'admin.attention.requests',
  mail: 'admin.attention.mail',
};

/** What needs a look, from the counts of `GET /admin/v1/overview`: nothing here names a person. */
export function attentionFrom(overview: AdminOverview): Attention[] {
  const items: Attention[] = [];
  if (overview.overdueRequests > 0) items.push({ kind: 'overdue', count: overview.overdueRequests });
  // An overdue request is open too: the open count names only the ones still within their time.
  const inTime = overview.openRequests - overview.overdueRequests;
  if (inTime > 0) items.push({ kind: 'requests', count: inTime });
  if (overview.pendingInvites > 0) items.push({ kind: 'invited', count: overview.pendingInvites });
  if (overview.disabledUsers > 0) items.push({ kind: 'disabled', count: overview.disabledUsers });
  if (!overview.mailConfigured) items.push({ kind: 'mail', count: 1 });
  return items;
}

export function AttentionCard({ items, unavailable }: { items: Attention[]; unavailable?: boolean }) {
  const t = useT();
  return (
    <section className="card" aria-labelledby="h-attention">
      <div className="card-head">
        <h2 id="h-attention">{t('admin.attention.title')}</h2>
      </div>
      {unavailable ? (
        <p className="empty">{t('admin.attention.unavailable')}</p>
      ) : items.length === 0 ? (
        <p className="empty">{t('admin.attention.none')}</p>
      ) : (
        items.map((item) => (
          <div className="row" key={item.kind}>
            <span className={item.kind === 'overdue' ? 'tag bad' : 'tag warn'}>{item.count}</span>
            <span className="grow">{t(ATTENTION[item.kind], { count: item.count })}</span>
          </div>
        ))
      )}
    </section>
  );
}

function Check({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  const t = useT();
  return (
    <div className="row">
      <span className={ok ? 'dot' : 'dot wn'} aria-hidden="true" />
      <span className="sr">{ok ? t('admin.check.ok') : t('admin.check.warn')}</span>
      <span className="grow">{label}</span>
      <span className="muted">{detail}</span>
    </div>
  );
}

export default function Overview() {
  const t = useT();
  const { data: config } = useQuery(configQuery);
  const attention = useQuery({ queryKey: ['admin', 'overview'], queryFn: () => admin.overview(), retry: false });
  return (
    <>
      <div>
        <h1 className="page-title">{t('admin.overview')}</h1>
        <p className="lede">
          {config ? t('admin.overview.lede', { version: config.version }) : t('state.loading')}
        </p>
        <p className="hint">
          <Icon name="lock" /> {t('admin.overview.noAccess')}
        </p>
      </div>

      {config ? (
        <div className="stats">
          <div className="stat">
            <b>{config.version}</b>
            <span>{t('admin.stat.version')}</span>
            <span className="hint">{config.apiVersions.join(', ')}</span>
          </div>
          <div className="stat">
            <b>{config.setup === 'complete' ? t('admin.stat.ready') : t('admin.stat.unfinished')}</b>
            <span>{t('admin.stat.setup')}</span>
            <span className="hint">{config.signupsAllowed ? t('admin.stat.signupsOpen') : t('admin.stat.signupsClosed')}</span>
          </div>
          <div className="stat">
            <b>{config.features.length}</b>
            <span>{t('admin.stat.features')}</span>
            <span className="hint">{config.features.join(', ')}</span>
          </div>
        </div>
      ) : null}

      {attention.data ? (
        <div className="stats">
          <div className="stat">
            <b>{count(attention.data.users)}</b>
            <span>{t('admin.stat.users')}</span>
            <span className="hint">{t('admin.stat.admins', { count: attention.data.admins })}</span>
          </div>
          <div className="stat">
            <b>{count(attention.data.devices)}</b>
            <span>{t('admin.stat.devices')}</span>
          </div>
          <div className="stat">
            <b>{count(attention.data.spaces)}</b>
            <span>{t('admin.stat.spaces')}</span>
            <span className="hint">{t('admin.stat.items', { count: attention.data.liveItems })}</span>
          </div>
          <div className="stat">
            <b>{count(attention.data.events24h)}</b>
            <span>{t('admin.stat.events')}</span>
          </div>
        </div>
      ) : null}

      <section className="card" aria-labelledby="h-checks">
        <div className="card-head">
          <h2 id="h-checks">{t('admin.checks')}</h2>
        </div>
        <Check
          ok={config?.setup === 'complete'}
          label={t('admin.check.setup')}
          detail={config?.setup ?? '—'}
        />
        <Check
          ok={window.isSecureContext}
          label={t('admin.check.secure')}
          detail={window.isSecureContext ? t('admin.check.secureYes') : t('admin.check.secureNo')}
        />
        <Check
          ok={config ? hostOf(config.domain) === window.location.host : false}
          label={t('admin.check.domain')}
          detail={config?.domain ?? '—'}
        />
      </section>

      <AttentionCard items={attention.data ? attentionFrom(attention.data) : []} unavailable={attention.isError} />

      <PushRelayPanel />
    </>
  );
}
