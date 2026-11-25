import { useQuery } from '@tanstack/react-query';
import { configQuery, hostOf } from '@/app/services';
import type { AdminOverview } from '@/api/admin';
import type { ConfigResponse } from '@/api/types';
import { type MessageId, useT } from '@/i18n';
import { Icon, type IconName } from '@/ui/Icon';
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

/** One number of the Overview, with the icon of what it counts. */
export function StatCard({
  icon,
  value,
  label,
  hint,
}: {
  icon: IconName;
  value: string | number;
  label: string;
  hint?: string | undefined;
}) {
  return (
    <div className="stat">
      <span className="si" aria-hidden="true">
        <Icon name={icon} />
      </span>
      <b>{value}</b>
      <span>{label}</span>
      {hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

/**
 * What the server holds, in one row: users, devices, spaces, the last day's events and the
 * features it serves. Each has its icon. The version is in the page's subtitle, not a card.
 */
export function OverviewStats({
  config,
  overview,
}: {
  config: Pick<ConfigResponse, 'features'> | undefined;
  overview: AdminOverview | undefined;
}) {
  const t = useT();
  if (!config && !overview) return null;
  return (
    <div className="stats adm-stats">
      {overview ? (
        <>
          <StatCard
            icon="users"
            value={count(overview.users)}
            label={t('admin.stat.users')}
            hint={t('admin.stat.admins', { count: overview.admins })}
          />
          <StatCard icon="device" value={count(overview.devices)} label={t('admin.stat.devices')} />
          <StatCard
            icon="building"
            value={count(overview.spaces)}
            label={t('admin.stat.spaces')}
            hint={t('admin.stat.items', { count: overview.liveItems })}
          />
          <StatCard icon="list" value={count(overview.events24h)} label={t('admin.stat.events')} />
        </>
      ) : null}
      {config ? (
        <StatCard
          icon="sliders"
          value={config.features.length}
          label={t('admin.stat.features')}
          hint={config.features.join(', ')}
        />
      ) : null}
    </div>
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

      <OverviewStats config={config} overview={attention.data} />

      {/* Checks and the users to look at in the left column, the push relay beside them. */}
      <div className="adm-split">
        <div className="adm-col">
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
        </div>
        <PushRelayPanel />
      </div>
    </>
  );
}
