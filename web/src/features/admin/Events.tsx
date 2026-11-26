import { keepPreviousData, useInfiniteQuery, useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import type { AdminEvent, AdminUser, EventsQuery } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { eventText, format } from './eventText';
import { clock, day } from './format';
import { useReauth } from './reauth';
import { ErrorNotice, Loading, PageHead, SelectBox } from './ui';

export type When = '24h' | '7d' | '30d';
export type Kind = 'all' | 'auth' | 'item' | 'space' | 'send' | 'device' | 'account' | 'admin';

export interface EventFilters {
  kind: Kind;
  /** A user's id; empty for anyone. */
  user: string;
  when: When;
}

export const DEFAULT_FILTERS: EventFilters = { kind: 'all', user: '', when: '24h' };

const WINDOW_SECONDS: Record<When, number> = { '24h': 86_400, '7d': 7 * 86_400, '30d': 30 * 86_400 };

/** The oldest time a filter reaches back to, as Unix seconds. */
export function sinceFor(when: When, nowSeconds: number): number {
  return Math.floor(nowSeconds - WINDOW_SECONDS[when]);
}

/** The query a filter makes: a kind is the prefix of the action codes (`item.*`). */
export function queryFor(filters: EventFilters, nowSeconds: number): EventsQuery {
  const query: EventsQuery = { from: sinceFor(filters.when, nowSeconds) };
  if (filters.kind !== 'all') query.action = `${filters.kind}.*`;
  if (filters.user !== '') query.actor = filters.user;
  return query;
}

const KINDS: Array<[Kind, MessageId]> = [
  ['all', 'admin.events.kind.all'],
  ['auth', 'admin.events.kind.signIn'],
  ['item', 'admin.events.kind.item'],
  ['space', 'admin.events.kind.space'],
  ['send', 'admin.events.kind.send'],
  ['device', 'admin.events.kind.device'],
  ['account', 'admin.events.kind.account'],
  ['admin', 'admin.events.kind.admin'],
];

function Who({ event }: { event: AdminEvent }) {
  const t = useT();
  if (event.actorEmail) return <>{event.actorEmail}</>;
  if (event.actor) return <span className="mono">{event.actor.slice(0, 8)}</span>;
  return <>{t('admin.events.server')}</>;
}

export interface EventsViewProps {
  events: AdminEvent[];
  users: AdminUser[];
  filters: EventFilters;
  onFilters: (filters: EventFilters) => void;
  /** Asks the server for the CSV of the filtered log. */
  onExport: () => void;
  exporting?: boolean;
  /** The export stopped at the server's row limit. */
  truncated?: boolean;
  hasMore?: boolean;
  onMore?: () => void;
  error?: unknown;
}

export function EventsView({
  events,
  users,
  filters,
  onFilters,
  onExport,
  exporting,
  truncated,
  hasMore,
  onMore,
  error,
}: EventsViewProps) {
  const t = useT();
  return (
    <>
      <PageHead
        title={t('admin.events')}
        lede={t('admin.events.lede')}
        actions={
          <Button size="small" isDisabled={events.length === 0 || exporting} onPress={onExport}>
            {t('admin.events.export')}
          </Button>
        }
      />
      <div className="adm-cols">
        <SelectBox
          label={t('admin.events.filter.kind')}
          value={filters.kind}
          onChange={(value) => onFilters({ ...filters, kind: value as Kind })}
          options={KINDS.map(([value, label]) => ({ value, label: t(label) }))}
        />
        <SelectBox
          label={t('admin.events.filter.user')}
          value={filters.user}
          onChange={(value) => onFilters({ ...filters, user: value })}
          options={[
            { value: '', label: t('admin.events.anyone') },
            ...users.map((user) => ({ value: user.id, label: user.name ?? user.email })),
          ]}
        />
        <SelectBox
          label={t('admin.events.filter.when')}
          value={filters.when}
          onChange={(value) => onFilters({ ...filters, when: value as When })}
          options={[
            { value: '24h', label: t('admin.events.when.24h') },
            { value: '7d', label: t('admin.events.when.7d') },
            { value: '30d', label: t('admin.events.when.30d') },
          ]}
        />
      </div>
      {error ? <ErrorNotice error={error} /> : null}
      {truncated ? (
        <Notice tone="warn" live>
          <p>{t('admin.events.truncated')}</p>
        </Notice>
      ) : null}
      <div className="card">
        {events.length === 0 ? (
          <p className="empty">{t('admin.events.none')}</p>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th scope="col">{t('admin.events.col.time')}</th>
                  <th scope="col">{t('admin.events.col.event')}</th>
                  <th scope="col">{t('admin.events.col.by')}</th>
                  <th scope="col">{t('admin.events.col.from')}</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => {
                  const text = eventText(event);
                  return (
                    <tr key={event.id}>
                      <td className="mono hint">
                        <time dateTime={new Date(event.at * 1000).toISOString()}>
                          {day(event.at)} {clock(event.at)}
                        </time>
                      </td>
                      {/* The code stays a hover away, for matching rows to the CSV export. */}
                      <td title={event.action}>
                        {format(text.words, t)}
                        {text.target ? (
                          <>
                            {' '}
                            <span className="mono">{text.target}</span>
                          </>
                        ) : null}
                      </td>
                      <td>
                        <Who event={event} />
                      </td>
                      <td className="hint">{event.ip ?? ''}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {hasMore ? (
          <div className="adm-pad">
            <Button size="small" onPress={onMore}>
              {t('admin.events.more')}
            </Button>
          </div>
        ) : null}
      </div>
    </>
  );
}

/** Saves text as a file. */
function download(text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `kemlock-events-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default function Events() {
  const [filters, setFilters] = useState<EventFilters>(DEFAULT_FILTERS);
  const { guard, dialog } = useReauth(admin);
  const users = useQuery({ queryKey: ['admin', 'users', 'filter'], queryFn: () => admin.users({ limit: 100 }) });
  const events = useInfiniteQuery({
    queryKey: ['admin', 'events', filters],
    queryFn: ({ pageParam }) =>
      admin.events({ ...queryFor(filters, Date.now() / 1000), cursor: pageParam, limit: 100 }),
    initialPageParam: undefined as string | undefined,
    // Keep the list on screen while a changed filter loads, so the filters stay mounted.
    placeholderData: keepPreviousData,
    getNextPageParam: (last) => last.next ?? undefined,
  });
  // The server writes the CSV (up to 100,000 rows) and records the export, which is a write.
  const exportCsv = useMutation({
    mutationFn: async () => {
      const response = await guard((token) => admin.eventsCsv(queryFor(filters, Date.now() / 1000), token));
      download(await response.text());
      return response.headers.get('X-Export-Truncated') === 'true';
    },
  });
  if (events.isPending) return <Loading />;
  return (
    <>
      <EventsView
        events={(events.data?.pages ?? []).flatMap((page) => page.events)}
        users={users.data?.users ?? []}
        filters={filters}
        onFilters={setFilters}
        onExport={() => exportCsv.mutate()}
        exporting={exportCsv.isPending}
        truncated={exportCsv.data === true}
        hasMore={events.hasNextPage}
        onMore={() => void events.fetchNextPage()}
        error={events.error ?? users.error ?? exportCsv.error}
      />
      {dialog}
    </>
  );
}
