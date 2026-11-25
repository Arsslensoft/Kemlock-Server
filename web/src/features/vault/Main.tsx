import { isFavorite } from './favorite';
import { Link, getRouteApi, useNavigate } from '@tanstack/react-router';
import { useMemo } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, buttonClass } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { useVault } from './hooks';
import { hostOfUrl, kindIcon, kindLabel, tileLetter, timeAgo } from './kinds';
import { type VaultItem, itemName, loginOf } from './vault';

const route = getRouteApi('/_vault/vault');
const PAGE_SIZE = 25;

const FILTERS = [
  { kind: undefined, label: 'nav.all' },
  { kind: 'login', label: 'nav.logins' },
  { kind: 'note', label: 'nav.notes' },
] as const;

/** What the Details column shows: never a secret, only what helps tell two items apart. */
function details(item: VaultItem, openLabel: string, noteLabel: string, unreadable: string): string {
  if (!item.data) return unreadable;
  if (item.kind === 'login') {
    const { urls } = loginOf(item);
    return urls.map(hostOfUrl).join(', ');
  }
  if (item.kind === 'note') return noteLabel;
  return openLabel;
}

export function matches(item: VaultItem, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === '') return true;
  const { username, urls } = loginOf(item);
  return [itemName(item), username, ...urls, item.kind].some((field) =>
    field.toLowerCase().includes(needle),
  );
}

export default function Main() {
  const t = useT();
  const navigate = useNavigate();
  const { kind, q = '', page = 1, fav } = route.useSearch();
  const { active, isLoading, error, refetch } = useVault();

  const filtered = useMemo(
    () =>
      active
        .filter((item) => (kind ? item.kind === kind : true))
        .filter((item) => (fav ? isFavorite(item) : true))
        .filter((item) => matches(item, q))
        .sort((a, b) => itemName(a).localeCompare(itemName(b))),
    [active, kind, fav, q],
  );
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const shown = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  // Any kind gets its own heading and a pressed chip, not just logins and notes; an unknown kind
  // reads as "Item", the same as in the Kind column.
  const filters: readonly { kind: string | undefined; label: MessageId }[] =
    !kind || FILTERS.some((filter) => filter.kind === kind) ? FILTERS : [...FILTERS, { kind, label: kindLabel(kind) }];
  const title = t(filters.find((filter) => filter.kind === (kind || undefined))?.label ?? 'nav.all');

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{title}</h1>
          <p className="lede">{t('main.lede')}</p>
          <p className="hint">
            <Icon name="lock" /> {t('main.encrypted')}
          </p>
        </div>
      </div>

      <div className="chips" role="group" aria-label={t('main.kind')}>
        {filters.map((filter) => (
          <button
            key={filter.label}
            type="button"
            className="chip"
            aria-pressed={(kind || undefined) === filter.kind}
            onClick={() =>
              void navigate({ to: '/vault', search: { kind: filter.kind, q: q || undefined, fav } })
            }
          >
            {t(filter.label)}
          </button>
        ))}
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(describeError(error).id)}</p>
          <div>
            <Button size="small" onPress={() => void refetch()}>
              {t('action.retry')}
            </Button>
          </div>
        </Notice>
      ) : null}

      <div className="card">
        {isLoading ? (
          <p className="empty" role="status">
            {t('main.loading')}
          </p>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <h2>{active.length === 0 ? t('main.empty.title') : t('main.noMatch.title')}</h2>
            <p>{active.length === 0 ? t('main.empty.body') : t('main.noMatch.body')}</p>
            {active.length === 0 ? (
              <Link to="/vault/new" className={buttonClass({ variant: 'primary' })}>
                <Icon name="plus" />
                {t('action.newItem')}
              </Link>
            ) : null}
          </div>
        ) : (
          <>
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">{t('table.name')}</th>
                    <th scope="col">{t('table.kind')}</th>
                    <th scope="col">{t('table.details')}</th>
                    <th scope="col">{t('table.updated')}</th>
                    <th scope="col">
                      <span className="sr">{t('table.actions')}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((item) => {
                    const name = itemName(item);
                    const login = item.kind === 'login' ? loginOf(item) : undefined;
                    return (
                      <tr key={item.id}>
                        <td>
                          <Link to="/vault/$itemId" params={{ itemId: item.id }} className="name">
                            <span className="tile" aria-hidden="true">
                              {tileLetter(name)}
                            </span>
                            <span>
                              <span>{name}</span>
                              <span className="sub">{login?.username ?? ''}</span>
                            </span>
                          </Link>
                        </td>
                        <td>
                          <span className="kind">
                            <Icon name={kindIcon(item.kind)} />
                            {t(kindLabel(item.kind))}
                          </span>
                        </td>
                        <td>
                          {details(
                            item,
                            t('main.details.item'),
                            t('main.details.note'),
                            t('main.details.unreadable'),
                          )}
                        </td>
                        <td>{timeAgo(item.data?.updatedAt)}</td>
                        <td>
                          {login && login.password ? (
                            <CopyButton
                              value={login.password}
                              secret
                              label={t('main.copyPassword', { name })}
                            />
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="pager">
              <span>{t('main.showing', { shown: shown.length, total: filtered.length })}</span>
              <div className="btns">
                <Button
                  size="small"
                  isDisabled={current <= 1}
                  onPress={() =>
                    void navigate({ to: '/vault', search: { kind, q: q || undefined, fav, page: current - 1 } })
                  }
                >
                  {t('action.previous')}
                </Button>
                <Button
                  size="small"
                  isDisabled={current >= pages}
                  onPress={() =>
                    void navigate({ to: '/vault', search: { kind, q: q || undefined, fav, page: current + 1 } })
                  }
                >
                  {t('action.next')}
                </Button>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
