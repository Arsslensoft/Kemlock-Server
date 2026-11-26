// Main (canvas: Main, VaultTypes, VaultTypesFiltered): All items, and one page per item type at
// `/vault?kind=<kind id>` (`login`, `otp`, `backup-codes`…). The type chips are on All items only.
// The Vault filter (All vaults, Personal, a space) combines with the type.
import { Link, getRouteApi, useNavigate } from '@tanstack/react-router';
import { useCallback, useMemo } from 'react';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { LockBadge } from '@/ui/LockBadge';
import { Notice } from '@/ui/Notice';
import '@/styles/lists.css';
import { useVault } from './hooks';
import { ManifestNotice } from './ManifestNotice';
import { RowCopy } from './ItemCopy';
import { detailParts } from './itemDetails';
import { type KeyFacts, useKeyFacts } from './keyFacts';
import { kindSubtitle, listKind } from './kindList';
import { KIND_ORDER, kindIcon, kindLabel, kindPluralLabel, tileLetter, timeAgo } from './kinds';
import { ALL_VAULTS, filterItems, knownVault } from './listFilters';
import { VaultPill, VaultSelect } from './VaultSelect';
import { useVaultFilter } from './vaultFilter';
import { type VaultOption, type Vaults, useVaults } from './vaults';
import { type VaultItem, itemName } from './vault';

const route = getRouteApi('/_vault/vault');
const PAGE_SIZE = 25;

/** The gray line under a row's name: a username, an email address or a cardholder. Never a secret. */
function subline(item: VaultItem): string {
  const data = item.data;
  for (const key of ['username', 'email', 'cardholder']) {
    const value = data?.[key];
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
  }
  return '';
}

export interface ItemListProps {
  /** The stored kind id of the page, or undefined for All items. */
  kind: string | undefined;
  vault: string;
  onVault: (vault: string) => void;
  vaults: Vaults;
  /** This page's rows. */
  rows: VaultItem[];
  /** How many items match across every page. */
  total: number;
  /** Whether the vault holds any item at all, to tell an empty vault from an empty filter. */
  hasItems: boolean;
  page: number;
  pages: number;
  onKind: (kind: string | undefined) => void;
  onPage: (page: number) => void;
  facts: ReadonlyMap<string, KeyFacts>;
  isLoading?: boolean;
  error?: unknown;
  onRetry?: () => void;
}

function DetailsCell({ item, facts }: { item: VaultItem; facts: ReadonlyMap<string, KeyFacts> }) {
  const t = useT();
  if (!item.data) return <>{t('main.details.unreadable')}</>;
  const line = detailParts(item, facts.get(item.id))
    .map((part) => ('text' in part ? part.text : t(part.id, part.values)))
    .join(' · ');
  return <>{line}</>;
}

export function ItemListView({
  kind,
  vault,
  onVault,
  vaults,
  rows,
  total,
  hasItems,
  page,
  pages,
  onKind,
  onPage,
  facts,
  isLoading = false,
  error,
  onRetry,
}: ItemListProps) {
  const t = useT();
  const title = kind ? t(kindPluralLabel(kind)) : t('nav.all');
  const vaultName = vaults.options.find((option: VaultOption) => option.id === vault)?.label ?? '';
  const footer =
    vault === ALL_VAULTS
      ? t('main.showing', { shown: rows.length, total })
      : t('lists.showingIn', { shown: rows.length, total, vault: vaultName });

  return (
    <>
      <div className="page-head">
        <div>
          <div className="title-row">
            <h1 className="page-title">{title}</h1>
            <LockBadge body="lists.enc.body" />
          </div>
          <p className="subtitle">{t(kindSubtitle(kind))}</p>
        </div>
      </div>

      <VaultSelect value={vault} options={vaults.options} onChange={onVault} />

      {kind === undefined ? (
        <div className="chips" role="group" aria-label={t('lists.filter.type')}>
          <button type="button" className="chip" aria-pressed="true" onClick={() => onKind(undefined)}>
            {t('nav.all')}
          </button>
          {KIND_ORDER.map((id) => (
            <button key={id} type="button" className="chip" aria-pressed="false" onClick={() => onKind(id)}>
              {t(kindPluralLabel(id))}
            </button>
          ))}
        </div>
      ) : null}

      {error ? (
        <Notice tone="error" live>
          <p>{t(describeError(error).id)}</p>
          {onRetry ? (
            <div>
              <Button size="small" onPress={onRetry}>
                {t('action.retry')}
              </Button>
            </div>
          ) : null}
        </Notice>
      ) : null}

      <div className="card">
        {isLoading ? (
          <p className="empty" role="status">
            {t('main.loading')}
          </p>
        ) : total === 0 ? (
          <div className="empty">
            <h2>{hasItems ? t('main.noMatch.title') : t('main.empty.title')}</h2>
            <p>{hasItems ? t('main.noMatch.body') : t('main.empty.body')}</p>
            {hasItems ? null : (
              <Link to="/vault/new" className={buttonClass({ variant: 'primary' })}>
                <Icon name="plus" />
                {t('action.newItem')}
              </Link>
            )}
          </div>
        ) : (
          <>
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">{t('table.name')}</th>
                    <th scope="col">{t('lists.table.type')}</th>
                    <th scope="col">{t('lists.table.vault')}</th>
                    <th scope="col">{t('table.details')}</th>
                    <th scope="col">{t('table.updated')}</th>
                    <th scope="col">
                      <span className="sr">{t('table.actions')}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((item) => {
                    const name = itemName(item);
                    return (
                      <tr key={item.id}>
                        <td>
                          <Link to="/vault/$itemId" params={{ itemId: item.id }} className="name">
                            <span className="tile" aria-hidden="true">
                              {tileLetter(name)}
                            </span>
                            <span>
                              <span>{name}</span>
                              <span className="sub">{subline(item)}</span>
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
                          <VaultPill label={vaults.labelOf(item.owner)} />
                        </td>
                        <td className="details">
                          <DetailsCell item={item} facts={facts} />
                        </td>
                        <td className="when">{timeAgo(item.data?.updatedAt)}</td>
                        <td>
                          <RowCopy item={item} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="pager">
              <span>{footer}</span>
              <div className="btns">
                <Button size="small" isDisabled={page <= 1} onPress={() => onPage(page - 1)}>
                  {t('action.previous')}
                </Button>
                <Button size="small" isDisabled={page >= pages} onPress={() => onPage(page + 1)}>
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

export default function Main() {
  const navigate = useNavigate();
  const { kind: rawKind, q = '', page = 1, fav } = route.useSearch();
  const kind = listKind(rawKind);
  const { active, isLoading, error, refetch } = useVault();
  const vaults = useVaults(active);
  const [chosen, setVault] = useVaultFilter('items');
  const vault = knownVault(chosen, vaults.options);
  const { facts } = useKeyFacts(active);

  const t = useT();
  const typeNames = useCallback((id: string) => [t(kindLabel(id)), t(kindPluralLabel(id))], [t]);
  const filtered = useMemo(
    () => filterItems(active, { kind, vault, fav, q, typeNames }),
    [active, kind, vault, fav, q, typeNames],
  );
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const rows = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const search = { q: q || undefined, fav };

  return (
    <>
      <ManifestNotice />
      <ItemListView
        kind={kind}
        vault={vault}
        onVault={(next) => {
          setVault(next);
          // The new filter starts at the first page.
          if (current > 1) void navigate({ to: '/vault', search: { kind, ...search } });
        }}
        vaults={vaults}
        rows={rows}
        total={filtered.length}
        hasItems={active.length > 0}
        page={current}
        pages={pages}
        onKind={(next) => void navigate({ to: '/vault', search: { kind: next, ...search } })}
        onPage={(next) => void navigate({ to: '/vault', search: { kind, ...search, page: next } })}
        facts={facts}
        isLoading={isLoading}
        error={error}
        onRetry={() => void refetch()}
      />
    </>
  );
}
