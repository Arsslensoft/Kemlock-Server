// Duplicates (canvas: Duplicates). Found in this browser from the opened vault; nothing is sent.
// Every item type is checked, each group says why it matched, and the chips and the Vault filter
// narrow the list. A group whose copies sit in two vaults lets the person pick which one keeps it.
import { Link } from '@tanstack/react-router';
import { type ReactNode, useEffect, useMemo, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/tools.css';
import '@/styles/lists.css';
import { useVault } from '@/features/vault/hooks';
import { detailParts } from '@/features/vault/itemDetails';
import { type KeyFacts, useKeyFacts } from '@/features/vault/keyFacts';
import { KIND_ORDER, kindLabel, kindPluralLabel, tileLetter, timeAgo } from '@/features/vault/kinds';
import { ALL_VAULTS, PERSONAL, inVault, knownVault, vaultIdOf } from '@/features/vault/listFilters';
import { VaultSelect } from '@/features/vault/VaultSelect';
import { useVaultFilter } from '@/features/vault/vaultFilter';
import { type Vaults, useVaults } from '@/features/vault/vaults';
import { type VaultItem, itemName, loginOf } from '@/features/vault/vault';
import { type WebsiteRule, ruleLabel } from '@/features/vault/websites';
import { type DuplicateGroup, SAME_LABEL, WHY_LABEL, findDuplicates } from './detect';
import { dismissedGroups } from './dismissed';
import {
  type MergePicks,
  allWebsites,
  defaultPicks,
  hasUnionMembers,
  keepInVault,
  planMerge,
  resultName,
  vaultsOf,
  websiteKey,
} from './merge';
import { type Merged, useMergeActions } from './useMerge';
import { type DuplicateFilter, duplicatesViewStore } from './viewState';

export type { DuplicateFilter } from './viewState';

const FILTERS: Array<{ id: DuplicateFilter; label: MessageId }> = [
  { id: 'all', label: 'dup.filter.all' },
  ...KIND_ORDER.map((kind) => ({ id: kind, label: kindPluralLabel(kind) })),
  { id: 'places', label: 'dup.filter.places' },
];

export function matchesFilter(group: DuplicateGroup, filter: DuplicateFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'places') return group.crossOwner;
  return group.kind === filter;
}

/** Whether a group has a copy in the vault the filter picks (`all` picks every group). */
export function groupInVault(group: DuplicateGroup, vault: string): boolean {
  return group.items.some((item) => inVault(item, vault));
}

/** Where an item lives, for a line about it: "Your vault", or the space's name. */
export function ownerName(owner: string, vaults: Vaults, mine: string): string {
  return vaultIdOf(owner) === PERSONAL ? mine : vaults.labelOf(owner);
}

export function groupTitle(group: DuplicateGroup): string {
  const first = group.items[0];
  if (!first) return '';
  const name = itemName(first);
  const user = first.kind === 'login' ? loginOf(first).username : '';
  return user === '' ? name : `${name} · ${user}`;
}

function PasswordMask({ password }: { password: string }) {
  return <span className="mono">{'•'.repeat(Math.min(Math.max(password.length, 6), 20))}</span>;
}

function Preview({
  group,
  vaults,
  onMerge,
  onDismiss,
  pending,
}: {
  group: DuplicateGroup;
  vaults: Vaults;
  onMerge: (picks: MergePicks) => void;
  onDismiss: () => void;
  pending?: boolean;
}) {
  const t = useT();
  const [picks, setPicks] = useState<MergePicks>(() => defaultPicks(group.items));
  const isLogin = group.kind === 'login';
  const sites = useMemo(() => allWebsites(group.items), [group.items]);
  const passwords = group.items.map((item) => ({ item, password: loginOf(item).password }));
  const passwordsDiffer = new Set(passwords.map((p) => p.password)).size > 1;
  const folders = group.items.map((item) => {
    const folder = item.data?.['folder'];
    return { item, folder: typeof folder === 'string' ? folder : '' };
  });
  const foldersDiffer = new Set(folders.map((f) => f.folder)).size > 1;
  const plan = planMerge(group.items, picks, new Date());
  const trashedNames = plan ? plan.trashed.map(itemName).join(', ') : '';
  const keptName = plan ? resultName(plan) || itemName(plan.kept) : '';
  const siteChecked = (rule: WebsiteRule) => picks.websites.includes(websiteKey(rule));
  const toggleSite = (rule: WebsiteRule) => {
    const key = websiteKey(rule);
    setPicks({
      ...picks,
      websites: picks.websites.includes(key)
        ? picks.websites.filter((k) => k !== key)
        : [...picks.websites, key],
    });
  };
  const radio = (
    name: string,
    value: string,
    checked: boolean,
    onPick: () => void,
    children: ReactNode,
  ) => (
    <label className="pick-opt" key={value}>
      <input type="radio" name={name} checked={checked} onChange={onPick} />
      <span>{children}</span>
    </label>
  );
  const gid = group.id;
  const mine = t('dup.owner.me');
  // Copies in two vaults: a login's "Keep" radios choose the item and so its vault; any other kind
  // picks the name on its own and where the kept item lives below it.
  const keepPicksItem = !group.crossOwner || isLogin;
  const groupVaults = vaultsOf(group.items);
  const vaultName = (vault: string) => {
    const item = group.items.find((candidate) => vaultIdOf(candidate.owner) === vault);
    return item ? ownerName(item.owner, vaults, mine) : vault;
  };
  const keptVault = plan ? vaultIdOf(plan.kept.owner) : '';
  return (
    <div className="stack">
      <p>{t(isLogin ? 'dup.preview.login' : 'dup.preview.other')}</p>

      <fieldset className="pick">
        <legend>{t(group.crossOwner && isLogin ? 'dup.pick.keep' : 'dup.pick.name')}</legend>
        {group.items.map((item) =>
          radio(
            `${gid}-name`,
            item.id,
            keepPicksItem ? picks.keepId === item.id : picks.nameFrom === item.id,
            () =>
              setPicks(
                keepPicksItem
                  ? { ...picks, keepId: item.id, nameFrom: item.id }
                  : { ...picks, nameFrom: item.id },
              ),
            <>
              <span>{itemName(item)}</span>
              <span className="hint">
                {group.crossOwner && isLogin ? `${ownerName(item.owner, vaults, mine)} · ` : ''}
                {timeAgo(item.data?.['updatedAt'])}
              </span>
            </>,
          ),
        )}
      </fieldset>

      {isLogin && passwordsDiffer ? (
        <fieldset className="pick">
          <legend>{t('dup.pick.password')}</legend>
          {passwords.map(({ item, password }) =>
            radio(
              `${gid}-password`,
              item.id,
              picks.passwordFrom === item.id,
              () => setPicks({ ...picks, passwordFrom: item.id }),
              <>
                <PasswordMask password={password} />
                <span className="hint">{t('dup.pick.from', { name: itemName(item) })}</span>
              </>,
            ),
          )}
        </fieldset>
      ) : (
        <div className="same">
          <span className="lbl">{t(SAME_LABEL[group.why])}</span>
          <span>{t('dup.pick.same')}</span>
        </div>
      )}

      {hasUnionMembers(group.items) ? (
        <div className="same">
          <span className="lbl">{t('dup.same.union')}</span>
          <span>{t('dup.same.unionValue')}</span>
        </div>
      ) : null}

      {isLogin && sites.length > 0 ? (
        <fieldset className="pick">
          <legend>{t('dup.pick.websites')}</legend>
          {sites.map((rule) => (
            <label className="pick-opt" key={websiteKey(rule)}>
              <input type="checkbox" checked={siteChecked(rule)} onChange={() => toggleSite(rule)} />
              <span className="mono">{rule.uri}</span>
              <span className="tag">{t(ruleLabel(rule.match))}</span>
            </label>
          ))}
        </fieldset>
      ) : null}

      {isLogin && foldersDiffer ? (
        <fieldset className="pick">
          <legend>{t('dup.pick.folder')}</legend>
          {folders.map(({ item, folder }) =>
            radio(
              `${gid}-folder`,
              item.id,
              picks.folderFrom === item.id,
              () => setPicks({ ...picks, folderFrom: item.id }),
              folder === '' ? t('dup.pick.noFolder') : folder,
            ),
          )}
        </fieldset>
      ) : null}

      {group.crossOwner && !isLogin ? (
        <fieldset className="pick">
          <legend>{t('dup.pick.keepIn')}</legend>
          {groupVaults.map((vault) =>
            radio(
              `${gid}-vault`,
              vault,
              keptVault === vault,
              () => setPicks(keepInVault(group.items, picks, vault)),
              vaultName(vault),
            ),
          )}
        </fieldset>
      ) : null}

      <p>{t('dup.preview.result', { name: keptName, trashed: trashedNames })}</p>
      <div className="actions">
        <Button variant="primary" isDisabled={pending || !plan} onPress={() => onMerge(picks)}>
          {t('dup.merge')}
        </Button>
        <Link to="/duplicates/$groupId" params={{ groupId: group.id }} className={buttonClass()}>
          {t('dup.chooseEvery')}
        </Link>
        <Button onPress={onDismiss}>{t('dup.notDuplicates')}</Button>
      </div>
    </div>
  );
}

export interface ToastState {
  id: MessageId;
  values: Record<string, string>;
  onUndo?: () => void;
}

export function DuplicatesView({
  groups,
  total,
  filter,
  onFilter,
  vault = ALL_VAULTS,
  onVault,
  vaults,
  facts,
  selectedId,
  onSelect,
  onMerge,
  onDismiss,
  onRecheck,
  toast,
  pending,
  error,
}: {
  groups: DuplicateGroup[];
  total: number;
  filter: DuplicateFilter;
  onFilter: (filter: DuplicateFilter) => void;
  /** The Vault filter: `all`, `personal` or a space's id. */
  vault?: string;
  onVault: (vault: string) => void;
  vaults: Vaults;
  /** The worked-out facts of key items, for their line in a group. */
  facts?: ReadonlyMap<string, KeyFacts> | undefined;
  selectedId: string | undefined;
  onSelect: (id: string) => void;
  onMerge: (group: DuplicateGroup, picks: MergePicks) => void;
  onDismiss: (group: DuplicateGroup) => void;
  onRecheck: () => void;
  toast?: ToastState | undefined;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
}) {
  const t = useT();
  const shown = groups.filter((group) => matchesFilter(group, filter) && groupInVault(group, vault));
  // With nothing picked, or the pick filtered away, the first group on show is the one reviewed.
  const selected = shown.find((group) => group.id === selectedId) ?? shown[0];
  const mine = t('dup.owner.me');
  const line = (item: VaultItem): string => {
    const detail = detailParts(item, facts?.get(item.id))
      .map((part) => ('text' in part ? part.text : t(part.id, part.values)))
      .join(' · ');
    return [ownerName(item.owner, vaults, mine), detail, timeAgo(item.data?.['updatedAt'])]
      .filter((part) => part !== '')
      .join(' · ');
  };
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t('dup.title')}</h1>
          <p className="lede">{t('dup.lede', { count: groups.length })}</p>
        </div>
        <Button size="small" onPress={onRecheck}>
          <Icon name="restore" />
          {t('dup.recheck')}
        </Button>
      </div>

      {toast ? (
        <div className="notice" role="status">
          <Icon name="check" />
          <p className="grow">{t(toast.id, toast.values)}</p>
          {toast.onUndo ? (
            <Button size="small" onPress={toast.onUndo}>
              {t('dup.undo')}
            </Button>
          ) : null}
        </div>
      ) : null}

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      <section className="card pad" aria-labelledby="h-how">
        <div className="how">
          <Icon name="shield" />
          <div className="stack">
            <h2 id="h-how">{t('dup.how.title')}</h2>
            <p>{t('dup.how.body')}</p>
            <p className="hint">{t('dup.how.checked', { count: total })}</p>
          </div>
        </div>
        <div className="switch-row">
          <input id="dup-server" className="sw" type="checkbox" role="switch" checked={false} disabled readOnly />
          <div>
            <label htmlFor="dup-server">{t('dup.server.label')}</label>
            <div className="hint">{t('dup.server.hint')}</div>
          </div>
        </div>
      </section>

      <VaultSelect value={vault} options={vaults.options} onChange={onVault} />

      <div className="chips" role="group" aria-label={t('dup.filter.label')}>
        {FILTERS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            className="chip"
            aria-pressed={filter === entry.id}
            onClick={() => onFilter(entry.id)}
          >
            {t(entry.label)}
          </button>
        ))}
      </div>

      <div className="two-col">
        <div className="stack">
          <h2 className="sr">{t('dup.groups')}</h2>
          {shown.length === 0 ? (
            <div className="card pad">{t(groups.length === 0 ? 'dup.none' : 'dup.noneHere')}</div>
          ) : (
            shown.map((group) => (
              <article
                key={group.id}
                className="card group"
                aria-current={group.id === selected?.id ? 'true' : undefined}
                aria-labelledby={`g-${group.id}`}
              >
                <div className="group-head">
                  <div>
                    <h3 id={`g-${group.id}`}>{groupTitle(group)}</h3>
                    <div className="hint">
                      {t('dup.group.count', { count: group.items.length, kind: t(kindLabel(group.kind)) })}
                    </div>
                  </div>
                  <span className="tag warn">{t(WHY_LABEL[group.why])}</span>
                </div>
                {group.items.map((item) => (
                  <div className="member" key={item.id}>
                    <span className="tile" aria-hidden="true">
                      {tileLetter(itemName(item))}
                    </span>
                    <div className="grow">
                      <Link to="/vault/$itemId" params={{ itemId: item.id }}>
                        {itemName(item)}
                      </Link>
                      <div className="hint">{line(item)}</div>
                    </div>
                    <span className="kind">{t(kindLabel(item.kind))}</span>
                  </div>
                ))}
                <div className="actions">
                  <Button size="small" onPress={() => onSelect(group.id)}>
                    {t('dup.review')}
                  </Button>
                  <Button size="small" onPress={() => onDismiss(group)}>
                    {t('dup.notDuplicates')}
                  </Button>
                </div>
              </article>
            ))
          )}
        </div>
        <section className="card pad" aria-labelledby="h-preview">
          <h2 id="h-preview">{t('dup.preview.title')}</h2>
          {selected ? (
            <Preview
              key={selected.id}
              group={selected}
              vaults={vaults}
              pending={pending}
              onMerge={(picks) => onMerge(selected, picks)}
              onDismiss={() => onDismiss(selected)}
            />
          ) : (
            <p>{t('dup.preview.none')}</p>
          )}
        </section>
      </div>
    </>
  );
}

export default function Duplicates() {
  const t = useT();
  const { active, isLoading, error, refetch } = useVault();
  const { merge, undo } = useMergeActions();
  const vaults = useVaults(active);
  const [chosen, setVault] = useVaultFilter('duplicates');
  const vault = knownVault(chosen, vaults.options);
  // The fingerprints of keys and certificates are worked out here, once per revision.
  const { facts, pending: readingKeys } = useKeyFacts(active);
  // Kept for the tab, so a trip into a group's merge screen and back finds the list as it was.
  const [{ filter, selectedId }, setView] = useState(() => duplicatesViewStore.load());
  const setFilter = (next: DuplicateFilter) => setView((view) => ({ ...view, filter: next }));
  const setSelectedId = (next: string | undefined) => setView((view) => ({ ...view, selectedId: next }));
  useEffect(() => {
    duplicatesViewStore.save({ filter, selectedId });
  }, [filter, selectedId]);
  const [toast, setToast] = useState<ToastState | undefined>(undefined);
  // The dismissed set lives outside React; this counter re-reads it.
  const [version, setVersion] = useState(0);
  const groups = useMemo(
    () => findDuplicates(active, facts).filter((group) => !dismissedGroups.has(group.id)),
    [active, facts, version],
  );
  if (isLoading || readingKeys) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  const failure = merge.error ?? undo.error ?? error;
  return (
    <DuplicatesView
      groups={groups}
      total={active.length}
      filter={filter}
      onFilter={setFilter}
      vault={vault}
      onVault={setVault}
      vaults={vaults}
      facts={facts}
      selectedId={selectedId}
      onSelect={setSelectedId}
      pending={merge.isPending || undo.isPending}
      error={failure ? describeError(failure) : undefined}
      toast={toast}
      onRecheck={() => {
        setToast(undefined);
        void refetch();
      }}
      onDismiss={(group) => {
        dismissedGroups.add(group.id);
        setVersion((n) => n + 1);
        setSelectedId(undefined);
        setToast({
          id: 'dup.toast.dismissed',
          values: { name: groupTitle(group) },
          onUndo: () => {
            dismissedGroups.remove(group.id);
            setToast(undefined);
            setVersion((n) => n + 1);
          },
        });
      }}
      onMerge={(group, picks) => {
        const plan = planMerge(group.items, picks, new Date());
        if (!plan) return;
        merge.mutate(plan, {
          onSuccess: (merged: Merged) => {
            setSelectedId(undefined);
            setToast({
              id: 'dup.toast.merged',
              values: { kept: resultName(plan) || itemName(plan.kept), trashed: plan.trashed.map(itemName).join(', ') },
              onUndo: () =>
                undo.mutate(merged, {
                  onSuccess: () => setToast(undefined),
                }),
            });
          },
        });
      }}
    />
  );
}
