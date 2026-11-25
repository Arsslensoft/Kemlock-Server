// DuplicateMerge (canvas): choose every field of the kept item. Nothing is lost: the password
// that isn't kept goes into its history, the linked items and custom fields of every item join the
// kept one's, and the other items wait in the Trash for 30 days.
import { Link, useNavigate, useParams } from '@tanstack/react-router';
import { type ReactNode, useMemo, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/tools.css';
import { useVault } from '@/features/vault/hooks';
import { useKeyFacts } from '@/features/vault/keyFacts';
import { tileLetter, timeAgo } from '@/features/vault/kinds';
import { type Vaults, useVaults } from '@/features/vault/vaults';
import { type VaultItem, itemName, loginOf } from '@/features/vault/vault';
import { readWebsites, ruleLabel } from '@/features/vault/websites';
import { type DuplicateGroup, SAME_LABEL, WHY_LABEL, findDuplicates } from './detect';
import { dismissedGroups } from './dismissed';
import { ownerName } from './Duplicates';
import {
  type MergePicks,
  defaultPicks,
  hasUnionMembers,
  passkeyId,
  passkeysOf,
  planMerge,
  websiteKey,
} from './merge';
import { type Merged, useMergeActions } from './useMerge';

function note(item: VaultItem): string {
  const value = item.data?.['notes'];
  return typeof value === 'string' ? value : '';
}

function folder(item: VaultItem): string {
  const value = item.data?.['folder'];
  return typeof value === 'string' ? value : '';
}

export function MergeView({
  group,
  vaults,
  onMerge,
  onDismiss,
  onCancel,
  pending,
  error,
  done,
}: {
  group: DuplicateGroup;
  vaults: Vaults;
  onMerge: (picks: MergePicks) => void;
  onDismiss: () => void;
  onCancel: () => void;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
  /** Set once the merge was written: the page offers Undo. */
  done?: { kept: string; trashed: string; onUndo: () => void } | undefined;
}) {
  const t = useT();
  const [picks, setPicks] = useState<MergePicks>(() => defaultPicks(group.items));
  const items = group.items;
  const isLogin = group.kind === 'login';
  const mine = t('dup.owner.me');
  // Copies in two vaults: a login's name pick also picks the item that stays; any other kind picks
  // the name on its own and the vault the kept item stays in on a row of its own.
  const namePicksItem = !group.crossOwner || isLogin;
  const plan = planMerge(items, picks, new Date());
  const keptSites = plan ? readWebsites({ uris: plan.fields['uris'] as unknown }) : [];
  const nameField: unknown = plan?.fields['name'];
  const folderField: unknown = plan?.fields['folder'];
  const keptName = typeof nameField === 'string' ? nameField : plan ? itemName(plan.kept) : '';
  const keptFolder = typeof folderField === 'string' ? folderField : '';

  const sameUsername = new Set(items.map((item) => loginOf(item).username)).size === 1;
  const passkeyOwner = new Map<string, string>();
  for (const item of items) {
    for (const passkey of passkeysOf(item)) {
      const id = passkeyId(passkey);
      if (!passkeyOwner.has(id)) passkeyOwner.set(id, item.id);
    }
  }
  const siteOwner = new Map<string, string>();
  for (const item of items) {
    for (const rule of readWebsites(item.data)) {
      const key = websiteKey(rule);
      if (!siteOwner.has(key)) siteOwner.set(key, item.id);
    }
  }
  const toggle = (list: string[], key: string): string[] =>
    list.includes(key) ? list.filter((k) => k !== key) : [...list, key];

  const choose = (
    field: 'nameFrom' | 'passwordFrom' | 'folderFrom' | 'notesFrom',
    id: string,
  ) => {
    switch (field) {
      case 'nameFrom':
        setPicks(namePicksItem ? { ...picks, nameFrom: id, keepId: id } : { ...picks, nameFrom: id });
        break;
      case 'passwordFrom':
        setPicks({ ...picks, passwordFrom: id });
        break;
      case 'folderFrom':
        setPicks({ ...picks, folderFrom: id });
        break;
      case 'notesFrom':
        setPicks({ ...picks, notesFrom: id });
        break;
    }
  };

  const radioCell = (
    field: 'nameFrom' | 'passwordFrom' | 'folderFrom' | 'notesFrom',
    item: VaultItem,
    label: ReactNode,
  ) => (
    <label className="pick-opt">
      <input
        type="radio"
        name={`m-${field}`}
        checked={picks[field] === item.id}
        onChange={() => choose(field, item.id)}
      />
      <span>{label}</span>
    </label>
  );

  return (
    <>
      <nav className="crumbs" aria-label={t('dup.breadcrumb')}>
        <Link to="/duplicates">{t('dup.title')}</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{itemName(items[0] as VaultItem)}</span>
      </nav>
      <div>
        <h1 className="page-title">{t('merge.title', { count: items.length })}</h1>
        <p className="lede">{t('merge.lede')}</p>
      </div>
      <div className="why-line">
        <span className="tag warn">{t(WHY_LABEL[group.why])}</span>
        <span className="hint">{t('merge.how')}</span>
      </div>

      {done ? (
        <div className="notice" role="status">
          <Icon name="check" />
          <p className="grow">{t('merge.done', { kept: done.kept, trashed: done.trashed })}</p>
          <Button size="small" onPress={done.onUndo}>
            {t('dup.undo')}
          </Button>
          <Link to="/duplicates" className={buttonClass({ size: 'small' })}>
            {t('merge.back')}
          </Link>
        </div>
      ) : null}
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      <div className="two-col">
        <section className="card" aria-labelledby="h-pick">
          <div className="card-head">
            <h2 id="h-pick">{t('merge.choose')}</h2>
          </div>
          <p className="hint pad-x">{t('merge.newest')}</p>
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th scope="col">{t('merge.field')}</th>
                  {items.map((item) => (
                    <th scope="col" key={item.id}>
                      <span className="name">
                        <span className="tile" aria-hidden="true">
                          {tileLetter(itemName(item))}
                        </span>
                        <span>
                          <span>{itemName(item)}</span>
                          <span className="sub">
                            {[ownerName(item.owner, vaults, mine), timeAgo(item.data?.['updatedAt'])]
                              .filter((part) => part !== '')
                              .join(' · ')}
                          </span>
                        </span>
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">{t('merge.name')}</th>
                  {items.map((item) => (
                    <td key={item.id}>{radioCell('nameFrom', item, itemName(item))}</td>
                  ))}
                </tr>
                {group.crossOwner && !isLogin ? (
                  <tr>
                    <th scope="row">{t('dup.pick.keepIn')}</th>
                    {items.map((item) => (
                      <td key={item.id}>
                        <label className="pick-opt">
                          <input
                            type="radio"
                            name="m-keepIn"
                            checked={picks.keepId === item.id}
                            onChange={() => setPicks({ ...picks, keepId: item.id })}
                          />
                          <span>{ownerName(item.owner, vaults, mine)}</span>
                        </label>
                      </td>
                    ))}
                  </tr>
                ) : null}
                {!isLogin ? (
                  <tr>
                    <th scope="row">{t(SAME_LABEL[group.why])}</th>
                    <td colSpan={items.length}>
                      <span className="sub">{t('merge.sameAll')}</span>
                    </td>
                  </tr>
                ) : null}
                {hasUnionMembers(items) ? (
                  <tr>
                    <th scope="row">{t('dup.same.union')}</th>
                    <td colSpan={items.length}>
                      <span className="sub">{t('dup.same.unionValue')}</span>
                    </td>
                  </tr>
                ) : null}
                {isLogin ? (
                  <>
                    <tr>
                      <th scope="row">{t('merge.username')}</th>
                      {sameUsername ? (
                        <td colSpan={items.length}>
                          {loginOf(items[0] as VaultItem).username}{' '}
                          <span className="sub">{t('merge.sameInAll')}</span>
                        </td>
                      ) : (
                        items.map((item) => <td key={item.id}>{loginOf(item).username}</td>)
                      )}
                    </tr>
                    <tr>
                      <th scope="row">{t('merge.password')}</th>
                      {items.map((item) => (
                        <td key={item.id}>
                          {radioCell(
                            'passwordFrom',
                            item,
                            <span className="mono">
                              {'•'.repeat(Math.min(Math.max(loginOf(item).password.length, 6), 20))}
                            </span>,
                          )}
                        </td>
                      ))}
                    </tr>
                    <tr>
                      <th scope="row">{t('merge.websites')}</th>
                      {items.map((item) => (
                        <td key={item.id}>
                          {readWebsites(item.data)
                            .filter((rule) => siteOwner.get(websiteKey(rule)) === item.id)
                            .map((rule) => (
                              <label className="pick-opt" key={websiteKey(rule)}>
                                <input
                                  type="checkbox"
                                  checked={picks.websites.includes(websiteKey(rule))}
                                  onChange={() =>
                                    setPicks({ ...picks, websites: toggle(picks.websites, websiteKey(rule)) })
                                  }
                                />
                                <span className="mono">{rule.uri}</span>
                                <span className="tag">{t(ruleLabel(rule.match))}</span>
                              </label>
                            ))}
                        </td>
                      ))}
                    </tr>
                    <tr>
                      <th scope="row">{t('merge.passkey')}</th>
                      {items.map((item) => {
                        const mine = passkeysOf(item).filter(
                          (passkey) => passkeyOwner.get(passkeyId(passkey)) === item.id,
                        );
                        return (
                          <td key={item.id}>
                            {mine.length === 0 ? (
                              <span className="sub">{t('merge.none')}</span>
                            ) : (
                              mine.map((passkey) => {
                                const id = passkeyId(passkey);
                                const label =
                                  typeof passkey['rpId'] === 'string' ? passkey['rpId'] : t('merge.passkey');
                                return (
                                  <label className="pick-opt" key={id}>
                                    <input
                                      type="checkbox"
                                      checked={picks.passkeys.includes(id)}
                                      onChange={() =>
                                        setPicks({ ...picks, passkeys: toggle(picks.passkeys, id) })
                                      }
                                    />
                                    <span>{t('merge.passkeyMoves', { name: label })}</span>
                                  </label>
                                );
                              })
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  </>
                ) : null}
                <tr>
                  <th scope="row">{t('merge.folder')}</th>
                  {items.map((item) => (
                    <td key={item.id}>
                      {radioCell('folderFrom', item, folder(item) || t('dup.pick.noFolder'))}
                    </td>
                  ))}
                </tr>
                <tr>
                  <th scope="row">{t('merge.notes')}</th>
                  {items.map((item) => (
                    <td key={item.id}>
                      {radioCell('notesFrom', item, note(item) || <span className="sub">{t('merge.none')}</span>)}
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="card pad" aria-labelledby="h-result">
          <h2 id="h-result">{t('merge.result')}</h2>
          {plan ? (
            <div className="stack">
              <div className="member">
                <span className="tile" aria-hidden="true">
                  {tileLetter(itemName(plan.kept))}
                </span>
                <div className="grow">
                  <div>{keptName}</div>
                  <div className="hint">
                    {[group.crossOwner ? ownerName(plan.kept.owner, vaults, mine) : '', keptFolder || t('dup.pick.noFolder')]
                      .filter((part) => part !== '')
                      .join(' · ')}
                  </div>
                </div>
              </div>
              {isLogin ? (
                <div>
                  <div className="lbl">{t('merge.password')}</div>
                  <div className="hint">
                    {t('merge.history', { count: plan.retired })}
                  </div>
                </div>
              ) : null}
              {isLogin ? (
                <div>
                  <div className="lbl">{t('merge.websitesCount', { count: keptSites.length })}</div>
                  {keptSites.map((rule) => (
                    <div key={websiteKey(rule)}>
                      <span className="mono">{rule.uri}</span> <span className="tag">{t(ruleLabel(rule.match))}</span>
                    </div>
                  ))}
                </div>
              ) : null}
              <div>
                <div className="lbl">{t('merge.trash')}</div>
                <div>{t('merge.trashBody', { names: plan.trashed.map(itemName).join(', ') })}</div>
              </div>
              <div className="actions">
                <Button variant="primary" isDisabled={pending || Boolean(done)} onPress={() => onMerge(picks)}>
                  {t('dup.merge')}
                </Button>
                <Button onPress={onDismiss}>{t('dup.notDuplicates')}</Button>
                <Button onPress={onCancel}>{t('action.cancel')}</Button>
              </div>
              <p className="hint">{t('merge.oneBatch')}</p>
            </div>
          ) : null}
        </section>
      </div>
    </>
  );
}

export default function DuplicateMerge() {
  const t = useT();
  const navigate = useNavigate();
  const { groupId } = useParams({ strict: false }) as { groupId?: string };
  const { active, isLoading } = useVault();
  const vaults = useVaults(active);
  const { facts, pending: readingKeys } = useKeyFacts(active);
  const { merge, undo } = useMergeActions();
  const [done, setDone] = useState<{ kept: string; trashed: string; merged: Merged } | undefined>(
    undefined,
  );
  const group = useMemo(
    () => findDuplicates(active, facts).find((candidate) => candidate.id === groupId),
    [active, facts, groupId],
  );
  // Right after a merge the group is gone (its twin is in the Trash): keep showing what was merged.
  if (isLoading || readingKeys) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  if (!group) {
    return (
      <div className="empty">
        <h1 className="page-title">{t(done ? 'merge.done.title' : 'merge.gone.title')}</h1>
        <p>
          {done
            ? t('merge.done', { kept: done.kept, trashed: done.trashed })
            : t('merge.gone.body')}
        </p>
        {done ? (
          <Button
            onPress={() =>
              undo.mutate(done.merged, {
                onSuccess: () => setDone(undefined),
              })
            }
          >
            {t('dup.undo')}
          </Button>
        ) : null}
        <Link to="/duplicates" className={buttonClass({ variant: 'primary' })}>
          {t('merge.back')}
        </Link>
      </div>
    );
  }
  const failure = merge.error ?? undo.error;
  return (
    <MergeView
      key={group.id}
      group={group}
      vaults={vaults}
      pending={merge.isPending}
      error={failure ? describeError(failure) : undefined}
      done={undefined}
      onCancel={() => void navigate({ to: '/duplicates' })}
      onDismiss={() => {
        dismissedGroups.add(group.id);
        void navigate({ to: '/duplicates' });
      }}
      onMerge={(picks) => {
        const plan = planMerge(group.items, picks, new Date());
        if (!plan) return;
        merge.mutate(plan, {
          onSuccess: (merged) =>
            setDone({
              kept: itemName(plan.kept),
              trashed: plan.trashed.map(itemName).join(', '),
              merged,
            }),
        });
      }}
    />
  );
}
