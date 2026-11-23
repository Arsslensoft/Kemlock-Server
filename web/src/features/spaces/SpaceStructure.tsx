// A space's collections, groups and grants: who can open what. Each card is a list with a small
// form under it, shown only to people whose role lets them change it.
import { type FormEvent, useState } from 'react';
import type { CollectionPermission } from '@/api/spaces';
import { COLLECTION_PERMISSIONS } from '@/api/spaces';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CheckList, SelectInput, TextInput } from '../account/controls';
import {
  type SpaceDetail,
  canCreateCollections,
  canManageGroups,
  canManageUsers,
  memberLabel,
} from './model';

export interface StructureActions {
  createCollection: (name: string, parent?: string) => void;
  renameCollection: (id: string, name: string) => void;
  deleteCollection: (id: string) => void;
  createGroup: (name: string, members: string[]) => void;
  setGroupMembers: (id: string, members: string[]) => void;
  deleteGroup: (id: string) => void;
  grant: (collection: string, grantee: string, permission: CollectionPermission) => void;
  revokeGrant: (collection: string, grantee: string) => void;
}

function CollectionsCard({
  detail,
  busy,
  actions,
}: {
  detail: SpaceDetail;
  busy: boolean;
  actions: StructureActions;
}) {
  const t = useT();
  const [name, setName] = useState('');
  const [parent, setParent] = useState('');
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const can = canCreateCollections(detail.view.me);
  const manage = canManageUsers(detail.view.me);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (name.trim() === '') return;
    actions.createCollection(name.trim(), parent === '' ? undefined : parent);
    setName('');
    setParent('');
  }

  return (
    <section className="card" aria-labelledby="h-collections">
      <div className="card-head">
        <h2 id="h-collections">{t('space.collections.title')}</h2>
      </div>
      {detail.collections.length === 0 ? (
        <p className="empty">{t('space.collections.none')}</p>
      ) : (
        detail.collections.map((collection) => {
          const title = collection.title ?? t('space.collection.locked');
          const parentTitle = detail.collections.find((c) => c.id === collection.parent)?.title;
          return (
            <div className="row" key={collection.id}>
              <div className="grow">
                {renaming?.id === collection.id ? (
                  <TextInput
                    label={t('space.collections.renameFor', { name: title })}
                    value={renaming.name}
                    onChange={(value) => setRenaming({ id: collection.id, name: value })}
                  />
                ) : (
                  <div>{title}</div>
                )}
                {parentTitle ? (
                  <div className="hint">{t('space.collections.inside', { name: parentTitle })}</div>
                ) : null}
              </div>
              {collection.staleSince !== null ? (
                <span className="tag warn">{t('space.keysPending')}</span>
              ) : null}
              {renaming?.id === collection.id ? (
                <>
                  <Button size="small" onPress={() => setRenaming(null)}>
                    {t('action.cancel')}
                  </Button>
                  <Button
                    size="small"
                    variant="primary"
                    isDisabled={busy || renaming.name.trim() === ''}
                    onPress={() => {
                      actions.renameCollection(collection.id, renaming.name.trim());
                      setRenaming(null);
                    }}
                  >
                    {t('action.save')}
                  </Button>
                </>
              ) : manage ? (
                <>
                  <Button
                    size="small"
                    aria-label={t('space.collections.rename', { name: title })}
                    isDisabled={collection.title === null}
                    onPress={() => setRenaming({ id: collection.id, name: collection.title ?? '' })}
                  >
                    {t('space.collections.renameShort')}
                  </Button>
                  <Button
                    size="small"
                    variant="danger"
                    aria-label={t('space.collections.delete', { name: title })}
                    isDisabled={busy}
                    onPress={() => actions.deleteCollection(collection.id)}
                  >
                    {t('space.collections.deleteShort')}
                  </Button>
                </>
              ) : null}
            </div>
          );
        })
      )}
      {can && detail.readable ? (
        <form className="inline-form" noValidate onSubmit={submit} aria-label={t('space.collections.new')}>
          <TextInput label={t('space.collections.newName')} value={name} onChange={setName} />
          <SelectInput
            label={t('space.collections.parent')}
            value={parent}
            onChange={setParent}
            options={[
              { value: '', label: t('space.collections.top') },
              ...detail.collections.map((c) => ({
                value: c.id,
                label: c.title ?? t('space.collection.locked'),
              })),
            ]}
          />
          <Button type="submit" variant="primary" isDisabled={busy}>
            {t('space.collections.add')}
          </Button>
        </form>
      ) : null}
    </section>
  );
}

function GroupsCard({
  detail,
  busy,
  actions,
}: {
  detail: SpaceDetail;
  busy: boolean;
  actions: StructureActions;
}) {
  const t = useT();
  const [name, setName] = useState('');
  const [chosen, setChosen] = useState<string[]>([]);
  const [editing, setEditing] = useState<{ id: string; members: string[] } | null>(null);
  const can = canManageGroups(detail.view.me);
  const people = detail.members
    .filter((m) => m.state !== 'revoked')
    .map((m) => ({ value: m.user, label: m.name || m.email }));

  function submit(event: FormEvent) {
    event.preventDefault();
    if (name.trim() === '') return;
    actions.createGroup(name.trim(), chosen);
    setName('');
    setChosen([]);
  }

  return (
    <section className="card" aria-labelledby="h-groups">
      <div className="card-head">
        <h2 id="h-groups">{t('space.groups.title')}</h2>
      </div>
      {detail.groups.length === 0 ? (
        <p className="empty">{t('space.groups.none')}</p>
      ) : (
        detail.groups.map((group) => {
          const title = group.title ?? t('space.group.locked');
          return (
            <div key={group.id}>
              <div className="row">
                <div className="grow">
                  <div>{title}</div>
                  <div className="hint">{t('space.groups.count', { count: group.members.length })}</div>
                </div>
                {can ? (
                  <>
                    <Button
                      size="small"
                      aria-label={t('space.groups.editFor', { name: title })}
                      onPress={() =>
                        setEditing(
                          editing?.id === group.id ? null : { id: group.id, members: group.members },
                        )
                      }
                    >
                      {t('space.groups.edit')}
                    </Button>
                    <Button
                      size="small"
                      variant="danger"
                      aria-label={t('space.groups.deleteFor', { name: title })}
                      isDisabled={busy}
                      onPress={() => actions.deleteGroup(group.id)}
                    >
                      {t('space.groups.delete')}
                    </Button>
                  </>
                ) : null}
              </div>
              {editing?.id === group.id ? (
                <div className="panel-body">
                  <CheckList
                    legend={t('space.groups.members', { name: title })}
                    options={people}
                    selected={editing.members}
                    onChange={(members) => setEditing({ id: group.id, members })}
                  />
                  <div className="actions">
                    <Button onPress={() => setEditing(null)}>{t('action.cancel')}</Button>
                    <Button
                      variant="primary"
                      isDisabled={busy}
                      onPress={() => {
                        actions.setGroupMembers(group.id, editing.members);
                        setEditing(null);
                      }}
                    >
                      {t('action.save')}
                    </Button>
                  </div>
                </div>
              ) : null}
            </div>
          );
        })
      )}
      {can && detail.readable ? (
        <form className="panel-body" noValidate onSubmit={submit} aria-label={t('space.groups.new')}>
          <TextInput label={t('space.groups.newName')} value={name} onChange={setName} />
          <CheckList
            legend={t('space.groups.newMembers')}
            options={people}
            selected={chosen}
            onChange={setChosen}
          />
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy}>
              {t('space.groups.add')}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}

function GrantsCard({
  detail,
  busy,
  actions,
}: {
  detail: SpaceDetail;
  busy: boolean;
  actions: StructureActions;
}) {
  const t = useT();
  const [collection, setCollection] = useState('');
  const [grantee, setGrantee] = useState('');
  const [permission, setPermission] = useState<CollectionPermission>('view');
  const can = canManageUsers(detail.view.me);
  const collectionTitle = (id: string) =>
    detail.collections.find((c) => c.id === id)?.title ?? t('space.collection.locked');
  const granteeLabel = (value: string) => {
    const [kind, id] = value.split(':');
    if (kind === 'group') {
      return detail.groups.find((g) => g.id === id)?.title ?? t('space.group.locked');
    }
    return memberLabel(detail.members, id ?? value);
  };
  const granteeOptions = [
    ...detail.members
      .filter((m) => m.state === 'confirmed' || m.state === 'accepted' || m.state === 'invited')
      .map((m) => ({ value: `user:${m.user}`, label: m.name || m.email })),
    ...detail.groups.map((g) => ({
      value: `group:${g.id}`,
      label: t('space.grants.groupLabel', { name: g.title ?? t('space.group.locked') }),
    })),
  ];
  const chosenCollection = collection || detail.collections[0]?.id || '';
  const chosenGrantee = grantee || granteeOptions[0]?.value || '';

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!chosenCollection || !chosenGrantee) return;
    actions.grant(chosenCollection, chosenGrantee, permission);
  }

  return (
    <section className="card" aria-labelledby="h-grants">
      <div className="card-head">
        <h2 id="h-grants">{t('space.grants.title')}</h2>
      </div>
      {detail.view.grants.length === 0 ? (
        <p className="empty">{t('space.grants.none')}</p>
      ) : (
        detail.view.grants.map((grant) => {
          const who = granteeLabel(grant.grantee);
          const what = collectionTitle(grant.collection);
          return (
            <div className="row" key={`${grant.collection}/${grant.grantee}`}>
              <div className="grow">
                <div>{t('space.grants.line', { who, what })}</div>
                <div className="hint">{t(`space.permission.${grant.permission}`)}</div>
              </div>
              {can ? (
                <Button
                  size="small"
                  aria-label={t('space.grants.revokeFor', { who, what })}
                  isDisabled={busy}
                  onPress={() => actions.revokeGrant(grant.collection, grant.grantee)}
                >
                  {t('space.grants.revoke')}
                </Button>
              ) : null}
            </div>
          );
        })
      )}
      {can && detail.readable && detail.collections.length > 0 ? (
        <form className="inline-form" noValidate onSubmit={submit} aria-label={t('space.grants.new')}>
          <SelectInput
            label={t('space.grants.collection')}
            value={chosenCollection}
            onChange={setCollection}
            options={detail.collections.map((c) => ({
              value: c.id,
              label: c.title ?? t('space.collection.locked'),
            }))}
          />
          <SelectInput
            label={t('space.grants.grantee')}
            value={chosenGrantee}
            onChange={setGrantee}
            options={granteeOptions}
          />
          <SelectInput
            label={t('space.grants.permission')}
            value={permission}
            onChange={(value) => setPermission(value as CollectionPermission)}
            options={COLLECTION_PERMISSIONS.map((p) => ({
              value: p,
              label: t(`space.permission.${p}`),
            }))}
          />
          <Button type="submit" variant="primary" isDisabled={busy}>
            {t('space.grants.add')}
          </Button>
        </form>
      ) : null}
    </section>
  );
}

export function SpaceStructure({
  detail,
  busy,
  actions,
}: {
  detail: SpaceDetail;
  busy: boolean;
  actions: StructureActions;
}) {
  return (
    <div className="acct-grid">
      <div className="acct-col">
        <CollectionsCard detail={detail} busy={busy} actions={actions} />
        <GroupsCard detail={detail} busy={busy} actions={actions} />
      </div>
      <div className="acct-col">
        <GrantsCard detail={detail} busy={busy} actions={actions} />
      </div>
    </div>
  );
}
