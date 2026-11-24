import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useState } from 'react';
import { session } from '@/app/services';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import type { LoginValues, NoteValues } from '@/lib/schemas';
import { buttonClass } from '@/ui/Button';
import { LoginForm, NoteForm } from './ItemForm';
import { KEY_KINDS, KeyItemForm, isKeyKind } from './forms/KeyItemForm';
import { useVaultActions, useVaultItem, useWritableCollections } from './hooks';
import { type EditableKind, isEditable, kindLabel } from './kinds';
import { type ItemData, type VaultItem, itemName, loginOf, noteOf } from './vault';
import { readWebsites, writeWebsites } from './websites';

const OTHER_KINDS = ['otp', 'backup-codes', 'card', 'identity'];

export function loginDefaults(item?: VaultItem): LoginValues {
  const login = item ? loginOf(item) : undefined;
  return {
    name: item ? itemName(item) : '',
    username: login?.username ?? '',
    password: login?.password ?? '',
    url: login?.urls[0] ?? '',
    notes: typeof item?.data?.notes === 'string' ? item.data.notes : '',
    favorite: item?.data?.favorite === true,
  };
}

export function noteDefaults(item?: VaultItem): NoteValues {
  return {
    name: item ? itemName(item) : '',
    text: item ? noteOf(item) : '',
    favorite: item?.data?.favorite === true,
  };
}

/** The fields a login form owns. Websites after the first, and fields other apps wrote, stay. */
export function loginFields(values: LoginValues, existing?: VaultItem): ItemData {
  // A login with match rules (the Websites screen) keeps its other websites and every rule; the
  // form changes only the first address, and `uris`, `urls` and `websites` stay in step.
  if (existing && Array.isArray(existing.data?.['uris'])) {
    const rules = readWebsites(existing.data);
    const first = rules[0];
    const next = [{ uri: values.url, match: first?.match ?? ('default' as const) }, ...rules.slice(1)];
    return {
      name: values.name,
      username: values.username,
      password: values.password,
      ...writeWebsites(next),
      notes: values.notes === '' ? undefined : values.notes,
      favorite: values.favorite ? true : undefined,
    };
  }
  const rest = existing ? loginOf(existing).urls.slice(1) : [];
  const urls = [values.url, ...rest].filter((url) => url !== '');
  return {
    name: values.name,
    username: values.username,
    password: values.password,
    urls,
    notes: values.notes === '' ? undefined : values.notes,
    favorite: values.favorite ? true : undefined,
  };
}

export function noteFields(values: NoteValues): ItemData {
  return { name: values.name, text: values.text, favorite: values.favorite ? true : undefined };
}

/** New item (`/vault/new`) and edit (`/vault/$itemId/edit`): one form, filled in or not. */
export default function NewItem() {
  const t = useT();
  const navigate = useNavigate();
  const { itemId } = useParams({ strict: false }) as { itemId?: string };
  const search = useSearch({ strict: false }) as { kind?: EditableKind };
  const { item, isLoading } = useVaultItem(itemId);
  const { save } = useVaultActions();
  const [chosen, setChosen] = useState<EditableKind>(search.kind ?? 'login');
  // Where a new item goes: '' is the account's own vault, otherwise `<space id>/<collection id>`.
  const [where, setWhere] = useState('');
  const collections = useWritableCollections();
  const editing = itemId !== undefined;
  const kind: EditableKind = editing && item && isEditable(item.kind) ? item.kind : chosen;
  const error = save.error ? describeError(save.error) : undefined;

  if (editing && isLoading) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  if (editing && (!item || !isEditable(item.kind))) {
    return (
      <div className="empty">
        <h1 className="page-title">{t('item.missing.title')}</h1>
        <p>{t('newItem.cantEdit')}</p>
        <Link to="/vault" className={buttonClass({ variant: 'primary' })}>
          {t('nav.all')}
        </Link>
      </div>
    );
  }

  const cancel = () =>
    void (editing && item
      ? navigate({ to: '/vault/$itemId', params: { itemId: item.id } })
      : navigate({ to: '/vault' }));

  function saved(result: VaultItem) {
    void navigate({ to: '/vault/$itemId', params: { itemId: result.id } });
  }

  const target = collections.data?.find((c) => `${c.spaceId}/${c.collectionId}` === where);
  const owner = target ? `space:${target.spaceId}` : `user:${session.getState().userId ?? ''}`;
  const collectionId = target?.collectionId;
  const heldIn = item?.collectionId
    ? collections.data?.find((c) => c.collectionId === item.collectionId)
    : undefined;

  return (
    <>
      <nav className="crumbs" aria-label={t('item.breadcrumb')}>
        <Link to="/vault">{t('nav.all')}</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{editing ? t('newItem.edit') : t('newItem.crumb')}</span>
      </nav>
      <div>
        <h1 className="page-title">
          {editing
            ? t('newItem.editTitle')
            : isKeyKind(kind)
              ? t('newItem.titleOf', { kind: t(kindLabel(kind)) })
              : t(kind === 'login' ? 'newItem.loginTitle' : 'newItem.noteTitle')}
        </h1>
        <p className="lede">{t('newItem.lede')}</p>
      </div>

      {editing ? null : (
        <div className="chips" role="group" aria-label={t('newItem.kind')}>
          {(['login', 'note', ...KEY_KINDS] as const).map((option) => (
            <button
              key={option}
              type="button"
              className="chip"
              aria-pressed={kind === option}
              onClick={() => setChosen(option)}
            >
              {t(kindLabel(option))}
            </button>
          ))}
          {OTHER_KINDS.map((other) => (
            <button key={other} type="button" className="chip" disabled title={t('newItem.later')}>
              {t(kindLabel(other))}
            </button>
          ))}
        </div>
      )}

      {editing && item?.collectionId ? (
        <p className="hint">
          {heldIn
            ? t('newItem.where.in', { collection: `${heldIn.spaceName}: ${heldIn.collectionName}` })
            : t('newItem.where.inSpace')}
        </p>
      ) : null}
      {!editing && collections.data && collections.data.length > 0 ? (
        <div className="field">
          <label htmlFor="item-where">{t('newItem.where')}</label>
          <select id="item-where" value={where} onChange={(event) => setWhere(event.target.value)}>
            <option value="">{t('newItem.where.vault')}</option>
            {collections.data.map((c) => (
              <option key={`${c.spaceId}/${c.collectionId}`} value={`${c.spaceId}/${c.collectionId}`}>
                {t('newItem.where.collection', { space: c.spaceName, collection: c.collectionName })}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      {isKeyKind(kind) ? (
        <KeyItemForm
          key={`${kind}-${item?.id ?? 'new'}`}
          kind={kind}
          item={item}
          submitLabel={t('action.save')}
          pending={save.isPending}
          error={error}
          onCancel={cancel}
          onSave={(fields) =>
            save.mutate({ existing: item, kind, owner, collectionId, fields, entry: true }, { onSuccess: saved })
          }
        />
      ) : kind === 'login' ? (
        <LoginForm
          key={`login-${item?.id ?? 'new'}`}
          initial={loginDefaults(item)}
          submitLabel={t('action.save')}
          pending={save.isPending}
          error={error}
          onCancel={cancel}
          onSubmit={(values) =>
            save.mutate(
              { existing: item, kind: 'login', owner, collectionId, fields: loginFields(values, item) },
              { onSuccess: saved },
            )
          }
        />
      ) : (
        <NoteForm
          key={`note-${item?.id ?? 'new'}`}
          initial={noteDefaults(item)}
          submitLabel={t('action.save')}
          pending={save.isPending}
          error={error}
          onCancel={cancel}
          onSubmit={(values) =>
            save.mutate(
              { existing: item, kind: 'note', owner, collectionId, fields: noteFields(values) },
              { onSuccess: saved },
            )
          }
        />
      )}
    </>
  );
}
