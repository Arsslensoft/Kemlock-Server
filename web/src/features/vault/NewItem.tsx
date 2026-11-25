import { Link, useCanGoBack, useNavigate, useParams, useRouter, useSearch } from '@tanstack/react-router';
import { useState } from 'react';
import { session } from '@/app/services';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import type { LoginValues, NoteValues } from '@/lib/schemas';
import { buttonClass } from '@/ui/Button';
import { LoginForm, NoteForm } from './ItemForm';
import { canCopy, copyDraft, copyFields } from './copy';
import { ENTRY_KINDS, ENTRY_TITLES, EntryForm, isEntryKind } from './forms';
import { KEY_KINDS, KeyItemForm, isKeyKind } from './forms/KeyItemForm';
import { useVaultActions, useVaultItem, useWritableCollections } from './hooks';
import { type EditableKind, isEditable, kindLabel } from './kinds';
import { type ItemData, type SaveInput, type VaultItem, itemName, loginOf, noteOf } from './vault';
import { readWebsites, writeWebsites } from './websites';

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
  const router = useRouter();
  const canGoBack = useCanGoBack();
  const { itemId } = useParams({ strict: false }) as { itemId?: string };
  const search = useSearch({ strict: false }) as { kind?: EditableKind; copyOf?: string };
  const { item: found, isLoading } = useVaultItem(itemId ?? search.copyOf);
  const { save, copy } = useVaultActions();
  const [chosen, setChosen] = useState<EditableKind>(search.kind ?? 'login');
  // Where a new item goes: '' is the account's own vault, otherwise `<space id>/<collection id>`.
  // Until the person picks, a copy goes where its source is, when the person may write there.
  const [picked, setWhere] = useState<string | undefined>(undefined);
  const collections = useWritableCollections();
  const editing = itemId !== undefined;
  // "Make a copy" fills the form from an item, without its ids, and saves a new item.
  const draft = !editing && found && canCopy(found) ? copyDraft(found) : undefined;
  const item = editing ? found : draft;
  const existing = editing ? item : undefined;
  const kind: EditableKind = item && isEditable(item.kind) ? item.kind : chosen;
  const failure = copy.error ?? save.error;
  const error = failure ? describeError(failure) : undefined;
  const pending = save.isPending || copy.isPending;
  const sourceHome =
    draft && found?.collectionId && kind !== 'contact'
      ? collections.data?.find((c) => c.collectionId === found.collectionId)
      : undefined;
  const where = picked ?? (sourceHome ? `${sourceHome.spaceId}/${sourceHome.collectionId}` : '');

  if ((editing || search.copyOf !== undefined) && isLoading) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  if (editing && (!item || !isEditable(item.kind) || item.data === null)) {
    return (
      <div className="empty">
        <h1 className="page-title">{t('item.missing.title')}</h1>
        <p>{item?.data === null ? t('item.unreadable') : t('newItem.cantEdit')}</p>
        <Link to="/vault" className={buttonClass({ variant: 'primary' })}>
          {t('nav.all')}
        </Link>
      </div>
    );
  }

  // Cancel goes back to where the person came from (a filtered list, Trash, a space); only a page
  // opened directly, with nothing behind it, falls back to the list or the item.
  const cancel = () => {
    if (canGoBack) router.history.back();
    else
      void (editing && item
        ? navigate({ to: '/vault/$itemId', params: { itemId: item.id }, replace: true })
        : navigate({ to: '/vault', replace: true }));
  };

  // The form is replaced by the item, so Back after Save doesn't reopen the form.
  function saved(result: VaultItem) {
    void navigate({ to: '/vault/$itemId', params: { itemId: result.id }, replace: true });
  }

  // A copy keeps what the form doesn't own (custom fields, tags, a TOTP secret, keys an app wrote):
  // its body is the source's, with the form's values on top, and a note's files are sent again.
  function submit(input: SaveInput) {
    if (draft && found) {
      copy.mutate(
        { input: { ...input, fields: copyFields(draft, input.fields) }, sourceId: found.id },
        { onSuccess: saved },
      );
    } else {
      save.mutate(input, { onSuccess: saved });
    }
  }

  // A contact is one person's own statement: it stays in the account's own vault.
  const target = kind === 'contact'
    ? undefined
    : collections.data?.find((c) => `${c.spaceId}/${c.collectionId}` === where);
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
            : isEntryKind(kind)
              ? t(ENTRY_TITLES[kind])
              : isKeyKind(kind)
                ? t('newItem.titleOf', { kind: t(kindLabel(kind)) })
                : t(kind === 'login' ? 'newItem.loginTitle' : 'newItem.noteTitle')}
        </h1>
        <p className="lede">{t('newItem.lede')}</p>
      </div>

      {editing || draft ? null : (
        <div className="chips" role="group" aria-label={t('newItem.kind')}>
          {(['login', 'note', ...ENTRY_KINDS, ...KEY_KINDS] as const).map((option) => (
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
        </div>
      )}

      {editing && item?.collectionId ? (
        <p className="hint">
          {heldIn
            ? t('newItem.where.in', { collection: `${heldIn.spaceName}: ${heldIn.collectionName}` })
            : t('newItem.where.inSpace')}
        </p>
      ) : null}
      {!editing && kind !== 'contact' && collections.data && collections.data.length > 0 ? (
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

      {isEntryKind(kind) ? (
        <EntryForm
          kind={kind}
          item={item}
          submitLabel={t('action.save')}
          pending={pending}
          error={error}
          onCancel={cancel}
          onSubmit={(fields) =>
            submit({ existing, kind, owner, collectionId, fields, entry: true })
          }
        />
      ) : isKeyKind(kind) ? (
        <KeyItemForm
          key={`${kind}-${item?.id ?? 'new'}`}
          kind={kind}
          item={item}
          submitLabel={t('action.save')}
          pending={pending}
          error={error}
          onCancel={cancel}
          onSave={(fields) =>
            submit({ existing, kind, owner, collectionId, fields, entry: true })
          }
        />
      ) : kind === 'login' ? (
        <LoginForm
          key={`login-${item?.id ?? 'new'}`}
          initial={loginDefaults(item)}
          submitLabel={t('action.save')}
          pending={pending}
          error={error}
          onCancel={cancel}
          onSubmit={(values) =>
            submit({ existing, kind: 'login', owner, collectionId, fields: loginFields(values, item) })
          }
        />
      ) : (
        <NoteForm
          key={`note-${item?.id ?? 'new'}`}
          initial={noteDefaults(item)}
          submitLabel={t('action.save')}
          pending={pending}
          error={error}
          onCancel={cancel}
          onSubmit={(values) =>
            submit({ existing, kind: 'note', owner, collectionId, fields: noteFields(values) })
          }
        />
      )}
    </>
  );
}
