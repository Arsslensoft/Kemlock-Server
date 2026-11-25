// New item (`/vault/new?kind=<kind>`), a copy (`/vault/new?copyOf=<item id>`) and edit
// (`/vault/$itemId/edit`): one form for each kind of item, filled in or not. The kind is in the
// address, so a New menu entry, a chip and a link all open the same page. The form is in forms/;
// what it makes is saved by saveFlow.ts.
import { Link, useCanGoBack, useNavigate, useParams, useRouter, useSearch } from '@tanstack/react-router';
import { useRef, useState } from 'react';
import { session } from '@/app/services';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { buttonClass } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import '@/styles/itemForms.css';
import { type AttachmentEntry, serverFileIds } from './attachments';
import { canCopy, copyFields, copySeed } from './copyDraft';
import { KindForm } from './forms';
import { FormEnvContext } from './forms/env';
import type { Described } from './forms/parts';
import { itemFiles, useVaultActions, useVaultItem, useWritableCollections } from './hooks';
import { KIND_ORDER, type KnownKind, isEditable, isKnownKind, kindLabel } from './kinds';
import { formLinks, incomingLinks } from './links';
import { type FormResult, UploadError, saveWithExtras } from './saveFlow';
import { useItemFormEnv } from './useItemFormEnv';
import { type VaultItem, vaultStore } from './vault';

const TITLES: Record<KnownKind, MessageId> = {
  login: 'itemForm.title.login',
  note: 'itemForm.title.note',
  file: 'itemForm.title.file',
  otp: 'itemForm.title.otp',
  'backup-codes': 'itemForm.title.backup-codes',
  passkey: 'itemForm.title.passkey',
  card: 'itemForm.title.card',
  identity: 'itemForm.title.identity',
  contact: 'itemForm.title.contact',
  certificate: 'itemForm.title.certificate',
  'ssh-key': 'itemForm.title.ssh-key',
  'pgp-key': 'itemForm.title.pgp-key',
};

export default function NewItem() {
  const t = useT();
  const navigate = useNavigate();
  const router = useRouter();
  const canGoBack = useCanGoBack();
  const { itemId } = useParams({ strict: false }) as { itemId?: string };
  const search = useSearch({ strict: false }) as { kind?: KnownKind; copyOf?: string };
  const { item, isLoading } = useVaultItem(itemId);
  const copying = useVaultItem(search.copyOf);
  const { save, remove } = useVaultActions();
  // Where a new item goes: '' is the account's own vault, otherwise `<space id>/<collection id>`. Until
  // the person picks, a copy goes where its original is, when they may write there.
  const [picked, setWhere] = useState<string | undefined>(undefined);
  const collections = useWritableCollections();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Described>();
  // The item an earlier try saved before something after it failed, and the files it sent: Save goes
  // on from them, so the item is never made twice and no file is sent twice.
  const [savedItem, setSavedItem] = useState<VaultItem>();
  const [uploaded, setUploaded] = useState<AttachmentEntry[]>([]);
  const [linkFailures, setLinkFailures] = useState<string[]>([]);
  const editing = itemId !== undefined;
  const copyOf = search.copyOf;
  const found = copyOf !== undefined ? copying.item : undefined;
  // An item that can't be read, or that is not copied (a passkey, a file), has nothing to fill a form from.
  const source = found && canCopy(found) ? found : undefined;
  const chosen = search.kind ?? (source && isKnownKind(source.kind) ? source.kind : undefined);
  const kind: KnownKind = editing && item && isKnownKind(item.kind) ? item.kind : (chosen ?? 'login');
  const existing = item ?? savedItem;
  const sourceHome =
    source?.collectionId && source.kind !== 'contact'
      ? collections.data?.find((c) => c.collectionId === source.collectionId)
      : undefined;
  const where = picked ?? (sourceHome ? `${sourceHome.spaceId}/${sourceHome.collectionId}` : '');
  const env = useItemFormEnv(existing?.id);
  // What the item had when the form opened: what it links to now is compared with the links, and the
  // files it keeps with the files, so an end or a file that failed once is dealt with by the next Save.
  const opened = useRef<{ links: string[]; files: string[] } | undefined>(undefined);
  if (opened.current === undefined && (!editing || item)) {
    const incoming = item ? incomingLinks(item.id, env.items) : [];
    opened.current = {
      links: [...new Set([...formLinks(item?.data), ...incoming])].sort(),
      files: serverFileIds(item?.data),
    };
  }

  if ((editing && isLoading) || (copyOf !== undefined && copying.isLoading)) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  // Saving an item that couldn't be opened would replace its body with what the form holds.
  const unreadable = (editing && item?.data === null) || found?.data === null;
  if ((editing && (!item || !isEditable(item.kind) || item.data === null)) || (copyOf !== undefined && !source)) {
    return (
      <div className="empty">
        <h1 className="page-title">{t('item.missing.title')}</h1>
        <p>{unreadable ? t('item.unreadable') : t('newItem.cantEdit')}</p>
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

  // A contact is one person's own statement: it stays in the account's own vault. A passkey is
  // made by a website, so nothing is saved from its page and there is nowhere to pick.
  const picksWhere = kind !== 'contact' && kind !== 'passkey';
  const target = picksWhere
    ? collections.data?.find((c) => `${c.spaceId}/${c.collectionId}` === where)
    : undefined;
  const owner = target ? `space:${target.spaceId}` : `user:${session.getState().userId ?? ''}`;
  const collectionId = target?.collectionId;
  const heldIn = item?.collectionId
    ? collections.data?.find((c) => c.collectionId === item.collectionId)
    : undefined;
  // A copy keeps what the original held that this page doesn't show, such as keys another app wrote.
  const seed = source ? copySeed(source) : undefined;
  const incoming = item ? incomingLinks(item.id, env.items) : [];

  async function submit(result: FormResult) {
    setPending(true);
    setError(undefined);
    setLinkFailures([]);
    try {
      const outcome = await saveWithExtras(
        {
          save: (input) => save.mutateAsync(input),
          lookup: (id) => vaultStore.items.get(id),
          files: itemFiles,
          removeItem: (made) => remove.mutateAsync(made),
        },
        {
          existing,
          kind,
          owner,
          collectionId,
          result: existing ? result : { ...result, fields: copyFields(seed, result.fields) },
          linksBefore: opened.current?.links ?? [],
          filesBefore: opened.current?.files ?? [],
          uploaded,
        },
      );
      if (outcome.linkFailures.length > 0) {
        // Saved; the link could not be written on these. Save again tries them again.
        setSavedItem(outcome.item);
        setUploaded([]);
        setLinkFailures(outcome.linkFailures);
        return;
      }
      // The form is replaced by the item, so Back after Save doesn't reopen the form.
      void navigate({ to: '/vault/$itemId', params: { itemId: outcome.item.id }, replace: true });
    } catch (caught) {
      if (caught instanceof UploadError) {
        setSavedItem(caught.saved);
        setUploaded(caught.uploaded);
        setError(describeError(caught.reason));
      } else {
        setError(describeError(caught));
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <nav className="crumbs" aria-label={t('item.breadcrumb')}>
        <Link to="/vault">{t('nav.all')}</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{editing ? t('newItem.edit') : t('newItem.crumb')}</span>
      </nav>
      <div>
        <h1 className="page-title">{editing ? t('newItem.editTitle') : t(TITLES[kind])}</h1>
        <p className="lede">{t('newItem.lede')}</p>
      </div>

      {editing || copyOf !== undefined ? null : (
        <div className="chips" role="group" aria-label={t('newItem.kind')}>
          {KIND_ORDER.map((option) => (
            <button
              key={option}
              type="button"
              className="chip"
              aria-pressed={kind === option}
              onClick={() => {
                // Another kind is another form: what an earlier try saved stays saved.
                setSavedItem(undefined);
                setUploaded([]);
                setError(undefined);
                setLinkFailures([]);
                void navigate({ to: '/vault/new', search: { kind: option }, replace: true });
              }}
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
      {!editing && picksWhere && collections.data && collections.data.length > 0 ? (
        <div className="field form-wide">
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

      {linkFailures.length > 0 ? (
        <Notice tone="warn" live>
          <p>{t('itemForm.links.failed', { names: linkFailures.join(', ') })}</p>
        </Notice>
      ) : null}

      <FormEnvContext.Provider value={env}>
        <KindForm
          kind={kind}
          item={item}
          existing={existing}
          seed={seed}
          incoming={incoming}
          submitLabel={t('action.save')}
          pending={pending}
          error={error}
          onCancel={cancel}
          onSubmit={(result) => void submit(result)}
        />
      </FormEnvContext.Provider>
    </>
  );
}
