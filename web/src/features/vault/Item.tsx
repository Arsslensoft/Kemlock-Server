// One item, read-only. Edit is the only main button; everything else (websites and rules, move to a
// space, make a copy, what the server holds, move to Trash) is in the `⋯` menu. A round lock beside
// the title carries the end-to-end encryption note, and the record the server keeps opens in a
// dialog. The first card ends with the item's custom fields; linked items are their own card.
import { Link, getRouteApi, useNavigate } from '@tanstack/react-router';
import { useCallback, useState } from 'react';
import { api } from '@/app/services';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, IconButton, buttonClass } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import { LockBadge } from '@/ui/LockBadge';
import { Notice } from '@/ui/Notice';
import '@/styles/item.css';
import { useBackToList } from './backNav';
import { readCustomFields } from './customFields';
import { CustomFieldRows } from './details/CustomFieldRows';
import { AttachmentsCard } from './details/FileDetails';
import { KindDetails } from './details/KindDetails';
import type { AttachedFile } from './details/files';
import { downloadFile } from './details/fileDownload';
import { useCanWrite, useVault, useVaultActions, useVaultItem } from './hooks';
import { ItemMenu, type ItemAction } from './ItemMenu';
import { LinkedItems } from './LinkedItems';
import { MoveDialog } from './MoveDialog';
import { ServerHolds } from './ServerHolds';
import { canCopy } from './copy';
import { hostOfUrl, isEditable, isWebUrl, kindLabel, tileLetter, timeAgo } from './kinds';
import { isTrashed, itemName, loginOf, noteOf } from './vault';

const route = getRouteApi('/_vault/vault/$itemId');

function PasswordRow({ password }: { password: string }) {
  const t = useT();
  const [shown, setShown] = useState(false);
  return (
    <div className="row">
      <div className="grow">
        <div className="lbl">{t('item.password')}</div>
        <div className="mono">{shown ? password : '••••••••••••••••••••'}</div>
      </div>
      <IconButton
        aria-label={shown ? t('item.hidePassword') : t('item.showPassword')}
        onPress={() => setShown((value) => !value)}
      >
        <Icon name={shown ? 'eyeOff' : 'eye'} />
      </IconButton>
      <CopyButton value={password} secret label={t('item.copyPassword')} />
    </div>
  );
}

export default function Item() {
  const t = useT();
  const backToList = useBackToList();
  const navigate = useNavigate();
  const { itemId } = route.useParams();
  const { item, isLoading } = useVaultItem(itemId);
  const { all } = useVault();
  const canWrite = useCanWrite();
  const { trash, restore, link } = useVaultActions();
  const [dialog, setDialog] = useState<'server' | 'move' | null>(null);
  const failure = trash.error ?? restore.error;
  const download = useCallback((file: AttachedFile) => downloadFile(api, itemId, file), [itemId]);

  if (isLoading) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  if (!item) {
    return (
      <div className="empty">
        <h1 className="page-title">{t('item.missing.title')}</h1>
        <p>{t('item.missing.body')}</p>
        <Link to="/vault" className={buttonClass({ variant: 'primary' })}>
          {t('nav.all')}
        </Link>
      </div>
    );
  }

  const name = itemName(item);
  const trashed = isTrashed(item);
  const login = item.kind === 'login' ? loginOf(item) : undefined;
  const notes =
    item.kind === 'note'
      ? noteOf(item)
      : typeof item.data?.notes === 'string'
        ? item.data.notes
        : typeof item.data?.['note'] === 'string'
          ? (item.data['note'] as string)
          : '';
  const ageText = timeAgo(item.data?.updatedAt);
  const custom = readCustomFields(item.data);
  const customRows = custom.length > 0 ? <CustomFieldRows fields={custom} /> : null;

  function onAction(action: ItemAction) {
    if (!item) return;
    switch (action) {
      case 'websites':
        void navigate({ to: '/vault/$itemId/websites', params: { itemId: item.id } });
        break;
      case 'copy':
        if (isEditable(item.kind)) void navigate({ to: '/vault/new', search: { kind: item.kind, copyOf: item.id } });
        break;
      case 'move':
        setDialog('move');
        break;
      case 'server':
        setDialog('server');
        break;
      case 'trash':
        trash.mutate(item, { onSuccess: backToList });
        break;
    }
  }

  return (
    <>
      <nav className="crumbs" aria-label={t('item.breadcrumb')}>
        <Link
          to="/vault"
          onClick={(event) => {
            if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
            event.preventDefault();
            backToList();
          }}
        >
          {t('nav.all')}
        </Link>
        <span aria-hidden="true">/</span>
        <Link to="/vault" search={{ kind: item.kind }}>
          {t(kindLabel(item.kind))}
        </Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{name}</span>
      </nav>

      <div className="page-head">
        <span className="tile big" aria-hidden="true">
          {tileLetter(name)}
        </span>
        <div className="head-title">
          <div className="title-row">
            <h1 className="page-title">{name}</h1>
            <LockBadge />
          </div>
          <p className="lede">
            {t('item.meta', { kind: t(kindLabel(item.kind)), revision: item.revision })}
            {ageText ? ` · ${ageText}` : ''}
          </p>
        </div>
        <div className="head-actions">
          {trashed ? (
            <Button variant="primary" isDisabled={restore.isPending} onPress={() => restore.mutate(item)}>
              <Icon name="restore" />
              {t('action.restore')}
            </Button>
          ) : isEditable(item.kind) ? (
            <Link to="/vault/$itemId/edit" params={{ itemId: item.id }} className={buttonClass({ variant: 'primary' })}>
              <Icon name="edit" />
              {t('action.edit')}
            </Link>
          ) : null}
          <ItemMenu
            name={name}
            trashed={trashed}
            websites={item.kind === 'login'}
            copy={canCopy(item) && isEditable(item.kind)}
            onAction={onAction}
          />
        </div>
      </div>

      {trashed ? (
        <Notice tone="warn">
          <p>{t('item.inTrash')}</p>
        </Notice>
      ) : null}
      {failure ? (
        <Notice tone="error" live>
          <p>{t(describeError(failure).id)}</p>
        </Notice>
      ) : null}
      {item.data === null ? (
        <Notice tone="warn">
          <p>{t('item.unreadable')}</p>
        </Notice>
      ) : null}

      {login ? (
        <section className="card" aria-labelledby="h-signin">
          <div className="card-head">
            <h2 id="h-signin">{t('item.signIn')}</h2>
          </div>
          <div className="row">
            <div className="grow">
              <div className="lbl">{t('item.username')}</div>
              <div>{login.username || '—'}</div>
            </div>
            {login.username ? <CopyButton value={login.username} label={t('item.copyUsername')} /> : null}
          </div>
          {login.password ? <PasswordRow password={login.password} /> : null}
          {login.urls.length > 0 ? (
            <div className="row">
              <div className="grow">
                <div className="lbl">{t('item.website')}</div>
                {login.urls.map((url) => (
                  <div key={url}>
                    {isWebUrl(url) ? (
                      <a href={url} target="_blank" rel="noreferrer noopener">
                        {hostOfUrl(url)}
                      </a>
                    ) : (
                      <span className="mono">{url}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {customRows}
        </section>
      ) : null}

      {item.kind !== 'login' && item.kind !== 'note' ? (
        <KindDetails item={item} extra={customRows} download={download} />
      ) : null}

      {item.kind === 'note' && (notes || custom.length > 0) ? (
        <section className="card" aria-labelledby="h-text">
          <div className="card-head">
            <h2 id="h-text">{t('item.text')}</h2>
          </div>
          <div className="row">
            <p className="grow pre-wrap">{notes}</p>
          </div>
          {customRows}
        </section>
      ) : null}
      {item.kind === 'note' ? <AttachmentsCard data={item.data} download={download} /> : null}

      {item.kind !== 'note' && notes ? (
        <section className="card" aria-labelledby="h-notes">
          <div className="card-head">
            <h2 id="h-notes">{t('item.notes')}</h2>
          </div>
          <div className="row">
            <p className="grow pre-wrap">{notes}</p>
          </div>
        </section>
      ) : null}

      <LinkedItems
        item={item}
        all={all}
        canWrite={canWrite}
        readOnly={trashed || item.data === null}
        onLink={async (other) => {
          await link.mutateAsync({ a: item, b: other, linked: true });
        }}
        onUnlink={async (other) => {
          await link.mutateAsync({ a: item, b: other, linked: false });
        }}
      />

      {dialog === 'server' ? <ServerHolds item={item} name={name} onClose={() => setDialog(null)} /> : null}
      {dialog === 'move' ? <MoveDialog item={item} name={name} onClose={() => setDialog(null)} /> : null}
    </>
  );
}
