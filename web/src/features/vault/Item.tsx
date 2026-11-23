import { Link, getRouteApi, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, IconButton, buttonClass } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { useVaultActions, useVaultItem } from './hooks';
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
  const navigate = useNavigate();
  const { itemId } = route.useParams();
  const { item, isLoading } = useVaultItem(itemId);
  const { trash, restore } = useVaultActions();
  const failure = trash.error ?? restore.error;

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
        : '';
  const ageText = timeAgo(item.data?.updatedAt);

  return (
    <>
      <nav className="crumbs" aria-label={t('item.breadcrumb')}>
        <Link to="/vault">{t('nav.all')}</Link>
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
        <div>
          <h1 className="page-title">{name}</h1>
          <p className="lede">
            {t('item.meta', { kind: t(kindLabel(item.kind)), revision: item.revision })}
            {ageText ? ` · ${ageText}` : ''}
          </p>
        </div>
        <div className="actions">
          {trashed ? (
            <Button
              variant="primary"
              isDisabled={restore.isPending}
              onPress={() => restore.mutate(item)}
            >
              <Icon name="restore" />
              {t('action.restore')}
            </Button>
          ) : (
            <>
              {item.kind === 'login' ? (
                <Link
                  to="/vault/$itemId/websites"
                  params={{ itemId: item.id }}
                  className={buttonClass()}
                >
                  <Icon name="globe" />
                  {t('sites.open')}
                </Link>
              ) : null}
              {isEditable(item.kind) ? (
                <Link
                  to="/vault/$itemId/edit"
                  params={{ itemId: item.id }}
                  className={buttonClass({ variant: 'primary' })}
                >
                  <Icon name="edit" />
                  {t('action.edit')}
                </Link>
              ) : null}
              <Button
                variant="danger"
                isDisabled={trash.isPending}
                onPress={() =>
                  trash.mutate(item, { onSuccess: () => void navigate({ to: '/vault' }) })
                }
              >
                <Icon name="trash" />
                {t('item.moveToTrash')}
              </Button>
            </>
          )}
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
        </section>
      ) : null}

      {notes ? (
        <section className="card" aria-labelledby="h-notes">
          <div className="card-head">
            <h2 id="h-notes">{t(item.kind === 'note' ? 'item.text' : 'item.notes')}</h2>
          </div>
          <div className="row">
            <p className="grow pre-wrap">
              {notes}
            </p>
          </div>
        </section>
      ) : null}

      <section className="card pad" aria-labelledby="h-enc">
        <h2 id="h-enc">
          <Icon name="lock" /> {t('item.enc.title')}
        </h2>
        <p className="muted">{t('item.enc.body')}</p>
      </section>

      <section className="card pad" aria-labelledby="h-server">
        <h2 id="h-server">
          <Icon name="server" /> {t('item.server.title')}
        </h2>
        <pre className="pre">
          {[
            `item     ${item.id}   ${item.kind}`,
            `owner    ${item.owner}`,
            `revision ${item.revision} · key version ${item.keyVersion}`,
            `key      ${item.sizes.itemKey} B wrapped`,
            `body     AES-256-GCM, ${item.sizes.ciphertext} B`,
          ].join('\n')}
        </pre>
        <p className="muted">{t('item.server.note')}</p>
      </section>
    </>
  );
}
