import { Link } from '@tanstack/react-router';
import { useState } from 'react';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button } from '@/ui/Button';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { Notice } from '@/ui/Notice';
import { useVault, useVaultActions } from './hooks';
import { kindLabel, shortDate, tileLetter, timeAgo } from './kinds';
import { type VaultItem, goneOn, itemName } from './vault';

type Pending = { type: 'empty' } | { type: 'one'; item: VaultItem } | null;

export default function Trash() {
  const t = useT();
  const { trashed, isLoading } = useVault();
  const { restore, remove, empty } = useVaultActions();
  const [confirm, setConfirm] = useState<Pending>(null);
  const failure = restore.error ?? remove.error ?? empty.error;
  const confirmFailure = remove.error ?? empty.error;
  const confirmError = confirmFailure ? describeError(confirmFailure) : null;
  /** Opens the dialog on a clean slate, so an earlier failure doesn't greet it. */
  function ask(next: Pending) {
    remove.reset();
    empty.reset();
    setConfirm(next);
  }
  const sorted = [...trashed].sort((a, b) =>
    String(b.data?.trashedAt ?? '').localeCompare(String(a.data?.trashedAt ?? '')),
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t('trash.title')}</h1>
          <p className="lede">{t('trash.lede')}</p>
        </div>
        <Button
          variant="danger"
          isDisabled={sorted.length === 0}
          onPress={() => ask({ type: 'empty' })}
        >
          {t('trash.empty')}
        </Button>
      </div>

      {failure && confirm === null ? (
        <Notice tone="error" live>
          <p>{t(describeError(failure).id)}</p>
        </Notice>
      ) : null}

      <div className="card">
        {isLoading ? (
          <p className="empty" role="status">
            {t('main.loading')}
          </p>
        ) : sorted.length === 0 ? (
          <div className="empty">
            <h2>{t('trash.none.title')}</h2>
            <p>{t('trash.none.body')}</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th scope="col">{t('table.name')}</th>
                  <th scope="col">{t('table.kind')}</th>
                  <th scope="col">{t('trash.deleted')}</th>
                  <th scope="col">{t('trash.goneOn')}</th>
                  <th scope="col">
                    <span className="sr">{t('table.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((item) => {
                  const name = itemName(item);
                  const gone = goneOn(item);
                  return (
                    <tr key={item.id}>
                      <td>
                        <Link to="/vault/$itemId" params={{ itemId: item.id }} className="name">
                          <span className="tile" aria-hidden="true">
                            {tileLetter(name)}
                          </span>
                          <span>{name}</span>
                        </Link>
                      </td>
                      <td>{t(kindLabel(item.kind))}</td>
                      <td>{timeAgo(item.data?.trashedAt)}</td>
                      <td>{gone ? shortDate(gone) : '—'}</td>
                      <td>
                        <div className="actions">
                          <Button
                            size="small"
                            isDisabled={restore.isPending}
                            aria-label={t('trash.restoreItem', { name })}
                            onPress={() => restore.mutate(item)}
                          >
                            {t('action.restore')}
                          </Button>
                          <Button
                            size="small"
                            aria-label={t('trash.deleteItem', { name })}
                            onPress={() => ask({ type: 'one', item })}
                          >
                            {t('trash.deleteNow')}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmDialog
        isOpen={confirm !== null}
        onOpenChange={(open) => {
          if (open) return;
          remove.reset();
          empty.reset();
          setConfirm(null);
        }}
        title={confirm?.type === 'empty' ? t('trash.confirmEmpty.title') : t('trash.confirmOne.title')}
        confirmLabel={confirm?.type === 'empty' ? t('trash.empty') : t('trash.deleteNow')}
        pending={remove.isPending || empty.isPending}
        error={confirmError ? t(confirmError.id, confirmError.values) : undefined}
        onConfirm={() => {
          if (confirm?.type === 'empty') {
            empty.mutate(sorted, { onSuccess: () => setConfirm(null) });
          } else if (confirm?.type === 'one') {
            remove.mutate(confirm.item, { onSuccess: () => setConfirm(null) });
          }
        }}
      >
        <p>
          {confirm?.type === 'empty'
            ? t('trash.confirmEmpty.body', { count: sorted.length })
            : t('trash.confirmOne.body')}
        </p>
      </ConfirmDialog>
    </>
  );
}
