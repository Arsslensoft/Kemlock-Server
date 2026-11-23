import { type FormEvent, useState } from 'react';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import '@/styles/account.css';
import { TextInput } from '../account/controls';
import type { Described } from '../account/errors';
import type { NewSpaceInput, SpaceRow } from './model';

export interface SpaceListViewProps {
  rows: SpaceRow[] | undefined;
  loading: boolean;
  error?: Described | undefined;
  creating: boolean;
  createError?: Described | undefined;
  /** Whether the worker can make space keys: when it can't, the form says so. */
  cryptoAvailable: boolean;
  onOpen: (id: string) => void;
  onCreate: (input: NewSpaceInput) => void;
}

export function SpaceListView({
  rows,
  loading,
  error,
  creating,
  createError,
  cryptoAvailable,
  onOpen,
  onCreate,
}: SpaceListViewProps) {
  const t = useT();
  const [name, setName] = useState('');
  const [first, setFirst] = useState('');

  function submit(event: FormEvent) {
    event.preventDefault();
    if (name.trim() === '' || first.trim() === '') return;
    onCreate({ name: name.trim(), firstCollection: first.trim() });
  }

  return (
    <>
      <div>
        <h1 className="page-title">{t('space.list.title')}</h1>
        <p className="lede">{t('space.list.lede')}</p>
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      <section className="card" aria-labelledby="h-spaces">
        <div className="card-head">
          <h2 id="h-spaces">{t('space.list.yours')}</h2>
        </div>
        {loading ? (
          <p className="empty" role="status">
            {t('state.loading')}
          </p>
        ) : !rows || rows.length === 0 ? (
          <div className="empty">
            <h2>{t('space.list.none.title')}</h2>
            <p>{t('space.list.none.body')}</p>
          </div>
        ) : (
          rows.map((row) => {
            const title = row.name ?? t('space.list.locked');
            return (
              <div className="row" key={row.id}>
                <div className="grow">
                  <div>{title}</div>
                  <div className="hint">
                    {t(`space.role.${row.role}`)} · {t(`space.state.${row.state}`)}
                  </div>
                </div>
                {row.keysPending ? <span className="tag warn">{t('space.keysPending')}</span> : null}
                <Button
                  size="small"
                  aria-label={t('space.list.open', { name: title })}
                  onPress={() => onOpen(row.id)}
                >
                  {t('space.list.openShort')}
                </Button>
              </div>
            );
          })
        )}
      </section>

      <section className="card pad" aria-labelledby="h-new-space">
        <h2 id="h-new-space">{t('space.new.title')}</h2>
        <p className="hint">{t('space.new.hint')}</p>
        {!cryptoAvailable ? (
          <Notice tone="warn">
            <p>{t('sharing.unavailable')}</p>
          </Notice>
        ) : null}
        <form className="stack" noValidate onSubmit={submit}>
          <TextInput label={t('space.new.name')} value={name} onChange={setName} required />
          <TextInput label={t('space.new.collection')} value={first} onChange={setFirst} required />
          {createError ? (
            <Notice tone="error" live>
              <p>{t(createError.id, createError.values)}</p>
            </Notice>
          ) : null}
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={creating}>
              {t('space.new.submit')}
            </Button>
          </div>
        </form>
      </section>
    </>
  );
}
