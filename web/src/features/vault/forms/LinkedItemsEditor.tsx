// The "Linked items" card: a chip for each linked item (its icon, name and kind, and a button to
// unlink it) and a "Link an item" picker. A link is two-way: saving the form writes it on both
// items (see saveFlow.ts), and unlinking here removes both ends.
import { useEffect, useId, useRef, useState } from 'react';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { formLinkCandidates } from '../links';
import { kindIcon, kindLabel } from '../kinds';
import { type VaultItem, itemName } from '../vault';

interface Props {
  /** The ids linked so far. */
  value: string[];
  onChange: (next: string[]) => void;
  /** The vault's items, which the chips name and the picker offers. */
  items: readonly VaultItem[];
  /** The item being edited, which can't be linked to itself; absent while it is new. */
  selfId?: string | undefined;
  canWrite?: (item: VaultItem) => boolean;
}

export function LinkedItemsEditor({ value, onChange, items, selfId, canWrite }: Props) {
  const t = useT();
  const id = useId();
  const byId = new Map(items.map((item) => [item.id.toLowerCase(), item]));
  const unlink = (linked: string) => onChange(value.filter((other) => other !== linked));
  return (
    <section className="card pad" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`}>{t('itemForm.links.title')}</h2>
      {value.length === 0 ? (
        <p className="hint">{t('itemForm.links.none')}</p>
      ) : (
        <ul className="chips-list plain" aria-label={t('itemForm.links.title')}>
          {value.map((linked) => {
            const item = byId.get(linked.toLowerCase());
            const name = item ? itemName(item) : t('itemForm.links.missing');
            const kind = item ? t(kindLabel(item.kind)) : '';
            return (
              <li key={linked} className="link-chip">
                <span className="link-icon">
                  <Icon name={item ? kindIcon(item.kind) : 'link'} />
                </span>
                <span className="link-name">{name}</span>
                {kind ? <span className="link-kind">{kind}</span> : null}
                <button
                  type="button"
                  className="link-x"
                  aria-label={kind ? t('itemForm.links.unlink', { name, kind }) : t('itemForm.links.unlinkMissing')}
                  onClick={() => unlink(linked)}
                >
                  <Icon name="close" />
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <Picker value={value} items={items} selfId={selfId} canWrite={canWrite} onPick={(picked) => onChange([...value, picked])} />
      <p className="hint">{t('itemForm.links.hint')}</p>
    </section>
  );
}

function Picker({
  value,
  items,
  selfId,
  canWrite,
  onPick,
}: {
  value: string[];
  items: readonly VaultItem[];
  selfId: string | undefined;
  canWrite: ((item: VaultItem) => boolean) | undefined;
  onPick: (id: string) => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const search = useRef<HTMLInputElement>(null);
  const wrap = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (open) search.current?.focus();
  }, [open]);
  const candidates = open
    ? formLinkCandidates(items, { selfId, chosen: value, query, ...(canWrite ? { canWrite } : {}) })
    : [];
  const close = () => {
    setOpen(false);
    setQuery('');
  };
  return (
    <div
      className="link-picker"
      ref={wrap}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.stopPropagation();
          close();
          wrap.current?.querySelector<HTMLButtonElement>('button[aria-haspopup]')?.focus();
        }
      }}
    >
      <Button size="small" aria-expanded={open} aria-haspopup="true" onPress={() => (open ? close() : setOpen(true))}>
        <Icon name="link" />
        {t('itemForm.links.add')}
      </Button>
      {open ? (
        <div className="pick" role="group" aria-label={t('itemForm.links.add')}>
          <div className="field">
            <label className="sr" htmlFor="link-search">
              {t('itemForm.links.search')}
            </label>
            <input
              id="link-search"
              ref={search}
              type="search"
              autoComplete="off"
              spellCheck={false}
              placeholder={t('itemForm.links.search')}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          {candidates.length === 0 ? (
            <p className="hint">{t('itemForm.links.noCandidates')}</p>
          ) : (
            <ul className="plain pick-list">
              {candidates.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className="pick-row"
                    onClick={() => {
                      onPick(item.id.toLowerCase());
                      close();
                    }}
                  >
                    <span className="link-icon">
                      <Icon name={kindIcon(item.kind)} />
                    </span>
                    <span className="link-name">{itemName(item)}</span>
                    <span className="link-kind">{t(kindLabel(item.kind))}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  );
}
