// The "Linked items" card of the item page: every item linked to this one (icon, name, type and a
// line about it) as a link to that item, an Unlink button on each that can be unlinked, and "Link
// an item", which opens a picker that searches the vault. A link is two-way (links.ts): linking and
// unlinking write both items, so the other item shows this one too. An item that links here, or
// that this one links to the older way (`linkedLoginId`), is listed as well (itemLinks.ts).
import { Link } from '@tanstack/react-router';
import { useEffect, useId, useRef, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { AppDialog } from '@/ui/AppDialog';
import { Button, IconButton } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/item.css';
import { backupCodesOf } from './details/KindDetails';
import { fileOf } from './details/files';
import { otpParamsOf } from './details/otp';
import { useFormatSize } from './details/useFormatSize';
import { connectedItems, pickableItems, siteInfoOf } from './itemLinks';
import { hostOfUrl, kindIcon, kindLabel } from './kinds';
import { type ItemData, type VaultItem, isTrashed, itemName } from './vault';

type T = (id: MessageId, values?: Record<string, string | number>) => string;

export interface SublineContext {
  /** A size in bytes as the language writes it. */
  size: (bytes: number) => string;
  /** The item's website, or the one of the login it is linked to. */
  site?: string | undefined;
}

/** What to say about an item under its name: its type, then one fact about it. */
export function sublineOf(item: VaultItem, t: T, context: SublineContext): string {
  const data: ItemData = item.data ?? {};
  const text = (key: string) => (typeof data[key] === 'string' ? (data[key] as string) : '');
  const host = context.site ? hostOfUrl(context.site) : '';
  const parts: string[] = [t(kindLabel(item.kind))];
  switch (item.kind) {
    case 'login':
      parts.push(text('username'));
      break;
    case 'otp': {
      parts.push(host);
      // A counter code has no period; a code whose secret can't be read has no settings at all.
      const params = otpParamsOf(data);
      if (params && params.type !== 'hotp') parts.push(t('detail.links.every', { seconds: params.period }));
      break;
    }
    case 'backup-codes': {
      const codes = backupCodesOf(item.data);
      parts.push(host || text('serviceName'));
      parts.push(t('detail.links.codes', { total: codes.length, unused: codes.filter((c) => !c.used).length }));
      break;
    }
    case 'passkey':
      parts.push(text('rpId') || host);
      break;
    case 'card': {
      const digits = text('number');
      parts.push(text('brand'), digits.length >= 4 ? `•••• ${digits.slice(-4)}` : '');
      break;
    }
    case 'identity':
    case 'contact':
      parts.push(text('email') || text('company'));
      break;
    case 'file': {
      const file = fileOf(item.data);
      parts.push(file ? context.size(file.size) : '');
      break;
    }
    default:
      break;
  }
  if (isTrashed(item)) parts.push(t('detail.links.trashed'));
  return parts.filter((part) => part !== '').join(' · ');
}

function Entry({ item, all }: { item: VaultItem; all: readonly VaultItem[] }) {
  const t = useT();
  const size = useFormatSize();
  const site = siteInfoOf(item, all)?.urls[0];
  return (
    <>
      <span className="linked-icon" aria-hidden="true">
        <Icon name={kindIcon(item.kind)} />
      </span>
      <span className="linked-text">
        <span className="linked-name">{itemName(item)}</span>
        <span className="linked-sub">{sublineOf(item, t, { size, site })}</span>
      </span>
    </>
  );
}

function Picker({
  item,
  all,
  canWrite,
  onPick,
  onClose,
}: {
  item: VaultItem;
  all: readonly VaultItem[];
  canWrite: (candidate: VaultItem) => boolean;
  onPick: (candidate: VaultItem) => Promise<void>;
  onClose: () => void;
}) {
  const t = useT();
  const searchId = useId();
  const [query, setQuery] = useState('');
  const [pending, setPending] = useState(false);
  const [failure, setFailure] = useState<unknown>(undefined);
  const results = pickableItems(item, all, query, canWrite);
  const error = failure === undefined ? undefined : describeError(failure);

  async function pick(candidate: VaultItem) {
    setPending(true);
    setFailure(undefined);
    try {
      await onPick(candidate);
      onClose();
    } catch (caught) {
      setFailure(caught);
      setPending(false);
    }
  }

  return (
    <AppDialog
      isOpen
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      isDismissable={!pending}
      title={t('detail.links.add')}
      icon="link"
      footer={
        <Button isDisabled={pending} onPress={onClose}>
          {t('action.cancel')}
        </Button>
      }
    >
      <div className="field">
        <label htmlFor={searchId}>{t('detail.links.search')}</label>
        <input
          id={searchId}
          type="search"
          autoComplete="off"
          // The person came here to search: the search box is where typing starts.
          autoFocus
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      {results.length === 0 ? (
        <p className="muted" role="status">
          {t('detail.links.pickNone')}
        </p>
      ) : (
        <ul className="picker" aria-label={t('detail.links.results')}>
          {results.map((candidate) => (
            <li key={candidate.id}>
              <button
                type="button"
                className="linked-row picker-item"
                disabled={pending}
                aria-label={t('detail.links.pick', { name: itemName(candidate) })}
                onClick={() => void pick(candidate)}
              >
                <Entry item={candidate} all={all} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </AppDialog>
  );
}

export function LinkedItems({
  item,
  all,
  canWrite,
  onLink,
  onUnlink,
  readOnly = false,
}: {
  item: VaultItem;
  all: readonly VaultItem[];
  /** Whether this person may change an item: a link writes both ends. */
  canWrite: (candidate: VaultItem) => boolean;
  onLink: (other: VaultItem) => Promise<void>;
  onUnlink: (other: VaultItem) => Promise<void>;
  /** The item is in the Trash, can't be read or can't be changed by this person: it lists its links and changes none. */
  readOnly?: boolean;
}) {
  const t = useT();
  const card = useRef<HTMLElement>(null);
  const [picking, setPicking] = useState(false);
  const [failure, setFailure] = useState<unknown>(undefined);
  // The items being unlinked, so a second press on the same one can't write it twice.
  const [unlinking, setUnlinking] = useState<ReadonlySet<string>>(new Set());
  // After an unlink the focus would fall with the row: it goes to the next Unlink, or to Link an item.
  const [refocus, setRefocus] = useState<{ id: string; index: number } | null>(null);
  const linked = connectedItems(item, all);
  const error = failure === undefined ? undefined : describeError(failure);
  // Only an item that can be read and changed has its end written.
  const unlinkable = (other: VaultItem) => !readOnly && other.data !== null && canWrite(other);

  useEffect(() => {
    if (!refocus || linked.some((other) => other.id === refocus.id)) return;
    const buttons = card.current?.querySelectorAll<HTMLElement>('[data-unlink]');
    const next = buttons && buttons.length > 0 ? buttons[Math.min(refocus.index, buttons.length - 1)] : undefined;
    (next ?? card.current?.querySelector<HTMLElement>('[data-link-add]'))?.focus();
    setRefocus(null);
  });

  async function unlink(other: VaultItem, index: number) {
    if (unlinking.has(other.id)) return;
    setUnlinking((held) => new Set(held).add(other.id));
    setFailure(undefined);
    try {
      await onUnlink(other);
      setRefocus({ id: other.id, index });
    } catch (caught) {
      setFailure(caught);
    } finally {
      setUnlinking((held) => {
        const rest = new Set(held);
        rest.delete(other.id);
        return rest;
      });
    }
  }

  return (
    <section ref={card} className="card pad linked" aria-labelledby="h-links">
      <div className="linked-head">
        <span className="linked-head-icon" aria-hidden="true">
          <Icon name="link" />
        </span>
        <h2 id="h-links">{t('detail.links.title')}</h2>
        {readOnly ? null : (
          <Button size="small" data-link-add="" onPress={() => setPicking(true)}>
            {t('detail.links.add')}
          </Button>
        )}
      </div>
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      {linked.length === 0 ? (
        <p className="muted">{t('detail.links.none')}</p>
      ) : (
        <ul className="linked-list">
          {linked.map((other, index) => (
            <li key={other.id} className="linked-row">
              <Link to="/vault/$itemId" params={{ itemId: other.id }} className="linked-link">
                <Entry item={other} all={all} />
              </Link>
              {unlinkable(other) ? (
                <IconButton
                  data-unlink=""
                  aria-label={t('detail.links.unlink', { name: itemName(other) })}
                  isDisabled={unlinking.has(other.id)}
                  onPress={() => void unlink(other, index)}
                >
                  <Icon name="close" />
                </IconButton>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {picking ? (
        <Picker item={item} all={all} canWrite={canWrite} onPick={onLink} onClose={() => setPicking(false)} />
      ) : null}
    </section>
  );
}
