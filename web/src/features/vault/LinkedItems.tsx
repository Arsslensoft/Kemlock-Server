// The "Linked items" card of the item page: every item linked to this one (icon, name, type and a
// line about it) as a link to that item, an Unlink button on each, and "Link an item", which opens
// a picker that searches the vault. A link is two-way (links.ts): linking and unlinking write both
// items, so the other item shows this one too.
import { Link } from '@tanstack/react-router';
import { useId, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { AppDialog } from '@/ui/AppDialog';
import { Button, IconButton } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/item.css';
import { backupCodesOf } from './details/KindDetails';
import { formatSize, fileOf } from './details/files';
import { hostOfUrl, kindIcon, kindLabel } from './kinds';
import { linkCandidates, linkedItems } from './links';
import { type ItemData, type VaultItem, isTrashed, itemName } from './vault';
import { readWebsites } from './websites';

type T = (id: MessageId, values?: Record<string, string | number>) => string;

/** What to say about an item under its name: its type, then one fact about it. */
export function sublineOf(item: VaultItem, t: T): string {
  const data: ItemData = item.data ?? {};
  const text = (key: string) => (typeof data[key] === 'string' ? (data[key] as string) : '');
  const site = readWebsites(item.data)[0]?.uri;
  const parts: string[] = [t(kindLabel(item.kind))];
  switch (item.kind) {
    case 'login':
      parts.push(text('username'));
      break;
    case 'otp': {
      if (site) parts.push(hostOfUrl(site));
      const period = typeof data['period'] === 'number' ? data['period'] : 30;
      parts.push(t('detail.links.every', { seconds: period }));
      break;
    }
    case 'backup-codes': {
      const codes = backupCodesOf(item.data);
      parts.push(site ? hostOfUrl(site) : text('serviceName'));
      parts.push(t('detail.links.codes', { total: codes.length, unused: codes.filter((c) => !c.used).length }));
      break;
    }
    case 'passkey':
      parts.push(text('rpId') || (site ? hostOfUrl(site) : ''));
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
      parts.push(file ? formatSize(file.size) : '');
      break;
    }
    default:
      break;
  }
  if (isTrashed(item)) parts.push(t('detail.links.trashed'));
  return parts.filter((part) => part !== '').join(' · ');
}

function Entry({ item }: { item: VaultItem }) {
  const t = useT();
  return (
    <>
      <span className="linked-icon" aria-hidden="true">
        <Icon name={kindIcon(item.kind)} />
      </span>
      <span className="linked-text">
        <span className="linked-name">{itemName(item)}</span>
        <span className="linked-sub">{sublineOf(item, t)}</span>
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
  const results = linkCandidates(item, all, query, canWrite);
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
                <Entry item={candidate} />
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
  /** The item is in the Trash or can't be read: it lists its links and changes none. */
  readOnly?: boolean;
}) {
  const t = useT();
  const [picking, setPicking] = useState(false);
  const [failure, setFailure] = useState<unknown>(undefined);
  const linked = linkedItems(item, all);
  const error = failure === undefined ? undefined : describeError(failure);

  async function unlink(other: VaultItem) {
    setFailure(undefined);
    try {
      await onUnlink(other);
    } catch (caught) {
      setFailure(caught);
    }
  }

  return (
    <section className="card pad linked" aria-labelledby="h-links">
      <div className="linked-head">
        <span className="linked-head-icon" aria-hidden="true">
          <Icon name="link" />
        </span>
        <h2 id="h-links">{t('detail.links.title')}</h2>
        {readOnly ? null : (
          <Button size="small" onPress={() => setPicking(true)}>
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
          {linked.map((other) => (
            <li key={other.id} className="linked-row">
              <Link to="/vault/$itemId" params={{ itemId: other.id }} className="linked-link">
                <Entry item={other} />
              </Link>
              {readOnly ? null : (
                <IconButton
                  aria-label={t('detail.links.unlink', { name: itemName(other) })}
                  onPress={() => void unlink(other)}
                >
                  <Icon name="close" />
                </IconButton>
              )}
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
