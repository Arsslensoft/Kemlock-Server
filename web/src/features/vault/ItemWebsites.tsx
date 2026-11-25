// The websites of a login, each with its own match rule (canvas: ItemWebsites). The list and its
// rules are part of the item's ciphertext: the server sees nothing of them.
import { Link, useCanGoBack, useNavigate, useParams, useRouter } from '@tanstack/react-router';
import { useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Button, IconButton, buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/tools.css';
import '@/styles/item.css';
import { useVaultActions, useVaultItem } from './hooks';
import { itemName } from './vault';
import {
  MATCH_RULES,
  type MatchRule,
  type WebsiteRule,
  hintOf,
  isRisky,
  phoneDomains,
  readWebsites,
  ruleLabel,
  writeWebsites,
} from './websites';
import { hostOfWebsite } from '@/lib/psl';

export interface WebsiteRow extends WebsiteRule {
  /** Stable while the row exists, so editing one doesn't move focus to another. */
  key: number;
}

type Described = { id: MessageId; values?: Record<string, string | number> } | undefined;

export function WebsitesView({
  name,
  rows,
  onChange,
  onSave,
  onCancel,
  pending,
  error,
}: {
  name: string;
  rows: WebsiteRow[];
  onChange: (rows: WebsiteRow[]) => void;
  onSave: () => void;
  onCancel: () => void;
  pending?: boolean;
  error?: Described;
}) {
  const t = useT();
  const update = (key: number, patch: Partial<WebsiteRule>) =>
    onChange(rows.map((row) => (row.key === key ? { ...row, ...patch } : row)));
  const add = () => {
    const next = rows.reduce((max, row) => Math.max(max, row.key), 0) + 1;
    onChange([...rows, { key: next, uri: '', match: 'default' }]);
  };
  const phones = phoneDomains(rows);
  const filled = rows.filter((row) => row.uri.trim() !== '');
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t('sites.title', { name })}</h1>
          <p className="lede">{t('sites.lede', { count: filled.length })}</p>
        </div>
        <div className="item-actions">
          <Button onPress={onCancel}>{t('action.cancel')}</Button>
          <Button variant="primary" isDisabled={pending} onPress={onSave}>
            {t('action.save')}
          </Button>
        </div>
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      <div className="two-col">
        <section className="card" aria-labelledby="h-sites">
          <div className="card-head">
            <h2 id="h-sites">{t('sites.websites')}</h2>
            <span className="hint">{t('sites.mostlyDefault')}</span>
          </div>
          {rows.map((row, index) => {
            const hint = hintOf(row);
            const n = index + 1;
            return (
              <div className="website-row" key={row.key}>
                <div className="field">
                  <label htmlFor={`w-uri-${row.key}`}>{t('sites.website', { n })}</label>
                  <input
                    id={`w-uri-${row.key}`}
                    className="mono"
                    type="text"
                    value={row.uri}
                    placeholder="example.co"
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(event) => update(row.key, { uri: event.target.value })}
                  />
                </div>
                <div className="field">
                  <label htmlFor={`w-rule-${row.key}`}>{t('sites.match', { n })}</label>
                  <select
                    id={`w-rule-${row.key}`}
                    value={row.match}
                    onChange={(event) => update(row.key, { match: event.target.value as MatchRule })}
                  >
                    {MATCH_RULES.filter((rule) => !isRisky(rule)).map((rule) => (
                      <option key={rule} value={rule}>
                        {t(ruleLabel(rule))}
                      </option>
                    ))}
                    <optgroup label={t('sites.moreRules')}>
                      {MATCH_RULES.filter(isRisky).map((rule) => (
                        <option key={rule} value={rule}>
                          {t(ruleLabel(rule))}
                        </option>
                      ))}
                    </optgroup>
                  </select>
                </div>
                <IconButton
                  aria-label={t('sites.remove', { site: row.uri === '' ? t('sites.thisWebsite') : row.uri })}
                  onPress={() => onChange(rows.filter((r) => r.key !== row.key))}
                >
                  <Icon name="trash" />
                </IconButton>
                <div className="website-hint">
                  <p className="hint">{t(hint.id, hint.values)}</p>
                  {isRisky(row.match) ? (
                    <p className="warn-line">
                      <Icon name="alert" />
                      {t('sites.risky')}
                    </p>
                  ) : null}
                </div>
              </div>
            );
          })}
          <div className="row">
            <Button size="small" onPress={add}>
              <Icon name="plus" />
              {t('sites.add')}
            </Button>
            <span className="hint">{t('sites.defaultNote')}</span>
          </div>
        </section>

        <div className="stack">
          <section className="card" aria-labelledby="h-view">
            <div className="card-head">
              <h2 id="h-view">{t('sites.preview')}</h2>
              <span className="hint">{t('sites.previewCount', { count: filled.length })}</span>
            </div>
            {filled.map((row) => {
              const hint = hintOf(row);
              return (
                <div className="row" key={row.key}>
                  <Icon name="globe" />
                  <div className="grow">
                    <div className="mono">{hostOfWebsite(row.uri) || row.uri}</div>
                    <div className="hint">{t(hint.id, hint.values)}</div>
                  </div>
                  <span className="tag">{t(ruleLabel(row.match))}</span>
                </div>
              );
            })}
            <div className="row">
              <Icon name="device" />
              <div className="grow">
                <div className="lbl">{t('sites.phones')}</div>
                <div>{phones.length > 0 ? phones.join(', ') : t('sites.nowhere')}</div>
                <div className="hint">{t('sites.phonesNote')}</div>
              </div>
            </div>
          </section>

          <section className="card pad" aria-labelledby="h-apps">
            <h2 id="h-apps">{t('sites.apps')}</h2>
            <dl className="defs">
              <dt>{t('sites.apps.kemlock')}</dt>
              <dd>{t('sites.apps.kemlockBody')}</dd>
              <dt>{t('sites.apps.bitwarden')}</dt>
              <dd>{t('sites.apps.bitwardenBody')}</dd>
              <dt>{t('sites.apps.older')}</dt>
              <dd>{t('sites.apps.olderBody')}</dd>
              <dt>{t('sites.apps.server')}</dt>
              <dd>{t('sites.apps.serverBody')}</dd>
            </dl>
          </section>
        </div>
      </div>
    </>
  );
}

function rowsOf(rules: WebsiteRule[]): WebsiteRow[] {
  return rules.map((rule, index) => ({ ...rule, key: index + 1 }));
}

export default function ItemWebsites() {
  const t = useT();
  const navigate = useNavigate();
  const router = useRouter();
  const canGoBack = useCanGoBack();
  const { itemId } = useParams({ strict: false }) as { itemId?: string };
  const { item, isLoading } = useVaultItem(itemId);
  const { save } = useVaultActions();
  // Edited rows live here once the person starts; until then they are the item's own.
  const [edited, setEdited] = useState<WebsiteRow[] | undefined>(undefined);

  if (isLoading) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  if (!item || item.kind !== 'login') {
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
  const rows = edited ?? rowsOf(readWebsites(item.data));
  const toItem = () => void navigate({ to: '/vault/$itemId', params: { itemId: item.id }, replace: true });
  const cancel = () => (canGoBack ? router.history.back() : toItem());
  return (
    <WebsitesView
      name={itemName(item)}
      rows={rows}
      onChange={setEdited}
      onCancel={cancel}
      pending={save.isPending}
      error={save.error ? describeError(save.error) : undefined}
      onSave={() =>
        save.mutate(
          { existing: item, kind: item.kind, owner: item.owner, fields: writeWebsites(rows) },
          { onSuccess: toItem },
        )
      }
    />
  );
}
