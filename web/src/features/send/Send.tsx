// Send (canvas: Send): share a text, a small file or an item of the vault through a link. It is encrypted in this
// browser and the key travels after the `#` in the link, which never reaches the server.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { createSendsApi } from '@/api/sends';
import type { SendDto, SendKind } from '@/api/sends';
import { ApiError } from '@/api/errors';
import { api } from '@/app/services';
import { type CryptoPort, vaultCrypto } from '@/crypto-port';
import { copyText } from '@/lib/clipboard';
import { decodeB64 } from '@/lib/b64url';
import { readBytes } from '@/lib/files';
import { describeError } from '@/lib/errors';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/tools.css';
import { useVault } from '@/features/vault/hooks';
import { EDITABLE_KINDS, type EditableKind, kindIcon, kindLabel, timeAgo } from '@/features/vault/kinds';
import { type VaultItem, itemName } from '@/features/vault/vault';
import { MAX_ENVELOPE_CHARS, buildEnvelope, parseEnvelope, serializeEnvelope } from './itemEnvelope';
import { SendItemPicker } from './SendItemPicker';
import { MAX_FILE_BYTES, type SendInput, makeSend, openOwnerView, parsePayload, sendLink } from './sendCrypto';

export interface SendRow {
  id: string;
  name: string;
  kind: SendKind;
  viewCount: number;
  maxViews: number | null;
  size: number | null;
  hasPassword: boolean;
  expiresAt: string;
  /** null when the owner's copy of the key could not be opened. */
  link: string | null;
  /** The kind of the item an item Send carries, found by opening its payload here; else absent. */
  itemKind?: EditableKind;
}

export function isSpent(row: SendRow, now: Date): boolean {
  if (new Date(row.expiresAt).getTime() <= now.getTime()) return true;
  return row.maxViews !== null && row.viewCount >= row.maxViews;
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export interface SendFormValues {
  kind: SendKind;
  name: string;
  text: string;
  file?: { name: string; mime: string; bytes: Uint8Array } | undefined;
  deleteAfterDays: number;
  maxViews: number | null;
  password: string;
  hideEmail: boolean;
}

type Described = { id: MessageId; values?: Record<string, string | number> } | undefined;

export function SendView({
  rows,
  now,
  onCreate,
  creating,
  createdLink,
  onCopy,
  copiedId,
  onDelete,
  error,
  loading,
  items = [],
}: {
  rows: SendRow[];
  now: Date;
  onCreate: (values: SendFormValues) => void;
  creating?: boolean;
  createdLink?: string | undefined;
  onCopy: (row: SendRow) => void;
  copiedId?: string | undefined;
  onDelete: (row: SendRow) => void;
  error?: Described;
  loading?: boolean;
  /** The vault's active items, to send one of them. */
  items?: VaultItem[];
}) {
  const t = useT();
  // Text and file are Send kinds; a kind of the vault sends an item, as a text Send.
  const [mode, setMode] = useState<'text' | 'file' | EditableKind>('text');
  const [itemId, setItemId] = useState<string | undefined>(undefined);
  const chosen = mode === 'text' || mode === 'file' ? undefined : items.find((item) => item.id === itemId && item.kind === mode);
  const kind: SendKind = mode === 'file' ? 'file' : 'text';
  const [name, setName] = useState('');
  const [text, setText] = useState('');
  const [file, setFile] = useState<SendFormValues['file']>(undefined);
  const [days, setDays] = useState(7);
  const [views, setViews] = useState('');
  const [password, setPassword] = useState('');
  const [hideEmail, setHideEmail] = useState(true);
  const [fileError, setFileError] = useState(false);
  const [itemError, setItemError] = useState(false);
  const parsedViews = views.trim() === '' ? null : Number.parseInt(views, 10);
  const viewsValid = parsedViews === null || (Number.isInteger(parsedViews) && parsedViews >= 1);
  const ready = name.trim() !== '' && viewsValid && (mode === 'file' ? file !== undefined : mode === 'text' ? text !== '' : chosen !== undefined);

  return (
    <>
      <div>
        <h1 className="page-title">{t('send.title')}</h1>
        <p className="lede">{t('send.lede')}</p>
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      <div className="two-col">
        <section className="card" aria-labelledby="h-list">
          <div className="card-head">
            <h2 id="h-list">{t('send.yours')}</h2>
          </div>
          {loading ? (
            <p className="empty" role="status">
              {t('state.loading')}
            </p>
          ) : rows.length === 0 ? (
            <p className="empty">{t('send.none')}</p>
          ) : (
            rows.map((row) => {
              const spent = isSpent(row, now);
              const parts = [
                row.kind === 'file'
                  ? t('send.fileSize', { size: formatSize(row.size ?? 0) })
                  : row.itemKind
                    ? t(kindLabel(row.itemKind))
                    : t('send.kind.text'),
                row.maxViews === null
                  ? t('send.views', { count: row.viewCount })
                  : t('send.viewsOf', { count: row.viewCount, max: row.maxViews }),
                row.hasPassword ? t('send.password') : '',
                spent ? t('send.spent') : t('send.deletes', { when: timeAgo(row.expiresAt, now) }),
              ].filter((part) => part !== '');
              return (
                <div className="row" key={row.id}>
                  <span className="tile" aria-hidden="true">
                    <Icon name={row.itemKind ? kindIcon(row.itemKind) : row.kind === 'file' ? 'note' : 'send'} />
                  </span>
                  <div className="grow">
                    <div>{row.name}</div>
                    <div className="hint">{parts.join(' · ')}</div>
                  </div>
                  {spent ? <span className="tag">{t('send.expired')}</span> : null}
                  {!spent && row.link ? (
                    <Button
                      size="small"
                      aria-label={t('send.copyLinkFor', { name: row.name })}
                      onPress={() => onCopy(row)}
                    >
                      {copiedId === row.id ? t('copy.done') : t('send.copyLink')}
                    </Button>
                  ) : null}
                  <Button
                    size="small"
                    aria-label={t('send.deleteFor', { name: row.name })}
                    onPress={() => onDelete(row)}
                  >
                    {t('send.delete')}
                  </Button>
                </div>
              );
            })
          )}
        </section>

        <section className="card pad" aria-labelledby="h-new">
          <h2 id="h-new">{t('send.new')}</h2>
          <form
            className="stack"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              if (!ready) return;
              const envelope = chosen ? buildEnvelope(chosen, itemName(chosen)) : null;
              const sealedText = envelope ? serializeEnvelope(envelope) : '';
              // An item that did not open, or is too large to send, can't be made into a Send.
              setItemError(chosen !== undefined && (!envelope || sealedText.length > MAX_ENVELOPE_CHARS));
              if (chosen && (!envelope || sealedText.length > MAX_ENVELOPE_CHARS)) return;
              onCreate({
                kind,
                name: name.trim(),
                text: envelope ? sealedText : text,
                file,
                deleteAfterDays: days,
                maxViews: parsedViews,
                password,
                hideEmail,
              });
            }}
          >
            <div className="chips" role="group" aria-label={t('send.type')}>
              {(['text', 'file', ...EDITABLE_KINDS] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  className="chip"
                  aria-pressed={mode === value}
                  onClick={() => {
                    setMode(value);
                    setItemId(undefined);
                    setItemError(false);
                  }}
                >
                  {t(value === 'text' ? 'send.kind.text' : value === 'file' ? 'send.kind.file' : kindLabel(value))}
                </button>
              ))}
            </div>
            <div className="field">
              <label htmlFor="s-name">{t('send.name')}</label>
              <input id="s-name" type="text" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            {mode !== 'text' && mode !== 'file' ? (
              <SendItemPicker
                items={items}
                kind={mode}
                selectedId={chosen?.id}
                onSelect={(item) => {
                  setItemId(item?.id);
                  if (item && name.trim() === '') setName(itemName(item));
                }}
              />
            ) : mode === 'text' ? (
              <div className="field">
                <label htmlFor="s-text">{t('send.text')}</label>
                <textarea id="s-text" value={text} onChange={(e) => setText(e.target.value)} />
              </div>
            ) : (
              <div className="field">
                <label htmlFor="s-file">{t('send.file')}</label>
                <input
                  id="s-file"
                  type="file"
                  onChange={(event) => {
                    const chosen = event.target.files?.[0];
                    setFileError(false);
                    if (!chosen) {
                      setFile(undefined);
                      return;
                    }
                    if (chosen.size > MAX_FILE_BYTES) {
                      setFile(undefined);
                      setFileError(true);
                      return;
                    }
                    void readBytes(chosen).then((bytes) =>
                      setFile({
                        name: chosen.name,
                        mime: chosen.type || 'application/octet-stream',
                        bytes,
                      }),
                    );
                  }}
                />
                <span className="hint">{t('send.fileLimit', { size: formatSize(MAX_FILE_BYTES) })}</span>
                {fileError ? (
                  <span className="field-error" role="alert">
                    {t('send.fileTooBig', { size: formatSize(MAX_FILE_BYTES) })}
                  </span>
                ) : null}
              </div>
            )}
            <div className="send-options">
              <div className="field">
                <label htmlFor="s-exp">{t('send.deleteAfter')}</label>
                <select id="s-exp" value={days} onChange={(e) => setDays(Number.parseInt(e.target.value, 10))}>
                  <option value={1}>{t('send.days', { count: 1 })}</option>
                  <option value={7}>{t('send.days', { count: 7 })}</option>
                  <option value={30}>{t('send.days', { count: 30 })}</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="s-max">{t('send.maxViews')}</label>
                <input
                  id="s-max"
                  type="number"
                  min={1}
                  inputMode="numeric"
                  value={views}
                  placeholder={t('send.noLimit')}
                  onChange={(e) => setViews(e.target.value)}
                />
                {!viewsValid ? (
                  <span className="field-error" role="alert">
                    {t('send.maxViewsInvalid')}
                  </span>
                ) : null}
              </div>
              <div className="field">
                <label htmlFor="s-pw">{t('send.passwordOptional')}</label>
                <input
                  id="s-pw"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>
            <div className="check-row">
              <input
                id="s-hide"
                type="checkbox"
                checked={hideEmail}
                onChange={(e) => setHideEmail(e.target.checked)}
              />
              <label htmlFor="s-hide">{t('send.hideEmail')}</label>
            </div>
            {itemError ? (
              <Notice tone="error" live>
                <p>{t('sendItem.unreadable')}</p>
              </Notice>
            ) : null}
            <Button type="submit" variant="primary" isDisabled={creating || !ready}>
              {t('send.create')}
            </Button>
          </form>
          {createdLink ? (
            <div className="stack" role="status">
              <p className="lbl">{t('send.linkMade')}</p>
              <p className="mono link-box">{createdLink}</p>
              <p className="hint">{t('send.linkHint')}</p>
            </div>
          ) : null}
        </section>
      </div>
    </>
  );
}

const sendsApi = createSendsApi(api);
const sendsKey = ['sends'] as const;

/**
 * The kind of item a text Send carries: its payload is opened here with the link key and read as an
 * item envelope. Only the kind is kept; nothing is fetched and the text goes no further.
 */
async function itemKindOf(
  send: SendDto,
  linkKey: string,
  worker: Pick<CryptoPort, 'openSendPayload'>,
): Promise<EditableKind | undefined> {
  if (send.kind !== 'text' || !send.payload) return undefined;
  try {
    const raw = await worker.openSendPayload({
      id: send.id,
      kind: send.kind,
      linkKey,
      sealed: decodeB64(send.payload),
    });
    const payload = parsePayload('text', raw);
    return payload?.kind === 'text' ? (parseEnvelope(payload.text)?.kind ?? undefined) : undefined;
  } catch {
    return undefined;
  }
}

/** Opens the owner's copy of each Send's key and name, and builds its link. */
export async function rowsFrom(
  sends: SendDto[],
  origin: string,
  worker: Pick<CryptoPort, 'unwrapSendKey' | 'openSendMeta' | 'openSendPayload'>,
): Promise<SendRow[]> {
  const rows: SendRow[] = [];
  for (const send of sends) {
    const opened = await openOwnerView(send, worker);
    const itemKind = opened ? await itemKindOf(send, opened.key, worker) : undefined;
    rows.push({
      id: send.id,
      name: opened?.name ?? send.id,
      kind: send.kind,
      viewCount: send.accessCount,
      maxViews: send.maxAccess,
      size: send.file?.size ?? null,
      hasPassword: send.hasPassword,
      expiresAt: new Date(send.deletionAt * 1000).toISOString(),
      link: opened ? sendLink(origin, send.accessId, opened.key) : null,
      ...(itemKind ? { itemKind } : {}),
    });
  }
  return rows;
}

/** The words for what a Send's own failures mean; the rest is described as everywhere else. */
function describeSendError(error: unknown): Described {
  if (error instanceof ApiError && error.slug === 'send-policy') return { id: 'send.policy' };
  return describeError(error);
}

export default function Send() {
  const client = useQueryClient();
  const vault = useVault();
  const [created, setCreated] = useState<string | undefined>(undefined);
  const [copied, setCopied] = useState<string | undefined>(undefined);
  const list = useQuery({
    queryKey: sendsKey,
    queryFn: async () => rowsFrom(await sendsApi.list(), window.location.origin, vaultCrypto),
  });
  const create = useMutation({
    mutationFn: async (values: SendFormValues) => {
      const input: SendInput = {
        kind: values.kind,
        name: values.name,
        text: values.text,
        deleteAfterDays: values.deleteAfterDays,
        maxViews: values.maxViews,
        password: values.password,
        hideEmail: values.hideEmail,
      };
      if (values.file) input.file = values.file;
      const made = await makeSend(input, { crypto: vaultCrypto });
      const send = await sendsApi.create(made.request);
      if (made.upload) await sendsApi.upload(send.id, made.upload);
      return sendLink(window.location.origin, send.accessId, made.key);
    },
    onSuccess: (link) => {
      setCreated(link);
      void client.invalidateQueries({ queryKey: sendsKey });
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => sendsApi.remove(id),
    onSuccess: () => client.invalidateQueries({ queryKey: sendsKey }),
  });
  const failure = create.error ?? remove.error ?? list.error;
  return (
    <SendView
      rows={list.data ?? []}
      items={vault.active}
      now={new Date()}
      loading={list.isPending}
      creating={create.isPending}
      createdLink={created}
      copiedId={copied}
      error={failure ? describeSendError(failure) : undefined}
      onCreate={(values) => create.mutate(values)}
      onDelete={(row) => remove.mutate(row.id)}
      onCopy={(row) => {
        if (!row.link) return;
        void copyText(row.link, {}).then((ok) => {
          if (ok) setCopied(row.id);
        });
      }}
    />
  );
}
