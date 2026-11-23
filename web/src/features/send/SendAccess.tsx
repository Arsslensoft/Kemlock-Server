// The page a Send's link opens (`/#/send/<accessId>/<key>`): no account, no sign-in. It asks the
// server for the sealed payload, asks the person for the password when the Send has one, and opens
// everything here with the key from the link's fragment. The key never goes to the server.
import { type ReactNode, useEffect, useState } from 'react';
import { createSendAccessApi } from '@/api/sends';
import { api } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { type MessageId, useT } from '@/i18n';
import { copyText } from '@/lib/clipboard';
import { Button } from '@/ui/Button';
import { Icon, Logo } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { SourceLink } from '@/ui/SourceLink';
import '@/styles/about.css';
import { formatSize } from './Send';
import {
  type FileResult,
  type OpenedSend,
  type RecipientDeps,
  type RecipientResult,
  type SendLink,
  downloadFile,
  openSend,
} from './recipient';

type Described = { id: MessageId; values?: Record<string, string | number> };

/** What the screen shows, from the last answer. */
export type AccessState =
  | { phase: 'opening' }
  | { phase: 'bad-link' }
  | { phase: 'password'; wrong: boolean; error?: Described | undefined }
  | { phase: 'unavailable' }
  | { phase: 'failed'; error: Described }
  | { phase: 'opened'; send: OpenedSend };

export function stateOf(result: RecipientResult): AccessState {
  switch (result.state) {
    case 'opened':
      return { phase: 'opened', send: result.send };
    case 'password':
      return { phase: 'password', wrong: result.wrong };
    case 'unavailable':
      return { phase: 'unavailable' };
    case 'rate-limited':
      return {
        phase: 'password',
        wrong: false,
        error:
          result.seconds === undefined
            ? { id: 'sendAccess.rateLimitedNow' }
            : { id: 'sendAccess.rateLimited', values: { seconds: result.seconds } },
      };
    case 'failed':
      return { phase: 'failed', error: { id: 'sendAccess.failed' } };
  }
}

function Frame({ children }: { children: ReactNode }) {
  const t = useT();
  return (
    <div className="auth-page">
      <div className="brand">
        <Logo />
        <span className="name">Kemlock</span>
        <span className="tag-chip">{t('brand.server')}</span>
      </div>
      <main className="auth-card w600">{children}</main>
      <p className="hint">{t('sendAccess.footer')}</p>
      {/* Outside the router (Root renders this page on its own), so a plain link, not LegalLinks. */}
      <nav className="legal-links" aria-label={t('about.nav')}>
        <SourceLink />
        <a href="/about">{t('about.link')}</a>
      </nav>
    </div>
  );
}

export function SendAccessView({
  state,
  onPassword,
  onDownload,
  onCopy,
  fileError,
  downloading,
  copied,
}: {
  state: AccessState;
  onPassword: (password: string) => void;
  onDownload: () => void;
  onCopy: (text: string) => void;
  fileError?: Described | undefined;
  downloading?: boolean;
  copied?: boolean;
}) {
  const t = useT();
  const [password, setPassword] = useState('');
  return (
    <Frame>
      {state.phase === 'opening' ? (
        <p role="status">{t('sendAccess.opening')}</p>
      ) : state.phase === 'bad-link' ? (
        <>
          <h1>{t('sendAccess.badLink.title')}</h1>
          <p className="lede">{t('sendAccess.badLink.body')}</p>
        </>
      ) : state.phase === 'unavailable' ? (
        <>
          <h1>{t('sendAccess.unavailable.title')}</h1>
          <p className="lede">{t('sendAccess.unavailable.body')}</p>
        </>
      ) : state.phase === 'failed' ? (
        <Notice tone="error" live>
          <p>{t(state.error.id, state.error.values)}</p>
        </Notice>
      ) : state.phase === 'password' ? (
        <form
          className="stack"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            if (password !== '') onPassword(password);
          }}
        >
          <div>
            <h1>{t('sendAccess.password.title')}</h1>
            <p className="lede">{t('sendAccess.password.lede')}</p>
          </div>
          <div className="field">
            <label htmlFor="send-access-password">{t('sendAccess.password.label')}</label>
            <input
              id="send-access-password"
              type="password"
              autoComplete="off"
              autoFocus
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            {state.wrong ? (
              <span className="field-error" role="alert">
                {t('sendAccess.password.wrong')}
              </span>
            ) : null}
          </div>
          {state.error ? (
            <Notice tone="error" live>
              <p>{t(state.error.id, state.error.values)}</p>
            </Notice>
          ) : null}
          <Button type="submit" variant="primary" size="large" block isDisabled={password === ''}>
            {t('sendAccess.password.open')}
          </Button>
        </form>
      ) : (
        <Opened
          send={state.send}
          onDownload={onDownload}
          onCopy={onCopy}
          fileError={fileError}
          downloading={downloading}
          copied={copied}
        />
      )}
    </Frame>
  );
}

function Opened({
  send,
  onDownload,
  onCopy,
  fileError,
  downloading,
  copied,
}: {
  send: OpenedSend;
  onDownload: () => void;
  onCopy: (text: string) => void;
  fileError?: Described | undefined;
  downloading?: boolean | undefined;
  copied?: boolean | undefined;
}) {
  const t = useT();
  const { payload } = send;
  return (
    <div className="stack">
      <div>
        <h1>{payload.name}</h1>
        <p className="lede">{t('sendAccess.lede')}</p>
      </div>
      {payload.kind === 'text' ? (
        <div className="field">
          <span className="lbl" id="send-access-text-label">
            {t('sendAccess.text.label')}
          </span>
          <pre className="mono link-box" aria-labelledby="send-access-text-label">
            {payload.text}
          </pre>
          <Button size="small" onPress={() => onCopy(payload.text)}>
            {copied ? t('copy.done') : t('sendAccess.copy')}
          </Button>
        </div>
      ) : (
        <div className="stack">
          <p className="hint">
            {t('sendAccess.file.size', { size: formatSize(payload.size), mime: payload.mime })}
          </p>
          <Button variant="primary" size="large" isDisabled={downloading} onPress={onDownload}>
            <Icon name="note" />
            {t('sendAccess.file.download', { name: payload.name })}
          </Button>
          {fileError ? (
            <Notice tone="error" live>
              <p>{t(fileError.id, fileError.values)}</p>
            </Notice>
          ) : null}
        </div>
      )}
      <p className="hint">
        {[
          send.senderEmail ? t('sendAccess.from', { email: send.senderEmail }) : '',
          t('sendAccess.deletes', { date: new Date(send.deletionAt * 1000).toLocaleDateString() }),
        ]
          .filter((part) => part !== '')
          .join(' ')}
      </p>
    </div>
  );
}

const realDeps: RecipientDeps = { access: createSendAccessApi(api), crypto: vaultCrypto };

/** Hands the decrypted bytes to the browser as a download. Nothing is kept afterwards. */
export function saveFile(name: string, mime: string, bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: mime }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.rel = 'noopener';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const NOOP = () => undefined;

// StrictMode runs an effect twice in development, and each open counts as a view of the Send, so
// the first open of a link is shared by whoever asks for it while the screen is mounted.
const firstOpens = new WeakMap<RecipientDeps, Map<string, Promise<RecipientResult>>>();

function firstOpen(deps: RecipientDeps, link: SendLink): Promise<RecipientResult> {
  let byLink = firstOpens.get(deps);
  if (!byLink) {
    byLink = new Map();
    firstOpens.set(deps, byLink);
  }
  const id = `${link.accessId}/${link.key}`;
  let pending = byLink.get(id);
  if (!pending) {
    pending = openSend(deps, link);
    byLink.set(id, pending);
  }
  return pending;
}

/** The route-less screen `main.tsx` shows for a Send link. */
export default function SendAccess({
  link,
  deps = realDeps,
  save = saveFile,
}: {
  link: SendLink | null;
  deps?: RecipientDeps;
  save?: typeof saveFile;
}) {
  const [state, setState] = useState<AccessState>(link ? { phase: 'opening' } : { phase: 'bad-link' });
  const [fileError, setFileError] = useState<Described | undefined>();
  const [downloading, setDownloading] = useState(false);
  const [copied, setCopied] = useState(false);
  const accessId = link?.accessId;
  const key = link?.key;

  // The first call counts one access. A Send with a password answers that it wants one, and the
  // person types it; nothing else asks the server again.
  useEffect(() => {
    if (!accessId || !key) {
      setState({ phase: 'bad-link' });
      return;
    }
    let live = true;
    setState({ phase: 'opening' });
    setFileError(undefined);
    void firstOpen(deps, { accessId, key }).then((result) => {
      if (live) setState(stateOf(result));
    });
    return () => {
      live = false;
    };
    // `deps` is fixed for a mounted screen.
  }, [accessId, key]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!link) {
    return <SendAccessView state={state} onPassword={NOOP} onDownload={NOOP} onCopy={NOOP} />;
  }

  async function withPassword(password: string) {
    if (!link) return;
    setState(stateOf(await openSend(deps, link, password)));
  }

  async function download() {
    if (!link || state.phase !== 'opened') return;
    setDownloading(true);
    setFileError(undefined);
    const result: FileResult = await downloadFile(deps, link, state.send);
    setDownloading(false);
    if (result.state === 'file') save(result.name, result.mime, result.bytes);
    else if (result.state === 'unavailable') setFileError({ id: 'sendAccess.file.unavailable' });
    else setFileError({ id: 'sendAccess.file.failed' });
  }

  return (
    <SendAccessView
      state={state}
      fileError={fileError}
      downloading={downloading}
      copied={copied}
      onPassword={(password) => void withPassword(password)}
      onDownload={() => void download()}
      onCopy={(text) => void copyText(text, { secret: true }).then(setCopied)}
    />
  );
}
