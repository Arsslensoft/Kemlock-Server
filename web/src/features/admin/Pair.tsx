import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import {
  ALL_ACKNOWLEDGEMENTS,
  type PairingAck,
  type PairingCode,
  type PairingConfirm,
  type PairingSession,
  type PairingState,
  type Peer,
  type ServerView,
} from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { clock, bytes, shortId } from './format';
import { pairFingerprint, shortFingerprint } from './fingerprint';
import { type AdminNav, useAdminNav } from './nav';
import { useReauth } from './reauth';
import { CheckBox, ErrorNotice, Loading, PageHead, TextBox, Toggle } from './ui';

/** The address the server dials: an http or https URL with a host (an IPv6 host in brackets). */
export function isPeerUrl(address: string): boolean {
  if (!URL.canParse(address)) return false;
  const url = new URL(address);
  return (url.protocol === 'https:' || url.protocol === 'http:') && url.hostname !== '';
}
/**
 * Whether typed text is a one-time code, read as the server reads it: spaces and dashes are
 * ignored, case does not matter, O, I and L stand for 0, 1 and 1, and twelve characters of
 * Crockford's base32 remain.
 */
export function isPairingCode(input: string): boolean {
  const text = input.replace(/[\s-]/g, '').toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
  return /^[0-9A-HJKMNP-TV-Z]{12}$/.test(text);
}

/** The words to compare, and each key's short form. */
export interface Comparison {
  words: string;
  selfShort: string | undefined;
  peerShort: string | undefined;
}

/**
 * Works the words out from both keys. It refuses when a key is missing: the words of an empty key
 * would not be the other admin's.
 */
export async function compareKeys(self: ServerView, peer: ServerView): Promise<Comparison> {
  if (self.identityKey === '' || peer.identityKey === '') throw new Error('a key is missing');
  const [words, selfShort, peerShort] = await Promise.all([
    pairFingerprint(self, peer),
    shortFingerprint(self.identityKey),
    shortFingerprint(peer.identityKey),
  ]);
  return { words, selfShort, peerShort };
}

export type CompareFn = (self: ServerView, peer: ServerView) => Promise<Comparison>;

export const ALL_ACKS: PairingAck[] = ALL_ACKNOWLEDGEMENTS;

/** Whether the confirm button may be pressed: words matched, and every acknowledgement given. */
export function canConfirm(session: PairingSession, wordsMatch: boolean, acks: PairingAck[]): boolean {
  if (!wordsMatch) return false;
  return session.peer.operator === 'own' || ALL_ACKS.every((ack) => acks.includes(ack));
}

const ACK_TEXT: Record<PairingAck, [MessageId, MessageId]> = {
  metadata: ['admin.pair.ack.metadata', 'admin.pair.ack.metadataHint'],
  'no-delete': ['admin.pair.ack.noDelete', 'admin.pair.ack.noDeleteHint'],
  'cross-border': ['admin.pair.ack.border', 'admin.pair.ack.borderHint'],
};

function Identity({ server, short, title }: { server: ServerView; short?: string | undefined; title: string }) {
  const t = useT();
  return (
    <div className="adm-box">
      <span className="hint">{title}</span>
      <div>{server.name}</div>
      <div className="hint">
        <span className="mono">{server.address}</span>
        {server.country ? ` · ${server.country}` : ''}
      </div>
      <div className="hint">
        {server.operator === 'own'
          ? t('admin.fed.runByYou')
          : t('admin.fed.runByOther', { name: server.operatorName ?? '' })}
      </div>
      {short ? <span className="fp">{short}</span> : null}
    </div>
  );
}

export interface PairViewProps {
  state: PairingState;
  onNewCode: () => void;
  onConnect: (address: string, code: string) => void;
  onConfirm: (confirm: PairingConfirm) => void;
  onCancel: () => void;
  onNavigate: (nav: AdminNav) => void;
  compare?: CompareFn;
  connecting?: boolean;
  confirming?: boolean;
  paired?: Peer | undefined;
  error?: unknown;
  now?: number;
}

export function PairView({
  state,
  onNewCode,
  onConnect,
  onConfirm,
  onCancel,
  onNavigate,
  compare = compareKeys,
  connecting,
  confirming,
  paired,
  error,
  now,
}: PairViewProps) {
  const t = useT();
  const { code, session } = state;
  const [address, setAddress] = useState('');
  const [typed, setTyped] = useState('');
  const [tried, setTried] = useState(false);
  const addressError: MessageId | undefined =
    tried && !isPeerUrl(address.trim()) ? 'admin.pair.error.address' : undefined;
  const codeError: MessageId | undefined =
    tried && !isPairingCode(typed) ? 'admin.pair.error.code' : undefined;
  const [wordsMatch, setWordsMatch] = useState(false);
  const [acks, setAcks] = useState<PairingAck[]>([]);
  const [offer, setOffer] = useState<string[]>([]);
  const [sendLogs, setSendLogs] = useState(false);
  const [pullLogs, setPullLogs] = useState(false);
  const [comparison, setComparison] = useState<Comparison | undefined>();

  const sessionKey = session ? `${session.id}` : '';
  useEffect(() => {
    if (!session) {
      setComparison(undefined);
      return;
    }
    let live = true;
    compare(session.self, session.peer).then(
      (value) => {
        if (live) setComparison(value);
      },
      () => {
        // Without both keys the words are the server's own, as it worked them out.
        if (live) {
          setComparison(
            session.words
              ? { words: session.words, selfShort: undefined, peerShort: undefined }
              : undefined,
          );
        }
      },
    );
    return () => {
      live = false;
    };
    // The comparison depends on the session's keys, which its id names.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionKey, compare]);

  const minutes = code ? Math.max(0, Math.round((code.expiresAt - (now ?? Date.now() / 1000)) / 60)) : 0;

  if (paired) {
    return (
      <>
        <PageHead title={t('admin.pair.title')} />
        <Notice tone="info" live>
          <p>{t('admin.pair.paired', { name: paired.name })}</p>
        </Notice>
        <div className="actions">
          <Button variant="primary" onPress={() => onNavigate({ to: 'federation' })}>
            {t('admin.pair.backToFederation')}
          </Button>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHead
        title={t('admin.pair.title')}
        // The server's own name comes with the pairing session; until then the lede leaves it out.
        lede={session ? t('admin.pair.lede', { name: session.self.name }) : t('admin.pair.ledeBare')}
      />
      {error ? <ErrorNotice error={error} /> : null}

      <section className="card" aria-labelledby="h-s1">
        <div className="adm-head">
          <h2 id="h-s1">{t('admin.pair.step1')}</h2>
        </div>
        <div className="adm-pad">
          <div className="adm-cols">
            <div className="adm-box">
              <span>{t('admin.pair.giveCode')}</span>
              {code ? (
                <>
                  <span className="adm-code">
                    {code.code}
                  </span>
                  <span className="hint">
                    {t('admin.pair.codeExpires', { at: clock(code.expiresAt), minutes })}
                  </span>
                  <div className="actions">
                    <CopyButton value={code.code} label={t('admin.pair.copyCode')} />
                    <Button size="small" onPress={onNewCode}>
                      {t('admin.pair.newCode')}
                    </Button>
                  </div>
                </>
              ) : (
                <div className="actions">
                  <Button size="small" onPress={onNewCode}>
                    {t('admin.pair.makeCode')}
                  </Button>
                </div>
              )}
            </div>
            <form
              className="adm-box"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                setTried(true);
                const goodAddress = isPeerUrl(address.trim());
                const goodCode = isPairingCode(typed);
                if (goodAddress && goodCode) onConnect(address.trim(), typed.trim());
              }}
            >
              <span>{t('admin.pair.enterCode')}</span>
              <div className="adm-g2">
                <TextBox
                  label={t('admin.pair.address')}
                  mono
                  value={address}
                  onChange={setAddress}
                  type="url"
                  placeholder="https://peer.example.org"
                  inputMode="url"
                  required
                  error={addressError}
                />
                <TextBox
                  label={t('admin.pair.theirCode')}
                  mono
                  value={typed}
                  onChange={setTyped}
                  placeholder="XXXX-XXXX-XXXX"
                  required
                  error={codeError}
                />
              </div>
              <div className="actions">
                <Button type="submit" size="small" isDisabled={connecting || address.trim() === '' || typed.trim() === ''}>
                  {t('admin.pair.connect')}
                </Button>
              </div>
            </form>
          </div>
          {session ? (
            <Notice tone="info" live>
              <p>{t('admin.pair.connected', { name: session.peer.name, address: session.peer.address })}</p>
            </Notice>
          ) : null}
        </div>
      </section>

      {session ? (
        <>
          <section className="card" aria-labelledby="h-s2">
            <div className="adm-head">
              <h2 id="h-s2">{t('admin.pair.step2')}</h2>
            </div>
            <div className="adm-pad">
              <p>{t('admin.pair.compareBody', { peer: session.peer.name })}</p>
              <div className="adm-box">
                <span className="hint">{t('admin.pair.words')}</span>
                <div className="words">
                  {comparison?.words ?? t('state.loading')}
                </div>
              </div>
              <div className="adm-cols">
                <Identity server={session.self} short={comparison?.selfShort} title={t('admin.pair.thisServer')} />
                <Identity server={session.peer} short={comparison?.peerShort} title={t('admin.pair.otherServer')} />
              </div>
              <CheckBox
                label={t('admin.pair.match', { peer: session.peer.name })}
                hint={t('admin.pair.matchHint')}
                checked={wordsMatch}
                onChange={setWordsMatch}
                disabled={comparison === undefined}
              />
            </div>
          </section>

          {session.peer.operator === 'other' ? (
            <section className="card" aria-labelledby="h-s3">
              <div className="adm-head">
                <h2 id="h-s3">{t('admin.pair.otherOrg', { name: session.peer.name })}</h2>
              </div>
              <div className="adm-pad">
                <p>{t('admin.pair.confirmEach', { operator: session.peer.operatorName ?? '', name: session.peer.name })}</p>
                {ALL_ACKS.map((ack) => (
                  <CheckBox
                    key={ack}
                    label={t(ACK_TEXT[ack][0], { name: session.peer.name })}
                    hint={t(ACK_TEXT[ack][1], {
                      name: session.peer.name,
                      there: session.peer.country ?? '?',
                      here: session.self.country ?? '?',
                    })}
                    checked={acks.includes(ack)}
                    onChange={(value) =>
                      setAcks((current) => (value ? [...current, ack] : current.filter((a) => a !== ack)))
                    }
                  />
                ))}
              </div>
            </section>
          ) : null}

          <section className="card" aria-labelledby="h-s4">
            <div className="adm-head">
              <h2 id="h-s4">{t('admin.pair.step4')}</h2>
            </div>
            <div className="adm-pad">
              <p>{t('admin.pair.shareBody', { peer: session.peer.name })}</p>
              {session.shareable.length === 0 ? (
                <p className="hint">{t('admin.pair.shareNone')}</p>
              ) : (
                session.shareable.map((vault) => (
                  <CheckBox
                    key={vault.id}
                    label={vault.name ?? shortId(vault.id)}
                    hint={t('admin.pair.shareHint', {
                      kind: vault.kind === 'personal' ? t('admin.fed.personal') : t('admin.fed.space', { members: vault.members ?? 0 }),
                      size: vault.sizeBytes === null ? '—' : bytes(vault.sizeBytes),
                    })}
                    checked={offer.includes(vault.id)}
                    onChange={(value) =>
                      setOffer((current) => (value ? [...current, vault.id] : current.filter((id) => id !== vault.id)))
                    }
                  />
                ))
              )}
              <fieldset className="stack">
                <legend>{t('admin.pair.logs')}</legend>
                <Toggle
                  label={t('admin.fed.logs.send')}
                  hint={t('admin.pair.sendHint', { peer: session.peer.name })}
                  checked={sendLogs}
                  onChange={setSendLogs}
                />
                <Toggle
                  label={t('admin.fed.logs.pull')}
                  hint={t('admin.pair.pullHint', { peer: session.peer.name })}
                  checked={pullLogs}
                  onChange={setPullLogs}
                />
                <span className="hint">{t('admin.pair.logsHint')}</span>
              </fieldset>
            </div>
          </section>

          <div className="actions">
            <Button onPress={onCancel}>{t('action.cancel')}</Button>
            <Button
              variant="primary"
              isDisabled={confirming || !canConfirm(session, wordsMatch, acks)}
              onPress={() =>
                onConfirm({
                  wordsMatch,
                  acknowledged: acks,
                  offer,
                  sendLogs,
                  pullLogs,
                })
              }
            >
              {offer.length > 0
                ? t('admin.pair.submitOffer', { peer: session.peer.name })
                : t('admin.pair.submit', { peer: session.peer.name })}
            </Button>
          </div>
        </>
      ) : null}
    </>
  );
}

export default function Pair() {
  const queryClient = useQueryClient();
  const navigate = useAdminNav();
  const { guard, dialog } = useReauth(admin);
  const [paired, setPaired] = useState<Peer | undefined>();
  const [connected, setConnected] = useState<PairingSession | undefined>();
  // The server does not repeat a code it made, so the page keeps the one it was given.
  const [code, setCode] = useState<PairingCode | null>(null);
  // A peer that used our code shows up as a pairing that waits: read every three seconds.
  const pairing = useQuery({
    queryKey: ['admin', 'pairing'],
    queryFn: () => admin.pairing(),
    refetchInterval: 3000,
  });
  const newCode = useMutation({
    mutationFn: () => admin.newPairingCode(),
    onSuccess: (made) => {
      setCode(made);
      void queryClient.invalidateQueries({ queryKey: ['admin', 'pairing'] });
    },
  });
  const connect = useMutation({
    mutationFn: (v: { address: string; code: string }) => guard((grant) => admin.connectPairing(v.address, v.code, grant)),
    onSuccess: setConnected,
  });
  const confirm = useMutation({
    mutationFn: (confirmation: PairingConfirm) => {
      const id = (connected ?? pairing.data?.session)?.id ?? '';
      return guard((grant) => admin.confirmPairing(id, confirmation, grant));
    },
    onSuccess: (peer) => {
      setPaired(peer);
      void queryClient.invalidateQueries({ queryKey: ['admin', 'federation'] });
    },
  });
  if (pairing.isPending) return <Loading />;
  const state: PairingState = {
    code,
    session: connected ?? pairing.data?.session ?? null,
  };
  return (
    <>
      <PairView
        state={state}
        paired={paired}
        connecting={connect.isPending}
        confirming={confirm.isPending}
        error={pairing.error ?? newCode.error ?? connect.error ?? confirm.error}
        onNewCode={() => newCode.mutate()}
        onConnect={(address, code) => connect.mutate({ address, code })}
        onConfirm={(confirmation) => confirm.mutate(confirmation)}
        onCancel={() => {
          const id = state.session?.id;
          const done = () => navigate({ to: 'federation' });
          if (id) void guard((grant) => admin.cancelPairing(id, grant)).finally(done);
          else done();
        }}
        onNavigate={navigate}
      />
      {dialog}
    </>
  );
}
