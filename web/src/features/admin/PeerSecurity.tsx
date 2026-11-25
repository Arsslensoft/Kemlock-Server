import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearch } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import type { KeyHolding, PeerSecurity as PeerSecurityData, SelfSecurity, SuiteSetting } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { day, dateTime, relative } from './format';
import { type LabelsOf, KeyBadge } from './keys';
import { type AdminNav, useAdminNav } from './nav';
import { useReauth } from './reauth';
import { ChoiceGroup, ErrorNotice, Fact, Loading, PageHead, Toggle } from './ui';

export const SUITES = {
  aes: 'kfed1-mlkem1024x25519-aes256gcm',
  chacha: 'kfed1-mlkem1024x25519-chacha20poly1305',
  fips: 'kfed1-mlkem1024p384-aes256gcm',
} as const;

const SUITE_TEXT: Record<string, MessageId> = {
  [SUITES.aes]: 'admin.peer.suite.aes',
  [SUITES.chacha]: 'admin.peer.suite.chacha',
  [SUITES.fips]: 'admin.peer.suite.fips',
};

/** Which sentence explains the order of the suites this server accepts. */
export function orderHint(suites: SuiteSetting[], aesInstructions: boolean): MessageId {
  const first = suites.find((s) => s.on);
  if (!first) return 'admin.peer.order.none';
  if (first.name === SUITES.fips) return 'admin.peer.order.fips';
  if (first.name === SUITES.chacha && aesInstructions) return 'admin.peer.order.chachaSlower';
  if (first.name === SUITES.chacha) return 'admin.peer.order.chacha';
  return aesInstructions ? 'admin.peer.order.aesFirst' : 'admin.peer.order.other';
}

/** Moves one suite up (-1) or down (+1); a move off either end changes nothing. */
export function moveSuite(suites: SuiteSetting[], index: number, by: -1 | 1): SuiteSetting[] {
  const to = index + by;
  const a = suites[index];
  const b = suites[to];
  if (!a || !b) return suites;
  const next = suites.slice();
  next[index] = b;
  next[to] = a;
  return next;
}

function PeerCards({
  data,
  labelsOf,
  now,
  onNavigate,
}: {
  data: PeerSecurityData;
  labelsOf?: LabelsOf | undefined;
  now?: number | undefined;
  onNavigate: (nav: AdminNav) => void;
}) {
  const t = useT();
  const { peer, kem, descriptor, suites } = data;
  return (
    <div className="adm-split">
      <div className="adm-col">
        <section className="card" aria-labelledby="h-id">
          <div className="adm-head">
            <h2 id="h-id">{t('admin.peer.identity')}</h2>
            <span className={data.keysMatch ? 'tag ok' : 'tag bad'}>
              {data.keysMatch ? t('admin.peer.matches') : t('admin.peer.differs')}
            </span>
          </div>
          <div className="adm-pad">
            <KeyBadge identityKey={peer.identityKey} labelsOf={labelsOf} />
          </div>
          <dl className="kv">
            <Fact label={t('admin.peer.algorithms')}>ML-DSA-65 + Ed25519</Fact>
            <Fact label={t('admin.peer.pinned')}>{t('admin.peer.pinnedBody', { date: dateTime(peer.pinnedAt) })}</Fact>
            <Fact label={t('admin.peer.lastPresented')}>
              {data.lastHandshakeAt === null ? '—' : dateTime(data.lastHandshakeAt)}
            </Fact>
            <Fact label={t('admin.peer.canChange')}>{t('admin.peer.canChangeBody')}</Fact>
          </dl>
          {!data.keysMatch ? (
            <div className="adm-pad">
              <Button variant="danger" onPress={() => onNavigate({ to: 'mismatch', peerId: peer.serverId })}>
                {t('admin.fed.mismatch.open')}
              </Button>
            </div>
          ) : null}
        </section>

        {kem ? (
          <section className="card" aria-labelledby="h-kem">
            <div className="adm-head">
              <h2 id="h-kem">{t('admin.peer.kem')}</h2>
            </div>
            <dl className="kv">
              <Fact label={t('admin.peer.algorithm')}>{kem.algorithm}</Fact>
              <Fact label={t('admin.peer.age')}>
                {kem.firstSeenAt === null ? '—' : t('admin.peer.firstSeen', { date: day(kem.firstSeenAt) })}
              </Fact>
              <Fact label={t('admin.peer.nextRotation')}>
                {kem.nextRotationAt === null
                  ? '—'
                  : t('admin.peer.nextRotationBody', { when: relative(kem.nextRotationAt, now) })}
              </Fact>
              <Fact label={t('admin.peer.fingerprint')}>
                <span className="fp">{kem.fingerprint}</span>
              </Fact>
            </dl>
          </section>
        ) : null}

        <section className="card" aria-labelledby="h-desc">
          <div className="adm-head">
            <h2 id="h-desc">{t('admin.peer.descriptor')}</h2>
            {descriptor ? (
              <span className={data.signatureOk ? 'tag ok' : 'tag bad'}>
                {data.signatureOk ? t('admin.peer.sigGood') : t('admin.peer.sigBad')}
              </span>
            ) : null}
          </div>
          {data.fetchError ? (
            <div className="adm-pad">
              <Notice tone="warn" live>
                <p>{t('admin.peer.fetchFailed', { reason: data.fetchError })}</p>
              </Notice>
            </div>
          ) : null}
          {descriptor ? (
            <dl className="kv">
              <Fact label={t('admin.peer.fetched')}>
                {data.fetchedAt === null ? '—' : dateTime(data.fetchedAt)}
              </Fact>
              <Fact label={t('admin.peer.valid')}>
                {t('admin.peer.validBody', { from: day(descriptor.notBefore), to: day(descriptor.notAfter) })}
              </Fact>
              <Fact label={t('admin.peer.addresses')}>
                <span className="mono">{descriptor.addresses.join(', ')}</span>
              </Fact>
            </dl>
          ) : (
            <p className="hint adm-pad">{t('admin.peer.noDescriptor')}</p>
          )}
        </section>
      </div>

      <div className="adm-col">
        <section className="card" aria-labelledby="h-suites">
          <div className="adm-head">
            <h2 id="h-suites">{t('admin.peer.suites')}</h2>
          </div>
          <p className="hint adm-pad">{t('admin.peer.suitesBody')}</p>
          {/* It scrolls sideways when narrow, so the keyboard can reach it (WCAG 2.1.1). */}
          <div className="table-wrap" role="region" aria-label={t('admin.peer.suitesCaption', { name: peer.name })} tabIndex={0}>
            <table className="tbl">
              <caption className="sr">{t('admin.peer.suitesCaption', { name: peer.name })}</caption>
              <thead>
                <tr>
                  <th scope="col">{t('admin.peer.col.suite')}</th>
                  <th scope="col">{peer.name}</th>
                  <th scope="col">{t('admin.peer.col.thisServer')}</th>
                </tr>
              </thead>
              <tbody>
                {suites.map((suite) => (
                  <tr key={suite.name}>
                    <th scope="row">
                      <div className="mono">{suite.name}</div>
                      {suite.inUse ? <span className="tag ok">{t('admin.peer.inUse')}</span> : null}
                    </th>
                    <td>{suite.theirs ?? t('admin.peer.notOffered')}</td>
                    <td>{suite.ours ?? t('admin.peer.off')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}

export interface SelfSectionProps {
  self: SelfSecurity;
  labelsOf?: LabelsOf | undefined;
  onDownload: () => void;
  onRotateKem: () => void;
  onRotateIdentity: () => void;
  onSaveSuites: (suites: SuiteSetting[], keyHolding: KeyHolding) => void;
  kemRotated?: boolean | undefined;
  /** The suites were just saved. */
  suitesSaved?: boolean | undefined;
  busy?: boolean | undefined;
  now?: number | undefined;
}

export function SelfSection({
  self,
  labelsOf,
  onDownload,
  onRotateKem,
  onRotateIdentity,
  onSaveSuites,
  kemRotated,
  suitesSaved,
  busy,
  now,
}: SelfSectionProps) {
  const t = useT();
  const [suites, setSuites] = useState<SuiteSetting[]>(self.suites);
  const [holding, setHolding] = useState<KeyHolding>(self.keyHolding);
  const [rotating, setRotating] = useState(false);
  // "Saved." goes at the first edit after it.
  const [edited, setEdited] = useState(false);
  // What the server keeps may change under the form (a refetch): start again from it.
  useEffect(() => {
    setSuites(self.suites);
    setHolding(self.keyHolding);
    setEdited(false);
  }, [self.suites, self.keyHolding]);
  const dirty = holding !== self.keyHolding || JSON.stringify(suites) !== JSON.stringify(self.suites);
  const noneOn = !suites.some((s) => s.on);
  return (
    <section className="card" aria-labelledby="h-own">
      <div className="adm-head">
        <h2 id="h-own">{t('admin.peer.own')}</h2>
        <Button size="small" onPress={onDownload}>
          {t('admin.peer.downloadOwn')}
        </Button>
      </div>
      {suitesSaved && !edited && !dirty ? (
        <div className="adm-saved">
          <Notice tone="info" live>
            <p>{t('admin.saved')}</p>
          </Notice>
        </div>
      ) : null}
      <p className="hint adm-pad">{t('admin.peer.ownBody', { name: self.server.name })}</p>
      <div className="adm-split">
        <div className="adm-pad">
          <div className="adm-box">
            <span className="hint">{t('admin.peer.identityKey')}</span>
            <KeyBadge identityKey={self.server.identityKey} labelsOf={labelsOf} />
            <span className="hint">
              ML-DSA-65 + Ed25519 · {self.identityFingerprint}
            </span>
          </div>
          <dl className="kv">
            <Fact label={t('admin.peer.kem')}>
              {self.kemMadeAt === null || self.kemNextRotationAt === null
                ? '—'
                : t('admin.peer.ownKem', {
                    made: day(self.kemMadeAt),
                    next: relative(self.kemNextRotationAt, now),
                  })}
            </Fact>
            <Fact label={t('admin.peer.valid')}>
              {t('admin.peer.validBody', { from: day(self.validFrom), to: day(self.validTo) })}
            </Fact>
            <Fact label={t('admin.peer.addresses')}>
              <span className="mono">{self.addresses.join(', ')}</span>
            </Fact>
          </dl>
          {kemRotated ? (
            <Notice tone="info" live>
              <p>{t('admin.peer.kemRotated')}</p>
            </Notice>
          ) : null}
          <ChoiceGroup
            legend={t('admin.peer.holding')}
            value={holding}
            onChange={(value) => {
              setHolding(value as KeyHolding);
              setEdited(true);
            }}
            options={[
              {
                value: 'sealed',
                title: t('admin.peer.holding.sealed'),
                hint: t('admin.peer.holding.sealedHint'),
              },
            ]}
          />
          <div className="actions">
            <Button size="small" isDisabled={busy} onPress={onRotateKem}>
              {t('admin.peer.rotateKem')}
            </Button>
            <Button size="small" aria-expanded={rotating} aria-controls="rot-id" onPress={() => setRotating((v) => !v)}>
              {t('admin.peer.rotateIdentity')}
            </Button>
          </div>
          {rotating ? (
            <div id="rot-id" role="region" aria-labelledby="h-rot" className="stack">
              <h3 id="h-rot">{t('admin.peer.rotateTitle', { name: self.server.name })}</h3>
              <p>{t('admin.peer.rotate1')}</p>
              <p>{t('admin.peer.rotate2')}</p>
              <p>{t('admin.peer.rotate3')}</p>
              <div className="actions">
                <Button size="small" onPress={() => setRotating(false)}>
                  {t('action.cancel')}
                </Button>
                <Button
                  size="small"
                  variant="primary"
                  isDisabled={busy}
                  onPress={() => {
                    onRotateIdentity();
                    setRotating(false);
                  }}
                >
                  {t('admin.peer.rotateConfirm')}
                </Button>
              </div>
            </div>
          ) : null}
        </div>

        <div className="adm-pad">
          <h3 id="h-order">{t('admin.peer.acceptOrder')}</h3>
          <p className="hint">{t('admin.peer.acceptOrderHint')}</p>
          <ol className="adm-list" aria-labelledby="h-order">
            {suites.map((suite, index) => {
              const id = SUITE_TEXT[suite.name];
              return (
                <li className={suite.on ? 'adm-suite' : 'adm-suite off'} key={suite.name}>
                  <span className="adm-ord">{index + 1}</span>
                  <div className="grow">
                    <Toggle
                      label={suite.name}
                      hint={id ? t(id) : undefined}
                      checked={suite.on}
                      onChange={(on) => {
                        setSuites((list) => list.map((s) => (s.name === suite.name ? { ...s, on } : s)));
                        setEdited(true);
                      }}
                    />
                  </div>
                  <Button
                    size="small"
                    aria-label={t('admin.peer.moveUp', { name: suite.name })}
                    isDisabled={index === 0}
                    onPress={() => {
                      setSuites((list) => moveSuite(list, index, -1));
                      setEdited(true);
                    }}
                  >
                    <span aria-hidden="true">↑</span>
                  </Button>
                  <Button
                    size="small"
                    aria-label={t('admin.peer.moveDown', { name: suite.name })}
                    isDisabled={index === suites.length - 1}
                    onPress={() => {
                      setSuites((list) => moveSuite(list, index, 1));
                      setEdited(true);
                    }}
                  >
                    <span aria-hidden="true">↓</span>
                  </Button>
                </li>
              );
            })}
          </ol>
          <p role="status" className="hint">
            {t(orderHint(suites, suites.some((s) => s.name === SUITES.aes && s.available !== false)))}
          </p>
          <p className="hint">{t('admin.peer.saveHint')}</p>
          <div className="actions">
            {dirty ? (
              <Button
                onPress={() => {
                  setSuites(self.suites);
                  setHolding(self.keyHolding);
                  setEdited(false);
                }}
              >
                {t('admin.discard')}
              </Button>
            ) : null}
            <Button variant="primary" isDisabled={busy || !dirty || noneOn} onPress={() => onSaveSuites(suites, holding)}>
              {t('action.save')}
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
}

export interface PeerSecurityViewProps extends Omit<SelfSectionProps, 'self'> {
  peer?: PeerSecurityData | undefined;
  self: SelfSecurity;
  onNavigate: (nav: AdminNav) => void;
  onDownloadPeer: () => void;
  onRevoke: () => void;
  error?: unknown;
}

export function PeerSecurityView(props: PeerSecurityViewProps) {
  const t = useT();
  const { peer, self, onNavigate, error } = props;
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  return (
    <>
      <nav aria-label={t('admin.crumbs')} className="crumbs">
        <Button size="small" onPress={() => onNavigate({ to: 'federation' })}>
          {t('admin.federation')}
        </Button>
        <span aria-hidden="true">›</span> {peer ? peer.peer.name : self.server.name}
      </nav>
      <PageHead
        title={peer ? peer.peer.name : self.server.name}
        lede={
          peer
            ? t('admin.peer.lede', {
                address: peer.peer.address,
                self: self.server.name,
                date: day(peer.peer.pinnedAt),
              })
            : t('admin.peer.ledeSelf')
        }
        actions={
          peer ? (
            <>
              <Button onPress={props.onDownloadPeer}>{t('admin.peer.download')}</Button>
              <Button variant="danger" onPress={() => setConfirmRevoke(true)}>
                {t('admin.peer.revoke')}
              </Button>
            </>
          ) : undefined
        }
      />
      {error ? <ErrorNotice error={error} /> : null}
      {peer ? (
        <PeerCards data={peer} labelsOf={props.labelsOf} now={props.now} onNavigate={onNavigate} />
      ) : null}
      <SelfSection
        self={self}
        labelsOf={props.labelsOf}
        onDownload={props.onDownload}
        onRotateKem={props.onRotateKem}
        onRotateIdentity={props.onRotateIdentity}
        onSaveSuites={props.onSaveSuites}
        kemRotated={props.kemRotated}
        busy={props.busy}
        now={props.now}
      />
      <ConfirmDialog
        isOpen={confirmRevoke}
        onOpenChange={setConfirmRevoke}
        title={t('admin.peer.revokeTitle', { name: peer?.peer.name ?? '' })}
        confirmLabel={t('admin.peer.revoke')}
        onConfirm={() => {
          setConfirmRevoke(false);
          props.onRevoke();
        }}
      >
        <p>{t('admin.peer.revokeBody')}</p>
      </ConfirmDialog>
    </>
  );
}

/** Saves a response as a file, for a descriptor. */
async function saveDescriptor(response: Response, name: string): Promise<void> {
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default function PeerSecurityPage() {
  const queryClient = useQueryClient();
  const navigate = useAdminNav();
  const { guard, dialog } = useReauth(admin);
  const { peer: peerId } = useSearch({ strict: false }) as { peer?: string };
  const peer = useQuery({
    queryKey: ['admin', 'peer-security', peerId],
    queryFn: () => admin.peerSecurity(peerId ?? ''),
    enabled: peerId !== undefined,
    refetchInterval: 15_000,
  });
  const self = useQuery({ queryKey: ['admin', 'self-security'], queryFn: () => admin.selfSecurity() });
  const refreshSelf = () => queryClient.invalidateQueries({ queryKey: ['admin', 'self-security'] });
  const rotateKem = useMutation({ mutationFn: () => guard((grant) => admin.rotateKem(grant)), onSuccess: refreshSelf });
  const rotateIdentity = useMutation({
    mutationFn: () => guard((grant) => admin.rotateIdentity(grant)),
    onSuccess: refreshSelf,
  });
  const saveSuites = useMutation({
    mutationFn: (v: { suites: SuiteSetting[]; holding: KeyHolding }) =>
      guard((grant) => admin.saveSuites(v.suites, v.holding, grant)),
    onSuccess: refreshSelf,
  });
  const revoke = useMutation({
    mutationFn: () => guard((grant) => admin.revokePeer(peerId ?? '', grant)),
    onSuccess: () => navigate({ to: 'pair' }),
  });
  const download = useMutation({
    mutationFn: async (which: 'peer' | 'self') => {
      const response = await (which === 'peer' ? admin.peerDescriptor(peerId ?? '') : admin.selfDescriptor());
      await saveDescriptor(response, which === 'peer' ? 'peer-descriptor.cbor' : 'descriptor.cbor');
    },
  });
  if (self.isPending || (peerId !== undefined && peer.isPending)) return <Loading />;
  if (!self.data) return <ErrorNotice error={self.error} />;
  return (
    <>
      <PeerSecurityView
        // Remounts when the saved suites change, so the form starts from what the server kept.
        key={JSON.stringify(self.data.suites) + self.data.keyHolding}
        peer={peer.data}
        self={self.data}
        onNavigate={navigate}
        onDownload={() => download.mutate('self')}
        onDownloadPeer={() => download.mutate('peer')}
        onRevoke={() => revoke.mutate()}
        onRotateKem={() => rotateKem.mutate()}
        onRotateIdentity={() => rotateIdentity.mutate()}
        onSaveSuites={(suites, holding) => saveSuites.mutate({ suites, holding })}
        kemRotated={rotateKem.isSuccess}
        suitesSaved={saveSuites.isSuccess}
        busy={rotateKem.isPending || rotateIdentity.isPending || saveSuites.isPending}
        error={
          peer.error ?? self.error ?? rotateKem.error ?? rotateIdentity.error ?? saveSuites.error ?? revoke.error ?? download.error
        }
      />
      {dialog}
    </>
  );
}
