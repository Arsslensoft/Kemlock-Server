import { useMutation, useQuery } from '@tanstack/react-query';
import { useParams } from '@tanstack/react-router';
import { useState } from 'react';
import type { KeyMismatch as KeyMismatchData } from '@/api/admin';
import { configQuery, hostOf } from '@/app/services';
import { useT } from '@/i18n';
import { copyText } from '@/lib/clipboard';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { bytes, dateTime, day, shortId } from './format';
import type { KeyLabels } from './fingerprint';
import { type LabelsOf, useKeyLabels } from './keys';
import { type AdminNav, useAdminNav } from './nav';
import { useReauth } from './reauth';
import { Fact, ErrorNotice, Loading, PageHead } from './ui';

/**
 * The details to send to the other admin, as plain English text: it is meant for a person at
 * another organisation, so it is not translated.
 */
export function mismatchDetails(
  m: KeyMismatchData,
  seenBy: string,
  pinned: KeyLabels,
  offered: KeyLabels,
): string {
  return [
    'Kemlock federation: possible man in the middle',
    `Seen by: ${seenBy}`,
    `Peer: ${m.peer.name} (${m.peer.address})`,
    `When: ${dateTime(m.offeredAt)}, ${m.attempts} attempt${m.attempts === 1 ? '' : 's'}, the last at ${dateTime(m.lastAttemptAt)}`,
    `From: ${m.fromAddress}`,
    `Pinned key: ${pinned.words} ${pinned.short}`,
    `Offered key: ${offered.words} ${offered.short}`,
    `Signed by the pinned key: ${m.signedByPinned ? 'yes' : 'no'}`,
  ].join('\n');
}

export interface KeyMismatchViewProps {
  data: KeyMismatchData;
  /** The name this server calls itself, for the text sent to the other admin. */
  seenBy: string;
  onKeepBlocking: () => void;
  /** Called once the person confirmed it is them: forgets the pinned key and goes to pairing. */
  onPairAgain: () => void;
  onNavigate: (nav: AdminNav) => void;
  labelsOf?: LabelsOf;
  copy?: (text: string) => Promise<boolean>;
  kept?: boolean;
  busy?: boolean;
  error?: unknown;
}

export function KeyMismatchView({
  data,
  seenBy,
  onKeepBlocking,
  onPairAgain,
  onNavigate,
  labelsOf,
  copy = copyText,
  kept,
  busy,
  error,
}: KeyMismatchViewProps) {
  const t = useT();
  const pinned = useKeyLabels(data.pinnedKey, labelsOf);
  const offered = useKeyLabels(data.offeredKey, labelsOf);
  const [copied, setCopied] = useState(false);
  const [pairing, setPairing] = useState(false);
  const name = data.peer.name;

  function copyDetails(): void {
    if (!pinned || !offered) return;
    void copy(mismatchDetails(data, seenBy, pinned, offered)).then(setCopied);
  }

  return (
    <>
      <nav aria-label={t('admin.crumbs')} className="crumbs">
        <Button size="small" onPress={() => onNavigate({ to: 'federation' })}>
          {t('admin.federation')}
        </Button>
        <span aria-hidden="true">›</span>
        <Button size="small" onPress={() => onNavigate({ to: 'peer', peerId: data.peer.serverId })}>
          {name}
        </Button>
        <span aria-hidden="true">›</span> {t('admin.mismatch.crumb')}
      </nav>
      <PageHead
        title={t('admin.mismatch.title')}
        lede={t('admin.mismatch.lede', { name, date: day(data.pinnedAt) })}
        actions={<span className="tag bad">{t('admin.mismatch.refused')}</span>}
      />
      {error ? <ErrorNotice error={error} /> : null}

      <section className="card" aria-labelledby="h-keys">
        <div className="adm-head">
          <h2 id="h-keys">{t('admin.mismatch.keys')}</h2>
          <span className="hint">ML-DSA-65 + Ed25519</span>
        </div>
        <div className="adm-pad">
          <div className="adm-cols">
            <div className="adm-box">
              <span className="hint">{t('admin.mismatch.pinned')}</span>
              <div className="words">{pinned?.words ?? t('state.loading')}</div>
              <div className="fp">{pinned?.short}</div>
              <span className="hint">{t('admin.mismatch.pinnedOn', { date: dateTime(data.pinnedAt) })}</span>
            </div>
            <div className="adm-box bad">
              <span className="hint">{t('admin.mismatch.offered', { at: dateTime(data.offeredAt) })}</span>
              <div className="words">{offered?.words ?? t('state.loading')}</div>
              <div className="fp">{offered?.short}</div>
              <span className="hint">
                {data.signedByPinned ? t('admin.mismatch.signed') : t('admin.mismatch.notSigned')}{' '}
                {data.seenBefore ? '' : t('admin.mismatch.neverSeen')}
              </span>
            </div>
          </div>
          <p className="hint">
            <span aria-hidden="true">≠</span> {t('admin.mismatch.doesNotMatch')}
          </p>
        </div>
      </section>

      <div className="adm-split">
        <div className="adm-col">
          <section className="card" aria-labelledby="h-what">
            <div className="adm-head">
              <h2 id="h-what">{t('admin.mismatch.what')}</h2>
            </div>
            <dl className="kv">
              <Fact label={t('admin.mismatch.when')}>
                {t('admin.mismatch.whenBody', {
                  at: dateTime(data.offeredAt),
                  more: Math.max(0, data.attempts - 1),
                  last: dateTime(data.lastAttemptAt),
                })}
              </Fact>
              <Fact label={t('admin.mismatch.from')}>
                <span className="mono">{data.fromAddress}</span>
                {data.usualAddresses.length > 0 ? (
                  <div className="hint">
                    {t('admin.mismatch.usual', { name, ips: data.usualAddresses.join(', ') })}
                  </div>
                ) : null}
              </Fact>
              <Fact label={t('admin.mismatch.answeredAs')}>
                {name}, <span className="mono">{data.peer.address}</span>
              </Fact>
              <Fact label={t('admin.mismatch.tls')}>
                {data.tlsValid
                  ? t('admin.mismatch.tlsValid', { cert: data.fromHost })
                  : t('admin.mismatch.tlsInvalid')}
              </Fact>
              <Fact label={t('admin.mismatch.refusedAt')}>{t('admin.mismatch.refusedAtBody')}</Fact>
              <Fact label={t('admin.mismatch.logged')}>
                <Button size="small" onPress={() => onNavigate({ to: 'events' })}>
                  {t('admin.mismatch.loggedOpen')}
                </Button>
              </Fact>
            </dl>
          </section>

          <section className="card" aria-labelledby="h-rep">
            <div className="adm-head">
              <h2 id="h-rep">{t('admin.mismatch.replication', { name })}</h2>
              <span className="tag warn">{t('admin.mismatch.paused')}</span>
            </div>
            <p className="hint adm-pad">{t('admin.mismatch.pausedBody')}</p>
            <ul className="adm-list">
              {data.pausedVaults.map((vault) => (
                <li key={vault.id}>
                  <div>
                    <div>
                      {t('admin.mismatch.pausedVault', { vault: vault.ownerEmail ?? shortId(vault.id), name })}
                    </div>
                    <div className="hint">
                      {t('admin.mismatch.pausedWaiting', {
                        n: vault.waitingChanges,
                        size: vault.sizeBytes === null ? '—' : bytes(vault.sizeBytes),
                      })}
                    </div>
                  </div>
                </li>
              ))}
              <li>
                <div>
                  <div>{t('admin.mismatch.stillWorking')}</div>
                  <div className="hint">{t('admin.mismatch.stillWorkingBody', { local: data.localVaults })}</div>
                </div>
              </li>
            </ul>
          </section>

          <section className="card" aria-labelledby="h-copy">
            <div className="adm-head">
              <h2 id="h-copy">{t('admin.mismatch.details')}</h2>
              <Button size="small" isDisabled={!pinned || !offered} onPress={copyDetails}>
                {t('admin.mismatch.copy')}
              </Button>
            </div>
            <div className="adm-pad">
              <pre className="adm-copy">
                {pinned && offered ? mismatchDetails(data, seenBy, pinned, offered) : t('state.loading')}
              </pre>
              {copied ? (
                <p role="status" className="hint">
                  {t('admin.mismatch.copied')}
                </p>
              ) : null}
            </div>
          </section>
        </div>

        <div className="adm-col">
          <section className="card" aria-labelledby="h-do">
            <div className="adm-head">
              <h2 id="h-do">{t('admin.mismatch.do')}</h2>
            </div>
            <div className="adm-pad">
              <div className="stack">
                <div className="actions">
                  <Button variant="primary" isDisabled={busy} onPress={onKeepBlocking}>
                    {t('admin.mismatch.keep')}
                  </Button>
                </div>
                <span className="hint">{t('admin.mismatch.keepHint', { name })}</span>
                {kept ? (
                  <Notice tone="info" live>
                    <p>{t('admin.mismatch.kept')}</p>
                  </Notice>
                ) : null}
              </div>
              <div className="stack">
                <div className="actions">
                  <Button
                    aria-expanded={pairing}
                    aria-controls="pair-check"
                    onPress={() => setPairing((open) => !open)}
                  >
                    {t('admin.mismatch.pairAgain')}
                  </Button>
                </div>
                <span className="hint">{t('admin.mismatch.pairAgainHint')}</span>
                {pairing ? (
                  <div id="pair-check" role="region" aria-labelledby="h-pk" className="stack">
                    <h3 id="h-pk">{t('admin.mismatch.confirmIt')}</h3>
                    <p>{t('admin.mismatch.confirmItBody')}</p>
                    <div className="actions">
                      <Button size="small" onPress={() => setPairing(false)}>
                        {t('action.cancel')}
                      </Button>
                      <Button size="small" variant="primary" isDisabled={busy} onPress={onPairAgain}>
                        {t('admin.mismatch.confirmWithCode')}
                      </Button>
                    </div>
                  </div>
                ) : null}
              </div>
              <div className="stack">
                <div className="actions">
                  <Button isDisabled aria-describedby="rot-why">
                    {t('admin.mismatch.acceptRotation')}
                  </Button>
                </div>
                <span id="rot-why" className="hint">
                  {t('admin.mismatch.rotationWhy')}
                </span>
              </div>
            </div>
          </section>

          <section className="card" aria-labelledby="h-mean">
            <div className="adm-head">
              <h2 id="h-mean">{t('admin.mismatch.mean')}</h2>
            </div>
            <ol className="adm-list">
              <li>
                <span className="tag bad" aria-hidden="true">
                  1
                </span>
                <div>
                  <div>{t('admin.mismatch.mean1')}</div>
                  <div className="hint">{t('admin.mismatch.mean1Hint', { name })}</div>
                </div>
              </li>
              <li>
                <span className="tag warn" aria-hidden="true">
                  2
                </span>
                <div>
                  <div>{t('admin.mismatch.mean2', { name })}</div>
                  <div className="hint">{t('admin.mismatch.mean2Hint')}</div>
                </div>
              </li>
              <li>
                <span className="tag warn" aria-hidden="true">
                  3
                </span>
                <div>
                  <div>{t('admin.mismatch.mean3')}</div>
                  <div className="hint">{t('admin.mismatch.mean3Hint')}</div>
                </div>
              </li>
            </ol>
            <p className="hint adm-pad">{t('admin.mismatch.meanFoot', { name })}</p>
          </section>
        </div>
      </div>
    </>
  );
}

export default function KeyMismatchPage() {
  const navigate = useAdminNav();
  const { guard, dialog } = useReauth(admin);
  const { peerId } = useParams({ strict: false }) as { peerId?: string };
  const { data: config } = useQuery(configQuery);
  const mismatch = useQuery({
    queryKey: ['admin', 'mismatch', peerId],
    queryFn: () => admin.keyMismatch(peerId ?? ''),
    enabled: peerId !== undefined,
  });
  const keep = useMutation({ mutationFn: () => guard((grant) => admin.keepBlocking(peerId ?? '', grant)) });
  const pairAgain = useMutation({
    mutationFn: () => guard((grant) => admin.revokePeer(peerId ?? '', grant)),
    onSuccess: () => navigate({ to: 'pair' }),
  });
  if (mismatch.isPending) return <Loading />;
  if (!mismatch.data) return <ErrorNotice error={mismatch.error} />;
  return (
    <>
      <KeyMismatchView
        data={mismatch.data}
        seenBy={hostOf(config?.domain)}
        onKeepBlocking={() => keep.mutate()}
        onPairAgain={() => pairAgain.mutate()}
        onNavigate={navigate}
        kept={keep.isSuccess}
        busy={keep.isPending || pairAgain.isPending}
        error={keep.error ?? pairAgain.error}
      />
      {dialog}
    </>
  );
}
