import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Fragment, useState } from 'react';
import type { AddressChange, FedVault, FederationOverview, Peer, PeerState } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { clock, dateTime, bytes, relative, shortId, span } from './format';
import { type LabelsOf, KeyBadge } from './keys';
import { type AdminNav, useAdminNav } from './nav';
import { useReauth } from './reauth';
import { CheckBox, ErrorNotice, Loading, PageHead, Toggle } from './ui';

const STATE: Record<PeerState, MessageId> = {
  online: 'admin.fed.state.online',
  degraded: 'admin.fed.state.degraded',
  offline: 'admin.fed.state.offline',
  'catching-up': 'admin.fed.state.catchingUp',
  revoked: 'admin.fed.state.revoked',
  contested: 'admin.fed.state.contested',
};

/** The promotions held for a vault: every one the server lists, or the one older servers show. */
function held(vault: FedVault) {
  if (vault.heldPromotions && vault.heldPromotions.length > 0) return vault.heldPromotions;
  return vault.heldDemotion ? [vault.heldDemotion] : [];
}

function stateTag(state: PeerState): string {
  return state === 'online'
    ? 'tag ok'
    : state === 'offline' || state === 'revoked' || state === 'contested'
      ? 'tag bad'
      : 'tag warn';
}

export interface FederationViewProps {
  overview: FederationOverview;
  onNavigate: (nav: AdminNav) => void;
  onSetLogs: (peer: Peer, send: boolean, pull: boolean) => void;
  onCheckKeys: () => void;
  onRunConsistency: () => void;
  onPromote: (vault: FedVault, homeIsDown: boolean) => void;
  onAccept: (vault: FedVault) => void;
  onDecline: (vault: FedVault) => void;
  /**
   * Accepts the promotion held for a vault: at the vault's home it hands the home to the server
   * that signed it, and at a replica it makes that server the home here.
   */
  onAcceptDemotion?: (vault: FedVault, newHomeId: string) => void;
  /** Drops the promotion held for a vault without applying it. */
  onRefuseDemotion?: (vault: FedVault, newHomeId: string) => void;
  /** The address changes that came with peers' key rotations and wait for the admin. */
  addressChanges?: AddressChange[] | undefined;
  /** Follows the peer to the addresses its rotation brought. */
  onApproveAddresses?: (change: AddressChange) => void;
  /** Keeps the addresses this server knew. */
  onRefuseAddresses?: (change: AddressChange) => void;
  /** Trusts a contested peer again. */
  onClearContest?: (peer: Peer) => void;
  /** Unpairs a contested peer, to pair it again with a new code. */
  onUnpair?: (peer: Peer) => void;
  labelsOf?: LabelsOf;
  busy?: boolean;
  error?: unknown;
  now?: number;
}

export function FederationView({
  overview,
  onNavigate,
  onSetLogs,
  onCheckKeys,
  onRunConsistency,
  onPromote,
  onAccept,
  onDecline,
  onAcceptDemotion,
  onRefuseDemotion,
  addressChanges,
  onApproveAddresses,
  onRefuseAddresses,
  onClearContest,
  onUnpair,
  labelsOf,
  busy,
  error,
  now,
}: FederationViewProps) {
  const t = useT();
  const { self, peers, vaults, consistency } = overview;
  const [promoting, setPromoting] = useState<string | null>(null);
  const [down, setDown] = useState(false);
  const nameOf = (id: string) => (id === self.serverId ? self.name : (peers.find((p) => p.serverId === id)?.name ?? id.slice(0, 8)));
  const stateOf = (id: string): PeerState =>
    id === self.serverId ? self.state : (peers.find((p) => p.serverId === id)?.state ?? 'online');
  const offline = peers.filter((p) => p.state === 'offline');
  const promoted = vaults.find((v) => v.id === promoting);

  return (
    <>
      <PageHead
        title={t('admin.federation')}
        lede={t('admin.fed.lede', { name: self.name })}
        actions={
          <Button variant="primary" onPress={() => onNavigate({ to: 'pair' })}>
            {t('admin.fed.pair')}
          </Button>
        }
      />
      {error ? <ErrorNotice error={error} /> : null}

      {offline.map((peer) => (
        <div className="adm-banner" role="status" key={peer.serverId}>
          <p>
            <b>
              {t('admin.fed.offline', {
                name: peer.name,
                for: span(Math.max(0, Math.round((now ?? Date.now() / 1000) - (peer.offlineSince ?? 0)))),
                since: peer.offlineSince === null ? '' : clock(peer.offlineSince),
              })}
            </b>{' '}
            {t('admin.fed.offlineBody', { name: peer.name })}
          </p>
        </div>
      ))}

      <section className="card" aria-labelledby="h-peers">
        <div className="adm-head">
          <h2 id="h-peers">{t('admin.fed.peers')}</h2>
          <Button size="small" isDisabled={busy} onPress={onCheckKeys}>
            {t('admin.fed.check')}
          </Button>
        </div>
        <p className="hint adm-pad">{t('admin.fed.peersHint')}</p>
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">{t('admin.fed.col.server')}</th>
                <th scope="col">{t('admin.fed.col.state')}</th>
                <th scope="col">{t('admin.fed.col.lag')}</th>
                <th scope="col">{t('admin.fed.col.last')}</th>
                <th scope="col">{t('admin.fed.col.key')}</th>
                <th scope="col">{t('admin.fed.col.logs')}</th>
                <th scope="col">
                  <span className="sr">{t('table.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <div>
                    {self.name} <span className="hint">{t('admin.fed.thisServer')}</span>
                  </div>
                  <div className="adm-cell-sub">
                    <span className="mono">{self.address}</span>
                    {self.database ? ` · ${self.database}` : ''}
                    {self.country ? ` · ${self.country}` : ''}
                  </div>
                  <div className="adm-cell-sub">{t('admin.fed.runByYou')}</div>
                </td>
                <td>
                  <span className={stateTag(self.state)}>{t(STATE[self.state])}</span>
                </td>
                <td>{t('admin.fed.lag.none')}</td>
                <td>{t('admin.fed.now')}</td>
                <td>
                  <KeyBadge identityKey={self.identityKey} labelsOf={labelsOf} />
                  <div className="adm-cell-sub">{t('admin.fed.itsOwn')}</div>
                </td>
                <td className="adm-cell-sub">{t('admin.fed.logs.perPeer')}</td>
                <td>
                  <div className="adm-row-actions">
                    <Button size="small" onPress={() => onNavigate({ to: 'peer' })}>
                      {t('admin.fed.security.self')}
                    </Button>
                  </div>
                </td>
              </tr>
              {peers.map((peer) => (
                <tr key={peer.serverId}>
                  <td>
                    <div>{peer.name}</div>
                    <div className="adm-cell-sub">
                      <span className="mono">{peer.address}</span>
                      {peer.database ? ` · ${peer.database}` : ''}
                      {peer.country ? ` · ${peer.country}` : ''}
                    </div>
                    <div className="adm-cell-sub">
                      {peer.operator === 'own'
                        ? t('admin.fed.runByYou')
                        : t('admin.fed.runByOther', { name: peer.operatorName ?? '' })}
                    </div>
                  </td>
                  <td>
                    <span className={stateTag(peer.state)}>{t(STATE[peer.state])}</span>
                    <div className="adm-cell-sub">
                      {peer.lastSeen === null
                        ? t('admin.fed.lastSeen.never')
                        : t('admin.fed.lastSeen', { when: relative(peer.lastSeen, now) })}
                      {peer.latencyMs !== null && peer.state !== 'offline'
                        ? ` · ${t('admin.fed.latency', { ms: peer.latencyMs })}`
                        : ''}
                    </div>
                    {peer.mismatch ? (
                      <div>
                        <span className="tag bad">{t('admin.fed.mismatch.tag')}</span>
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {peer.lagSeconds === null
                      ? t('admin.fed.lag.none')
                      : peer.lagChanges
                        ? t('admin.fed.lag.changes', { span: span(peer.lagSeconds), changes: peer.lagChanges })
                        : span(peer.lagSeconds)}
                  </td>
                  <td>
                    {peer.lastChangeAt === null ? '—' : relative(peer.lastChangeAt, now)}
                    {peer.lastChangeVault ? <div className="adm-cell-sub">{peer.lastChangeVault}</div> : null}
                  </td>
                  <td>
                    <KeyBadge identityKey={peer.identityKey} labelsOf={labelsOf} />
                    <div className="adm-cell-sub">
                      {t('admin.fed.pinned', { date: dateTime(peer.pinnedAt) })}
                    </div>
                  </td>
                  <td>
                    <div className="stack">
                      <Toggle
                        label={t('admin.fed.logs.send')}
                        checked={peer.sendLogs}
                        onChange={(value) => onSetLogs(peer, value, peer.pullLogs)}
                      />
                      <Toggle
                        label={t('admin.fed.logs.pull')}
                        checked={peer.pullLogs}
                        onChange={(value) => onSetLogs(peer, peer.sendLogs, value)}
                      />
                      <div className="adm-cell-sub">
                        {peer.theySendLogs && !peer.pullLogs
                          ? t('admin.fed.logs.sendsNotPulled')
                          : peer.sendLogs && peer.pullLogs
                            ? t('admin.fed.logs.both')
                            : t('admin.fed.logs.off')}
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="adm-row-actions">
                      <Button
                        size="small"
                        aria-label={t('admin.fed.security.of', { name: peer.name })}
                        onPress={() => onNavigate({ to: 'peer', peerId: peer.serverId })}
                      >
                        {t('admin.fed.security')}
                      </Button>
                      {peer.mismatch ? (
                        <Button
                          size="small"
                          variant="danger"
                          aria-label={t('admin.fed.mismatch.of', { name: peer.name })}
                          onPress={() => onNavigate({ to: 'mismatch', peerId: peer.serverId })}
                        >
                          {t('admin.fed.mismatch.open')}
                        </Button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card" aria-labelledby="h-vaults">
        <div className="adm-head">
          <h2 id="h-vaults">{t('admin.fed.vaults')}</h2>
        </div>
        <p className="hint adm-pad">{t('admin.fed.vaultsHint')}</p>
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">{t('admin.fed.col.vault')}</th>
                <th scope="col">{t('admin.fed.col.owner')}</th>
                <th scope="col">{t('admin.fed.col.policy')}</th>
                <th scope="col">{t('admin.fed.col.home')}</th>
                <th scope="col">{t('admin.fed.col.replicas')}</th>
                <th scope="col">{t('admin.fed.col.size')}</th>
                <th scope="col">{t('admin.fed.col.requests')}</th>
                <th scope="col">
                  <span className="sr">{t('table.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {vaults.map((vault) => {
                const name = vault.name ?? vault.ownerEmail ?? shortId(vault.id);
                const homeHere = vault.homeId === self.serverId;
                return (
                  <tr key={vault.id}>
                    <td>{name}</td>
                    <td>
                      <div>
                        {vault.kind === 'personal'
                          ? t('admin.fed.personal')
                          : t('admin.fed.space', { members: vault.members ?? 0 })}
                      </div>
                      <div className="adm-cell-sub">
                        {vault.waitingChanges > 0
                          ? t('admin.fed.waiting', { n: vault.waitingChanges })
                          : (vault.ownerEmail ?? '')}
                      </div>
                    </td>
                    <td>
                      <span className={vault.federated ? 'tag ok' : 'tag'}>
                        {vault.federated ? t('admin.fed.federated') : t('admin.fed.local')}
                      </span>
                    </td>
                    <td>
                      <div>{nameOf(vault.homeId)}</div>
                      <div className="adm-cell-sub">
                        {homeHere ? t('admin.fed.thisServer') : t(STATE[stateOf(vault.homeId)])}
                      </div>
                    </td>
                    <td>
                      {vault.replicas.length === 0
                        ? t('admin.fed.none')
                        : vault.replicas.map((id, index) => (
                            <span className="tag mute" key={id}>
                              {index + 1} {nameOf(id)}
                            </span>
                          ))}
                    </td>
                    <td className="mono">{vault.sizeBytes === null ? '—' : bytes(vault.sizeBytes)}</td>
                    <td>
                      {held(vault).length > 0 ? (
                        held(vault).map((promotion) => (
                          <div key={promotion.newHomeId}>
                            <div>{t('admin.fed.demotion.asks', { peer: nameOf(promotion.newHomeId) })}</div>
                            <div className="adm-cell-sub">
                              {t('admin.fed.demotion.sub')} · {relative(promotion.at, now)}
                            </div>
                          </div>
                        ))
                      ) : vault.request ? (
                        <>
                          <div>{t('admin.fed.asks')}</div>
                          <div className="adm-cell-sub">
                            {vault.request.by} · {relative(vault.request.at, now)}
                          </div>
                        </>
                      ) : (
                        t('admin.fed.none')
                      )}
                    </td>
                    <td>
                      <div className="adm-row-actions">
                        {held(vault).map((promotion) => (
                          <Fragment key={promotion.newHomeId}>
                            {onAcceptDemotion ? (
                              <Button
                                size="small"
                                isDisabled={busy}
                                aria-label={
                                  homeHere
                                    ? t('admin.fed.demotion.accept.of', { name, peer: nameOf(promotion.newHomeId) })
                                    : t('admin.fed.promotion.accept.of', { name, peer: nameOf(promotion.newHomeId) })
                                }
                                onPress={() => onAcceptDemotion(vault, promotion.newHomeId)}
                              >
                                {homeHere ? t('admin.fed.demotion.accept') : t('admin.fed.promotion.accept')}
                              </Button>
                            ) : null}
                            {onRefuseDemotion ? (
                              <Button
                                size="small"
                                isDisabled={busy}
                                aria-label={t('admin.fed.promotion.refuse.of', { name, peer: nameOf(promotion.newHomeId) })}
                                onPress={() => onRefuseDemotion(vault, promotion.newHomeId)}
                              >
                                {t('admin.fed.promotion.refuse')}
                              </Button>
                            ) : null}
                          </Fragment>
                        ))}
                        {vault.federated && !homeHere && !vault.request ? (
                          <Button
                            size="small"
                            aria-expanded={promoting === vault.id}
                            aria-controls="promote"
                            aria-label={t('admin.fed.promote.of', { name })}
                            onPress={() => {
                              setPromoting(vault.id);
                              setDown(false);
                            }}
                          >
                            {t('admin.fed.promote')}
                          </Button>
                        ) : null}
                        {vault.request ? (
                          <>
                            <Button
                              size="small"
                              variant="primary"
                              isDisabled={busy}
                              aria-label={t('admin.fed.accept.of', { name })}
                              onPress={() => onAccept(vault)}
                            >
                              {t('admin.fed.accept')}
                            </Button>
                            <Button
                              size="small"
                              isDisabled={busy}
                              aria-label={t('admin.fed.decline.of', { name })}
                              onPress={() => onDecline(vault)}
                            >
                              {t('admin.fed.decline')}
                            </Button>
                          </>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {promoted ? (
          <div id="promote" role="region" aria-labelledby="h-promote" className="adm-pad">
            <h3 id="h-promote">
              {t('admin.fed.promote.title', {
                self: self.name,
                vault: promoted.name ?? promoted.ownerEmail ?? shortId(promoted.id),
              })}
            </h3>
            <p>
              {t('admin.fed.promote.takes', {
                self: self.name,
                waiting: promoted.waitingNote ?? t('admin.fed.promote.nothingWaiting'),
              })}
            </p>
            <p>
              {t('admin.fed.promote.epoch', {
                from: promoted.epoch,
                to: promoted.epoch + 1,
                old: nameOf(promoted.homeId),
              })}
            </p>
            <p>{t('admin.fed.promote.apps')}</p>
            <CheckBox
              label={t('admin.fed.promote.down', { old: nameOf(promoted.homeId) })}
              hint={t('admin.fed.promote.downHint')}
              checked={down}
              onChange={setDown}
            />
            <div className="actions">
              <Button size="small" onPress={() => setPromoting(null)}>
                {t('action.cancel')}
              </Button>
              <Button
                size="small"
                variant="primary"
                isDisabled={busy}
                onPress={() => {
                  onPromote(promoted, down);
                  setPromoting(null);
                }}
              >
                {t('admin.fed.promote')}
              </Button>
            </div>
          </div>
        ) : null}
      </section>

      {peers.some((p) => p.state === 'contested') ? (
        <section className="card" aria-labelledby="h-contested">
          <div className="adm-head">
            <h2 id="h-contested">{t('admin.fed.contested.title')}</h2>
          </div>
          <p className="hint adm-pad">{t('admin.fed.contested.hint')}</p>
          <ul className="adm-list">
            {peers
              .filter((p) => p.state === 'contested')
              .map((peer) => (
                <li key={peer.serverId}>
                  <div>
                    <b>{peer.name}</b>
                    <div className="adm-cell-sub">{t('admin.fed.contested.sub')}</div>
                  </div>
                  <div className="adm-row-actions">
                    {onClearContest ? (
                      <Button
                        size="small"
                        isDisabled={busy}
                        aria-label={t('admin.fed.contested.trust.of', { peer: peer.name })}
                        onPress={() => onClearContest(peer)}
                      >
                        {t('admin.fed.contested.trust')}
                      </Button>
                    ) : null}
                    {onUnpair ? (
                      <Button
                        size="small"
                        variant="danger"
                        isDisabled={busy}
                        aria-label={t('admin.fed.contested.unpair.of', { peer: peer.name })}
                        onPress={() => onUnpair(peer)}
                      >
                        {t('admin.fed.contested.unpair')}
                      </Button>
                    ) : null}
                  </div>
                </li>
              ))}
          </ul>
        </section>
      ) : null}

      {addressChanges && addressChanges.length > 0 ? (
        <section className="card" aria-labelledby="h-addresses">
          <div className="adm-head">
            <h2 id="h-addresses">{t('admin.fed.addresses.title')}</h2>
          </div>
          <p className="hint adm-pad">{t('admin.fed.addresses.hint')}</p>
          <ul className="adm-list">
            {addressChanges.map((change) => (
              <li key={change.peerId}>
                <div>
                  <b>{nameOf(change.peerId)}</b>
                  <div className="adm-cell-sub">
                    {t('admin.fed.addresses.now', { addresses: change.addresses.join(', ') })} ·{' '}
                    {relative(change.receivedAt, now)}
                  </div>
                </div>
                <div className="adm-row-actions">
                  {onApproveAddresses ? (
                    <Button
                      size="small"
                      isDisabled={busy}
                      aria-label={t('admin.fed.addresses.approve.of', { peer: nameOf(change.peerId) })}
                      onPress={() => onApproveAddresses(change)}
                    >
                      {t('admin.fed.addresses.approve')}
                    </Button>
                  ) : null}
                  {onRefuseAddresses ? (
                    <Button
                      size="small"
                      isDisabled={busy}
                      aria-label={t('admin.fed.addresses.refuse.of', { peer: nameOf(change.peerId) })}
                      onPress={() => onRefuseAddresses(change)}
                    >
                      {t('admin.fed.addresses.refuse')}
                    </Button>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className="adm-split">
        <section className="card" aria-labelledby="h-check">
          <div className="adm-head">
            <h2 id="h-check">{t('admin.fed.consistency')}</h2>
            <Button size="small" isDisabled={busy} onPress={onRunConsistency}>
              {t('admin.fed.runNow')}
            </Button>
          </div>
          <p className="hint adm-pad">{t('admin.fed.consistencyHint')}</p>
          <ul className="adm-list">
            {consistency.map((entry) => (
              <li key={`${entry.peerId}-${entry.at}`}>
                <time dateTime={new Date(entry.at * 1000).toISOString()}>{clock(entry.at)}</time>
                <div>
                  {t(entry.ok ? 'admin.fed.consistency.match' : 'admin.fed.consistency.differ', {
                    peer: nameOf(entry.peerId),
                    vaults: entry.vaults.join(', '),
                  })}
                </div>
              </li>
            ))}
          </ul>
        </section>
        <section className="card" aria-labelledby="h-never">
          <div className="adm-head">
            <h2 id="h-never">{t('admin.fed.never')}</h2>
          </div>
          <p className="adm-pad">{t('admin.fed.neverBody')}</p>
          <div className="adm-pad">
            <Notice tone="info">
              <p>{t('admin.fed.neverNote')}</p>
            </Notice>
          </div>
        </section>
      </div>
    </>
  );
}

export default function Federation() {
  const queryClient = useQueryClient();
  const navigate = useAdminNav();
  const { guard, dialog } = useReauth(admin);
  const overview = useQuery({
    queryKey: ['admin', 'federation'],
    queryFn: () => admin.federation(),
    refetchInterval: 15_000,
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'federation'] });
  const logs = useMutation({
    mutationFn: (v: { peer: Peer; send: boolean; pull: boolean }) =>
      guard((grant) => admin.setLogs(v.peer.serverId, v.send, v.pull, grant)),
    onSuccess: refresh,
  });
  const check = useMutation({ mutationFn: () => guard((grant) => admin.checkKeys(grant)), onSuccess: refresh });
  const consistency = useMutation({ mutationFn: () => guard((grant) => admin.runConsistency(grant)), onSuccess: refresh });
  const promote = useMutation({
    mutationFn: (v: { vault: FedVault; homeIsDown: boolean }) =>
      guard((grant) => admin.promote(v.vault.id, { homeIsDown: v.homeIsDown }, grant)),
    onSuccess: refresh,
  });
  const accept = useMutation({
    mutationFn: (vault: FedVault) => guard((grant) => admin.federate(vault.id, grant)),
    onSuccess: refresh,
  });
  const decline = useMutation({
    mutationFn: (vault: FedVault) => guard((grant) => admin.declineFederation(vault.id, grant)),
    onSuccess: refresh,
  });
  const clearContest = useMutation({
    mutationFn: (peer: Peer) => guard((grant) => admin.clearContest(peer.serverId, grant)),
    onSuccess: refresh,
  });
  const unpair = useMutation({
    mutationFn: (peer: Peer) => guard((grant) => admin.unpairPeer(peer.serverId, grant)),
    onSuccess: refresh,
  });
  const addressChanges = useQuery({
    queryKey: ['admin', 'federation', 'address-changes'],
    queryFn: () => admin.addressChanges(),
    refetchInterval: 15_000,
  });
  const approveAddresses = useMutation({
    mutationFn: (change: AddressChange) => guard((grant) => admin.approveAddressChange(change.peerId, grant)),
    onSuccess: refresh,
  });
  const refuseAddresses = useMutation({
    mutationFn: (change: AddressChange) => guard((grant) => admin.refuseAddressChange(change.peerId, grant)),
    onSuccess: refresh,
  });
  const demotion = useMutation({
    mutationFn: (v: { vault: FedVault; newHomeId: string }) =>
      guard((grant) => admin.acceptDemotion(v.vault.id, grant, v.newHomeId)),
    onSuccess: refresh,
  });
  const refuseDemotion = useMutation({
    mutationFn: (v: { vault: FedVault; newHomeId: string }) =>
      guard((grant) => admin.refuseDemotion(v.vault.id, grant, v.newHomeId)),
    onSuccess: refresh,
  });
  if (overview.isPending) return <Loading />;
  if (!overview.data) return <ErrorNotice error={overview.error} />;
  return (
    <>
      <FederationView
        overview={overview.data}
        onNavigate={navigate}
        onSetLogs={(peer, send, pull) => logs.mutate({ peer, send, pull })}
        onCheckKeys={() => check.mutate()}
        onRunConsistency={() => consistency.mutate()}
        onPromote={(vault, homeIsDown) => promote.mutate({ vault, homeIsDown })}
        onAccept={(vault) => accept.mutate(vault)}
        onDecline={(vault) => decline.mutate(vault)}
        onAcceptDemotion={(vault, newHomeId) => demotion.mutate({ vault, newHomeId })}
        onRefuseDemotion={(vault, newHomeId) => refuseDemotion.mutate({ vault, newHomeId })}
        addressChanges={addressChanges.data}
        onApproveAddresses={(change) => approveAddresses.mutate(change)}
        onRefuseAddresses={(change) => refuseAddresses.mutate(change)}
        onClearContest={(peer) => clearContest.mutate(peer)}
        onUnpair={(peer) => unpair.mutate(peer)}
        busy={
          logs.isPending ||
          check.isPending ||
          consistency.isPending ||
          promote.isPending ||
          accept.isPending ||
          demotion.isPending ||
          refuseDemotion.isPending ||
          approveAddresses.isPending ||
          refuseAddresses.isPending ||
          clearContest.isPending ||
          unpair.isPending
        }
        error={
          logs.error ??
          check.error ??
          consistency.error ??
          promote.error ??
          accept.error ??
          decline.error ??
          demotion.error ??
          refuseDemotion.error ??
          approveAddresses.error ??
          refuseAddresses.error ??
          clearContest.error ??
          unpair.error
        }
      />
      {dialog}
    </>
  );
}
