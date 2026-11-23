import type { DeviceEntryDto, KeyCopyResponse } from '@/api/devices';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import '@/styles/account.css';
import { timeAgo } from '../vault/kinds';
import { type ApprovalRow, isKemlockApp } from './devicesModel';
import type { Described } from './errors';

export interface DevicesViewProps {
  /** The address other apps connect to. */
  address: string;
  approvals: ApprovalRow[] | undefined;
  approvalsError?: Described | undefined;
  /** null: the server has no device list; undefined: still loading. */
  others: DeviceEntryDto[] | null | undefined;
  /** null: this device holds no key copy; undefined: still loading. */
  keyCopy: KeyCopyResponse | null | undefined;
  cryptoAvailable: boolean;
  /** Whether this browser can keep a trusted-device key copy; defaults to `cryptoAvailable`. */
  trustAvailable?: boolean;
  busy: boolean;
  error?: Described | undefined;
  /** For "N seconds ago"; tests pin it. */
  now?: Date;
  onApprove: (row: ApprovalRow) => void;
  onDeny: (id: string) => void;
  onSignOut: (device: DeviceEntryDto) => void;
  onSignOutOthers: () => void;
  onTrust: () => void;
  onUntrust: () => void;
}

function Tile({ kemlock, children }: { kemlock: boolean; children: string }) {
  return (
    <span className={kemlock ? 'tile' : 'tile faint'} aria-hidden="true">
      {children}
    </span>
  );
}

export function DevicesView({
  address,
  approvals,
  approvalsError,
  others,
  keyCopy,
  cryptoAvailable,
  trustAvailable = cryptoAvailable,
  busy,
  error,
  now = new Date(),
  onApprove,
  onDeny,
  onSignOut,
  onSignOutOthers,
  onTrust,
  onUntrust,
}: DevicesViewProps) {
  const t = useT();
  const ago = (seconds: number) => timeAgo(new Date(now.getTime() - seconds * 1000).toISOString(), now);

  return (
    <>
      <div>
        <h1 className="page-title">{t('devices.title')}</h1>
        <p className="lede">{t('devices.lede')}</p>
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      {approvalsError ? (
        <Notice tone="error" live>
          <p>{t(approvalsError.id, approvalsError.values)}</p>
        </Notice>
      ) : null}

      {(approvals ?? []).map((row) => (
        <section className="approval" key={row.id} aria-labelledby={`h-req-${row.id}`}>
          <div className="body">
            <h2 id={`h-req-${row.id}`}>{t('devices.approval.title', { name: row.deviceName })}</h2>
            <p>{t('devices.approval.from', { ip: row.ip, ago: ago(row.ageSeconds) })}</p>
            {row.phrase ? (
              <p className="phrase" aria-label={t('devices.approval.phraseLabel')}>
                {row.phrase}
              </p>
            ) : (
              <Notice tone="warn">
                <p>{t('devices.approval.noKey')}</p>
              </Notice>
            )}
            <p className="hint">{t('devices.approval.what')}</p>
            {!cryptoAvailable ? (
              <Notice tone="warn">
                <p>{t('sharing.unavailable')}</p>
              </Notice>
            ) : null}
          </div>
          <div className="actions">
            <Button
              isDisabled={busy}
              aria-label={t('devices.approval.denyFor', { name: row.deviceName })}
              onPress={() => onDeny(row.id)}
            >
              {t('devices.approval.deny')}
            </Button>
            <Button
              variant="primary"
              isDisabled={busy || !row.phrase || !cryptoAvailable}
              aria-label={t('devices.approval.approveFor', { name: row.deviceName })}
              onPress={() => onApprove(row)}
            >
              {t('devices.approval.approve')}
            </Button>
          </div>
        </section>
      ))}

      <section className="card" aria-labelledby="h-dev">
        <div className="card-head">
          <h2 id="h-dev">
            {t('devices.signedIn')}
          </h2>
          <Button
            size="small"
            isDisabled={busy || !others || others.length === 0}
            onPress={onSignOutOthers}
          >
            {t('devices.signOutOthers')}
          </Button>
        </div>
        <div className="row">
          <Tile kemlock>K</Tile>
          <div className="grow">
            <div>{t('devices.thisBrowser')}</div>
            <div className="hint">{t('devices.thisBrowser.hint')}</div>
          </div>
          <span className="tag ok">{t('devices.api.kemlock')}</span>
          <span className="hint">{t('devices.now')}</span>
        </div>
        {others === undefined ? (
          <p className="empty" role="status">
            {t('state.loading')}
          </p>
        ) : others === null ? (
          <div className="row">
            <p className="hint grow">{t('devices.notListed')}</p>
          </div>
        ) : (
          others.map((device) => (
            <div className="row" key={device.id}>
              <Tile kemlock={isKemlockApp(device.kind)}>{(device.name[0] ?? '?').toUpperCase()}</Tile>
              <div className="grow">
                <div>{device.name}</div>
                <div className="hint">
                  {device.lastSeenAt
                    ? t('devices.lastSync', { ago: timeAgo(device.lastSeenAt, now) })
                    : t('devices.neverSynced')}
                </div>
              </div>
              <span className={isKemlockApp(device.kind) ? 'tag ok' : 'tag'}>
                {t(isKemlockApp(device.kind) ? 'devices.api.kemlock' : 'devices.api.bitwarden')}
              </span>
              <Button
                size="small"
                isDisabled={busy}
                aria-label={t('devices.signOutFor', { name: device.name })}
                onPress={() => onSignOut(device)}
              >
                {t('action.signOut')}
              </Button>
            </div>
          ))
        )}
      </section>

      <section className="card" aria-labelledby="h-trust">
        <div className="card-head">
          <h2 id="h-trust">{t('devices.trust.title')}</h2>
        </div>
        <div className="panel-body">
          <p className="hint">{t('devices.trust.body')}</p>
          {keyCopy === undefined ? (
            <p role="status" className="muted">
              {t('state.loading')}
            </p>
          ) : keyCopy ? (
            <>
              <p>
                <span className="tag ok">{t('devices.trust.on')}</span>{' '}
                {t('devices.trust.since', { when: timeAgo(keyCopy.createdAt, now) })}
              </p>
              <div className="actions">
                <Button isDisabled={busy} onPress={onUntrust}>
                  {t('devices.trust.remove')}
                </Button>
              </div>
            </>
          ) : (
            <>
              {!trustAvailable ? (
                <Notice tone="warn">
                  <p>{t('sharing.unavailable')}</p>
                </Notice>
              ) : null}
              <div className="actions">
                <Button variant="primary" isDisabled={busy || !trustAvailable} onPress={onTrust}>
                  {t('devices.trust.add')}
                </Button>
              </div>
            </>
          )}
        </div>
      </section>

      <section className="card pad" aria-labelledby="h-connect">
        <h2 id="h-connect">{t('devices.connect.title')}</h2>
        <div className="cmd">
          <code>{address}</code>
          <CopyButton value={address} label={t('devices.connect.copy')} />
        </div>
        <div className="grid">
          <p className="hint">{t('devices.connect.kemlock')}</p>
          <p className="hint">{t('devices.connect.amethystora')}</p>
          <p className="hint">{t('devices.connect.bitwarden')}</p>
        </div>
      </section>
    </>
  );
}
