import { useEffect, useId, useRef, useState } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import type { DeviceEntryDto, KeyCopyResponse } from '@/api/devices';
import { useT } from '@/i18n';
import { copyText } from '@/lib/clipboard';
import { Button, IconButton } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { RowMenu, type RowMenuItem } from '@/ui/RowMenu';
import '@/styles/account.css';
import { timeAgo } from '../vault/kinds';
import { type ApprovalRow, deviceKindLabelId, deviceMenu, isKemlockApp } from './devicesModel';
import type { Described } from './errors';

export interface DevicesViewProps {
  /**
   * The address other apps connect to: the server's configured public address, from its
   * `/config`. Undefined until that answer is here; the page's own address is no stand-in.
   */
  address: string | undefined;
  /** Whether asking the server for its address failed. */
  addressFailed?: boolean;
  approvals: ApprovalRow[] | undefined;
  approvalsError?: Described | undefined;
  /**
   * This account's key fingerprint, shown beside each request so the person can compare it with
   * the one the new device shows once it has opened its keys. null: this browser can't work it
   * out; undefined: still loading.
   */
  ownFingerprint?: string | null | undefined;
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
  /** Signs another device out. */
  onSignOut: (device: DeviceEntryDto) => void;
  onSignOutOthers: () => void;
  /** Signs this browser out. */
  onSignOutThisBrowser: () => void;
  /** Trusts this browser: it makes its own copy of the key. */
  onTrust: () => void;
  /** Stops trusting this browser. */
  onUntrust: () => void;
  /** Stops trusting another Kemlock app of the account. */
  onUntrustDevice: (device: DeviceEntryDto) => void;
}

function Tile({ kemlock, children }: { kemlock: boolean; children: string }) {
  return (
    <span className={kemlock ? 'tile' : 'tile faint'} aria-hidden="true">
      {children}
    </span>
  );
}

/**
 * The blue shield beside a trusted device's name. Its tooltip, on hover and on keyboard focus,
 * says since when and what trust means; Escape puts it away while the pointer or focus stays.
 */
export function TrustedMark({ since, now }: { since?: string | null | undefined; now: Date }) {
  const t = useT();
  const tip = useId();
  const [dismissed, setDismissed] = useState(false);
  const when = since ? timeAgo(since, now) : '';
  return (
    <span className="tr-i" onMouseLeave={() => setDismissed(false)}>
      <button
        type="button"
        className="tr-b"
        aria-label={t('devices.trusted.label')}
        aria-describedby={tip}
        onBlur={() => setDismissed(false)}
        onKeyDown={(event) => {
          if (event.key === 'Escape') setDismissed(true);
        }}
      >
        <Icon name="shieldCheck" />
      </button>
      <span id={tip} role="tooltip" className="tr-tip" data-dismissed={dismissed ? true : undefined}>
        <span className="tr-title">{when ? t('devices.trusted.since', { when }) : t('devices.trusted.label')}</span>
        {t('devices.trusted.body')}
      </span>
    </span>
  );
}

/** A button that copies the address, "Copied" for a moment after; off while there is none. */
function CopyAddress({ address }: { address: string | undefined }) {
  const t = useT();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <>
      <Button
        size="small"
        isDisabled={address === undefined}
        onPress={() => {
          if (address === undefined) return;
          void copyText(address).then((ok) => {
            setState(ok ? 'copied' : 'failed');
            clearTimeout(timer.current);
            timer.current = setTimeout(() => setState('idle'), 2000);
          });
        }}
      >
        <Icon name={state === 'copied' ? 'check' : 'copy'} />
        {t('devices.connect.copy')}
      </Button>
      <span className="sr" role="status">
        {state === 'copied' ? t('copy.done') : state === 'failed' ? t('copy.failed') : ''}
      </span>
    </>
  );
}

/** "Connect": the server's address to copy, then how each kind of app takes it, one under another. */
export function ConnectDialog({
  address,
  failed,
  isOpen,
  onOpenChange,
}: {
  address: string | undefined;
  failed?: boolean | undefined;
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  return (
    <ModalOverlay isOpen={isOpen} onOpenChange={onOpenChange} isDismissable className="overlay">
      <Modal>
        <Dialog className="dialog wide">
          {({ close }) => (
            <>
              <div className="dlg-head">
                <Icon name="device" />
                <Heading slot="title">{t('devices.connect.title')}</Heading>
                <IconButton aria-label={t('devices.connect.close')} onPress={close}>
                  <Icon name="close" />
                </IconButton>
              </div>
              <p className="hint">{t('devices.connect.lede')}</p>
              <div className="addr-row">
                {address === undefined ? null : <code>{address}</code>}
                <CopyAddress address={address} />
              </div>
              {address === undefined && !failed ? (
                <p className="hint" role="status">
                  {t('devices.connect.loading')}
                </p>
              ) : null}
              {address === undefined && failed ? (
                <Notice tone="error" live>
                  <p>{t('devices.connect.failed')}</p>
                </Notice>
              ) : null}
              <div className="stack-steps">
                <p className="hint">{t('devices.connect.kemlock')}</p>
                <p className="hint">{t('devices.connect.amethystora')}</p>
                <p className="hint">{t('devices.connect.bitwarden')}</p>
              </div>
              <div className="dlg-foot">
                <Button onPress={close}>{t('devices.connect.done')}</Button>
              </div>
            </>
          )}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}

export function DevicesView({
  address,
  addressFailed,
  approvals,
  approvalsError,
  ownFingerprint,
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
  onSignOutThisBrowser,
  onTrust,
  onUntrust,
  onUntrustDevice,
}: DevicesViewProps) {
  const t = useT();
  const [connectOpen, setConnectOpen] = useState(false);
  const ago = (seconds: number) => timeAgo(new Date(now.getTime() - seconds * 1000).toISOString(), now);

  const signOutItem = (label: string, onAction: () => void): RowMenuItem => ({
    id: 'sign-out',
    label,
    icon: <Icon name="logout" />,
    danger: true,
    onAction,
  });

  // This browser: it can trust itself, because it holds the wrapping key; it signs itself out.
  const thisBrowserItems: RowMenuItem[] = deviceMenu({ kind: 'kemlock-web', trusted: Boolean(keyCopy), current: true }).map(
    (action) => {
      switch (action) {
        case 'trust':
          return {
            id: 'trust',
            label: t('devices.trust.trust'),
            icon: <Icon name="shieldCheck" />,
            disabled: keyCopy === undefined || !trustAvailable,
            onAction: onTrust,
          };
        case 'untrust':
          return {
            id: 'untrust',
            label: t('devices.trust.stop'),
            icon: <Icon name="shieldOff" />,
            onAction: onUntrust,
          };
        case 'sign-out':
          return signOutItem(t('devices.signOut.thisBrowser'), onSignOutThisBrowser);
      }
    },
  );
  const cannotTrustHere = keyCopy === null && !trustAvailable;

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
            {ownFingerprint ? (
              <>
                <p className="hint">{t('devices.approval.fingerprint')}</p>
                <p className="phrase" aria-label={t('devices.approval.fingerprintLabel')}>
                  {ownFingerprint}
                </p>
              </>
            ) : ownFingerprint === null ? (
              <Notice tone="warn">
                <p>{t('devices.approval.noFingerprint')}</p>
              </Notice>
            ) : null}
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
          <h2 id="h-dev">{t('devices.signedIn')}</h2>
          <div className="head-actions">
            <Button
              size="small"
              variant="primary"
              aria-label={t('devices.connect.aria')}
              onPress={() => setConnectOpen(true)}
            >
              <Icon name="plus" />
              {t('devices.connect')}
            </Button>
            <Button size="small" isDisabled={busy || !others || others.length === 0} onPress={onSignOutOthers}>
              <Icon name="logout" />
              {t('devices.signOutOthers')}
            </Button>
          </div>
        </div>
        <div className="row">
          <Tile kemlock>K</Tile>
          <div className="grow">
            <div>
              {t('devices.thisBrowser')}
              {keyCopy ? <TrustedMark since={keyCopy.createdAt} now={now} /> : null}
            </div>
            <div className="hint">{t('devices.thisBrowser.hint')}</div>
          </div>
          <span className="tag ok">{t('devices.api.kemlock')}</span>
          <span className="hint">{t('devices.now')}</span>
          <RowMenu
            label={t('devices.actionsFor', { name: t('devices.thisBrowser.name') })}
            items={thisBrowserItems}
            note={cannotTrustHere ? t('sharing.unavailable') : undefined}
            isDisabled={busy}
          />
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
          others.map((device) => {
            const actions = deviceMenu(device);
            const items: RowMenuItem[] = actions.map((action) => {
              switch (action) {
                case 'untrust':
                  return {
                    id: 'untrust',
                    label: t('devices.trust.stop'),
                    icon: <Icon name="shieldOff" />,
                    onAction: () => onUntrustDevice(device),
                  };
                case 'trust':
                  // Only the device that holds the wrapping key can make its copy, so from here
                  // the item is shown off, with the reason under the menu.
                  return {
                    id: 'trust',
                    label: t('devices.trust.trust'),
                    icon: <Icon name="shieldCheck" />,
                    disabled: true,
                    onAction: () => undefined,
                  };
                case 'sign-out':
                  return signOutItem(t('action.signOut'), () => onSignOut(device));
              }
            });
            return (
              <div className="row" key={device.id}>
                <Tile kemlock={isKemlockApp(device.kind)}>{(device.name[0] ?? '?').toUpperCase()}</Tile>
                <div className="grow">
                  <div>
                    {device.name}
                    {device.trusted ? <TrustedMark since={device.trustedSince} now={now} /> : null}
                  </div>
                  <div className="hint">{t(deviceKindLabelId(device.kind))}</div>
                  <div className="hint">
                    {device.lastSeenAt
                      ? t('devices.lastSync', { ago: timeAgo(device.lastSeenAt, now) })
                      : t('devices.neverSynced')}
                  </div>
                </div>
                <span className={isKemlockApp(device.kind) ? 'tag ok' : 'tag'}>
                  {t(isKemlockApp(device.kind) ? 'devices.api.kemlock' : 'devices.api.bitwarden')}
                </span>
                <RowMenu
                  label={t('devices.actionsFor', { name: device.name })}
                  items={items}
                  note={actions.includes('trust') ? t('devices.trust.onlyThere') : undefined}
                  isDisabled={busy}
                />
              </div>
            );
          })
        )}
      </section>

      <ConnectDialog
        address={address}
        failed={addressFailed}
        isOpen={connectOpen}
        onOpenChange={setConnectOpen}
      />
    </>
  );
}
