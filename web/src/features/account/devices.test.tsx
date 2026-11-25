import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { DeviceEntryDto, KeyCopyResponse, PendingApprovalDto } from '@/api/devices';
import { ApiError } from '@/api/errors';
import { createDevicesApi } from '@/api/devices';
import { I18nProvider } from '@/i18n';
import { encodeB64, fromUtf8, decodeB64 } from '@/lib/b64url';
import { renderWithIntl } from '@/test/render';
import { fakeSharingCrypto } from '@/test/fake-space-crypto';
import { DevicesView, type DevicesViewProps } from './DevicesView';
import {
  type ApprovalRow,
  approveRequest,
  deviceKindLabelId,
  deviceMenu,
  isKemlockApp,
  loadApprovals,
  otherDevices,
} from './devicesModel';

const KEY = new Uint8Array(1600).fill(7);

function pending(over: Partial<PendingApprovalDto> = {}): PendingApprovalDto {
  return {
    id: '50000000-0000-4000-8000-000000000001',
    deviceName: 'Firefox on Linux',
    deviceKind: 'other',
    ip: '203.0.113.0',
    phrase: 'server says these words never',
    createdAt: '2026-11-22T10:00:00Z',
    expiresAt: '2026-11-22T10:10:00Z',
    ageSeconds: 40,
    publicKey: encodeB64(KEY),
    ...over,
  };
}

describe('approval requests', () => {
  it('work the phrase out from the key and drop the server’s words', async () => {
    const api = { approvals: vi.fn(async () => [pending()]) };
    const phraseOf = vi.fn(async () => 'tulip anchor rover mint ladle');
    const rows = await loadApprovals(api, phraseOf);
    expect(rows[0]?.phrase).toBe('tulip anchor rover mint ladle');
    expect(phraseOf).toHaveBeenCalledWith(KEY);
    expect(JSON.stringify(rows)).not.toContain('server says');
  });

  it('have no phrase when the key is not 1,600 bytes of base64url', async () => {
    const api = {
      approvals: vi.fn(async () => [
        pending({ publicKey: '' }),
        pending({ id: '2', publicKey: encodeB64(new Uint8Array(10)) }),
        pending({ id: '3', publicKey: '!!not base64!!' }),
      ]),
    };
    const rows = await loadApprovals(api, async () => 'x');
    expect(rows.map((r) => r.phrase)).toEqual([null, null, null]);
    expect(rows.map((r) => r.publicKey)).toEqual([null, null, null]);
  });

  it('are approved by sealing the root key to the request’s key, bound to my account', async () => {
    const crypto = fakeSharingCrypto();
    const api = { approve: vi.fn(async (_id: string, _sealed: string) => undefined) };
    const row: ApprovalRow = {
      id: '50000000-0000-4000-8000-000000000001',
      deviceName: 'x',
      deviceKind: 'other',
      ip: '',
      ageSeconds: 0,
      phrase: 'a b c d e',
      publicKey: KEY,
    };
    await approveRequest({ api, crypto }, row, '60000000-0000-4000-8000-000000000001');
    expect(crypto.calls).toEqual(['sealRootKey:device-approval']);
    const [id, sealed] = api.approve.mock.calls[0] ?? [];
    expect(id).toBe('50000000-0000-4000-8000-000000000001');
    // The aad is the account id then the request id: 32 bytes.
    expect(fromUtf8(decodeB64(sealed ?? ''))).toBe('root>device-approval>1600>32');
  });

  it('are never approved without a key', async () => {
    const api = { approve: vi.fn(async (_id: string, _sealed: string) => undefined) };
    const row: ApprovalRow = { id: 'r', deviceName: '', deviceKind: 'other', ip: '', ageSeconds: 0, phrase: null, publicKey: null };
    await expect(approveRequest({ api, crypto: fakeSharingCrypto() }, row, '60000000-0000-4000-8000-000000000001')).rejects.toThrow();
    expect(api.approve).not.toHaveBeenCalled();
  });
});

describe('device helpers', () => {
  it('tell Kemlock apps from the Bitwarden-API ones', () => {
    expect(isKemlockApp('kemlock-ios')).toBe(true);
    expect(isKemlockApp('bitwarden')).toBe(false);
    expect(isKemlockApp('amethystora')).toBe(false);
    expect(isKemlockApp('kemlock-browser')).toBe(true);
  });

  it('give the extension and the web vault each their own label', () => {
    expect(deviceKindLabelId('kemlock-browser')).toBe('devices.kind.kemlockBrowser');
    expect(deviceKindLabelId('kemlock-web')).toBe('devices.kind.kemlockWeb');
    expect(deviceKindLabelId('kemlock-browser')).not.toBe(deviceKindLabelId('kemlock-web'));
    expect(deviceKindLabelId('other')).toBe('devices.kind.other');
  });

  it('give a row its menu: trust is for Kemlock apps only, and only a device can start trusting itself', () => {
    // This browser can trust itself, or stop.
    expect(deviceMenu({ kind: 'kemlock-web', trusted: false, current: true })).toEqual(['trust', 'sign-out']);
    expect(deviceMenu({ kind: 'kemlock-web', trusted: true, current: true })).toEqual(['untrust', 'sign-out']);
    // Another Kemlock app can be taken off; one that is not trusted still lists Trust this device,
    // which the screen shows off, because only that app can turn it on.
    expect(deviceMenu({ kind: 'kemlock-ios', trusted: true, current: false })).toEqual(['untrust', 'sign-out']);
    expect(deviceMenu({ kind: 'kemlock-android', trusted: false, current: false })).toEqual(['trust', 'sign-out']);
    expect(deviceMenu({ kind: 'kemlock-browser', trusted: false, current: false })).toEqual(['trust', 'sign-out']);
    // Amethystora and Bitwarden: Sign out alone, trusted or not.
    for (const kind of ['amethystora', 'bitwarden', 'other'] as const) {
      expect(deviceMenu({ kind, trusted: false, current: false })).toEqual(['sign-out']);
      expect(deviceMenu({ kind, trusted: true, current: false })).toEqual(['sign-out']);
    }
  });

  it('list the other devices, newest sync first', () => {
    const d = (id: string, lastSeenAt: string, current = false): DeviceEntryDto => ({
      id,
      name: id,
      kind: 'other',
      createdAt: '2025-12-01T00:00:00Z',
      lastSeenAt,
      current,
      trusted: false,
    });
    const list = otherDevices([d('old', '2026-01-01'), d('me', '2026-11-01', true), d('new', '2026-11-20')], null);
    expect(list.map((x) => x.id)).toEqual(['new', 'old']);
    expect(otherDevices([d('a', '2026-11-02'), d('b', '2026-11-03')], 'a').map((x) => x.id)).toEqual(['b']);
  });
});

describe('the devices client', () => {
  it('reads "no key copy" and "no device list" from a 404', async () => {
    const request = vi.fn(async () => {
      throw new ApiError(404, undefined);
    });
    const api = createDevicesApi({ request, send: vi.fn() } as never);
    expect(await api.keyCopy()).toBeNull();
    expect(await api.devices()).toBeNull();
  });

  it('stops trusting another device by its id, and keeps the session', async () => {
    const send = vi.fn(async () => undefined);
    const api = createDevicesApi({ request: vi.fn(), send } as never);
    await api.untrustDevice('50000000-0000-4000-8000-0000000000aa');
    expect(send).toHaveBeenCalledWith({
      method: 'DELETE',
      path: '/kem/v1/devices/50000000-0000-4000-8000-0000000000aa/key-copy',
    });
  });

  it('reads when a device made its key copy', async () => {
    const entry = {
      id: 'd1',
      name: 'iPhone',
      kind: 'kemlock-ios',
      createdAt: '2026-10-01T00:00:00Z',
      lastSeenAt: '2026-11-22T09:01:00Z',
      current: false,
      trusted: true,
      trustedSince: '2026-09-22T10:00:00Z',
    };
    const api = createDevicesApi({ request: vi.fn(async () => ({ devices: [entry] })), send: vi.fn() } as never);
    expect(await api.devices()).toEqual([entry]);
  });

  it('answers an approval with the decision and the sealed key', async () => {
    const send = vi.fn(async () => undefined);
    const api = createDevicesApi({ request: vi.fn(), send } as never);
    await api.approve('r1', 'SEALED');
    await api.deny('r2');
    expect(send).toHaveBeenNthCalledWith(1, {
      method: 'POST',
      path: '/kem/v1/devices/approvals/r1',
      body: { decision: 'approve', sealedKey: 'SEALED' },
    });
    expect(send).toHaveBeenNthCalledWith(2, {
      method: 'POST',
      path: '/kem/v1/devices/approvals/r2',
      body: { decision: 'deny' },
    });
  });
});

const copied = vi.hoisted(() => ({ copyText: vi.fn(async (_text: string) => true) }));
vi.mock('@/lib/clipboard', () => ({ copyText: copied.copyText }));

function device(over: Partial<DeviceEntryDto> = {}): DeviceEntryDto {
  return {
    id: 'd1',
    name: 'Pixel 9',
    kind: 'kemlock-android',
    createdAt: '2026-10-01T00:00:00Z',
    lastSeenAt: '2026-11-22T09:01:00Z',
    current: false,
    trusted: false,
    ...over,
  };
}

const KEY_COPY: KeyCopyResponse = {
  deviceId: 'me',
  wrappedKey: 'k',
  protection: 'web-crypto',
  createdAt: '2026-11-01T10:00:00Z',
  updatedAt: '2026-11-01T10:00:00Z',
};

function baseProps(): DevicesViewProps {
  return {
    address: 'https://vault.example.org',
    approvals: [],
    others: [],
    keyCopy: null,
    cryptoAvailable: true,
    busy: false,
    now: new Date('2026-11-22T10:01:00Z'),
    onApprove: vi.fn(),
    onDeny: vi.fn(),
    onSignOut: vi.fn(),
    onSignOutOthers: vi.fn(),
    onSignOutThisBrowser: vi.fn(),
    onTrust: vi.fn(),
    onUntrust: vi.fn(),
    onUntrustDevice: vi.fn(),
  };
}

function view(over: Partial<DevicesViewProps> = {}) {
  const props: DevicesViewProps = { ...baseProps(), ...over };
  renderWithIntl(<DevicesView {...props} />);
  return props;
}

/** Opens a row's menu and returns the names of its items. */
async function openMenu(user: ReturnType<typeof userEvent.setup>, name: string): Promise<string[]> {
  await user.click(screen.getByRole('button', { name: `Actions for ${name}` }));
  const menu = await screen.findByRole('menu', { name: `Actions for ${name}` });
  return within(menu)
    .getAllByRole('menuitem')
    .map((item) => item.textContent ?? '');
}

const ROW: ApprovalRow = {
  id: 'req-1',
  deviceName: 'Firefox on Linux',
  deviceKind: 'other',
  ip: '203.0.113.0',
  ageSeconds: 40,
  phrase: 'tulip anchor rover mint ladle',
  publicKey: KEY,
};

describe('DevicesView', () => {
  it('shows this browser and the title', () => {
    view();
    expect(screen.getByRole('heading', { name: 'Devices & apps', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('This browser')).toBeInTheDocument();
  });

  it('shows the client-side phrase and approves or denies', async () => {
    const props = view({ approvals: [ROW] });
    expect(screen.getByText('Firefox on Linux is asking to sign in as you')).toBeInTheDocument();
    expect(screen.getByText('tulip anchor rover mint ladle')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Approve Firefox on Linux' }));
    expect(props.onApprove).toHaveBeenCalledWith(ROW);
    await user.click(screen.getByRole('button', { name: 'Deny Firefox on Linux' }));
    expect(props.onDeny).toHaveBeenCalledWith('req-1');
  });

  it('will not approve a request whose key the server did not send', () => {
    view({ approvals: [{ ...ROW, phrase: null, publicKey: null }] });
    expect(screen.getByRole('button', { name: 'Approve Firefox on Linux' })).toBeDisabled();
    expect(screen.getByText(/can't work out its phrase and won't approve it/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deny Firefox on Linux' })).toBeEnabled();
  });

  it('will not approve when the worker can not seal the key yet', () => {
    view({ approvals: [ROW], cryptoAvailable: false });
    expect(screen.getByRole('button', { name: 'Approve Firefox on Linux' })).toBeDisabled();
  });

  it('lists other devices with their API and their last sync', () => {
    view({
      others: [
        device({
          id: 'd1',
          name: 'Bitwarden extension in Firefox',
          kind: 'bitwarden',
          lastBitwardenUseAt: '2026-11-22T09:01:00Z',
        }),
      ],
    });
    const row = screen.getByText('Bitwarden extension in Firefox').closest('.row') as HTMLElement;
    expect(within(row).getByText('Bitwarden API')).toBeInTheDocument();
    expect(within(row).getByText('Last sync 1 hour ago')).toBeInTheDocument();
  });

  it('names the extension "Kemlock for browsers" and the web vault apart from it', () => {
    view({
      others: [
        device({ id: 'e1', name: 'Kemlock, Firefox', kind: 'kemlock-browser' }),
        device({ id: 'w1', name: 'Web vault, Firefox', kind: 'kemlock-web' }),
      ],
    });
    const extension = screen.getByText('Kemlock, Firefox').closest('.row') as HTMLElement;
    expect(within(extension).getByText('Kemlock for browsers')).toBeInTheDocument();
    expect(within(extension).getByText('Kemlock API')).toBeInTheDocument();
    const web = screen.getByText('Web vault, Firefox').closest('.row') as HTMLElement;
    expect(within(web).getByText('Kemlock web vault')).toBeInTheDocument();
    expect(within(web).queryByText('Kemlock for browsers')).toBeNull();
  });

  it('says plainly when the server has no device list', () => {
    view({ others: null });
    expect(screen.getByText(/doesn't list the other apps/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out everyone else' })).toBeDisabled();
  });

  it('has no panel for trust and none for connecting: both moved into the table and a dialog', () => {
    view();
    expect(screen.queryByRole('heading', { name: 'Trust this device' })).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Connect another app' })).toBeNull();
    expect(screen.queryByText('https://vault.example.org')).toBeNull();
  });
});

describe('the header buttons', () => {
  it('are Connect and Sign out everyone else', () => {
    view({ others: [device()] });
    const header = screen.getByRole('heading', { name: 'Signed in' }).closest('.card-head') as HTMLElement;
    expect(within(header).getAllByRole('button').map((b) => b.textContent)).toEqual([
      'Connect',
      'Sign out everyone else',
    ]);
    expect(within(header).getByRole('button', { name: 'Connect an app or device' })).toBeInTheDocument();
  });

  it('sign everyone else out, and only while there is someone else', async () => {
    const props = view({ others: [device()] });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Sign out everyone else' }));
    expect(props.onSignOutOthers).toHaveBeenCalled();
  });

  it('keep Sign out everyone else off when this browser is alone', () => {
    view({ others: [] });
    expect(screen.getByRole('button', { name: 'Sign out everyone else' })).toBeDisabled();
  });
});

describe('the Connect dialog', () => {
  it('opens with the server address and the three steps stacked', async () => {
    view();
    const user = userEvent.setup();
    expect(screen.queryByRole('dialog')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    expect(within(dialog).getByText('https://vault.example.org')).toBeInTheDocument();
    expect(
      within(dialog).getByText(/Use this server's address in the app, then sign in\. A new device may ask/),
    ).toBeInTheDocument();
    const steps = Array.from(dialog.querySelectorAll('.stack-steps > p')).map((p) => p.textContent);
    expect(steps).toEqual([
      'Kemlock: Settings, Sync, Kemlock Server, then sign in.',
      'Amethystora Vault: the Sync page, with this address as the server.',
      'Bitwarden apps: choose a self-hosted server and paste this address.',
    ]);
  });

  it('shows the address it is given, whatever the page is served from', async () => {
    view({ address: 'https://vault.example.co' });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    expect(within(dialog).getByText('https://vault.example.co')).toBeInTheDocument();
    expect(within(dialog).queryByText('https://vault.example.org')).toBeNull();
  });

  it('waits for the server to say its address: a loading line, and nothing to copy', async () => {
    copied.copyText.mockClear();
    view({ address: undefined });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    expect(within(dialog).getByText("Loading this server's address…")).toHaveAttribute('role', 'status');
    expect(within(dialog).getByRole('button', { name: 'Copy the address' })).toBeDisabled();
    // The page's own address is no stand-in.
    expect(within(dialog).queryByText(window.location.origin)).toBeNull();
    expect(dialog.querySelector('code')).toBeNull();
    await user.click(within(dialog).getByRole('button', { name: 'Copy the address' }));
    expect(copied.copyText).not.toHaveBeenCalled();
  });

  it('says so when the server could not give its address, and still has nothing to copy', async () => {
    view({ address: undefined, addressFailed: true });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    expect(within(dialog).getByText(/Couldn't read this server's address/)).toBeInTheDocument();
    expect(within(dialog).queryByText(/Loading this server's address/)).toBeNull();
    expect(within(dialog).getByRole('button', { name: 'Copy the address' })).toBeDisabled();
  });

  it('turns Copy on when the address arrives', async () => {
    const user = userEvent.setup();
    const { rerender } = renderWithIntl(
      <DevicesView
        {...baseProps()}
        address={undefined}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    expect(within(dialog).getByRole('button', { name: 'Copy the address' })).toBeDisabled();
    rerender(
      <I18nProvider>
        <DevicesView {...baseProps()} address="https://vault.example.org" />
      </I18nProvider>,
    );
    expect(within(screen.getByRole('dialog')).getByText('https://vault.example.org')).toBeInTheDocument();
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: 'Copy the address' })).toBeEnabled();
    expect(screen.queryByText(/Loading this server's address/)).toBeNull();
  });

  it('copies the address and says so', async () => {
    copied.copyText.mockClear();
    view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    await user.click(within(dialog).getByRole('button', { name: 'Copy the address' }));
    expect(copied.copyText).toHaveBeenCalledWith('https://vault.example.org');
    expect(await within(dialog).findByText('Copied')).toBeInTheDocument();
  });

  it('says when the copy did not work', async () => {
    copied.copyText.mockResolvedValueOnce(false);
    view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Connect an app or device' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an app or device' });
    await user.click(within(dialog).getByRole('button', { name: 'Copy the address' }));
    expect(await within(dialog).findByText("Couldn't copy")).toBeInTheDocument();
  });

  it('closes with Done, with its cross and with Escape', async () => {
    view();
    const user = userEvent.setup();
    const open = async () => {
      await user.click(screen.getByRole('button', { name: 'Connect an app or device' }));
      return screen.findByRole('dialog', { name: 'Connect an app or device' });
    };
    await within(await open()).findByRole('button', { name: 'Done' });
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await open();
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await open();
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });
});

describe('trust in the table', () => {
  it('puts a shield by the name of a trusted device, with a tooltip that says since when', () => {
    view({
      keyCopy: KEY_COPY,
      others: [device({ id: 'd1', name: 'Sam’s iPhone 16', kind: 'kemlock-ios', trusted: true, trustedSince: '2026-09-22T10:00:00Z' })],
    });
    const shields = screen.getAllByRole('button', { name: 'Trusted device' });
    expect(shields).toHaveLength(2);
    // This browser: its key copy was made three weeks ago.
    const mine = screen.getByText('This browser').closest('.row') as HTMLElement;
    const mineTip = within(mine).getByRole('tooltip');
    expect(mineTip).toHaveTextContent('Trusted since 21 days ago');
    expect(mineTip).toHaveTextContent('wrapped by a key only it holds, so it can open the vault without the master password');
    expect(within(mine).getByRole('button', { name: 'Trusted device' })).toHaveAccessibleDescription(
      /^Trusted since 21 days ago/,
    );
    const phone = screen.getByText('Sam’s iPhone 16').closest('.row') as HTMLElement;
    expect(within(phone).getByRole('tooltip')).toHaveTextContent('Trusted since 2 months ago');
  });

  it('puts no shield on a device that is not trusted', () => {
    view({ keyCopy: null, others: [device({ trusted: false })] });
    expect(screen.queryByRole('button', { name: 'Trusted device' })).toBeNull();
    expect(screen.queryByRole('tooltip')).toBeNull();
  });

  it('says only that it is trusted when the server did not say since when', () => {
    view({ others: [device({ kind: 'kemlock-ios', trusted: true })] });
    expect(screen.getByRole('tooltip')).toHaveTextContent(/^Trusted device/);
  });

  it('puts the tooltip away on Escape and brings it back on the next focus', async () => {
    view({ others: [device({ kind: 'kemlock-ios', trusted: true, trustedSince: '2026-11-20T10:00:00Z' })] });
    const user = userEvent.setup();
    const tip = screen.getByRole('tooltip');
    expect(tip).not.toHaveAttribute('data-dismissed');
    await user.click(screen.getByRole('button', { name: 'Trusted device' }));
    await user.keyboard('{Escape}');
    expect(tip).toHaveAttribute('data-dismissed', 'true');
    // Moving on brings it back for the next time.
    await user.tab();
    expect(tip).not.toHaveAttribute('data-dismissed');
  });

  it('offers this browser Trust this device, then Sign out of this browser', async () => {
    const props = view({ keyCopy: null });
    const user = userEvent.setup();
    expect(await openMenu(user, 'this browser')).toEqual(['Trust this device', 'Sign out of this browser']);
    await user.click(screen.getByRole('menuitem', { name: 'Trust this device' }));
    expect(props.onTrust).toHaveBeenCalledTimes(1);
  });

  it('offers a trusted browser Stop trusting, then Sign out of this browser', async () => {
    const props = view({ keyCopy: KEY_COPY });
    const user = userEvent.setup();
    expect(await openMenu(user, 'this browser')).toEqual(['Stop trusting', 'Sign out of this browser']);
    await user.click(screen.getByRole('menuitem', { name: 'Stop trusting' }));
    expect(props.onUntrust).toHaveBeenCalledTimes(1);
  });

  it('signs this browser out from its own row', async () => {
    const props = view();
    const user = userEvent.setup();
    await openMenu(user, 'this browser');
    await user.click(screen.getByRole('menuitem', { name: 'Sign out of this browser' }));
    expect(props.onSignOutThisBrowser).toHaveBeenCalledTimes(1);
  });

  it('will not trust a browser that can not keep a key copy, and says why', async () => {
    const props = view({ keyCopy: null, trustAvailable: false });
    const user = userEvent.setup();
    await openMenu(user, 'this browser');
    expect(screen.getByRole('menuitem', { name: 'Trust this device' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByText(/This browser can't seal or sign keys yet/)).toBeInTheDocument();
    await user.click(screen.getByRole('menuitem', { name: 'Trust this device' }));
    expect(props.onTrust).not.toHaveBeenCalled();
  });

  it('waits for the key copy before it offers to trust', async () => {
    view({ keyCopy: undefined });
    const user = userEvent.setup();
    await openMenu(user, 'this browser');
    expect(screen.getByRole('menuitem', { name: 'Trust this device' })).toHaveAttribute('aria-disabled', 'true');
  });

  it('offers a trusted Kemlock app Stop trusting, then Sign out', async () => {
    const phone = device({ id: 'd7', name: 'Sam’s iPhone 16', kind: 'kemlock-ios', trusted: true });
    const props = view({ others: [phone] });
    const user = userEvent.setup();
    expect(await openMenu(user, 'Sam’s iPhone 16')).toEqual(['Stop trusting', 'Sign out']);
    await user.click(screen.getByRole('menuitem', { name: 'Stop trusting' }));
    expect(props.onUntrustDevice).toHaveBeenCalledWith(phone);
    expect(props.onSignOut).not.toHaveBeenCalled();
  });

  it('lists Trust this device, off, in another Kemlock app menu, with the reason tied to the menu', async () => {
    const props = view({ others: [device({ name: 'Pixel 9', kind: 'kemlock-android', trusted: false })] });
    const user = userEvent.setup();
    expect(await openMenu(user, 'Pixel 9')).toEqual(['Trust this device', 'Sign out']);
    const trust = screen.getByRole('menuitem', { name: 'Trust this device' });
    expect(trust).toHaveAttribute('aria-disabled', 'true');
    const note = screen.getByText('Only that device can turn this on: open Kemlock on it.');
    expect(screen.getByRole('menu', { name: 'Actions for Pixel 9' })).toHaveAttribute('aria-describedby', note.id);
    expect(screen.getByRole('menu', { name: 'Actions for Pixel 9' })).toHaveAccessibleDescription(
      'Only that device can turn this on: open Kemlock on it.',
    );
    await user.click(trust);
    expect(props.onTrust).not.toHaveBeenCalled();
    expect(props.onUntrustDevice).not.toHaveBeenCalled();
    expect(props.onSignOut).not.toHaveBeenCalled();
  });

  it('gives a trusted Kemlock app no note: it is already trusted', async () => {
    view({ others: [device({ name: 'Pixel 9', kind: 'kemlock-android', trusted: true })] });
    await openMenu(userEvent.setup(), 'Pixel 9');
    expect(document.querySelector('.menu-note')).toBeNull();
  });

  it('offers Amethystora and Bitwarden rows Sign out alone, with no note', async () => {
    const props = view({
      others: [
        device({ id: 'a1', name: 'Workstation', kind: 'amethystora' }),
        device({ id: 'b1', name: 'Build server', kind: 'bitwarden' }),
      ],
    });
    const user = userEvent.setup();
    for (const name of ['Workstation', 'Build server']) {
      expect(await openMenu(user, name)).toEqual(['Sign out']);
      expect(document.querySelector('.menu-note')).toBeNull();
      expect(screen.queryByRole('menuitem', { name: /trust/i })).toBeNull();
      await user.keyboard('{Escape}');
      await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
    }
    await openMenu(user, 'Build server');
    await user.click(screen.getByRole('menuitem', { name: 'Sign out' }));
    expect(props.onSignOut).toHaveBeenCalledWith(expect.objectContaining({ id: 'b1' }));
  });

  it('shows a shield only by a device that holds a copy, whatever its kind', () => {
    view({ others: [device({ name: 'Build server', kind: 'bitwarden', trusted: false })] });
    expect(screen.queryByRole('button', { name: 'Trusted device' })).toBeNull();
  });

  it('turns the row menus off while a change is on its way', () => {
    view({ busy: true, others: [device()] });
    expect(screen.getByRole('button', { name: 'Actions for this browser' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Actions for Pixel 9' })).toBeDisabled();
  });
});
