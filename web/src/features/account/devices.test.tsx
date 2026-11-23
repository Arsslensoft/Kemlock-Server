import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { DeviceEntryDto, PendingApprovalDto } from '@/api/devices';
import { ApiError } from '@/api/errors';
import { createDevicesApi } from '@/api/devices';
import { encodeB64, fromUtf8, decodeB64 } from '@/lib/b64url';
import { renderWithIntl } from '@/test/render';
import { fakeSharingCrypto } from '@/test/fake-space-crypto';
import { DevicesView, type DevicesViewProps } from './DevicesView';
import { type ApprovalRow, approveRequest, isKemlockApp, loadApprovals, otherDevices } from './devicesModel';

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

function view(over: Partial<DevicesViewProps> = {}) {
  const props: DevicesViewProps = {
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
    onTrust: vi.fn(),
    onUntrust: vi.fn(),
    ...over,
  };
  renderWithIntl(<DevicesView {...props} />);
  return props;
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

  it('lists other devices with their API and signs one out', async () => {
    const device: DeviceEntryDto = {
      id: 'd1',
      name: 'Bitwarden extension in Firefox',
      kind: 'bitwarden',
      createdAt: '2026-10-01T00:00:00Z',
      lastSeenAt: '2026-11-22T09:01:00Z',
      lastBitwardenUseAt: '2026-11-22T09:01:00Z',
      current: false,
      trusted: false,
    };
    const props = view({ others: [device] });
    const row = screen.getByText('Bitwarden extension in Firefox').closest('.row') as HTMLElement;
    expect(within(row).getByText('Bitwarden API')).toBeInTheDocument();
    expect(within(row).getByText('Last sync 1 hour ago')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Sign out Bitwarden extension in Firefox' }));
    expect(props.onSignOut).toHaveBeenCalledWith(device);
    await user.click(screen.getByRole('button', { name: 'Sign out everywhere else' }));
    expect(props.onSignOutOthers).toHaveBeenCalled();
  });

  it('says plainly when the server has no device list', () => {
    view({ others: null });
    expect(screen.getByText(/doesn't list the other apps/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out everywhere else' })).toBeDisabled();
  });

  it('trusts this device, and stops trusting it', async () => {
    const props = view();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Trust this device' }));
    expect(props.onTrust).toHaveBeenCalled();
  });

  it('shows an existing key copy and removes it', async () => {
    const props = view({
      keyCopy: {
        deviceId: 'd',
        wrappedKey: 'k',
        protection: 'web-crypto',
        createdAt: '2026-11-20T10:00:00Z',
        updatedAt: '2026-11-20T10:00:00Z',
      },
    });
    expect(screen.getByText('Trusted')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Stop trusting this device' }));
    expect(props.onUntrust).toHaveBeenCalled();
  });

  it('shows the address other apps connect to', () => {
    view();
    expect(screen.getByText('https://vault.example.org')).toBeInTheDocument();
  });
});
