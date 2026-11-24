import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { Placement } from '@/api/placement';
import { PLACEMENT } from '@/test/placement-fixture';
import { renderInRouter } from '@/test/tools-fixtures';
import { FailoverBannerView } from './Banner';
import { StorageView } from './Storage';

describe('FailoverBannerView', () => {
  it('says the home server is offline and which replica is serving', async () => {
    await renderInRouter(<FailoverBannerView placement={PLACEMENT} />);
    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent('Your home server, Home server, is offline. Syncing through VPS.');
    expect(banner).toHaveTextContent("Changes to members and keys wait until it's back.");
    expect(within(banner).getByRole('link', { name: 'Where your vault is stored' })).toBeInTheDocument();
  });

  it('shows nothing when every home is up, there is no placement, or the server has none', async () => {
    const healthy: Placement = { ...PLACEMENT, vaults: PLACEMENT.vaults.slice(1) };
    for (const placement of [healthy, null, undefined]) {
      const view = await renderInRouter(<FailoverBannerView placement={placement} />);
      expect(screen.queryByRole('status')).not.toBeInTheDocument();
      view.unmount();
    }
  });
});

describe('StorageView', () => {
  it('lists each vault\'s servers in order with their state', async () => {
    await renderInRouter(<StorageView placement={PLACEMENT} onCancelPending={vi.fn()} />);
    expect(screen.getByRole('heading', { name: 'Where your vault is stored', level: 1 })).toBeInTheDocument();
    const yours = screen.getByRole('list', { name: 'Servers of Your vault' });
    const items = within(yours).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent('Home server');
    expect(items[0]).toHaveTextContent(/Offline/);
    expect(items[1]).toHaveTextContent('VPS');
    expect(items[1]).toHaveTextContent('In use');
    const space = screen.getByRole('list', { name: 'Servers of Example Co' });
    expect(within(space).getAllByRole('listitem')[0]).toHaveTextContent('In use');
    expect(within(space).getAllByRole('listitem')[1]).toHaveTextContent('Online');
  });

  it('shows a change waiting for the home server and cancels it', async () => {
    const onCancelPending = vi.fn();
    await renderInRouter(<StorageView placement={PLACEMENT} onCancelPending={onCancelPending} />);
    expect(screen.getByText(/Adding jordan@example\.org to Family/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel this change' }));
    expect(onCancelPending).toHaveBeenCalledWith('me', 'c1');
  });

  it('says what each app is using', async () => {
    const placement: Placement = {
      ...PLACEMENT,
      apps: [
        { name: 'Kemlock on iPhone 16', server: 'VPS', since: '2026-11-22T09:07:00Z' },
        { name: 'Bitwarden extension', server: 'Home server', localCopy: true, address: 'nas.example.org' },
      ],
    };
    await renderInRouter(<StorageView placement={placement} onCancelPending={vi.fn()} />);
    expect(screen.getByText('nas.example.org, local copy')).toBeInTheDocument();
    expect(screen.getByText(/^VPS since /)).toBeInTheDocument();
  });

  it('explains a single server', async () => {
    await renderInRouter(<StorageView placement={null} onCancelPending={vi.fn()} />);
    expect(screen.getByRole('heading', { name: 'One server' })).toBeInTheDocument();
  });
});

describe('a server whose status is unknown', () => {
  const unknown: Placement = {
    ...PLACEMENT,
    vaults: PLACEMENT.vaults.map((vault) => ({
      ...vault,
      pending: null,
      servers: vault.servers.map((server) => ({ ...server, status: 'unknown' as const, offlineSince: null })),
    })),
  };

  it('is not called offline by the banner', async () => {
    await renderInRouter(<FailoverBannerView placement={unknown} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('is listed as such, not as online', async () => {
    await renderInRouter(<StorageView placement={unknown} onCancelPending={vi.fn()} />);
    const yours = screen.getByRole('list', { name: 'Servers of Your vault' });
    expect(within(yours).getAllByRole('listitem')[0]).toHaveTextContent('Status unknown');
  });
});
