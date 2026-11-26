import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { FedVault, FederationOverview } from '@/api/admin';
import { renderWithIntl } from '@/test/render';
import { FederationView } from './Federation';
import { NOW, OVERVIEW, fakeLabels, peer } from './fixtures';

function view(overview: FederationOverview = OVERVIEW) {
  const handlers = {
    onNavigate: vi.fn(),
    onSetLogs: vi.fn(),
    onCheckKeys: vi.fn(),
    onRunConsistency: vi.fn(),
    onPromote: vi.fn(),
    onAccept: vi.fn(),
    onDecline: vi.fn(),
  };
  renderWithIntl(<FederationView overview={overview} labelsOf={fakeLabels} now={NOW} {...handlers} />);
  return handlers;
}

describe('FederationView', () => {
  it('says which server is offline and for how long', () => {
    view();
    expect(screen.getByRole('status')).toHaveTextContent(/Home server has been offline for 47 min, since/);
  });

  it('says when each peer was last seen and how fast it answered', () => {
    view();
    const peers = within(screen.getByRole('region', { name: 'Servers in this federation' }));
    expect(peers.getAllByText(/Last seen now/).length).toBeGreaterThan(0);
    expect(peers.getByText(/· 48 ms/)).toBeInTheDocument();
  });

  it('shows a peer that was never seen, and one that is slow', () => {
    view({
      ...OVERVIEW,
      peers: [peer({ lastSeen: null, latencyMs: null }), peer({ serverId: 'c'.repeat(32), name: 'Slow', state: 'degraded' })],
    });
    expect(screen.getByText('Not seen yet')).toBeInTheDocument();
    expect(screen.getByText('Slow or unsteady')).toBeInTheDocument();
  });

  it('lists this server and its peers with their identity keys, worked out from the key', async () => {
    view();
    expect(await screen.findByText('words-of-AQIDBA')).toBeInTheDocument();
    expect(screen.getByText('words-of-BQYHCA')).toBeInTheDocument();
    expect(screen.getByText('Run by Example Co IT, another organisation')).toBeInTheDocument();
    expect(screen.getAllByText('Run by you')).toHaveLength(2);
  });

  it('turns the event-log switches on and off one at a time', async () => {
    const { onSetLogs } = view();
    const user = userEvent.setup();
    const peers = within(screen.getByRole('region', { name: 'Servers in this federation' }));
    const office = peers.getByRole('row', { name: /Office server/ });
    await user.click(within(office).getByRole('switch', { name: 'Pull their logs' }));
    expect(onSetLogs).toHaveBeenLastCalledWith(expect.objectContaining({ name: 'Office server' }), false, true);
    const home = peers.getByRole('row', { name: /Home server/ });
    await user.click(within(home).getByRole('switch', { name: 'Send our logs' }));
    expect(onSetLogs).toHaveBeenLastCalledWith(expect.objectContaining({ name: 'Home server' }), false, true);
  });

  it('tells the admin which servers must be upgraded before writes are signed', () => {
    view({ ...OVERVIEW, peers: [peer({ signedWrites: false })] });
    expect(screen.getByText('Upgrade needed')).toBeInTheDocument();
    expect(screen.getByText(/doesn't read signed writes yet/)).toBeInTheDocument();
  });

  it('says nothing of upgrades when every peer reads signed writes and past keys', () => {
    view({ ...OVERVIEW, peers: [peer()] });
    expect(screen.queryByText('Upgrade needed')).toBeNull();
  });

  it('says when a peer sends its logs and this server does not pull them', () => {
    view({ ...OVERVIEW, peers: [peer({ theySendLogs: true, pullLogs: false })] });
    expect(screen.getByText('It sends, but Pull is off here')).toBeInTheDocument();
  });

  it('opens the promotion for a vault whose home is elsewhere, and fences only on confirmation', async () => {
    const { onPromote } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Promote to home: this server for Family' }));
    const region = screen.getByRole('region', { name: 'Make VPS the home of Family?' });
    expect(within(region).getByText(/epoch goes from 1 to 2/)).toBeInTheDocument();
    expect(within(region).getByText(/One change is waiting/)).toBeInTheDocument();
    expect(onPromote).not.toHaveBeenCalled();
    await user.click(within(region).getByRole('checkbox', { name: /Home server is down/ }));
    await user.click(within(region).getByRole('button', { name: 'Promote to home' }));
    expect(onPromote).toHaveBeenCalledWith(expect.objectContaining({ id: 'v1' }), true);
  });

  it('does not offer a promotion for a vault already homed here', () => {
    view();
    expect(screen.queryByRole('button', { name: 'Promote to home: this server for Side projects' })).not.toBeInTheDocument();
  });

  it('accepts or declines a request to federate a vault', async () => {
    const { onAccept, onDecline } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Accept request to federate Side projects' }));
    expect(onAccept).toHaveBeenCalledWith(expect.objectContaining({ id: 'v2' }));
    await user.click(screen.getByRole('button', { name: 'Decline the request to federate Side projects' }));
    expect(onDecline).toHaveBeenCalledWith(expect.objectContaining({ id: 'v2' }));
  });

  it('shows a revoked peer as revoked', () => {
    view({ ...OVERVIEW, peers: [peer({ state: 'revoked' })] });
    expect(screen.getByText('Revoked')).toBeInTheDocument();
  });

  it('shows a vault the server gives no size for, and offers no promotion for an offer not yet accepted', () => {
    const offered = {
      ...OVERVIEW.vaults[0],
      id: 'space:44444444-4444-4444-8444-444444444444',
      name: null,
      sizeBytes: null,
      request: { by: 'Home server', at: NOW - 60 },
    } as FedVault;
    view({ ...OVERVIEW, vaults: [offered] });
    expect(screen.getByText('44444444')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Accept request to federate 44444444' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Promote to home/ })).not.toBeInTheDocument();
  });

  it('shows a promotion another server sent for a vault homed here, and hands the home over only on request', async () => {
    const held = {
      ...OVERVIEW.vaults[1],
      federated: true,
      replicas: ['a'.repeat(32)],
      request: null,
      heldDemotion: { newHomeId: 'a'.repeat(32), epoch: 2, at: NOW - 600 },
    } as FedVault;
    const onAcceptDemotion = vi.fn();
    renderWithIntl(
      <FederationView
        overview={{ ...OVERVIEW, vaults: [held] }}
        labelsOf={fakeLabels}
        now={NOW}
        onNavigate={vi.fn()}
        onSetLogs={vi.fn()}
        onCheckKeys={vi.fn()}
        onRunConsistency={vi.fn()}
        onPromote={vi.fn()}
        onAccept={vi.fn()}
        onDecline={vi.fn()}
        onAcceptDemotion={onAcceptDemotion}
      />,
    );
    expect(screen.getByText('Home server asks to become the home')).toBeInTheDocument();
    expect(onAcceptDemotion).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Hand over the home of Side projects to Home server' }));
    expect(onAcceptDemotion).toHaveBeenCalledWith(expect.objectContaining({ id: 'v2' }), 'a'.repeat(32));
  });

  it('shows a promotion held at a replica, and accepts or refuses it only on request', async () => {
    const office = '02020202020202020202020202020202';
    const held = {
      ...OVERVIEW.vaults[0],
      heldDemotion: { newHomeId: office, epoch: 2, at: NOW - 300 },
    } as FedVault;
    const onAcceptDemotion = vi.fn();
    const onRefuseDemotion = vi.fn();
    renderWithIntl(
      <FederationView
        overview={{ ...OVERVIEW, vaults: [held] }}
        labelsOf={fakeLabels}
        now={NOW}
        onNavigate={vi.fn()}
        onSetLogs={vi.fn()}
        onCheckKeys={vi.fn()}
        onRunConsistency={vi.fn()}
        onPromote={vi.fn()}
        onAccept={vi.fn()}
        onDecline={vi.fn()}
        onAcceptDemotion={onAcceptDemotion}
        onRefuseDemotion={onRefuseDemotion}
      />,
    );
    expect(screen.getByText('Office server asks to become the home')).toBeInTheDocument();
    expect(onAcceptDemotion).not.toHaveBeenCalled();
    expect(onRefuseDemotion).not.toHaveBeenCalled();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Refuse the promotion of Office server for Family' }));
    expect(onRefuseDemotion).toHaveBeenCalledWith(expect.objectContaining({ id: 'v1' }), office);
    await user.click(screen.getByRole('button', { name: 'Accept Office server as the home of Family' }));
    expect(onAcceptDemotion).toHaveBeenCalledWith(expect.objectContaining({ id: 'v1' }), office);
  });

  it('lists every promotion held for a vault and settles the one it is asked about', async () => {
    const office = '02020202020202020202020202020202';
    const home = 'a'.repeat(32);
    const held = {
      ...OVERVIEW.vaults[0],
      heldDemotion: { newHomeId: office, epoch: 2, at: NOW - 300 },
      heldPromotions: [
        { newHomeId: office, epoch: 2, at: NOW - 300 },
        { newHomeId: home, epoch: 2, at: NOW - 60 },
      ],
    } as FedVault;
    const onAcceptDemotion = vi.fn();
    const onRefuseDemotion = vi.fn();
    renderWithIntl(
      <FederationView
        overview={{ ...OVERVIEW, vaults: [held] }}
        labelsOf={fakeLabels}
        now={NOW}
        onNavigate={vi.fn()}
        onSetLogs={vi.fn()}
        onCheckKeys={vi.fn()}
        onRunConsistency={vi.fn()}
        onPromote={vi.fn()}
        onAccept={vi.fn()}
        onDecline={vi.fn()}
        onAcceptDemotion={onAcceptDemotion}
        onRefuseDemotion={onRefuseDemotion}
      />,
    );
    expect(screen.getByText('Office server asks to become the home')).toBeInTheDocument();
    expect(screen.getByText('Home server asks to become the home')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Accept Home server as the home of Family' }));
    expect(onAcceptDemotion).toHaveBeenCalledWith(expect.objectContaining({ id: 'v1' }), home);
    await user.click(screen.getByRole('button', { name: 'Refuse the promotion of Office server for Family' }));
    expect(onRefuseDemotion).toHaveBeenCalledWith(expect.objectContaining({ id: 'v1' }), office);
  });

  it('lists the address changes a rotation brought and follows or refuses them only on request', async () => {
    const office = '02020202020202020202020202020202';
    const change = {
      peerId: office,
      operator: 'Example Co IT',
      addresses: ['https://moved.example.co'],
      suites: [],
      receivedAt: NOW - 120,
    };
    const onApproveAddresses = vi.fn();
    const onRefuseAddresses = vi.fn();
    renderWithIntl(
      <FederationView
        overview={OVERVIEW}
        labelsOf={fakeLabels}
        now={NOW}
        onNavigate={vi.fn()}
        onSetLogs={vi.fn()}
        onCheckKeys={vi.fn()}
        onRunConsistency={vi.fn()}
        onPromote={vi.fn()}
        onAccept={vi.fn()}
        onDecline={vi.fn()}
        addressChanges={[change]}
        onApproveAddresses={onApproveAddresses}
        onRefuseAddresses={onRefuseAddresses}
      />,
    );
    const card = within(screen.getByRole('region', { name: 'Address changes waiting' }));
    expect(card.getByText(/Now says: https:\/\/moved\.example\.co/)).toBeInTheDocument();
    expect(onApproveAddresses).not.toHaveBeenCalled();
    const user = userEvent.setup();
    await user.click(card.getByRole('button', { name: 'Keep the old addresses of Office server' }));
    expect(onRefuseAddresses).toHaveBeenCalledWith(change);
    await user.click(card.getByRole('button', { name: 'Follow Office server to its new addresses' }));
    expect(onApproveAddresses).toHaveBeenCalledWith(change);
  });

  it('shows no address-change card when nothing waits', () => {
    view();
    expect(screen.queryByRole('region', { name: 'Address changes waiting' })).not.toBeInTheDocument();
  });

  it('shows a contested server and trusts or unpairs it only on request', async () => {
    const contested = peer({ state: 'contested' });
    const onClearContest = vi.fn();
    const onUnpair = vi.fn();
    renderWithIntl(
      <FederationView
        overview={{ ...OVERVIEW, peers: [contested] }}
        labelsOf={fakeLabels}
        now={NOW}
        onNavigate={vi.fn()}
        onSetLogs={vi.fn()}
        onCheckKeys={vi.fn()}
        onRunConsistency={vi.fn()}
        onPromote={vi.fn()}
        onAccept={vi.fn()}
        onDecline={vi.fn()}
        onClearContest={onClearContest}
        onUnpair={onUnpair}
      />,
    );
    const card = within(screen.getByRole('region', { name: 'Contested servers' }));
    expect(card.getByText('Not syncing until you decide')).toBeInTheDocument();
    expect(onClearContest).not.toHaveBeenCalled();
    const user = userEvent.setup();
    await user.click(card.getByRole('button', { name: 'Keep trusting Office server' }));
    expect(onClearContest).toHaveBeenCalledWith(expect.objectContaining({ serverId: contested.serverId }));
    await user.click(card.getByRole('button', { name: 'Unpair Office server to pair it again with a new code' }));
    expect(onUnpair).toHaveBeenCalledWith(expect.objectContaining({ serverId: contested.serverId }));
  });

  it('shows no contested card when no server is contested', () => {
    view();
    expect(screen.queryByRole('region', { name: 'Contested servers' })).not.toBeInTheDocument();
  });

  it('leads to a peer with a key mismatch', async () => {
    const { onNavigate } = view({ ...OVERVIEW, peers: [peer({ mismatch: true })] });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Possible man in the middle with Office server' }));
    expect(onNavigate).toHaveBeenCalledWith({ to: 'mismatch', peerId: '02020202020202020202020202020202' });
  });

  it('goes to pairing, and checks keys and consistency on request', async () => {
    const { onNavigate, onCheckKeys, onRunConsistency } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Pair a server' }));
    expect(onNavigate).toHaveBeenCalledWith({ to: 'pair' });
    await user.click(screen.getByRole('button', { name: 'Check the keys again' }));
    expect(onCheckKeys).toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Run now' }));
    expect(onRunConsistency).toHaveBeenCalled();
  });
});
