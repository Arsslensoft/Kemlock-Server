import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PairingState } from '@/api/admin';
import { renderWithIntl } from '@/test/render';
import { NOW, SESSION, peer } from './fixtures';
import { ALL_ACKS, type CompareFn, PairView, canConfirm, compareKeys } from './Pair';

const compare: CompareFn = async () => ({
  words: 'tulip-anchor-rover-mint-ladle-orbit',
  selfShort: '3B9E 71C4 A05D 2F86',
  peerShort: '9F14 D6A2 3C78 E05B',
});

function view(state: PairingState, props: Partial<Parameters<typeof PairView>[0]> = {}) {
  const handlers = {
    onNewCode: vi.fn(),
    onConnect: vi.fn(),
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
    onNavigate: vi.fn(),
  };
  renderWithIntl(<PairView state={state} compare={compare} now={NOW} {...handlers} {...props} />);
  return handlers;
}

describe('canConfirm', () => {
  it('needs the six words to match, and every acknowledgement for another organisation', () => {
    expect(canConfirm(SESSION, false, ALL_ACKS)).toBe(false);
    expect(canConfirm(SESSION, true, [])).toBe(false);
    expect(canConfirm(SESSION, true, ['metadata', 'no-delete'])).toBe(false);
    expect(canConfirm(SESSION, true, ALL_ACKS)).toBe(true);
  });

  it('needs no acknowledgement for a server you run yourself', () => {
    const own = { ...SESSION, peer: { ...SESSION.peer, operator: 'own' as const, operatorName: null } };
    expect(canConfirm(own, true, [])).toBe(true);
    expect(canConfirm(own, false, [])).toBe(false);
  });
});

describe('PairView, step 1', () => {
  it('shows this server\'s one-time code with its expiry, and makes a new one on request', async () => {
    const { onNewCode } = view({ code: { code: 'HXQ7-42MD-R9KT', expiresAt: NOW + 540 }, session: null });
    expect(screen.getByText('HXQ7-42MD-R9KT')).toBeInTheDocument();
    expect(screen.getByText(/Works once\. Expires at .*, in 9 minutes\./)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Make a new code' }));
    expect(onNewCode).toHaveBeenCalled();
  });

  it('connects to another server with its address and code', async () => {
    const { onConnect } = view({ code: null, session: null });
    const user = userEvent.setup();
    const connect = screen.getByRole('button', { name: 'Connect' });
    expect(connect).toBeDisabled();
    await user.type(screen.getByLabelText('Its address'), 'vps.example.org');
    await user.type(screen.getByLabelText('Its one-time code'), '7KP2-WQ4N-D8RJ');
    await user.click(connect);
    expect(onConnect).toHaveBeenCalledWith('vps.example.org', '7KP2-WQ4N-D8RJ');
    expect(screen.queryByText('The six words for both keys')).not.toBeInTheDocument();
  });
});

describe('PairView, with a connected server', () => {
  async function ready() {
    const handlers = view({ code: null, session: SESSION });
    await screen.findByText('tulip-anchor-rover-mint-ladle-orbit');
    return handlers;
  }

  it('shows the six words worked out here, and each key\'s short form', async () => {
    await ready();
    expect(screen.getByText('3B9E 71C4 A05D 2F86')).toBeInTheDocument();
    expect(screen.getByText('9F14 D6A2 3C78 E05B')).toBeInTheDocument();
  });

  it('stays closed until the words match and every acknowledgement is given', async () => {
    const { onConfirm } = await ready();
    const user = userEvent.setup();
    const pair = screen.getByRole('button', { name: 'Pair with Office server' });
    expect(pair).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /six words match/ }));
    expect(pair).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /sees the metadata/ }));
    await user.click(screen.getByRole('checkbox', { name: /make Office server delete/ }));
    expect(pair).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /cross-border transfer/ }));
    expect(pair).toBeEnabled();
    await user.click(pair);
    expect(onConfirm).toHaveBeenCalledWith({
      wordsMatch: true,
      acknowledged: ['metadata', 'no-delete', 'cross-border'],
      offer: [],
      sendLogs: false,
      pullLogs: false,
    });
  });

  it('offers the chosen vaults, with the log switches', async () => {
    const { onConfirm } = await ready();
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: /six words match/ }));
    for (const name of [/sees the metadata/, /make Office server delete/, /cross-border transfer/]) {
      await user.click(screen.getByRole('checkbox', { name }));
    }
    await user.click(screen.getByRole('checkbox', { name: /Lab notes/ }));
    await user.click(screen.getByRole('switch', { name: /Send our logs/ }));
    await user.click(screen.getByRole('button', { name: 'Pair and offer to Office server' }));
    expect(onConfirm).toHaveBeenCalledWith(
      expect.objectContaining({ offer: ['v9'], sendLogs: true, pullLogs: false }),
    );
  });

  it('asks for no acknowledgements from a server of the same organisation', async () => {
    const own = { ...SESSION, peer: { ...SESSION.peer, operator: 'own' as const, operatorName: null } };
    view({ code: null, session: own });
    await screen.findByText('tulip-anchor-rover-mint-ladle-orbit');
    expect(screen.queryByRole('checkbox', { name: /sees the metadata/ })).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('checkbox', { name: /six words match/ }));
    expect(screen.getByRole('button', { name: 'Pair with Office server' })).toBeEnabled();
  });

  it("shows the server's own words when the other server's key is not known here", async () => {
    const unkeyed = {
      ...SESSION,
      peer: { ...SESSION.peer, identityKey: '' },
      words: 'tulip-anchor-rover-mint-ladle-orbit',
    };
    view({ code: null, session: unkeyed }, { compare: compareKeys });
    expect(await screen.findByText('tulip-anchor-rover-mint-ladle-orbit')).toBeInTheDocument();
    expect(screen.queryByText('3B9E 71C4 A05D 2F86')).not.toBeInTheDocument();
  });

  it('never works words out from a missing key', async () => {
    await expect(compareKeys(SESSION.self, { ...SESSION.peer, identityKey: '' })).rejects.toThrow('a key is missing');
  });

  it('cancels', async () => {
    const { onCancel } = await ready();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalled();
  });
});

describe('PairView, once paired', () => {
  it('says so and leads back to Federation', async () => {
    const { onNavigate } = view({ code: null, session: null }, { paired: peer() });
    expect(screen.getByText('Paired with Office server. Its identity key is pinned.')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Back to Federation' }));
    expect(onNavigate).toHaveBeenCalledWith({ to: 'federation' });
  });
});
