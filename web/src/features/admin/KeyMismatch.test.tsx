import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { KeyMismatchView, mismatchDetails } from './KeyMismatch';
import { MISMATCH, fakeLabels } from './fixtures';

const pinned = { words: 'tulip-anchor-rover-mint-ladle-orbit', short: '9F14 D6A2 3C78 E05B' };
const offered = { words: 'walnut-ember-sonnet-pivot-lagoon-brisk', short: '4C02 E9B7 18FA 6D35' };

describe('mismatchDetails', () => {
  it('names both keys, the address and whether the offered key was signed', () => {
    const text = mismatchDetails(MISMATCH, 'vps.example.org', pinned, offered);
    expect(text).toContain('Kemlock federation: possible man in the middle');
    expect(text).toContain('Seen by: vps.example.org');
    expect(text).toContain('Peer: Office server (vault.example.co)');
    expect(text).toContain('From: https://203.0.113.77:8443');
    expect(text).toContain('Pinned key: tulip-anchor-rover-mint-ladle-orbit 9F14 D6A2 3C78 E05B');
    expect(text).toContain('Offered key: walnut-ember-sonnet-pivot-lagoon-brisk 4C02 E9B7 18FA 6D35');
    expect(text).toContain('Signed by the pinned key: no');
    expect(text).toContain('4 attempts');
  });

  it('is plain text with one fact to a line', () => {
    const lines = mismatchDetails({ ...MISMATCH, attempts: 1 }, 'x', pinned, offered).split('\n');
    expect(lines).toHaveLength(8);
    expect(lines[3]).toMatch(/, 1 attempt, the last at /);
    expect(lines[4]).toBe('From: https://203.0.113.77:8443');
  });
});

describe('KeyMismatchView', () => {
  function view(props: Partial<Parameters<typeof KeyMismatchView>[0]> = {}) {
    const handlers = {
      onKeepBlocking: vi.fn(),
      onPairAgain: vi.fn(),
      onNavigate: vi.fn(),
      copy: vi.fn(async (_text: string) => true),
    };
    renderWithIntl(
      <KeyMismatchView data={MISMATCH} seenBy="vps.example.org" labelsOf={fakeLabels} {...handlers} {...props} />,
    );
    return handlers;
  }

  it('puts the pinned key beside the one offered, both worked out from their bytes', async () => {
    view();
    expect(screen.getByRole('heading', { level: 1, name: 'Possible man in the middle' })).toBeInTheDocument();
    expect(screen.getByText('Session refused')).toBeInTheDocument();
    expect((await screen.findAllByText('words-of-BQYHCA')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('words-of-CQoLDA')).length).toBeGreaterThan(0);
    expect(screen.getByText(/Not signed by the pinned key\./)).toBeInTheDocument();
    expect(screen.getByText(/Never seen on this server before\./)).toBeInTheDocument();
  });

  it('says what happened, from where, and what is paused', () => {
    view();
    expect(screen.getByText('https://203.0.113.77:8443')).toBeInTheDocument();
    expect(screen.getByText(/Office server's sessions until now came from https:\/\/vault\.example\.co/)).toBeInTheDocument();
    // A vault has no name the server can read: the owner's email names it.
    expect(screen.getByText('sam@example.co, to and from Office server')).toBeInTheDocument();
    expect(screen.getByText(/3 changes wait to be exchanged \(1\.9 MB held here\)/)).toBeInTheDocument();
    expect(screen.getByText(/2 local vaults aren't affected/)).toBeInTheDocument();
  });

  it('copies the details for the other admin', async () => {
    const { copy } = view();
    const button = screen.getByRole('button', { name: 'Copy' });
    await waitFor(() => expect(button).toBeEnabled());
    await userEvent.setup().click(button);
    expect(copy).toHaveBeenCalledTimes(1);
    const text = copy.mock.calls[0]?.[0] as string;
    expect(text).toContain('Offered key: words-of-CQoLDA SHORT CQOLDA');
    expect(await screen.findByText(/Copied\. Send it over a channel you already trust/)).toBeInTheDocument();
  });

  it('keeps blocking, and says so', async () => {
    const { onKeepBlocking } = view({ kept: true });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Keep blocking' }));
    expect(onKeepBlocking).toHaveBeenCalled();
    expect(screen.getByText(/Still blocking\./)).toBeInTheDocument();
  });

  it('asks for a fresh check before pairing again', async () => {
    const { onPairAgain } = view();
    const user = userEvent.setup();
    expect(screen.queryByRole('region', { name: 'Confirm it\'s you' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Pair again with a new code' }));
    expect(screen.getByRole('region', { name: "Confirm it's you" })).toBeInTheDocument();
    expect(onPairAgain).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Confirm with a code' }));
    expect(onPairAgain).toHaveBeenCalledTimes(1);
  });

  it('offers no way to accept a rotation that was not signed', () => {
    view();
    const accept = screen.getByRole('button', { name: 'Accept signed rotation' });
    expect(accept).toBeDisabled();
    expect(accept).toHaveAccessibleDescription(/isn't signed by the pinned key/);
  });

  it('leads back to Federation, the peer and the event log', async () => {
    const { onNavigate } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Federation' }));
    expect(onNavigate).toHaveBeenLastCalledWith({ to: 'federation' });
    await user.click(screen.getByRole('button', { name: 'Office server' }));
    expect(onNavigate).toHaveBeenLastCalledWith({ to: 'peer', peerId: MISMATCH.peer.serverId });
    await user.click(screen.getByRole('button', { name: 'Open the event log' }));
    expect(onNavigate).toHaveBeenLastCalledWith({ to: 'events' });
  });
});
