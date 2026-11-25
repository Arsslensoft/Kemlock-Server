import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { SuiteSetting } from '@/api/admin';
import { I18nProvider } from '@/i18n';
import { renderWithIntl } from '@/test/render';
import { NOW, PEER_SECURITY, SELF_SECURITY, fakeLabels } from './fixtures';
import { PeerSecurityView, SUITES, moveSuite, orderHint } from './PeerSecurity';

const on = (name: string, enabled = true, available = true): SuiteSetting => ({ name, on: enabled, available });

describe('orderHint', () => {
  it('names what the first suite means for this server', () => {
    expect(orderHint([on(SUITES.aes), on(SUITES.chacha)], true)).toBe('admin.peer.order.aesFirst');
    expect(orderHint([on(SUITES.chacha), on(SUITES.aes)], true)).toBe('admin.peer.order.chachaSlower');
    expect(orderHint([on(SUITES.chacha), on(SUITES.aes)], false)).toBe('admin.peer.order.chacha');
    expect(orderHint([on(SUITES.fips), on(SUITES.aes)], true)).toBe('admin.peer.order.fips');
    expect(orderHint([on(SUITES.aes, false)], true)).toBe('admin.peer.order.none');
  });

  it('skips a suite that is off', () => {
    expect(orderHint([on(SUITES.fips, false), on(SUITES.aes)], true)).toBe('admin.peer.order.aesFirst');
  });
});

describe('moveSuite', () => {
  const list = [on('a'), on('b'), on('c')];
  it('swaps with the neighbour', () => {
    expect(moveSuite(list, 1, -1).map((s) => s.name)).toEqual(['b', 'a', 'c']);
    expect(moveSuite(list, 1, 1).map((s) => s.name)).toEqual(['a', 'c', 'b']);
  });
  it('leaves the list alone past either end, and does not change the original', () => {
    expect(moveSuite(list, 0, -1)).toBe(list);
    expect(moveSuite(list, 2, 1)).toBe(list);
    expect(list.map((s) => s.name)).toEqual(['a', 'b', 'c']);
  });
});

describe('PeerSecurityView', () => {
  function view(props: Partial<Parameters<typeof PeerSecurityView>[0]> = {}) {
    const handlers = {
      onNavigate: vi.fn(),
      onDownload: vi.fn(),
      onDownloadPeer: vi.fn(),
      onRevoke: vi.fn(),
      onRotateKem: vi.fn(),
      onRotateIdentity: vi.fn(),
      onSaveSuites: vi.fn(),
    };
    renderWithIntl(
      <PeerSecurityView peer={PEER_SECURITY} self={SELF_SECURITY} labelsOf={fakeLabels} now={NOW} {...handlers} {...props} />,
    );
    return handlers;
  }

  it('shows the pinned key, its fingerprint and the suite in use', async () => {
    view();
    expect(screen.getByRole('heading', { level: 1, name: 'Office server' })).toBeInTheDocument();
    expect(await screen.findAllByText('words-of-BQYHCA')).not.toHaveLength(0);
    expect(screen.getByText('Matches')).toBeInTheDocument();
    expect(screen.getByText('E71A 0C5D 92B3 4F68')).toBeInTheDocument();
    expect(screen.getByText('In use')).toBeInTheDocument();
    // The server sees no transport of the peer's: there is no TLS or session block to show.
    expect(screen.queryByText(/TLS/)).not.toBeInTheDocument();
  });

  it('flags a key that no longer matches and leads to the warning', async () => {
    const { onNavigate } = view({ peer: { ...PEER_SECURITY, keysMatch: false } });
    expect(screen.getByText("Doesn't match")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Possible man in the middle' }));
    expect(onNavigate).toHaveBeenCalledWith({ to: 'mismatch', peerId: PEER_SECURITY.peer.serverId });
  });

  it('asks before revoking a peer', async () => {
    const { onRevoke } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Revoke and pair again' }));
    expect(onRevoke).not.toHaveBeenCalled();
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Revoke and pair again' }));
    expect(onRevoke).toHaveBeenCalledTimes(1);
  });

  it('says when the descriptor could not be read again, and shows the copy it has', () => {
    view({ peer: { ...PEER_SECURITY, fetchError: 'connection refused' } });
    expect(screen.getByText(/could not be read again \(connection refused\)/)).toBeInTheDocument();
    expect(screen.getByText('E71A 0C5D 92B3 4F68')).toBeInTheDocument();
  });

  it('says so when no descriptor or KEM key has been read yet', () => {
    view({ peer: { ...PEER_SECURITY, descriptor: null, kem: null, fetchedAt: null } });
    expect(screen.getByText('No descriptor of this peer has been read yet.')).toBeInTheDocument();
    expect(screen.queryByText('E71A 0C5D 92B3 4F68')).not.toBeInTheDocument();
  });

  it('reorders the suites this server accepts and saves the new order', async () => {
    const { onSaveSuites } = view();
    const user = userEvent.setup();
    expect(screen.getByText('This server has AES instructions, so AES-256-GCM is first.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: `Move ${SUITES.chacha} up` }));
    expect(screen.getByText(/AES-256-GCM would be faster here than ChaCha20-Poly1305/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSaveSuites).toHaveBeenCalledWith(
      [on(SUITES.chacha), on(SUITES.aes), on(SUITES.fips, false, false)],
      'sealed',
    );
  });

  it('has Save off and no Discard until the suites change', async () => {
    const { onSaveSuites } = view();
    const user = userEvent.setup();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Discard' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: `Move ${SUITES.chacha} up` }));
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Discard' })).not.toBeInTheDocument();
    expect(onSaveSuites).not.toHaveBeenCalled();
  });

  it('cannot save with every suite off, and discards', async () => {
    view();
    const user = userEvent.setup();
    const list = within(screen.getByRole('list', { name: 'Suites this server accepts, most preferred first' }));
    await user.click(list.getByRole('switch', { name: SUITES.aes }));
    await user.click(list.getByRole('switch', { name: SUITES.chacha }));
    expect(screen.getByText(/No suite is on/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(screen.getByText(/AES-256-GCM is first/)).toBeInTheDocument();
  });

  it('names a suite switch by the suite alone and describes it with its hint', () => {
    view();
    const aes = screen.getByRole('switch', { name: SUITES.aes });
    expect(aes).toHaveAccessibleDescription(/.+/);
  });

  it('clears Saved. at the first edit, and starts again when the saved suites change', async () => {
    const user = userEvent.setup();
    const props = { peer: PEER_SECURITY, self: SELF_SECURITY, labelsOf: fakeLabels, now: NOW, suitesSaved: true } as const;
    const handlers = {
      onNavigate: vi.fn(),
      onDownload: vi.fn(),
      onDownloadPeer: vi.fn(),
      onRevoke: vi.fn(),
      onRotateKem: vi.fn(),
      onRotateIdentity: vi.fn(),
      onSaveSuites: vi.fn(),
    };
    const { rerender } = renderWithIntl(<PeerSecurityView {...props} {...handlers} />);
    expect(screen.getByText('Saved.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: `Move ${SUITES.chacha} up` }));
    expect(screen.queryByText('Saved.')).not.toBeInTheDocument();
    const next = { ...SELF_SECURITY, suites: [...SELF_SECURITY.suites].reverse() };
    rerender(
      <I18nProvider>
        <PeerSecurityView {...props} self={next} {...handlers} />
      </I18nProvider>,
    );
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('says Saved. under the section title once the suites are saved', () => {
    view({ suitesSaved: true });
    expect(screen.getByText('Saved.')).toBeInTheDocument();
  });

  it('rotates the key exchange key at once, and the identity key only after confirming', async () => {
    const { onRotateKem, onRotateIdentity } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Rotate key exchange key now' }));
    expect(onRotateKem).toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Rotate identity key' }));
    expect(onRotateIdentity).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Confirm and rotate' }));
    expect(onRotateIdentity).toHaveBeenCalledTimes(1);
  });

  it('keeps the keys of this server sealed: there is no other way to hold them', () => {
    view();
    expect(screen.queryByRole('radio', { name: /In this machine's TPM/ })).not.toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /sealed/i })).toBeChecked();
  });

  it('shows only this server\'s keys when no peer is chosen', () => {
    view({ peer: undefined });
    expect(screen.getByRole('heading', { level: 1, name: 'VPS' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke and pair again' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'This server publishes' })).toBeInTheDocument();
  });
});
