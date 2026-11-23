import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { PushRelay } from '@/api/admin';
import { renderWithIntl } from '@/test/render';
import { PushRelayCard } from './PushRelay';

const OFF: PushRelay = { enabled: false, installationId: null, relayUrl: 'https://push.kemlock.example' };
const ON: PushRelay = { ...OFF, enabled: true, installationId: 'inst-4f2a' };

function view(props: Partial<Parameters<typeof PushRelayCard>[0]> = {}) {
  const handlers = { onEnable: vi.fn(), onDisable: vi.fn() };
  renderWithIntl(<PushRelayCard relay={OFF} {...handlers} {...props} />);
  return handlers;
}

describe('PushRelayCard', () => {
  it('says the relay is off, shows its address and offers to turn it on', async () => {
    const { onEnable } = view();
    expect(screen.getByText('Off')).toBeInTheDocument();
    expect(screen.getByText('https://push.kemlock.example')).toBeInTheDocument();
    expect(screen.queryByText("This server's id at the relay")).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Turn on' }));
    expect(onEnable).toHaveBeenCalledTimes(1);
  });

  it('shows the installation id when it is on, and asks before turning it off', async () => {
    const { onDisable } = view({ relay: ON });
    expect(screen.getByText('On')).toBeInTheDocument();
    expect(screen.getByText('inst-4f2a')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Turn off' }));
    expect(onDisable).not.toHaveBeenCalled();
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/erases this server's installation at the relay and here/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Turn off' }));
    expect(onDisable).toHaveBeenCalledTimes(1);
  });

  it('says so when this server has no relay to control', () => {
    view({ relay: undefined, unavailable: true });
    expect(screen.getByText('This server has no push relay to turn on or off.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Turn on' })).not.toBeInTheDocument();
  });

  it('disables the buttons while a change is under way', () => {
    view({ busy: true });
    expect(screen.getByRole('button', { name: 'Turn on' })).toBeDisabled();
  });
});
