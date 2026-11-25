import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { LOG_SOURCES } from './logSources';
import { WhereToFind } from './SetupCode';

describe('WhereToFind', () => {
  it('starts collapsed and opens on its summary', async () => {
    const { container } = renderWithIntl(<WhereToFind />);
    const panel = container.querySelector('details');
    expect(panel).not.toHaveAttribute('open');
    await userEvent.setup({ delay: null }).click(screen.getByText('Where to find the setup code'));
    expect(panel).toHaveAttribute('open');
  });

  it('lists the sample line and every deployment target', () => {
    renderWithIntl(<WhereToFind />);
    expect(screen.getByText(/setup code 7QF4-9M2X-HD3P/)).toBeInTheDocument();
    for (const name of ['Docker', 'Kubernetes', 'Proxmox', 'Unraid', 'Synology', 'QNAP']) {
      expect(screen.getByText(name, { selector: 'b' })).toBeInTheDocument();
    }
    expect(screen.getByText('docker compose logs kemlock | grep -i "setup code"')).toBeInTheDocument();
    expect(screen.getByText("grep -i 'setup code' /var/log/kemlock-server.log")).toBeInTheDocument();
    expect(screen.getByText('Docker tab, the kemlock icon, then Logs.')).toBeInTheDocument();
  });

  it('gives each target a command or a place to look', () => {
    for (const source of LOG_SOURCES) expect(Boolean(source.command) !== Boolean(source.where)).toBe(true);
  });
});
