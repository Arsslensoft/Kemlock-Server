import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { LOG_SOURCES } from './logSources';
import { WhereToFind } from './SetupCode';

const NAMES: Record<string, string> = {
  'setup.code.targetDocker': 'Docker',
  'setup.code.targetCompose': 'Docker Compose',
  'setup.code.targetPodman': 'Podman',
  'setup.code.targetKubernetes': 'Kubernetes',
  'setup.code.targetSystemd': 'systemd',
  'setup.code.targetProxmox': 'Proxmox',
  'setup.code.targetBinary': 'Release binary',
  'setup.code.targetUnraid': 'Unraid',
  'setup.code.targetTruenas': 'TrueNAS',
  'setup.code.targetHa': 'Home Assistant',
  'setup.code.targetSynology': 'Synology',
  'setup.code.targetQnap': 'QNAP',
};
const targetName = (id: string) => NAMES[id];

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
    expect(screen.getByText("grep -i 'setup code' /var/log/kemlock-server.log | tail -n 1")).toBeInTheDocument();
    expect(screen.getByText('Docker tab, the kemlock icon, then Logs.')).toBeInTheDocument();
  });

  it('gives each target a command with a copy button, or a place to look', async () => {
    const { container } = renderWithIntl(<WhereToFind />);
    await userEvent.setup({ delay: null }).click(screen.getByText('Where to find the setup code'));
    for (const source of LOG_SOURCES) {
      const item = screen.getAllByRole('listitem').find((li) => li.querySelector('b')?.textContent === targetName(source.target));
      expect(item).toBeDefined();
      if (source.command) {
        expect(within(item!).getByText(source.command)).toBeInTheDocument();
        expect(within(item!).getAllByRole('button', { name: /^Copy the .* command/ }).length).toBeGreaterThan(0);
      } else {
        expect(item!.querySelectorAll('button')).toHaveLength(0);
        expect(item!.textContent?.length).toBeGreaterThan((targetName(source.target) ?? '').length);
      }
    }
    expect(container.querySelectorAll('.cmd code').length).toBe(7);
    expect(screen.getByText('docker logs <container> 2>&1 | grep -i "setup code"')).toBeInTheDocument();
    expect(screen.getByText(/docker ps/)).toBeInTheDocument();
  });
});
