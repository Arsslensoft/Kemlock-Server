import type { MessageId } from '@/i18n';

/** Where the setup code is printed for one way of running the server. */
export interface LogSource {
  id: string;
  target: MessageId;
  /** A command to copy, or the words that say where to look. */
  command?: string;
  where?: MessageId;
  /** A second command for a variant of the same target (Proxmox on Alpine). */
  alpine?: string;
}

export const LOG_SOURCES: LogSource[] = [
  { id: 'docker', target: 'setup.code.targetDocker', command: 'docker logs kemlock 2>&1 | grep -i "setup code"' },
  { id: 'compose', target: 'setup.code.targetCompose', command: 'docker compose logs kemlock | grep -i "setup code"' },
  { id: 'podman', target: 'setup.code.targetPodman', command: 'journalctl --user -u kemlock | grep -i "setup code"' },
  {
    id: 'kubernetes',
    target: 'setup.code.targetKubernetes',
    command: 'kubectl logs deploy/kemlock-kemlock-server | grep -i "setup code"',
  },
  { id: 'systemd', target: 'setup.code.targetSystemd', command: 'journalctl -u kemlock -o cat | grep -i "setup code"' },
  {
    id: 'proxmox',
    target: 'setup.code.targetProxmox',
    command: 'journalctl -u kemlock-server -o cat | grep -i "setup code" | tail -n 1',
    alpine: "grep -i 'setup code' /var/log/kemlock-server.log",
  },
  { id: 'binary', target: 'setup.code.targetBinary', where: 'setup.code.whereBinary' },
  { id: 'unraid', target: 'setup.code.targetUnraid', where: 'setup.code.whereUnraid' },
  { id: 'truenas', target: 'setup.code.targetTruenas', where: 'setup.code.whereTruenas' },
  { id: 'ha', target: 'setup.code.targetHa', where: 'setup.code.whereHa' },
  { id: 'synology', target: 'setup.code.targetSynology', where: 'setup.code.whereSynology' },
  { id: 'qnap', target: 'setup.code.targetQnap', where: 'setup.code.whereQnap' },
];
