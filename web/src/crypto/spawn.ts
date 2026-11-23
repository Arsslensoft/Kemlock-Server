// The crypto worker's real constructor. Kept in a file of its own so Vitest can swap it for a
// stub (vite.config.ts): the `?worker&url` import is Vite's, and only the real build resolves it.
import { spawnWorker } from '@/lib/spawn-worker';
import workerUrl from './worker.ts?worker&url';
import type { WorkerPort } from './index';

export function spawnCryptoWorker(): WorkerPort {
  return spawnWorker(workerUrl) as unknown as WorkerPort;
}
