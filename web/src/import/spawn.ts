// The import worker's real constructor; see src/crypto/spawn.ts for why it is its own file.
import { spawnWorker } from '@/lib/spawn-worker';
import type { ImportWorkerPort } from './client';
import workerUrl from './worker.ts?worker&url';

export function spawnImportWorker(): ImportWorkerPort {
  return spawnWorker(workerUrl) as unknown as ImportWorkerPort;
}
