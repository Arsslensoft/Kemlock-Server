// Plugs the real import worker into the client: `setImportWorkerFactory` is where
// src/import/client.ts takes its worker from, and until it is called the client answers
// `unavailable`. The app calls this once at start (src/main.tsx); the module is only fetched when
// someone imports or exports.
import { spawnImportWorker } from '@/import/spawn';
import { setImportWorkerFactory } from './client';

export function installImportWorker(): void {
  setImportWorkerFactory(spawnImportWorker);
}
