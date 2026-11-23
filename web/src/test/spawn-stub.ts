// Stands in for src/crypto/spawn.ts and src/import/spawn.ts under Vitest: no worker is started,
// and a test that reaches for one fails loudly.
export function spawnCryptoWorker(): never {
  throw new Error('the crypto worker is not started under Vitest');
}
export function spawnImportWorker(): never {
  throw new Error('the import worker is not started under Vitest');
}
