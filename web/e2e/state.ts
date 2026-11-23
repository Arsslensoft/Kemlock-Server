// What the journeys hand to each other: global setup writes the setup code, the setup journey
// adds the authenticator secret of the admin it makes, and the vault journey reads both.
import { readFileSync, writeFileSync } from 'node:fs';

export interface E2EState {
  baseURL: string;
  setupCode: string;
  totpSecret?: string;
  /** The last 30-second step a code was used in: the server refuses a code used twice. */
  totpStep?: number;
}

/**
 * Global setup makes a private directory with mkdtemp (mode 0700) and puts the state file's path in
 * this variable; the workers it starts inherit it. A fixed name in the shared temp directory would
 * let another local user pre-create or read the file, which holds the setup code and TOTP secret.
 */
export const STATE_ENV = 'KEMLOCK_E2E_STATE_FILE';

export function stateFile(): string {
  const file = process.env[STATE_ENV];
  if (!file) throw new Error(`${STATE_ENV} is not set: global setup has not run`);
  return file;
}

export const ADMIN = {
  name: 'Sam Rivera',
  email: 'sam@example.co',
  password: 'correct horse battery staple',
};

export function readState(): E2EState {
  return JSON.parse(readFileSync(stateFile(), 'utf8')) as E2EState;
}

export function saveState(patch: Partial<E2EState>): void {
  writeFileSync(stateFile(), `${JSON.stringify({ ...readState(), ...patch })}\n`);
}
