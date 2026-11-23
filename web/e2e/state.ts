// What the journeys hand to each other: global setup writes the setup code, the setup journey
// adds the authenticator secret of the admin it makes, and the vault journey reads both.
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface E2EState {
  baseURL: string;
  setupCode: string;
  totpSecret?: string;
  /** The last 30-second step a code was used in: the server refuses a code used twice. */
  totpStep?: number;
}

export const STATE_FILE = join(tmpdir(), 'kemlock-e2e-state.json');

export const ADMIN = {
  name: 'Sam Rivera',
  email: 'sam@example.co',
  password: 'correct horse battery staple',
};

export function readState(): E2EState {
  return JSON.parse(readFileSync(STATE_FILE, 'utf8')) as E2EState;
}

export function saveState(patch: Partial<E2EState>): void {
  writeFileSync(STATE_FILE, `${JSON.stringify({ ...readState(), ...patch })}\n`);
}
