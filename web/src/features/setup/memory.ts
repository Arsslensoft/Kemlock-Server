// What the setup screens hand to each other. Memory only: the grant is a credential, and a
// reload sends you back to the setup code, which is what the server expects.
import type { ServerBasicsValues } from '@/lib/schemas';

export interface SetupMemory {
  /** From /setup/verify: lets one registration make the first admin. */
  grant?: string;
  adminName?: string;
  adminEmail?: string;
  /** The server-basics choices, kept for the summary on the last screen. */
  basics?: ServerBasicsValues;
  /** The two-step method the admin confirmed. */
  twoStep?: 'totp';
}

let memory: SetupMemory = {};

export const setupMemory = {
  get: (): SetupMemory => memory,
  set(patch: SetupMemory): void {
    memory = { ...memory, ...patch };
  },
  clear(): void {
    memory = {};
  },
};
