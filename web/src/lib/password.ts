// Password strength for the master-password meter, and the generator for item passwords.

export type Strength = 0 | 1 | 2 | 3 | 4;

/**
 * A rough 0 to 4 score from length and variety: enough to steer a person, not a promise. The
 * server never sees the password, so the real check is the length floor in the schema.
 */
export function passwordStrength(password: string): Strength {
  if (password.length === 0) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(password)).length;
  const unique = new Set(password).size;
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12 && unique >= 6) score += 1;
  if (password.length >= 16 && classes >= 2) score += 1;
  if (password.length >= 20 && classes >= 3) score += 1;
  if (/^(.)\1+$/.test(password)) score = 0;
  return Math.min(score, 4) as Strength;
}

export interface GeneratorOptions {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
}

export const DEFAULT_GENERATOR: GeneratorOptions = {
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
};

const SETS = {
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lower: 'abcdefghijkmnopqrstuvwxyz',
  digits: '23456789',
  symbols: '!@#$%^&*',
} as const;

/** A uniform random integer in [0, max): rejection sampling over the secure random source. */
export function randomBelow(max: number, random: (buffer: Uint32Array) => void = fill): number {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buffer = new Uint32Array(1);
  for (;;) {
    random(buffer);
    const value = buffer[0] ?? 0;
    if (value < limit) return value % max;
  }
}

function fill(buffer: Uint32Array): void {
  globalThis.crypto.getRandomValues(buffer);
}

/** Made in this browser from its secure random source; at least one of each chosen kind. */
export function generatePassword(
  options: GeneratorOptions = DEFAULT_GENERATOR,
  random?: (buffer: Uint32Array) => void,
): string {
  const chosen = (Object.keys(SETS) as Array<keyof typeof SETS>).filter((k) => options[k]);
  if (chosen.length === 0) return '';
  const length = Math.min(128, Math.max(chosen.length, options.length));
  const pool = chosen.map((k) => SETS[k]).join('');
  const out: string[] = chosen.map((k) => {
    const set = SETS[k];
    return set.charAt(randomBelow(set.length, random));
  });
  while (out.length < length) out.push(pool.charAt(randomBelow(pool.length, random)));
  // Fisher-Yates, so the guaranteed characters aren't always first.
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = randomBelow(i + 1, random);
    const a = out[i] as string;
    out[i] = out[j] as string;
    out[j] = a;
  }
  return out.join('');
}
