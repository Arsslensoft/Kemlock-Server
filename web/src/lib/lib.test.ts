import { describe, expect, it } from 'vitest';
import { decodeB64, encodeB64, wipe } from './b64url';
import { ApiErrorFixture } from './lib.fixture';
import { describeError } from './errors';
import { safeNext } from './safe-next';
import {
  DEFAULT_GENERATOR,
  generatePassword,
  passwordStrength,
  randomBelow,
} from './password';
import {
  codeSchema,
  loginSchema,
  noteSchema,
  normaliseCode,
  normaliseSetupCode,
  serverBasicsResolverSchema,
  setupAdminSchema,
  setupCodeSchema,
} from './schemas';
import { NetworkError } from '@/api/errors';

describe('base64url', () => {
  it('round-trips bytes without padding', () => {
    for (const length of [0, 1, 2, 3, 4, 31, 32, 33]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 11) % 256);
      const text = encodeB64(bytes);
      expect(text).not.toMatch(/[=+/]/);
      expect(decodeB64(text)).toEqual(bytes);
    }
  });

  it('uses the URL-safe alphabet', () => {
    expect(encodeB64(Uint8Array.of(0xfb, 0xff, 0xfe))).toBe('-__-');
  });

  it('refuses padding, other alphabets and impossible lengths', () => {
    expect(() => decodeB64('AA==')).toThrow();
    expect(() => decodeB64('a+b/')).toThrow();
    expect(() => decodeB64('A')).toThrow();
  });

  it('wipes key material in place', () => {
    const key = Uint8Array.of(1, 2, 3);
    wipe(key, undefined);
    expect(key).toEqual(Uint8Array.of(0, 0, 0));
  });
});

describe('setup code', () => {
  it('accepts the log format in any case, with or without dashes', () => {
    for (const code of ['7QF4-9M2X-HD3P', '7qf4-9m2x-hd3p', ' 7QF49M2XHD3P ']) {
      expect(setupCodeSchema.safeParse({ code }).success).toBe(true);
    }
    expect(normaliseSetupCode('7qf4-9m2x-hd3p')).toBe('7QF49M2XHD3P');
  });

  it('refuses letters the code never uses and wrong lengths', () => {
    for (const code of ['', '7QF4-9M2X-HD3', '7QF4-9M2X-HD3PX', 'IIII-OOOO-LLLL', '7QF4-9M2X-HD3U']) {
      const result = setupCodeSchema.safeParse({ code });
      expect(result.success, code).toBe(false);
    }
  });
});

describe('two-step code', () => {
  it('takes six digits, spaces allowed', () => {
    expect(codeSchema.safeParse({ code: '482 913' }).success).toBe(true);
    expect(normaliseCode('482 913')).toBe('482913');
    expect(codeSchema.safeParse({ code: '48291' }).success).toBe(false);
    expect(codeSchema.safeParse({ code: 'abcdef' }).success).toBe(false);
  });
});

describe('admin account', () => {
  const good = { name: 'Sam', email: 'sam@example.co', password: 'a long enough password', confirm: 'a long enough password' };

  it('accepts a complete form', () => {
    expect(setupAdminSchema.safeParse(good).success).toBe(true);
  });

  it('names the message id of each failure', () => {
    const messages = (input: object) => {
      const result = setupAdminSchema.safeParse({ ...good, ...input });
      return result.success ? [] : result.error.issues.map((i) => i.message);
    };
    expect(messages({ name: ' ' })).toContain('error.required');
    expect(messages({ email: 'nope' })).toContain('error.email');
    expect(messages({ password: 'short', confirm: 'short' })).toContain('error.passwordShort');
    expect(messages({ confirm: 'different but long enough' })).toContain('error.passwordMismatch');
  });
});

describe('items', () => {
  it('needs a name and a web address that is http or https', () => {
    const base = { name: 'GitHub', username: '', password: '', url: '', notes: '', favorite: false };
    expect(loginSchema.safeParse(base).success).toBe(true);
    expect(loginSchema.safeParse({ ...base, url: 'https://github.com' }).success).toBe(true);
    expect(loginSchema.safeParse({ ...base, url: 'javascript:alert(1)' }).success).toBe(false);
    expect(loginSchema.safeParse({ ...base, name: '  ' }).success).toBe(false);
    expect(noteSchema.safeParse({ name: 'N', text: 'x', favorite: false }).success).toBe(true);
    expect(noteSchema.safeParse({ name: '', text: 'x', favorite: false }).success).toBe(false);
  });
});

describe('server basics', () => {
  const base = {
    address: 'https://vault.example.org',
    join: 'invite',
    joinDomains: '',
    mailHost: '',
    mailPort: '587',
    mailSecurity: 'starttls',
    mailFrom: '',
    mailUser: '',
    push: false,
    files: 'local',
    folder: '/data/files',
    backups: false,
    backupEvery: 'night',
    backupKeep: '7',
    backupRecipient: '',
    serverKeyStored: false,
  };
  const issues = (input: object) => {
    const result = serverBasicsResolverSchema.safeParse({ ...base, ...input });
    return result.success ? [] : result.error.issues.map((i) => `${i.path.join('.')}:${i.message}`);
  };

  it('needs nothing optional', () => {
    expect(issues({})).toEqual([]);
  });

  it('checks mail only when a host is given', () => {
    expect(issues({ mailHost: 'smtp.example.org', mailFrom: 'nope', mailPort: '99999' })).toEqual([
      'mailPort:error.port',
      'mailFrom:error.email',
    ]);
  });

  it('wants an age recipient and the server.key confirmation for backups', () => {
    expect(issues({ backups: true })).toEqual([
      'backupRecipient:error.ageRecipient',
      'serverKeyStored:error.serverKeyStored',
    ]);
    const age = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';
    expect(issues({ backups: true, backupRecipient: age, serverKeyStored: true })).toEqual([]);
  });

  it('needs domains when joining by domain', () => {
    expect(issues({ join: 'domains' })).toEqual(['joinDomains:error.required']);
  });
});

describe('passwords', () => {
  it('scores length and variety', () => {
    expect(passwordStrength('')).toBe(0);
    expect(passwordStrength('aaaaaaaaaaaaaaaa')).toBe(0);
    expect(passwordStrength('abcdefgh')).toBe(1);
    expect(passwordStrength('correct horse')).toBe(2);
    expect(passwordStrength('correct horse battery staple')).toBeGreaterThanOrEqual(3);
    expect(passwordStrength('Tr0ub4dor&3-correct-horse-battery')).toBe(4);
  });

  it('generates the length asked, with each chosen kind present', () => {
    for (let i = 0; i < 50; i += 1) {
      const pw = generatePassword({ ...DEFAULT_GENERATOR, length: 12 });
      expect(pw).toHaveLength(12);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[2-9]/);
      expect(pw).toMatch(/[!@#$%^&*]/);
    }
  });

  it('honours the kinds switched off, and returns nothing with none on', () => {
    const digitsOnly = generatePassword({ length: 30, upper: false, lower: false, digits: true, symbols: false });
    expect(digitsOnly).toMatch(/^[2-9]{30}$/);
    expect(generatePassword({ length: 10, upper: false, lower: false, digits: false, symbols: false })).toBe('');
  });

  it('samples without modulo bias', () => {
    // Values at or above the largest multiple of 10 below 2^32 are thrown away.
    const values = [0xffff_ffff, 0xffff_fffb, 12];
    const picked = randomBelow(10, (buffer) => {
      buffer[0] = values.shift() ?? 0;
    });
    expect(picked).toBe(2);
  });
});

describe('error messages and links', () => {
  it('maps problems to message ids', () => {
    expect(describeError(new NetworkError(null)).id).toBe('error.network');
    expect(describeError(ApiErrorFixture(403, 'setup-code-wrong')).id).toBe('error.setupCodeWrong');
    expect(describeError(ApiErrorFixture(409, 'stale-revision')).id).toBe('error.stale');
    expect(describeError(ApiErrorFixture(429, 'rate-limited', { retryAfter: 9 }))).toEqual({
      id: 'error.rateLimited',
      values: { seconds: 9 },
    });
    expect(describeError(ApiErrorFixture(500, 'internal')).id).toBe('error.server');
    expect(describeError(new Error('x')).id).toBe('error.generic');
  });

  it('only follows same-origin paths after sign-in', () => {
    expect(safeNext('/vault?kind=login')).toBe('/vault?kind=login');
    for (const bad of [undefined, '', 'https://evil.example', '//evil.example', '/\\evil.example', 'vault']) {
      expect(safeNext(bad), String(bad)).toBeUndefined();
    }
  });
});
