// One Zod schema checks each form's input, in the form and again before encryption. Error
// messages are message ids from src/i18n/en.json; src/ui/fields.tsx translates them.
import { z } from 'zod';

const email = z.string().trim().min(1, 'error.required').pipe(z.email('error.email'));

export const MASTER_PASSWORD_MIN = 12;

/** Only http and https: an address or a website, never javascript: or data:. */
const httpUrl = z.url({ protocol: /^https?$/, message: 'error.url' });

/** Crockford base32 in groups of four, as the server's log prints it; dashes, spaces and case are free. */
export function normaliseSetupCode(value: string): string {
  return value.replace(/[\s-]/g, '').toUpperCase();
}

export const setupCodeSchema = z.object({
  code: z.string().refine((v) => /^[0-9A-HJKMNP-TV-Z]{12}$/.test(normaliseSetupCode(v)), 'error.setupCode'),
});
export type SetupCodeValues = z.infer<typeof setupCodeSchema>;

export const setupAdminSchema = z
  .object({
    name: z.string().trim().min(1, 'error.required').max(100, 'error.tooLong'),
    email,
    password: z.string().min(MASTER_PASSWORD_MIN, 'error.passwordShort'),
    confirm: z.string(),
  })
  .refine((v) => v.password === v.confirm, { path: ['confirm'], message: 'error.passwordMismatch' });
export type SetupAdminValues = z.infer<typeof setupAdminSchema>;

export const emailSchema = z.object({ email });
export type EmailValues = z.infer<typeof emailSchema>;

export const passwordSchema = z.object({
  password: z.string().min(1, 'error.required'),
});
export type PasswordValues = z.infer<typeof passwordSchema>;

/** A one-time code: six digits, spaces allowed, from an authenticator app. */
export function normaliseCode(value: string): string {
  return value.replace(/\s/g, '');
}

export const codeSchema = z.object({
  code: z.string().refine((v) => /^\d{6}$/.test(normaliseCode(v)), 'error.code'),
});
export type CodeValues = z.infer<typeof codeSchema>;

export const serverBasicsSchema = z.object({
  address: z.string().trim().pipe(httpUrl),
  join: z.enum(['invite', 'domains', 'anyone']),
  joinDomains: z.string().trim().max(500, 'error.tooLong'),
  mailHost: z.string().trim().max(253, 'error.tooLong'),
  mailPort: z.string().trim(),
  mailSecurity: z.enum(['starttls', 'tls']),
  mailFrom: z.string().trim().max(254, 'error.tooLong'),
  mailUser: z.string().trim().max(254, 'error.tooLong'),
  push: z.boolean(),
  files: z.enum(['local', 's3']),
  folder: z.string().trim().max(500, 'error.tooLong'),
  backups: z.boolean(),
  backupEvery: z.enum(['night', 'six-hours']),
  backupKeep: z.enum(['7', '14', '30']),
  backupRecipient: z.string().trim(),
  serverKeyStored: z.boolean(),
});
export type ServerBasicsValues = z.infer<typeof serverBasicsSchema>;

export const serverBasicsResolverSchema = serverBasicsSchema.superRefine((v, ctx) => {
  if (v.join === 'domains' && v.joinDomains === '') {
    ctx.addIssue({ code: 'custom', path: ['joinDomains'], message: 'error.required' });
  }
  if (v.mailHost !== '') {
    if (!/^\d{1,5}$/.test(v.mailPort) || Number(v.mailPort) > 65535) {
      ctx.addIssue({ code: 'custom', path: ['mailPort'], message: 'error.port' });
    }
    if (!z.email().safeParse(v.mailFrom).success) {
      ctx.addIssue({ code: 'custom', path: ['mailFrom'], message: 'error.email' });
    }
  }
  if (v.backups) {
    if (!/^age1[a-z0-9]{50,}$/.test(v.backupRecipient)) {
      ctx.addIssue({ code: 'custom', path: ['backupRecipient'], message: 'error.ageRecipient' });
    }
    if (!v.serverKeyStored) {
      ctx.addIssue({ code: 'custom', path: ['serverKeyStored'], message: 'error.serverKeyStored' });
    }
  }
});

/** What the items carry inside their ciphertext (test-vectors/kem1.json: login and note). */
const optionalUrl = z
  .string()
  .trim()
  .refine((v) => v === '' || httpUrl.safeParse(v).success, 'error.url');

export const loginSchema = z.object({
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  username: z.string().trim().max(500, 'error.tooLong'),
  password: z.string().max(5000, 'error.tooLong'),
  url: optionalUrl,
  notes: z.string().max(10000, 'error.tooLong'),
  favorite: z.boolean(),
});
export type LoginValues = z.infer<typeof loginSchema>;

export const noteSchema = z.object({
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  text: z.string().max(50000, 'error.tooLong'),
  favorite: z.boolean(),
});
export type NoteValues = z.infer<typeof noteSchema>;
