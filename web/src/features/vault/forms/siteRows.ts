// A login's websites as the form edits them: a row each, with the rule that says how closely an
// address must match. The body holds them the way `websites.ts` describes (`uris`, `urls` and
// `websites`, kept in step); this reads and writes those.
import { z } from 'zod';
import type { MessageId } from '@/i18n';
import type { ItemData } from '../vault';
import { MATCH_RULES, type MatchRule, readWebsites, writeWebsites } from '../websites';

export interface SiteRow {
  /** Names the row in the form; never stored. */
  key: string;
  uri: string;
  match: MatchRule;
}

/** The rules a person picks from, in the order the form lists them. */
export const RULE_CHOICES: MatchRule[] = ['domain', 'host', 'startsWith', 'exact', 'regex', 'never'];

let counter = 0;

/** A row for a website the person is about to type, on the base-domain rule. */
export function newSiteRow(uri = '', match: MatchRule = 'domain'): SiteRow {
  counter += 1;
  return { key: `site-${counter}`, uri, match };
}

/** The websites of a login as rows; a login with none gets one empty row to type in. */
export function siteRowsOf(data: ItemData | null | undefined): SiteRow[] {
  const rules = readWebsites(data);
  return rules.length > 0 ? rules.map((rule) => newSiteRow(rule.uri, rule.match)) : [newSiteRow()];
}

const SCHEME = /^([a-z][a-z0-9+.-]*):/i;
/** The schemes a website may use: the web, and the package names the phone apps write. */
const SCHEMES = ['http', 'https', 'androidapp', 'iosapp'];

/**
 * What is wrong with a row, if anything. A blank row is not wrong (it is dropped when saved). An
 * address is a host (`github.com`), a web address, or an app's package name; a regular expression
 * has to be one. Anything else, such as `javascript:`, is refused.
 */
export function siteProblem(row: SiteRow): MessageId | undefined {
  const text = row.uri.trim();
  if (text === '') return undefined;
  if (row.match === 'regex') {
    try {
      new RegExp(text);
      return undefined;
    } catch {
      return 'itemForm.websites.badRegex';
    }
  }
  // `localhost:8080` looks like a scheme to the test below, and is a host with a port.
  if (/^[a-z0-9.-]+:\d{1,5}(?:[/?#].*)?$/i.test(text)) return undefined;
  const scheme = SCHEME.exec(text)?.[1]?.toLowerCase();
  if (scheme === undefined) return /\s/.test(text) ? 'itemForm.websites.bad' : undefined;
  if (!SCHEMES.includes(scheme)) return 'itemForm.websites.bad';
  if (scheme === 'http' || scheme === 'https') {
    try {
      return new URL(text).host === '' ? 'itemForm.websites.bad' : undefined;
    } catch {
      return 'itemForm.websites.bad';
    }
  }
  return undefined;
}

/**
 * The `urls`, `uris` and `websites` members for the rows. `urls` is always written (an empty list
 * for a login with no website); `uris` and `websites` only when there is something in them.
 */
export function sitesFields(rows: readonly SiteRow[]): ItemData {
  const written = writeWebsites(rows.map((row) => ({ uri: row.uri, match: row.match })));
  return {
    urls: written.urls,
    uris: written.uris.length > 0 ? written.uris : undefined,
    websites: written.websites.length > 0 ? written.websites : undefined,
  };
}

export const siteRowSchema = z.object({
  key: z.string(),
  uri: z.string().max(2000, 'error.tooLong'),
  match: z.enum(MATCH_RULES as [MatchRule, ...MatchRule[]]),
});

export const sitesSchema = z
  .array(siteRowSchema)
  .max(50, 'error.tooLong')
  .refine((rows) => rows.every((row) => siteProblem(row) === undefined), 'itemForm.websites.fix');
