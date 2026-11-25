// The Details column of the lists: one short line that helps tell two items of a type apart, as
// parts (a message or plain text) so the page words it and tests need no catalogue. Never a secret:
// a password, a code's secret, a card number, a key or a backup code is never in it.
import type { MessageId, Values } from '@/i18n';
import type { KeyFacts } from './keyFacts';
import { hostOfUrl } from './kinds';
import { otpParamsOf } from './details/otp';
import type { ItemData, VaultItem } from './vault';
import { readWebsites } from './websites';

export type DetailPart = { id: MessageId; values?: Values } | { text: string };

const text = (data: ItemData, key: string): string => {
  const value = data[key];
  return typeof value === 'string' ? value.trim() : '';
};

const parts = (...list: Array<DetailPart | string | undefined | false>): DetailPart[] =>
  list.flatMap((part) => (part === undefined || part === false || part === '' ? [] : [typeof part === 'string' ? { text: part } : part]));

/** `SHA256:q7Fv…k2Lw`: enough of a fingerprint to recognise a key, not all of it. */
export function shortFingerprint(fingerprint: string): string {
  const plain = fingerprint.replace(/\s+/g, '');
  const prefix = plain.startsWith('SHA256:') ? 'SHA256:' : '';
  const body = plain.slice(prefix.length);
  return body.length <= 12 ? plain : `${prefix}${body.slice(0, 4)}…${body.slice(-4)}`;
}

const SIZE_UNITS = ['B', 'KB', 'MB', 'GB'] as const;

/** `2.4 MB`, `860 KB`, `12 B`. */
export function formatSize(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < SIZE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const shown = unit === 0 || value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${shown} ${SIZE_UNITS[unit] ?? 'B'}`;
}

function fileType(data: ItemData): string {
  const name = text(data, 'fileName') || text(data, 'filename');
  const dot = name.lastIndexOf('.');
  if (dot > 0 && dot < name.length - 1) return name.slice(dot + 1).toUpperCase();
  const mime = text(data, 'mimeType') || text(data, 'mime');
  const subtype = mime.split('/')[1];
  return subtype ? subtype.toUpperCase() : '';
}

function codesOf(data: ItemData): { total: number; unused: number } {
  const list = data['codes'];
  if (!Array.isArray(list)) return { total: 0, unused: 0 };
  let total = 0;
  let unused = 0;
  for (const entry of list) {
    if (typeof entry === 'string') {
      total += 1;
      unused += 1;
    } else if (entry && typeof entry === 'object' && typeof (entry as { code?: unknown }).code === 'string') {
      total += 1;
      if ((entry as { used?: unknown }).used !== true) unused += 1;
    }
  }
  return { total, unused };
}

/** The earliest year an identity's documents expire, or undefined when none says. */
export function identityExpiryYear(data: ItemData): string | undefined {
  const docs = data['documents'];
  if (!Array.isArray(docs)) return undefined;
  const years: string[] = [];
  for (const doc of docs) {
    const on = doc && typeof doc === 'object' ? (doc as { expiresOn?: unknown }).expiresOn : undefined;
    const year = typeof on === 'string' ? /^(\d{4})/.exec(on.trim())?.[1] : undefined;
    if (year) years.push(year);
  }
  return years.sort()[0];
}

/** `2 Feb 2027`, the day in UTC as certificate tools print it. */
const longDate = (date: Date): string =>
  new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(date);

/** `08/28` from a card's expiry month and year, or '' when it has none. */
export function cardExpiry(data: ItemData): string {
  const month = Number(data['expMonth']);
  const year = Number(data['expYear']);
  if (!Number.isInteger(month) || !Number.isInteger(year) || month < 1 || month > 12 || year < 0) return '';
  return `${String(month).padStart(2, '0')}/${String(year % 100).padStart(2, '0')}`;
}

/** The Details of an item as parts; `facts` are the worked-out facts of a key item, when known. */
export function detailParts(item: VaultItem, facts?: KeyFacts): DetailPart[] {
  const data = item.data;
  if (!data) return [];
  const other = parts({ id: 'main.details.item' });
  switch (item.kind) {
    case 'login':
      return parts(
        readWebsites(data)
          .map((site) => hostOfUrl(site.uri))
          .join(', '),
      );
    case 'note': {
      const attachments = Array.isArray(data['attachments']) ? data['attachments'].length : 0;
      return parts(
        { id: 'main.details.note' },
        attachments > 0 && { id: 'lists.details.attachments', values: { count: attachments } },
      );
    }
    case 'file': {
      const size = typeof data['size'] === 'number' && data['size'] >= 0 ? formatSize(data['size']) : '';
      const list = parts(fileType(data), size);
      return list.length > 0 ? list : other;
    }
    case 'otp': {
      const params = otpParamsOf(data);
      const who = text(data, 'label') || text(data, 'issuer');
      const list = parts(who, params && params.type !== 'hotp' && { id: 'lists.details.every', values: { seconds: params.period } });
      return list.length > 0 ? list : other;
    }
    case 'backup-codes': {
      const { total, unused } = codesOf(data);
      return total === 0 ? other : parts({ id: 'lists.details.codes', values: { total, unused } });
    }
    case 'passkey': {
      const list = parts(text(data, 'rpId') || text(data, 'rp'));
      return list.length > 0 ? list : other;
    }
    case 'card': {
      const number = text(data, 'number').replace(/\D/g, '');
      const brand = text(data, 'brand');
      const last4 = number.slice(-4);
      const expiry = cardExpiry(data);
      const list = parts(
        last4 !== '' &&
          (brand
            ? { id: 'lists.details.cardEnding', values: { brand, last4 } }
            : { id: 'lists.details.cardEndingNoBrand', values: { last4 } }),
        expiry !== '' && { id: 'lists.details.expiresShort', values: { date: expiry } },
      );
      return list.length > 0 ? list : other;
    }
    case 'identity': {
      const year = identityExpiryYear(data);
      return year ? parts({ id: 'lists.details.expiresOn', values: { date: year } }) : other;
    }
    case 'contact': {
      const list = parts(text(data, 'phone'), text(data, 'company'));
      return list.length > 0 ? list : parts(text(data, 'email') || text(data, 'sourceEmail'));
    }
    case 'certificate': {
      const list = parts(
        facts?.subject,
        facts?.notAfter && { id: 'lists.details.expiresShort', values: { date: longDate(facts.notAfter) } },
      );
      return list.length > 0 ? list : other;
    }
    case 'ssh-key': {
      const list = parts(facts?.algorithm, facts && shortFingerprint(facts.fingerprint));
      return list.length > 0 ? list : other;
    }
    case 'pgp-key': {
      const list = parts(facts?.userId, facts && shortFingerprint(facts.fingerprint));
      return list.length > 0 ? list : other;
    }
    default:
      return other;
  }
}
