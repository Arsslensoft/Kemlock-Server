// Small formatters for the admin screens. Times are Unix seconds on the wire.
export { shortId } from '@/api/federation';

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

/** "12 minutes ago" or "in 3 days". `nowSeconds` is injectable for tests. */
export function relative(at: number | null | undefined, nowSeconds = Date.now() / 1000): string {
  if (at === null || at === undefined) return '';
  const diff = Math.round(at - nowSeconds);
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  for (const [unit, size] of UNITS) {
    if (Math.abs(diff) >= size) return formatter.format(Math.round(diff / size), unit);
  }
  return formatter.format(0, 'second');
}

export function clock(at: number): string {
  return new Intl.DateTimeFormat('en', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(at * 1000));
}

export function dateTime(at: number): string {
  return new Intl.DateTimeFormat('en', {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(at * 1000));
}

export function day(at: number): string {
  return new Intl.DateTimeFormat('en', { day: 'numeric', month: 'short', year: 'numeric' }).format(
    new Date(at * 1000),
  );
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const shown = value >= 100 || Number.isInteger(value) ? String(Math.round(value)) : value.toFixed(1);
  return `${shown} ${units[unit] ?? 'TB'}`;
}

/** Whole seconds as "47 min", "41 s" or "3 h". */
export function span(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds / 3600)} h`;
}

export function count(n: number): string {
  return new Intl.NumberFormat('en').format(n);
}
