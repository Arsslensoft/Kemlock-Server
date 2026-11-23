/** Only same-origin paths: `next` comes from the address bar. */
export function safeNext(next: string | undefined): string | undefined {
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\')
    ? next
    : undefined;
}
