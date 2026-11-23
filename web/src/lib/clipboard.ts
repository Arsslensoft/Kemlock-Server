const CLEAR_AFTER_MS = 30_000;
let clearTimer: ReturnType<typeof setTimeout> | undefined;

/** Copies text. A secret is overwritten with an empty string 30 seconds later. */
export async function copyText(text: string, options: { secret?: boolean } = {}): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }
  if (clearTimer) clearTimeout(clearTimer);
  if (options.secret) {
    clearTimer = setTimeout(() => {
      void navigator.clipboard.writeText('').catch(() => undefined);
    }, CLEAR_AFTER_MS);
  }
  return true;
}
