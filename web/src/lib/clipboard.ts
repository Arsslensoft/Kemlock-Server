// Copying, and taking a secret back off the clipboard.
//
// A secret copied here is meant to leave the clipboard after CLEAR_AFTER_MS, but a browser only lets
// a page write the clipboard while it has focus, and by then the person has usually switched to the
// app they are pasting into. So a clear that is refused stays pending and is tried again when the
// page is back in view or focused, and it is also done at once when the vault locks, the person signs
// out, or the page goes away (`clearCopiedSecret`).
//
// It only ever clears what this page put there. Where the browser lets the page read the clipboard
// (the permission is already granted: asking would put a prompt in front of the person), a clipboard
// that no longer holds the value is left alone. Where it does not, the clear still happens, but only
// for a copy of ours that is pending, never otherwise.
const CLEAR_AFTER_MS = 30_000;

interface Pending {
  value: string;
  /** The time is up: the clear is only waiting for the browser to let it through. */
  due: boolean;
}

let pending: Pending | undefined;
let clearTimer: ReturnType<typeof setTimeout> | undefined;
let listening = false;

/** What the clipboard holds, when reading it is already allowed; otherwise nothing is known. */
async function readIfAllowed(): Promise<string | undefined> {
  try {
    const status = await navigator.permissions.query({ name: 'clipboard-read' as PermissionName });
    if (status.state !== 'granted') return undefined;
    return await navigator.clipboard.readText();
  } catch {
    return undefined;
  }
}

/** Overwrites the clipboard with nothing, if it still holds the copy. False when the browser refused. */
async function attemptClear(): Promise<boolean> {
  const held = pending;
  if (!held) return true;
  const now = await readIfAllowed();
  // Copied over by someone else in the meantime: not ours to clear.
  if (now !== undefined && now !== held.value) {
    if (pending === held) pending = undefined;
    return true;
  }
  // Another copy took its place while this waited.
  if (pending !== held) return true;
  try {
    await navigator.clipboard.writeText('');
  } catch {
    return false;
  }
  if (pending === held) pending = undefined;
  return true;
}

function retryDue(): void {
  if (pending?.due && document.visibilityState !== 'hidden') void attemptClear();
}

function listen(): void {
  if (listening || typeof window === 'undefined') return;
  listening = true;
  window.addEventListener('focus', retryDue);
  document.addEventListener('visibilitychange', retryDue);
  // The page is going away: what it copied should not outlive it.
  window.addEventListener('pagehide', () => void clearCopiedSecret());
}

/**
 * Takes a secret this page copied off the clipboard now (the vault locked, the person signed out, the
 * page is closing). Nothing happens when nothing is pending.
 */
export async function clearCopiedSecret(): Promise<void> {
  clearTimeout(clearTimer);
  clearTimer = undefined;
  if (!pending) return;
  // Now is the time, so a refusal is retried as soon as the page is back in view.
  pending.due = true;
  await attemptClear();
}

/** Copies text. A secret is taken off the clipboard 30 seconds later, or as soon as it can be. */
export async function copyText(text: string, options: { secret?: boolean } = {}): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }
  // This copy replaced whatever was there, an earlier secret included.
  clearTimeout(clearTimer);
  clearTimer = undefined;
  pending = undefined;
  if (options.secret) {
    pending = { value: text, due: false };
    listen();
    const mine = pending;
    clearTimer = setTimeout(() => {
      clearTimer = undefined;
      if (pending !== mine) return;
      mine.due = true;
      void attemptClear();
    }, CLEAR_AFTER_MS);
  }
  return true;
}
