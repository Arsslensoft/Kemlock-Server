// A Send's link, `/#/send/<accessId>/<key>`, carries the key that opens the Send in its fragment. A
// fragment stays in the address bar and in this tab's history entry, so the page takes the link out of
// the address as soon as it has read it, and holds it here, in memory, for the page that opens the
// Send. The address is left as the page's own, with no fragment. `replaceState` changes the tab's
// entry; it does not reach into the browser's global history (the list of visited addresses the
// person can search), which may already have recorded the address the page was opened with, and a
// page cannot remove that. A reload of the page does not open the Send again: the link has to be
// used again.
import { type SendLink, isSendHash, parseSendLink } from '@/features/send/recipient';

/** The link this page was opened with; `link` is null when it had the shape of one but not the lengths. */
export interface HeldSendLink {
  link: SendLink | null;
}

let held: HeldSendLink | undefined;
/** The fragment `held` was read from, so reading the same one again keeps the same object. */
let lastHash: string | undefined;
const listeners = new Set<() => void>();

/**
 * Reads a Send link from the address, if there is one, and replaces the address with one that has no
 * fragment. Nothing happens when the address holds no Send link, so calling it again is harmless.
 */
export function absorbSendLinkFromAddress(): void {
  const { hash, pathname, search } = window.location;
  if (isSendHash(hash)) {
    // A browser that refuses to change the address leaves the fragment there, and this is called on
    // every render: a new object each time would make the page render without end.
    if (hash !== lastHash || held === undefined) {
      held = { link: parseSendLink(hash) };
      lastHash = hash;
    }
    try {
      window.history.replaceState(window.history.state, '', `${pathname}${search}`);
    } catch {
      // A browser that refuses leaves the address as it was; the page still opens the Send.
    }
    return;
  }
  // Another fragment is the app's own: the person has left the Send.
  if (hash !== '') {
    held = undefined;
    lastHash = undefined;
  }
}

/** What the page holds now, after taking anything new from the address. */
export function heldSendLink(): HeldSendLink | undefined {
  absorbSendLinkFromAddress();
  return held;
}

/** Calls `onChange` when the address changes to another fragment. */
export function subscribeSendLink(onChange: () => void): () => void {
  const listener = () => {
    absorbSendLinkFromAddress();
    onChange();
  };
  listeners.add(listener);
  window.addEventListener('hashchange', listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener('hashchange', listener);
  };
}

/** Lets go of the link (the person is done with it). */
export function forgetSendLink(): void {
  held = undefined;
  lastHash = undefined;
  for (const listener of listeners) listener();
}
