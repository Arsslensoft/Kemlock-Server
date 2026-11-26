// A Send's link, `/#/send/<accessId>/<key>`, carries the key that opens the Send in its fragment. A
// fragment stays in the address bar, in the history and in anything that records the page's address,
// so the page takes the link out of the address as soon as it has read it, and holds it here, in
// memory, for the page that opens the Send. The address is left as the page's own, with no fragment.
// A reload of the page therefore does not open the Send again: the link has to be used again.
import { type SendLink, isSendHash, parseSendLink } from '@/features/send/recipient';

/** The link this page was opened with; `link` is null when it had the shape of one but not the lengths. */
export interface HeldSendLink {
  link: SendLink | null;
}

let held: HeldSendLink | undefined;
const listeners = new Set<() => void>();

/**
 * Reads a Send link from the address, if there is one, and replaces the address with one that has no
 * fragment. Nothing happens when the address holds no Send link, so calling it again is harmless.
 */
export function absorbSendLinkFromAddress(): void {
  const { hash, pathname, search } = window.location;
  if (isSendHash(hash)) {
    held = { link: parseSendLink(hash) };
    try {
      window.history.replaceState(window.history.state, '', `${pathname}${search}`);
    } catch {
      // A browser that refuses leaves the address as it was; the page still opens the Send.
    }
    return;
  }
  // Another fragment is the app's own: the person has left the Send.
  if (hash !== '') held = undefined;
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
  for (const listener of listeners) listener();
}
