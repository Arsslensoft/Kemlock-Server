import { useRef, useState } from 'react';
import { type Accepted, bwInvitations } from '@/api/bwInvitations';
import { vaultCrypto } from '@/crypto-port';

export type Outcome =
  | { status: 'ready' }
  | { status: 'working' }
  | { status: 'done' }
  /** The server did not take the password: a wrong one and an unknown account look the same. */
  | { status: 'wrong' }
  /** Too many tries; the wait in seconds when the server says it. */
  | { status: 'limited'; retryAfter?: number }
  /** The account's key settings could not be read, or the hash could not be made here. */
  | { status: 'unavailable' }
  | { status: 'refused'; message: string }
  | { status: 'incomplete' };

/**
 * Accepts an invitation with the invitee's master password, when the person presses the button and
 * never before. The account's KDF comes from the server's prelogin for the invited address; the
 * worker makes the master password hash from it, so the password stays in the worker and the server
 * is sent the hash only. The password is held by the caller's field, which empties it as it submits,
 * and nowhere here: not in this state, not in a closure that outlives the call, not in storage.
 *
 * A try that fails leaves the form open for another press (a wrong password counts against a limit
 * on the server, so nothing here tries again by itself). A token works once: after `done` nothing
 * more is sent. `accept` is `undefined` when the link lacks something it needs.
 */
export function useAcceptInvitation(
  email: string | undefined,
  accept: ((masterPasswordHash: string) => Promise<Accepted>) | undefined,
): { outcome: Outcome; submit: (password: string) => void } {
  const [outcome, setOutcome] = useState<Outcome>(accept && email ? { status: 'ready' } : { status: 'incomplete' });
  const busy = useRef(false);
  function submit(password: string) {
    if (!accept || !email || busy.current || outcome.status === 'done' || password === '') return;
    busy.current = true;
    setOutcome({ status: 'working' });
    void (async (): Promise<Outcome> => {
      const kdf = await bwInvitations.prelogin(email);
      if (!kdf) return { status: 'unavailable' };
      let hash: string;
      try {
        hash = await vaultCrypto.bitwardenPasswordHash({ password, email, kdf });
      } catch {
        return { status: 'unavailable' };
      }
      const answer = await accept(hash);
      if (answer.ok) return { status: 'done' };
      if (answer.reason === 'password') return { status: 'wrong' };
      if (answer.reason === 'limited') {
        return { status: 'limited', ...(answer.retryAfter === undefined ? {} : { retryAfter: answer.retryAfter }) };
      }
      return { status: 'refused', message: answer.message };
    })()
      .then(setOutcome)
      .finally(() => {
        busy.current = false;
      });
  }
  return { outcome, submit };
}
