import { useRef, useState } from 'react';
import type { Accepted } from '@/api/bwInvitations';

export type Outcome =
  | { status: 'ready' }
  | { status: 'working' }
  | { status: 'done' }
  | { status: 'refused'; message: string }
  | { status: 'incomplete' };

/**
 * Spends the token of a link once, when `start` is called (a button press, never the page opening:
 * a mail scanner that runs the page's script must not accept for the person), and reports what
 * happened. A token works once, so a second press does nothing. `accept` is `undefined` when the
 * link lacks something it needs.
 */
export function useAcceptOnce(accept: (() => Promise<Accepted>) | undefined): {
  outcome: Outcome;
  start: () => void;
} {
  const [outcome, setOutcome] = useState<Outcome>(accept ? { status: 'ready' } : { status: 'incomplete' });
  const asked = useRef(false);
  function start() {
    if (!accept || asked.current) return;
    asked.current = true;
    setOutcome({ status: 'working' });
    void accept().then((answer) =>
      setOutcome(answer.ok ? { status: 'done' } : { status: 'refused', message: answer.message }),
    );
  }
  return { outcome, start };
}
