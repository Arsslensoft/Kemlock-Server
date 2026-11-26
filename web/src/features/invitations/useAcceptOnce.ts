import { useEffect, useRef, useState } from 'react';
import type { Accepted } from '@/api/bwInvitations';

export type Outcome =
  | { status: 'working' }
  | { status: 'done' }
  | { status: 'refused'; message: string }
  | { status: 'incomplete' };

/**
 * Spends the token of a link once and reports what happened. A token works once, and React may run
 * an effect twice, so there is one trip to the server per page. `accept` is `undefined` when the
 * link lacks something it needs.
 */
export function useAcceptOnce(accept: (() => Promise<Accepted>) | undefined): Outcome {
  const [outcome, setOutcome] = useState<Outcome>(accept ? { status: 'working' } : { status: 'incomplete' });
  const asked = useRef(false);
  useEffect(() => {
    if (!accept || asked.current) return;
    asked.current = true;
    void accept().then((answer) =>
      setOutcome(answer.ok ? { status: 'done' } : { status: 'refused', message: answer.message }),
    );
    // `accept` is rebuilt on every render; the link's own values decide, and they don't change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return outcome;
}
