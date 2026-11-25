import { useState } from 'react';

/**
 * What a space action hands back: a promise of whether it worked, or nothing for a caller that
 * doesn't say (a test double). Forms close and clear only once it says yes.
 */
export type Done = Promise<boolean> | void;

/** Waits for an action and says whether the form may close: anything but an explicit `false`. */
export async function succeeded(done: Done): Promise<boolean> {
  return (await done) !== false;
}

/**
 * A confirm dialog's state: what is being asked about, and whether the person has pressed the
 * button since it opened (so an older failure from the page isn't shown as this one's).
 */
export function useAsk<T>(run: (target: T) => Done) {
  const [target, setTarget] = useState<T | null>(null);
  const [tried, setTried] = useState(false);
  return {
    target,
    tried,
    ask: (next: T) => {
      setTried(false);
      setTarget(next);
    },
    close: () => setTarget(null),
    confirm: async () => {
      if (target === null) return;
      setTried(true);
      if (await succeeded(run(target))) setTarget(null);
    },
  };
}
