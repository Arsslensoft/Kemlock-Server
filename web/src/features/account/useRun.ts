import { useState } from 'react';
import { type Described, describeAccountError } from './errors';

/**
 * Runs one action at a time and keeps its failure for the screen to show. `run` resolves with the
 * action's value, or undefined when it failed, so a caller never has to catch.
 */
export function useRun() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Described | undefined>(undefined);

  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    setPending(true);
    setError(undefined);
    try {
      return await action();
    } catch (caught) {
      setError(describeAccountError(caught));
      return undefined;
    } finally {
      setPending(false);
    }
  }

  return { run, pending, error, clearError: () => setError(undefined) };
}
