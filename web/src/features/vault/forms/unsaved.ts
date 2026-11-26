// Whether an item form holds changes nobody has saved yet. The vault locks itself when a tab has
// been out of sight for a few minutes (src/app/autoLock.ts), and locking throws the open form away;
// a person who went to copy something from another tab would come back to lose what they typed. So
// while a form has had input, the hidden-tab limit is held (the idle limit and the policy's still
// apply). Any input or change inside the form counts, even one typed back to where it began: it is
// a guard against losing work, so it errs towards holding.
import { useCallback, useEffect, useRef } from 'react';

const touched = new Set<symbol>();

/** Whether any item form on the page has had input since it opened. */
export function hasUnsavedItemForm(): boolean {
  return touched.size > 0;
}

/**
 * For one item form: returns the function to call on any input or change inside it. The mark goes
 * when the form goes (saved, cancelled, or the page left).
 */
export function useUnsavedMark(): () => void {
  const id = useRef<symbol>(Symbol('item form'));
  useEffect(() => {
    const mine = id.current;
    return () => void touched.delete(mine);
  }, []);
  return useCallback(() => void touched.add(id.current), []);
}
