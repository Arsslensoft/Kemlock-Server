// What keeps a signed-in person's decrypted data in the page registers here how to drop it, so
// locking and signing out (src/app/actions.ts) clear it without the sign-in screen loading the
// vault's code: a module that never loaded holds nothing to clear.

const resets = new Set<() => void>();

/** Registers what drops the data a module holds; called once, when the module loads. */
export function onForget(reset: () => void): void {
  resets.add(reset);
}

/** Drops the data every loaded module holds. */
export function forgetLoaded(): void {
  for (const reset of resets) reset();
}
