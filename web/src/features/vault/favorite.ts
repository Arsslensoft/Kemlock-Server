import type { VaultItem } from './vault';

/** Logins and notes keep `favorite`; the app's entries (codes, cards, identities) keep `pinned`. */
export function isFavorite(item: VaultItem): boolean {
  return item.data?.favorite === true || item.data?.pinned === true;
}
