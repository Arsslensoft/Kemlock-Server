// The small decisions behind the vault shell's header search and sidebar, kept apart from React.

/** What the vault list's address holds: the header search must keep all but `q` and `page`. */
export interface VaultListSearch {
  kind?: string | undefined;
  q?: string | undefined;
  page?: number | undefined;
  fav?: boolean | undefined;
}

/**
 * The list's search after the person types `q` in the header: the filters (`kind`, `fav`) stay, the
 * page starts over, and an empty box removes `q`.
 */
export function withQuery(previous: VaultListSearch, q: string): VaultListSearch {
  const kept = { ...previous };
  delete kept.q;
  delete kept.page;
  return q === '' ? kept : { ...kept, q };
}

/**
 * Whether a sidebar kind link ("All items", "Logins", "Notes") is the page being shown: the list
 * itself, with that kind. The search box (`q`), the page and the favourites filter do not matter.
 */
export function isKindActive(pathname: string, shownKind: unknown, kind: string | undefined): boolean {
  if (pathname !== '/vault') return false;
  return (typeof shownKind === 'string' && shownKind !== '' ? shownKind : undefined) === kind;
}

/**
 * The letters in the avatar: the first letters of the first two words of the name (or of the
 * email's parts when there is no name), else the first two characters.
 */
export function initials(name: string | null, email: string | null): string {
  const source = name?.trim() || email?.trim() || '?';
  const words = source.split(/[\s@.]+/).filter(Boolean);
  const letters = words.length > 1 ? `${words[0]?.[0] ?? ''}${words[1]?.[0] ?? ''}` : source.slice(0, 2);
  return letters.toUpperCase();
}
