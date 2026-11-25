// The numbers behind the sidebar: how many items there are, and how many of each kind.

export interface KindCounts {
  /** Every item counted. */
  total: number;
  /** By stored kind id (`login`, `otp`, `backup-codes`…); a kind with none is absent. */
  byKind: Record<string, number>;
}

/**
 * Counts items by kind. A kind this app does not know (an item from a newer app) has a count that
 * nothing shows, but the total still has it.
 */
export function countKinds(items: ReadonlyArray<{ kind: string }>): KindCounts {
  const byKind: Record<string, number> = {};
  for (const item of items) byKind[item.kind] = (byKind[item.kind] ?? 0) + 1;
  return { total: items.length, byKind };
}
