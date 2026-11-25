import type { QueryClient } from '@tanstack/react-query';

/** The query key of the space list; one space is ['spaces', id]. */
export const spacesKey = ['spaces'] as const;

/** The collections a new item may be saved to. */
export const writableCollectionsKey = ['writable-collections'] as const;

/**
 * Reads the spaces again after a change to one (every ['spaces', id] is under `spacesKey`), and
 * the writable collections too, so New item's "Where" doesn't offer what is gone.
 */
export async function refreshSpaces(client: QueryClient): Promise<void> {
  await Promise.all([
    client.invalidateQueries({ queryKey: spacesKey }),
    client.invalidateQueries({ queryKey: writableCollectionsKey }),
  ]);
}
