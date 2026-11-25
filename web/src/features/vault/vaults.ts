// The vaults an item can be in, named for the Vault column and the Vault filter: "Personal" and
// each space by its name. The names come from the space list (opened in the worker); a space whose
// name can't be opened yet is "A space".
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { useT } from '@/i18n';
import { spaceDeps, spacesKey } from '@/features/spaces/deps';
import { loadSpaceList } from '@/features/spaces/model';
import { PERSONAL, vaultIdOf } from './listFilters';
import type { VaultItem } from './vault';

export interface VaultOption {
  /** `personal` or the space's id: what the filter stores. */
  id: string;
  label: string;
}

export interface SpaceName {
  id: string;
  name: string | null;
  state: string;
}

export interface VaultWords {
  personal: string;
  space: string;
}

/**
 * Personal first, then every space the person belongs to (or has an item in) by name. A space with
 * no readable name is called `words.space`.
 */
export function vaultOptions(
  spaces: readonly SpaceName[],
  items: readonly Pick<VaultItem, 'owner'>[],
  words: VaultWords,
): VaultOption[] {
  const named = new Map<string, string>();
  for (const space of spaces) {
    if (space.state === 'confirmed' || space.state === 'accepted') {
      named.set(space.id, space.name ?? words.space);
    }
  }
  // An item of a space the list doesn't give (still loading, or left) still has somewhere to be.
  for (const item of items) {
    const id = vaultIdOf(item.owner);
    if (id !== PERSONAL && !named.has(id)) {
      named.set(id, spaces.find((space) => space.id === id)?.name ?? words.space);
    }
  }
  const spacesSorted = [...named].sort((a, b) => a[1].localeCompare(b[1]) || a[0].localeCompare(b[0]));
  return [
    { id: PERSONAL, label: words.personal },
    ...spacesSorted.map(([id, label]) => ({ id, label })),
  ];
}

/** The name of the vault an owner is: "Personal" or the space's name. */
export function vaultLabel(owner: string, options: readonly VaultOption[], words: VaultWords): string {
  const id = vaultIdOf(owner);
  return options.find((option) => option.id === id)?.label ?? (id === PERSONAL ? words.personal : words.space);
}

export interface Vaults {
  options: VaultOption[];
  /** The vault of an item's owner, by name. */
  labelOf: (owner: string) => string;
}

/** The vaults for `items`, with the space names from the space list. */
export function useVaults(items: readonly Pick<VaultItem, 'owner'>[]): Vaults {
  const t = useT();
  const spaces = useQuery({
    queryKey: spacesKey,
    queryFn: () => loadSpaceList(spaceDeps),
    staleTime: 60_000,
  });
  const personal = t('lists.vault.personal');
  const space = t('lists.vault.space');
  const rows = spaces.data;
  return useMemo(() => {
    const words = { personal, space };
    const options = vaultOptions(rows ?? [], items, words);
    return { options, labelOf: (owner) => vaultLabel(owner, options, words) };
  }, [rows, items, personal, space]);
}
