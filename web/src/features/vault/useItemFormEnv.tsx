// What the item forms are given by the page: the admin's custom fields (fetched), the vault's items,
// which of them this person may change, and how to draw a mention of an item as a link.
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { api } from '@/app/services';
import { NO_DEFINITIONS, createCustomFieldsApi } from '@/api/customFields';
import type { FormEnv } from './forms/env';
import { useVault, useWritableCollections } from './hooks';
import type { VaultItem } from './vault';
import { spaceOf } from './vault';

const customFields = createCustomFieldsApi(api);

export const customFieldsKey = ['custom-fields'] as const;

export function useItemFormEnv(selfId: string | undefined): FormEnv {
  const { active } = useVault();
  const collections = useWritableCollections();
  // A server that can't say what its admin set up (an error that isn't a missing route) offers no
  // admin fields; people may still add their own.
  const definitions = useQuery({
    queryKey: customFieldsKey,
    queryFn: () => customFields.list(),
    staleTime: 60_000,
    retry: false,
  });
  return useMemo<FormEnv>(() => {
    const writable = new Set((collections.data ?? []).map((c) => c.collectionId));
    return {
      definitions: definitions.data ?? NO_DEFINITIONS,
      items: active,
      // An item of the person's own vault is theirs to change; one of a space needs a collection they may write.
      canWrite: (item: VaultItem) =>
        spaceOf(item.owner) === null || (item.collectionId !== undefined && writable.has(item.collectionId)),
      selfId,
      renderItem: (item, label) => (
        <Link to="/vault/$itemId" params={{ itemId: item.id }}>
          {label}
        </Link>
      ),
    };
  }, [active, collections.data, definitions.data, selfId]);
}
