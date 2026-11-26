// What the item forms are given by the page: the admin's custom fields (fetched), the vault's items,
// which of them this person may change, and how to draw a mention of an item as a link.
import { Link } from '@tanstack/react-router';
import { useMemo } from 'react';
import type { FormEnv } from './forms/env';
import { useCanWrite, useCustomFieldDefinitions, useVault } from './hooks';

export function useItemFormEnv(selfId: string | undefined): FormEnv {
  const { active } = useVault();
  const canWrite = useCanWrite();
  // A server that can't say what its admin set up offers no admin fields; people may still add
  // their own (useCustomFieldDefinitions).
  const definitions = useCustomFieldDefinitions();
  return useMemo<FormEnv>(
    () => ({
      definitions,
      items: active,
      canWrite,
      selfId,
      renderItem: (item, label) => (
        <Link to="/vault/$itemId" params={{ itemId: item.id }}>
          {label}
        </Link>
      ),
    }),
    [active, canWrite, definitions, selfId],
  );
}
