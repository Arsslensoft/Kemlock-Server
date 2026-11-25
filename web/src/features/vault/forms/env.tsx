// What the item forms need from outside themselves: the admin's custom fields, and the vault's
// items for the "Link an item" picker and for the website a linked login lends a code. The page
// (NewItem) fetches them and provides them; a form rendered alone, as the tests do, sees none.
import { type ReactNode, createContext, useContext } from 'react';
import { type CustomFieldDefinitions, NO_DEFINITIONS } from '@/api/customFields';
import type { VaultItem } from '../vault';

export interface FormEnv {
  definitions: CustomFieldDefinitions;
  /** The items of the vault that are not in the Trash. */
  items: readonly VaultItem[];
  /** Whether this person may change an item, which a link needs of both ends. */
  canWrite: (item: VaultItem) => boolean;
  /** The id of the item being edited; absent while it is new. */
  selfId?: string | undefined;
  /** Draws a mention of an item as a link to its page. The page provides it; alone it is bold text. */
  renderItem: (item: VaultItem, label: ReactNode) => ReactNode;
}

export const EMPTY_ENV: FormEnv = {
  definitions: NO_DEFINITIONS,
  items: [],
  canWrite: () => true,
  renderItem: (_item, label) => <b>{label}</b>,
};

export const FormEnvContext = createContext<FormEnv>(EMPTY_ENV);

export function useFormEnv(): FormEnv {
  return useContext(FormEnvContext);
}
