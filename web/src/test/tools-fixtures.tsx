// Shared by the tools' tests: vault items made by hand, and a render that supplies the router the
// views' links need.
import {
  RouterProvider,
  createMemoryHistory,
  createRootRoute,
  createRouter,
} from '@tanstack/react-router';
import { render } from '@testing-library/react';
import { act } from 'react';
import type { ReactElement } from 'react';
import type { ItemData, VaultItem } from '@/features/vault/vault';
import { I18nProvider } from '@/i18n';

export const ME = 'user:00000000-0000-4000-8000-0000000000aa';
export const SPACE = 'space:00000000-0000-4000-8000-0000000000bb';

let counter = 0;

/** A vault item with the given plaintext. Ids count up so a test reads them in order. */
export function vaultItem(
  kind: string,
  data: ItemData | null,
  extra: Partial<Pick<VaultItem, 'id' | 'owner' | 'revision'>> = {},
): VaultItem {
  counter += 1;
  return {
    id: extra.id ?? `00000000-0000-4000-8000-${String(counter).padStart(12, '0')}`,
    owner: extra.owner ?? ME,
    kind,
    revision: extra.revision ?? 1,
    keyVersion: 1,
    data,
    sizes: { ciphertext: 10, itemKey: 10 },
  };
}

export function login(
  name: string,
  username: string,
  password: string,
  urls: string[],
  more: ItemData = {},
  extra: Partial<Pick<VaultItem, 'id' | 'owner' | 'revision'>> = {},
): VaultItem {
  return vaultItem('login', { name, username, password, urls, ...more }, extra);
}

/** Renders `ui` as the only route of a memory router, inside the message provider. */
export async function renderInRouter(ui: ReactElement) {
  const root = createRootRoute({ component: () => ui });
  const router = createRouter({
    routeTree: root,
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });
  await router.load();
  let view!: ReturnType<typeof render>;
  await act(async () => {
    view = render(
      <I18nProvider>
        <RouterProvider router={router} />
      </I18nProvider>,
    );
  });
  return view;
}
