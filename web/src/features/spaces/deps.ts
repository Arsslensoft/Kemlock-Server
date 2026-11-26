import { api } from '@/app/services';
import { createSpacesApi } from '@/api/spaces';
import { defaultStores } from '@/spaces/anchors';
import { spaceCrypto } from '@/spaces/crypto';
import type { ItemDto } from '@/api/types';
import type { Manifest } from '@/manifest/format';
import type { SpaceDeps } from './model';

/** The real clients, for the screens' thin wrappers. Tests build their own `SpaceDeps`. */
// The chains' anchors and the pinned members live in this browser's IndexedDB, in a database of
// their own, each value sealed by the worker under the account's key.
const stores = defaultStores(spaceCrypto);

/**
 * Where the manifest keeper (src/manifest/instance.ts, which needs these deps) plugs in, so the
 * items a key replacement writes reach the signed manifest without the two files importing each
 * other.
 */
export const manifestHooks: {
  wrote?: (items: ItemDto[]) => Promise<void>;
  accepted?: (spaceId: string) => Promise<Manifest | null>;
} = {};

export const spaceDeps: SpaceDeps = {
  api: createSpacesApi(api),
  crypto: spaceCrypto,
  anchors: stores.anchors,
  pins: stores.pins,
  wrote: (items) => manifestHooks.wrote?.(items) ?? Promise.resolve(),
  acceptedManifest: (spaceId) => manifestHooks.accepted?.(spaceId) ?? Promise.resolve(null),
};

export { spacesKey } from './refresh';
