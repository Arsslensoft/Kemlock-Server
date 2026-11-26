import { api } from '@/app/services';
import { createSpacesApi } from '@/api/spaces';
import { defaultStores } from '@/spaces/anchors';
import { spaceCrypto } from '@/spaces/crypto';
import type { SpaceDeps } from './model';

/** The real clients, for the screens' thin wrappers. Tests build their own `SpaceDeps`. */
// The chains' anchors and the pinned members live in this browser's IndexedDB, in a database of
// their own, each value sealed by the worker under the account's key.
const stores = defaultStores(spaceCrypto);

export const floorStore = stores.floors;

export const spaceDeps: SpaceDeps = {
  api: createSpacesApi(api),
  crypto: spaceCrypto,
  anchors: stores.anchors,
  pins: stores.pins,
};

export { spacesKey } from './refresh';
