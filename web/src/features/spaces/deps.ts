import { api, session } from '@/app/services';
import { createSpacesApi } from '@/api/spaces';
import { defaultStores } from '@/spaces/anchors';
import { defaultBoxStore } from '@/spaces/boxstore';
import { spaceCrypto } from '@/spaces/crypto';
import type { SpaceDeps } from './model';

/** The real clients, for the screens' thin wrappers. Tests build their own `SpaceDeps`. */
// The chains' anchors and the pinned members live in this browser's IndexedDB, in a database of
// their own, each value sealed by the worker under the account's key.
const stores = defaultStores(spaceCrypto);

export const spaceDeps: SpaceDeps = {
  api: createSpacesApi(api),
  crypto: spaceCrypto,
  anchors: stores.anchors,
  pins: stores.pins,
  // The key boxes it accepted, which is how a box sealed before keys were signed is flagged once.
  boxes: defaultBoxStore(spaceCrypto),
  // The account signed in here: what this browser keeps is keyed by it, not by what the server says.
  account: () => session.getState().userId,
};

export { spacesKey } from './refresh';
