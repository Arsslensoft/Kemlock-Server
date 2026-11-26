import { api } from '@/app/services';
import { createSpacesApi } from '@/api/spaces';
import { defaultAnchorStore } from '@/spaces/anchors';
import { spaceCrypto } from '@/spaces/crypto';
import type { SpaceDeps } from './model';

/** The real clients, for the screens' thin wrappers. Tests build their own `SpaceDeps`. */
export const spaceDeps: SpaceDeps = {
  api: createSpacesApi(api),
  crypto: spaceCrypto,
  // The chains' anchors live in this browser's IndexedDB, in a database of their own.
  anchors: defaultAnchorStore(),
};

export { spacesKey } from './refresh';
