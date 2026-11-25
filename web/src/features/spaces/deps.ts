import { api } from '@/app/services';
import { createSpacesApi } from '@/api/spaces';
import { spaceCrypto } from '@/spaces/crypto';
import type { SpaceDeps } from './model';

/** The real clients, for the screens' thin wrappers. Tests build their own `SpaceDeps`. */
export const spaceDeps: SpaceDeps = { api: createSpacesApi(api), crypto: spaceCrypto };

export { spacesKey } from './refresh';
