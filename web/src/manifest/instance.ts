// The app's manifest keeper: the real API, the real worker, this browser's IndexedDB.
import { createManifestsApi } from '@/api/manifests';
import { createSpacesApi } from '@/api/spaces';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { checkSpaceChain } from '@/features/spaces/chain';
import { manifestHooks, spaceDeps } from '@/features/spaces/deps';
import { type ManifestKeeper, createManifestKeeper } from './keeper';
import { browserRecordStore } from './records';
import { createSpaceSigner } from './spaceSigner';

const accountId = () => session.getState().userId;

const spacesApi = createSpacesApi(api);

export const manifestKeeper: ManifestKeeper = createManifestKeeper({
  api: createManifestsApi(api),
  crypto: vaultCrypto,
  records: browserRecordStore(typeof indexedDB === 'undefined' ? undefined : indexedDB),
  accountId,
  spaceSigner: createSpaceSigner({
    spaces: spacesApi,
    crypto: vaultCrypto,
    accountId,
    // A space with a chain is read from the chain the worker verified, as the space page does.
    chain: (space, me) => checkSpaceChain(spaceDeps, space, me),
    trace: { crypto: spaceDeps.crypto, pins: spaceDeps.pins },
  }),
  // The spaces the account is a confirmed member of: what is checked, and where a 404 means "left".
  spaces: async () =>
    (await spacesApi.list()).filter((entry) => entry.member.state === 'confirmed').map((entry) => entry.space.id),
});

// The items a key replacement writes into a space are listed in its manifest like any other write.
manifestHooks.wrote = (items) => manifestKeeper.wrote(items);
