// The app's manifest keeper: the real API, the real worker, this browser's IndexedDB.
import { createManifestsApi } from '@/api/manifests';
import { createSpacesApi } from '@/api/spaces';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { createManifestKeeper } from './keeper';
import { createWriteChecker } from './writes';
import { browserRecordStore } from './records';
import { createSpaceSigner } from './spaceSigner';

const accountId = () => session.getState().userId;

const spacesApi = createSpacesApi(api);
const spaceSigner = createSpaceSigner({ spaces: spacesApi, crypto: vaultCrypto, accountId });

export const manifestKeeper = createManifestKeeper({
  api: createManifestsApi(api),
  crypto: vaultCrypto,
  records: browserRecordStore(typeof indexedDB === 'undefined' ? undefined : indexedDB),
  accountId,
  spaceSigner,
  // The spaces the account is a confirmed member of: what is checked, and where a 404 means "left".
  spaces: async () =>
    (await spacesApi.list()).filter((entry) => entry.member.state === 'confirmed').map((entry) => entry.space.id),
});

// The write signature of each item the server serves (docs/crypto.md, "Signed item writes"): the
// account's own key for its own vault, the space's vouched member for a space.
export const writeChecker = createWriteChecker({ crypto: vaultCrypto, accountId, spaceSigner });
