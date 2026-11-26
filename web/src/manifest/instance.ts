// The app's manifest keeper: the real API, the real worker, this browser's IndexedDB.
import { createBundlesApi } from '@/api/bundles';
import { createManifestsApi } from '@/api/manifests';
import { createSpacesApi } from '@/api/spaces';
import { api, session } from '@/app/services';
import { bundlePinStore } from '@/features/spaces/deps';
import { vaultCrypto } from '@/crypto-port';
import { createBundleHistory } from './bundleHistory';
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
// A write names the key version it was signed under; one under a version the writer has replaced
// is checked against that version's bundle, from the server's history, when it is the one this
// browser pinned while it was current.
const bundleHistory = createBundleHistory({
  api: createBundlesApi(api),
  crypto: vaultCrypto,
  accountId,
  pins: bundlePinStore,
});

export const writeChecker = createWriteChecker({
  crypto: vaultCrypto,
  accountId,
  spaceSigner,
  history: bundleHistory,
});
