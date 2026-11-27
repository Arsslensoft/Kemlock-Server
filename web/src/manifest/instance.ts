// The app's manifest keeper: the real API, the real worker, this browser's IndexedDB.
import { createBundlesApi } from '@/api/bundles';
import { createManifestsApi } from '@/api/manifests';
import { createSpacesApi } from '@/api/spaces';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { checkSpaceChain } from '@/features/spaces/chain';
import { bundlePinStore, manifestHooks, spaceDeps } from '@/features/spaces/deps';
import { createBundleHistory } from './bundleHistory';
import { type ManifestKeeper, createManifestKeeper } from './keeper';
import { browserRecordStore } from './records';
import { createSpaceSigner } from './spaceSigner';
import { createWriteChecker } from './writes';

const accountId = () => session.getState().userId;

const spacesApi = createSpacesApi(api);
const spaceSigner = createSpaceSigner({
  spaces: spacesApi,
  crypto: vaultCrypto,
  accountId,
  // A space with a chain is read from the chain the worker verified, as the space page does.
  chain: (space, me) => checkSpaceChain(spaceDeps, space, me),
  trace: { crypto: spaceDeps.crypto, pins: spaceDeps.pins },
});

export const manifestKeeper: ManifestKeeper = createManifestKeeper({
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

// The items a key replacement writes into a space are listed in its manifest like any other write.
manifestHooks.wrote = (items) => manifestKeeper.wrote(items);
manifestHooks.accepted = (spaceId) => manifestKeeper.acceptedManifest(`space:${spaceId}`);
// A key box its sealer signed under a key version they have since replaced is checked against that
// version's bundle, the same way a write is.
manifestHooks.pastBundle = (account, version) => bundleHistory.past(account, version);
// The spaces the account's own signed manifest says have a chain, and the chains this browser met:
// what a server that withholds a chain is held against (manifest/chained.ts).
manifestHooks.chainedSpaces = () => manifestKeeper.chainedSpaces();
manifestHooks.noteChained = (spaceId) => manifestKeeper.noteChained(spaceId);
