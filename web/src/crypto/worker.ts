// The crypto worker: a dedicated Web Worker that loads the WebAssembly module and answers the
// page's requests. Every key lives in this worker's WebAssembly memory (or, for DPoP, in a
// non-extractable WebCrypto key); React and the rest of the page never read from it.

import { createDeviceWrap } from './devicewrap';
import { createDpop } from './dpop';
import { indexedDbDeviceKeyStore, indexedDbKeyStore, indexedDbTabKeyStore } from './keystore';
import { attachWorker, createDispatcher } from './protocol';
import { loadWasm } from './wasm';

const dispatcher = createDispatcher({
  loadWasm,
  dpop: createDpop({ store: indexedDbKeyStore() }),
  deviceWrap: createDeviceWrap({ store: indexedDbDeviceKeyStore() }),
  tabWrap: (tabId, purpose) =>
    createDeviceWrap({
      store: indexedDbTabKeyStore(tabId),
      label: purpose === 'root' ? 'kemlock/v1/reload-wrap/root' : 'kemlock/v1/reload-wrap/session',
    }),
});

attachWorker(self as unknown as Parameters<typeof attachWorker>[0], dispatcher);
