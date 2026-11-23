// The import worker: a dedicated Web Worker that loads the import WebAssembly module and answers
// the page's requests (src/import/contract.ts). A file is read and an export written inside this
// worker; nothing of either reaches the server or the page except the batch and the export file.

import { attachImportWorker, createImportDispatcher } from './protocol';
import { loadImportWasm } from './wasm';

attachImportWorker(
  self as unknown as Parameters<typeof attachImportWorker>[0],
  createImportDispatcher({ loadWasm: loadImportWasm }),
);
