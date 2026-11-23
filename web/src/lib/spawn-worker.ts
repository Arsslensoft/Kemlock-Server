// Starts a module Worker from a script URL under Trusted Types. The server's CSP has
// `require-trusted-types-for 'script'; trusted-types kemlock`, so `new Worker(url)` with a plain
// string or URL throws: the URL has to come out of the `kemlock` policy (src/lib/trusted-types.ts).
//
// Vite only bundles a worker for the literal `new Worker(new URL(...))` form, which leaves nowhere
// to wrap the URL. The `?worker&url` import is Vite's other documented way in: it bundles the
// worker the same way and hands back its URL as a string, which is wrapped here.
import { scriptUrl } from './trusted-types';

/** A module worker for the script at `url` (a `?worker&url` import), through the policy. */
export function spawnWorker(url: string): Worker {
  // `scriptUrl` returns the browser's TrustedScriptURL (a string where Trusted Types is absent).
  return new Worker(scriptUrl(url), { type: 'module' });
}
