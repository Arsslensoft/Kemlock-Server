// The one Trusted Types policy, `kemlock` (design: Security, "Trusted Types"). The server sends
// `require-trusted-types-for 'script'; trusted-types kemlock`, so a script URL passed to
// `new Worker(...)` must come from a policy by that name, and a second policy with the same name
// throws. React renders without any sink; the crypto worker's URL is the one exception:
//
//   spawnWorker(workerUrl)      (src/lib/spawn-worker.ts, workerUrl from `./worker.ts?worker&url`)
//
// Anything else that needs a Trusted Types value goes through this file, so there is one policy.

interface PolicyFactory {
  createPolicy(
    name: string,
    rules: { createScriptURL?: (input: string) => string },
  ): { createScriptURL(input: string): unknown };
}

let policy: { createScriptURL(input: string): unknown } | undefined;

/** A script URL the browser accepts under Trusted Types: same origin only. */
export function scriptUrl(url: URL | string): string {
  const factory = (globalThis as { trustedTypes?: PolicyFactory }).trustedTypes;
  if (!factory) return String(url);
  policy ??= factory.createPolicy('kemlock', {
    createScriptURL: (input) => {
      const resolved = new URL(input, globalThis.location.href);
      if (resolved.origin !== globalThis.location.origin) {
        throw new TypeError(`refusing a script from ${resolved.origin}`);
      }
      return resolved.href;
    },
  });
  // The browser's TrustedScriptURL is a string-like object that Worker accepts as is.
  return policy.createScriptURL(String(url)) as string;
}
