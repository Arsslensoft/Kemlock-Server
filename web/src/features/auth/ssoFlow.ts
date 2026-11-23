// Single sign-on from the web vault (crates/kemlock-api-kem/src/routes/sso.rs). No React in here.
//
//   begin:    a PKCE pair and a `state` of our own, `start` with a DPoP proof, then the browser goes
//             to the provider. The verifier waits in sessionStorage: the page is left and loaded again.
//   complete: back at /sign-in/sso with a one-time code, `finish` trades it, the PKCE verifier and
//             a proof of the same DPoP key (kept by the worker across the visit) for tokens.
//
// SSO says who is signing in and never holds a vault key. What opens the vault is for the caller:
// this browser's trusted-device copy (trustedDevice.ts), or another device's approval
// (approvalFlow.ts). An account that SSO has just made has no keys at all: this device makes them
// (enrolKeys.ts).
import type { Api } from '@/api/client';
import { tokensFromResponse } from '@/api/client';
import type { SsoApi } from '@/api/sso';
import type { DeviceDto, TokenResponse } from '@/api/types';
import type { Session } from '@/app/session';
import { encodeB64 } from '@/lib/b64url';
import { rememberDeviceId } from '@/lib/device';

const KEY = 'kemlock.sso';
/** Where the provider's trip ends: a path of this server, which the web vault serves. */
export const SSO_RETURN_PATH = '/sign-in/sso';

interface Stash {
  verifier: string;
  state: string;
  email: string;
  next?: string | undefined;
}

type Area = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

export interface SsoDeps {
  sso: SsoApi;
  api: Pick<Api, 'twoFactor'>;
  session: Session;
  device: () => DeviceDto;
  origin: string;
  storage?: Area;
  now?: () => number;
}

function store(deps: SsoDeps): Area {
  return deps.storage ?? sessionStorage;
}

function randomText(bytes: number): string {
  return encodeB64(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Starts a sign-in: the address to send the browser to. `email` is what the person typed. */
export async function beginSso(deps: SsoDeps, email: string, next?: string): Promise<string> {
  const verifier = randomText(48);
  const challenge = encodeB64(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
  );
  const state = randomText(24);
  const started = await deps.sso.start({
    challenge,
    state,
    redirect: `${deps.origin}${SSO_RETURN_PATH}`,
  });
  const stash: Stash = { verifier, state, email, next };
  store(deps).setItem(KEY, JSON.stringify(stash));
  return started.authorizationUrl;
}

export type SsoOutcome =
  /** Tokens are in, the vault is shut: open it with another device's approval. */
  | { status: 'signed-in'; email: string; admin: boolean; next?: string | undefined }
  /** Kemlock's own second step is owed (the provider did not do multi-factor authentication). */
  | { status: 'second-step'; email: string; methods: string[] }
  /** The sign-in made the account, which has no keys: tokens are in and this device makes them. */
  | { status: 'new-account'; email: string; admin: boolean; next?: string | undefined }
  /** The page was reached with no sign-in of ours behind it, or with another `state`. */
  | { status: 'lost' };

let waiting: { challenge: string; next?: string | undefined } | undefined;

function signedIn(deps: SsoDeps, email: string, tokens: TokenResponse): void {
  const now = deps.now ?? (() => Date.now());
  deps.session.tokenStore.set(tokensFromResponse(tokens, now()));
  rememberDeviceId(tokens.deviceId);
  deps.session.signedIn({
    email,
    userId: tokens.userId,
    deviceId: tokens.deviceId,
    admin: tokens.admin,
  });
}

/** Ends the trip: the code and `state` from the address. A code is good once, so call this once. */
export async function completeSso(
  deps: SsoDeps,
  returned: { code: string; state: string },
): Promise<SsoOutcome> {
  const area = store(deps);
  let stash: Stash;
  try {
    stash = JSON.parse(area.getItem(KEY) ?? '') as Stash;
  } catch {
    return { status: 'lost' };
  }
  area.removeItem(KEY);
  if (!stash.verifier || stash.state !== returned.state) return { status: 'lost' };
  const finished = await deps.sso.finish({
    code: returned.code,
    verifier: stash.verifier,
    device: deps.device(),
  });
  if (finished.status === 'two_factor_required' && finished.challenge) {
    waiting = { challenge: finished.challenge, next: stash.next };
    return { status: 'second-step', email: stash.email, methods: finished.methods ?? ['totp'] };
  }
  if (!finished.tokens) throw new Error('the server answered the sign-in with something unexpected');
  signedIn(deps, stash.email, finished.tokens);
  if (finished.newAccount) {
    return { status: 'new-account', email: stash.email, admin: finished.tokens.admin, next: stash.next };
  }
  return { status: 'signed-in', email: stash.email, admin: finished.tokens.admin, next: stash.next };
}

/** The second step, with a code from the authenticator app. */
export async function secondSsoStep(deps: SsoDeps, email: string, code: string): Promise<SsoOutcome> {
  if (!waiting) throw new Error('there is no sign-in waiting for a code');
  const { challenge, next } = waiting;
  const tokens = await deps.api.twoFactor({ challenge, method: 'totp', code });
  waiting = undefined;
  signedIn(deps, email, tokens);
  return { status: 'signed-in', email, admin: tokens.admin, next };
}
