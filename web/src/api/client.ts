// The /kem/v1 client. Hand-written for the routes the server has today (see
// crates/kemlock-api-kem/src/routes); src/api/types.ts holds the wire shapes and
// src/api/wire.check.ts ties them to the generated OpenAPI types.
//
// Every authenticated call carries `Authorization: DPoP <token>` and a proof from the crypto
// worker, whose key the token is bound to. The server's DPoP nonce is remembered from every
// response and retried once on `use-dpop-nonce`; an expired access token is refreshed once.
import { ApiError, NetworkError } from './errors';
import type { Proof } from './twoStep';
import type {
  AccountKeysResponse,
  BatchRequest,
  BatchResponse,
  ConfigResponse,
  ItemDto,
  KdfDto,
  MethodsResponse,
  OpaqueFinishRequest,
  OpaqueStartRequest,
  OpaqueStartResponse,
  PreloginResponse,
  ProblemBody,
  RegisterFinishRequest,
  RegisterFinishResponse,
  RegisterStartRequest,
  RegisterStartResponse,
  SetupVerifyResponse,
  SignInResponse,
  SyncResponse,
  TokenResponse,
  TotpEnrolResponse,
  TwoFactorRequest,
} from './types';

const BASE = '/kem/v1';

/** The server basics `POST /setup/finish` takes: the ones the server has a setting for. */
export interface SetupBasicsBody {
  join: 'invite' | 'domains' | 'anyone';
  joinDomains: string;
  mailHost: string;
  mailPort: string;
  mailSecurity: 'starttls' | 'tls';
  mailFrom: string;
  mailUser: string;
}

export interface Tokens {
  access: string;
  refresh: string;
  /** Milliseconds since the epoch. */
  accessExpiresAt: number;
  refreshExpiresAt: number;
}

export interface TokenStore {
  get(): Tokens | undefined;
  set(tokens: Tokens): void;
  clear(): void;
}

export interface ApiDeps {
  /** The page's origin, which is what a DPoP proof's `htu` names. */
  origin: string;
  tokens: TokenStore;
  /** Signs a DPoP proof (RFC 9449); the crypto client's `dpopProof`. */
  dpop: (htm: string, htu: string, nonce?: string, accessToken?: string) => Promise<string>;
  fetch?: typeof fetch;
  now?: () => number;
  /** Called when the refresh token no longer works: the person has to sign in again. */
  onSessionEnded?: () => void;
}

export type Mode = 'public' | 'proof' | 'auth';

/** A call the feature modules make through `api.request`: authenticated unless it says otherwise. */
export type FeatureCall = Omit<Call, 'mode'> & { mode?: Mode };

export interface Call {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  mode: Mode;
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  headers?: Record<string, string>;
  /** A 304 is an answer, not an error (sync). */
  allowNotModified?: boolean;
}

export type Precondition = { ifMatch: number } | { ifNoneMatch: true };

export interface PutResult {
  item: ItemDto;
  etag: string | null;
}

export type SyncResult =
  | { notModified: true; cursor: string | null }
  | { notModified: false; page: SyncResponse };

export function tokensFromResponse(response: TokenResponse, now: number): Tokens {
  return {
    access: response.accessToken,
    refresh: response.refreshToken,
    accessExpiresAt: now + response.expiresIn * 1000,
    refreshExpiresAt: now + response.refreshExpiresIn * 1000,
  };
}

async function readProblem(res: Response): Promise<ApiError> {
  let problem: ProblemBody | undefined;
  try {
    const parsed: unknown = await res.json();
    if (parsed && typeof parsed === 'object' && 'type' in parsed) problem = parsed as ProblemBody;
  } catch {
    // Not JSON: a proxy's error page. The status is all there is.
  }
  return new ApiError(res.status, problem);
}

export function createApi(deps: ApiDeps) {
  const doFetch = deps.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const now = deps.now ?? (() => Date.now());
  let nonce: string | undefined;
  let refreshing: Promise<Tokens> | undefined;

  async function once(call: Call): Promise<Response> {
    const htu = `${deps.origin}${call.path}`;
    const headers: Record<string, string> = { Accept: 'application/json', ...call.headers };
    // A Uint8Array goes as it is (a file Send's bytes); anything else is JSON.
    const binary = call.body instanceof Uint8Array;
    if (call.body !== undefined && !binary) headers['Content-Type'] = 'application/json';
    if (call.mode === 'auth') {
      const tokens = deps.tokens.get();
      if (!tokens) throw new ApiError(401, undefined, 'Not signed in');
      headers['Authorization'] = `DPoP ${tokens.access}`;
      headers['DPoP'] = await deps.dpop(call.method, htu, nonce, tokens.access);
    } else if (call.mode === 'proof') {
      headers['DPoP'] = await deps.dpop(call.method, htu, nonce);
    }
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(call.query ?? {})) {
      if (value !== undefined) query.set(key, String(value));
    }
    const search = query.toString();
    const url = `${call.path}${search ? `?${search}` : ''}`;
    let res: Response;
    try {
      res = await doFetch(url, {
        method: call.method,
        headers,
        body:
          call.body === undefined
            ? undefined
            : binary
              ? (call.body as BodyInit)
              : JSON.stringify(call.body),
        cache: 'no-store',
        credentials: 'same-origin',
        referrerPolicy: 'no-referrer',
      });
    } catch (cause) {
      throw new NetworkError(cause);
    }
    nonce = res.headers.get('DPoP-Nonce') ?? nonce;
    if (res.ok || (call.allowNotModified && res.status === 304)) return res;
    throw await readProblem(res);
  }

  async function refresh(): Promise<Tokens> {
    refreshing ??= (async () => {
      const current = deps.tokens.get();
      if (!current || current.refreshExpiresAt <= now()) {
        deps.tokens.clear();
        deps.onSessionEnded?.();
        throw new ApiError(401, undefined, 'The session has ended');
      }
      try {
        const res = await run({
          method: 'POST',
          path: `${BASE}/auth/token`,
          mode: 'proof',
          body: { grantType: 'refresh_token', refreshToken: current.refresh },
        });
        const tokens = tokensFromResponse((await res.json()) as TokenResponse, now());
        deps.tokens.set(tokens);
        return tokens;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          deps.tokens.clear();
          deps.onSessionEnded?.();
        }
        throw error;
      }
    })().finally(() => {
      refreshing = undefined;
    });
    return refreshing;
  }

  /** `once`, plus the nonce retry and (for authenticated calls) one token refresh. */
  async function run(call: Call): Promise<Response> {
    if (call.mode === 'auth') {
      const tokens = deps.tokens.get();
      if (tokens && tokens.accessExpiresAt - now() < 15_000) await refresh();
    }
    let refreshed = false;
    let nonceRetried = false;
    for (;;) {
      try {
        return await once(call);
      } catch (error) {
        if (!(error instanceof ApiError)) throw error;
        if (error.slug === 'use-dpop-nonce' && call.mode !== 'public' && !nonceRetried) {
          nonceRetried = true;
          continue;
        }
        // Only an expired token is worth a refresh, not a bad proof or a stale nonce.
        if (
          call.mode === 'auth' &&
          error.status === 401 &&
          error.slug === 'unauthorized' &&
          !refreshed &&
          deps.tokens.get()
        ) {
          refreshed = true;
          await refresh();
          continue;
        }
        throw error;
      }
    }
  }

  async function json<T>(call: Call): Promise<T> {
    const res = await run(call);
    return (await res.json()) as T;
  }

  async function none(call: Call): Promise<void> {
    await run(call);
  }

  const methodsFor = (email: string) =>
    json<MethodsResponse>({
      method: 'POST',
      path: `${BASE}/auth/methods`,
      mode: 'public',
      body: { email },
    });

  return {
    /**
     * The generic calls the feature modules (spaces, devices, Send, the admin console) build their
     * own clients on: `request` reads a JSON answer, `send` ignores the body (a 204), `raw` hands
     * back the Response (a file). Every one carries the DPoP proof and the refresh described above.
     */
    request: <T>(call: FeatureCall) => json<T>({ mode: 'auth', ...call }),
    send: (call: FeatureCall) => none({ mode: 'auth', ...call }),
    raw: (call: FeatureCall) => run({ mode: 'auth', ...call }),

    /** What a client reads before signing in. */
    config: () => json<ConfigResponse>({ method: 'GET', path: `${BASE}/config`, mode: 'public' }),

    /** Trades the setup code from the server's log for a grant to register the first admin. */
    setupVerify: (code: string) =>
      json<SetupVerifyResponse>({
        method: 'POST',
        path: `${BASE}/setup/verify`,
        mode: 'public',
        body: { code },
      }),
    /**
     * Closes setup, for an admin who has confirmed a two-step method. The server basics (who may
     * join, the outgoing mail) go with it and are saved as the admin Settings; the server checks
     * them first, so a bad value leaves setup open.
     */
    setupFinish: (basics?: SetupBasicsBody) =>
      none({
        method: 'POST',
        path: `${BASE}/setup/finish`,
        mode: 'auth',
        ...(basics ? { body: { basics } } : {}),
      }),

    prelogin: async (email: string): Promise<KdfDto> =>
      (
        await json<PreloginResponse>({
          method: 'POST',
          path: `${BASE}/auth/prelogin`,
          mode: 'public',
          body: { email },
        })
      ).kdf,
    methods: async (email: string): Promise<string[]> => (await methodsFor(email)).methods,
    /** The ways in for an email, with the single sign-on provider's name when there is one. */
    methodsInfo: (email: string): Promise<MethodsResponse> => methodsFor(email),

    registerStart: (body: RegisterStartRequest) =>
      json<RegisterStartResponse>({
        method: 'POST',
        path: `${BASE}/accounts/register/start`,
        mode: 'public',
        body,
      }),
    registerFinish: (body: RegisterFinishRequest) =>
      json<RegisterFinishResponse>({
        method: 'POST',
        path: `${BASE}/accounts/register/finish`,
        mode: 'public',
        body,
      }),

    opaqueStart: (body: OpaqueStartRequest) =>
      json<OpaqueStartResponse>({
        method: 'POST',
        path: `${BASE}/auth/opaque/start`,
        mode: 'proof',
        body,
      }),
    /** The last OPAQUE message, with a DPoP proof whose key the new tokens are bound to. */
    opaqueFinish: (body: OpaqueFinishRequest) =>
      json<SignInResponse>({
        method: 'POST',
        path: `${BASE}/auth/opaque/finish`,
        mode: 'proof',
        body,
      }),
    twoFactor: (body: TwoFactorRequest) =>
      json<TokenResponse>({
        method: 'POST',
        path: `${BASE}/auth/two-factor`,
        mode: 'proof',
        body,
      }),
    refresh,

    totpEnrol: () =>
      json<TotpEnrolResponse>({
        method: 'POST',
        path: `${BASE}/account/two-factor/totp`,
        mode: 'auth',
      }),
    /** `proof` is the recovery code, asked for when another second step is on already. */
    totpConfirm: (code: string, proof?: Proof) =>
      none({
        method: 'POST',
        path: `${BASE}/account/two-factor/totp/confirm`,
        mode: 'auth',
        body: proof ? { code, proof } : { code },
      }),

    /** `GET /kem/v1/account/keys`: the wrapped root key and key material, for a browser that did not make the account. */
    accountKeys: () =>
      json<AccountKeysResponse>({ method: 'GET', path: `${BASE}/account/keys`, mode: 'auth' }),

    /** Creates (`ifNoneMatch`), replaces (`ifMatch`) or, with `deleted`, removes one item. */
    putItem: async (item: ItemDto, precondition: Precondition): Promise<PutResult> => {
      const headers: Record<string, string> =
        'ifMatch' in precondition
          ? { 'If-Match': String(precondition.ifMatch) }
          : { 'If-None-Match': '*' };
      const res = await run({
        method: 'PUT',
        path: `${BASE}/items/${item.id}`,
        mode: 'auth',
        body: item,
        headers,
      });
      return { item: (await res.json()) as ItemDto, etag: res.headers.get('ETag') };
    },
    /** Up to 500 puts and deletes, all or none. */
    putBatch: async (request: BatchRequest): Promise<ItemDto[]> =>
      (
        await json<BatchResponse>({
          method: 'POST',
          path: `${BASE}/items:batch`,
          mode: 'auth',
          body: request,
        })
      ).items,

    /** What changed since `since`. Throws `full-sync-required` (410) when the cursor is stale. */
    sync: async (since?: string, limit?: number): Promise<SyncResult> => {
      const res = await run({
        method: 'GET',
        path: `${BASE}/sync`,
        mode: 'auth',
        query: { since, limit },
        allowNotModified: true,
      });
      if (res.status === 304) return { notModified: true, cursor: since ?? null };
      return { notModified: false, page: (await res.json()) as SyncResponse };
    },
  };
}

export type Api = ReturnType<typeof createApi>;
