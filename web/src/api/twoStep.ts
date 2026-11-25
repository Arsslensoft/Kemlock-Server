// The account's own second steps (crates/kemlock-api-kem/src/routes/two_step.rs): which methods it
// has set up, whether each is on, and whether it holds a recovery code. Never a secret.
import type { Api } from './client';

export type TwoStepMethodName = 'totp' | 'webauthn' | 'email' | 'yubikey' | 'duo';

export interface TwoStepMethodDto {
  method: TwoStepMethodName;
  enabled: boolean;
}

/** `GET /kem/v1/account/two-step`. */
export interface TwoStepListDto {
  methods: TwoStepMethodDto[];
  recoveryCodes: boolean;
}

type Http = Pick<Api, 'request'>;

export function createTwoStepApi(http: Http) {
  return {
    list: () => http.request<TwoStepListDto>({ method: 'GET', path: '/kem/v1/account/two-step' }),
  };
}

export type TwoStepApi = ReturnType<typeof createTwoStepApi>;

/** The names of the methods that are on: a method that was set up and switched off is not asked for. */
export function enabledMethods(list: TwoStepListDto): string[] {
  return list.methods.filter((m) => m.enabled).map((m) => m.method);
}

/** `GET /kem/v1/account/two-step/setup`: what the account set up, never a secret. */
export interface TwoStepSetupDto {
  /** The address codes go to, when the method is on. */
  email: string | null;
  yubikey: { keys: string[]; nfc: boolean } | null;
  duo: { integration: 'own' | 'server'; host: string | null } | null;
  /** Whether this server can mail a code, check a YubiKey OTP, or offers Duo keys of its own. */
  emailOffered: boolean;
  yubikeyOffered: boolean;
  duoServerKeys: boolean;
}

/** One security key: its slot (1 to 5) and the name it was given. */
export interface SecurityKeyDto {
  id: number;
  name: string;
}

/** `GET /kem/v1/account/two-factor/webauthn`, and what each change to the keys answers. */
export interface SecurityKeysDto {
  enabled: boolean;
  keys: SecurityKeyDto[];
}

/** The account's own Duo integration; none of the three means the server's. */
export interface DuoKeysInput {
  host: string;
  clientId: string;
  clientSecret: string;
}

type SetupHttp = Pick<Api, 'request' | 'send'>;

const factor = '/kem/v1/account/two-factor';

/**
 * A fresh proof: a code as typed, or the answer of a security key or passkey to the options of
 * `proofKeyOptions`, which the server takes as `{ webauthn }`.
 */
export type WebauthnProof = { webauthn: Record<string, unknown> };
export type Proof = string | WebauthnProof;

/** A request that turns a method on carries `proof` only when a second step is on already. */
function withProof<T extends object>(body: T, proof: Proof | undefined): T & { proof?: Proof } {
  return proof ? { ...body, proof } : body;
}

/**
 * Setting the other second steps up from a signed-in device
 * (crates/kemlock-api-kem/src/routes/two_step.rs and passkeys.rs). A secret goes only where the
 * server must see it to check it: a Duo key, a YubiKey OTP, a mailed code.
 */
export function createSecondStepsApi(http: SetupHttp) {
  return {
    setup: () => http.request<TwoStepSetupDto>({ method: 'GET', path: '/kem/v1/account/two-step/setup' }),

    emailBegin: (address: string) => http.send({ method: 'POST', path: `${factor}/email`, body: { address } }),
    /** With another second step on, `proof` is the fresh proof a removal takes (see `proofRequest`). */
    emailConfirm: (address: string, code: string, proof?: Proof) =>
      http.send({ method: 'POST', path: `${factor}/email/confirm`, body: withProof({ address, code }, proof) }),
    /** Mails the one-time code that proves the owner, which every turning off takes as `proof`. */
    proofRequest: () => http.send({ method: 'POST', path: `${factor}/proof` }),
    /** The options for answering a fresh proof with a security key or passkey; 404 with none. */
    proofKeyOptions: () =>
      http
        .request<{ options: Record<string, unknown> }>({ method: 'POST', path: `${factor}/proof/webauthn/options` })
        .then((r) => r.options),

    emailOff: (proof: Proof) => http.send({ method: 'DELETE', path: `${factor}/email`, body: { proof } }),

    yubikeySet: (otps: string[], nfc: boolean, proof?: Proof) =>
      http.request<{ keys: string[]; nfc: boolean }>({
        method: 'PUT',
        path: `${factor}/yubikey`,
        body: withProof({ otps, nfc }, proof),
      }),
    yubikeyOff: (proof: Proof) =>
      http.send({ method: 'DELETE', path: `${factor}/yubikey`, body: { proof } }),

    duoSet: (keys: DuoKeysInput | null, proof?: Proof) =>
      http.request<{ integration: 'own' | 'server'; host: string | null }>({
        method: 'PUT',
        path: `${factor}/duo`,
        body: withProof(keys ? { ...keys } : {}, proof),
      }),
    duoOff: (proof: Proof) => http.send({ method: 'DELETE', path: `${factor}/duo`, body: { proof } }),

    securityKeys: () => http.request<SecurityKeysDto>({ method: 'GET', path: `${factor}/webauthn` }),
    securityKeyOptions: () =>
      http
        .request<{ options: Record<string, unknown> }>({ method: 'POST', path: `${factor}/webauthn` })
        .then((r) => r.options),
    securityKeyConfirm: (name: string, credential: Record<string, unknown>, proof?: Proof) =>
      http.request<SecurityKeysDto>({
        method: 'POST',
        path: `${factor}/webauthn/confirm`,
        body: withProof({ name, credential }, proof),
      }),
    securityKeyRemove: (slot: number, proof: Proof) =>
      http.request<SecurityKeysDto>({
        method: 'DELETE',
        path: `${factor}/webauthn/${slot}`,
        body: { proof },
      }),

    /**
     * The account's recovery code, or null when it has none (or has spent it). `proof` is a fresh
     * proof that is not the recovery code itself: a mailed code or an authenticator code.
     */
    recoveryCode: (proof: Proof) =>
      http
        .request<{ code: string | null }>({ method: 'POST', path: `${factor}/recovery-code`, body: { proof } })
        .then((r) => r.code),
  };
}

export type SecondStepsApi = ReturnType<typeof createSecondStepsApi>;
