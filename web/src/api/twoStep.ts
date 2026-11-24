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
 * Setting the other second steps up from a signed-in device
 * (crates/kemlock-api-kem/src/routes/two_step.rs and passkeys.rs). A secret goes only where the
 * server must see it to check it: a Duo key, a YubiKey OTP, a mailed code.
 */
export function createSecondStepsApi(http: SetupHttp) {
  return {
    setup: () => http.request<TwoStepSetupDto>({ method: 'GET', path: '/kem/v1/account/two-step/setup' }),

    emailBegin: (address: string) => http.send({ method: 'POST', path: `${factor}/email`, body: { address } }),
    emailConfirm: (address: string, code: string) =>
      http.send({ method: 'POST', path: `${factor}/email/confirm`, body: { address, code } }),
    /** Mails the one-time code that proves the owner, which every turning off takes as `proof`. */
    proofRequest: () => http.send({ method: 'POST', path: `${factor}/proof` }),

    emailOff: (proof: string) => http.send({ method: 'DELETE', path: `${factor}/email`, body: { proof } }),

    yubikeySet: (otps: string[], nfc: boolean) =>
      http.request<{ keys: string[]; nfc: boolean }>({ method: 'PUT', path: `${factor}/yubikey`, body: { otps, nfc } }),
    yubikeyOff: (proof: string) =>
      http.send({ method: 'DELETE', path: `${factor}/yubikey`, body: { proof } }),

    duoSet: (keys: DuoKeysInput | null) =>
      http.request<{ integration: 'own' | 'server'; host: string | null }>({
        method: 'PUT',
        path: `${factor}/duo`,
        body: keys ?? {},
      }),
    duoOff: (proof: string) => http.send({ method: 'DELETE', path: `${factor}/duo`, body: { proof } }),

    securityKeys: () => http.request<SecurityKeysDto>({ method: 'GET', path: `${factor}/webauthn` }),
    securityKeyOptions: () =>
      http
        .request<{ options: Record<string, unknown> }>({ method: 'POST', path: `${factor}/webauthn` })
        .then((r) => r.options),
    securityKeyConfirm: (name: string, credential: Record<string, unknown>) =>
      http.request<SecurityKeysDto>({ method: 'POST', path: `${factor}/webauthn/confirm`, body: { name, credential } }),
    securityKeyRemove: (slot: number, proof: string) =>
      http.request<SecurityKeysDto>({
        method: 'DELETE',
        path: `${factor}/webauthn/${slot}`,
        body: { proof },
      }),

    /** The account's recovery code, or null when it has none (or has spent it). */
    recoveryCode: () =>
      http.request<{ code: string | null }>({ method: 'GET', path: `${factor}/recovery-code` }).then((r) => r.code),
  };
}

export type SecondStepsApi = ReturnType<typeof createSecondStepsApi>;
