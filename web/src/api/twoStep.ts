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
