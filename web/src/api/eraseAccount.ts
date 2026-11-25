// Deleting the account (`DELETE /kem/v1/account`, crates/kemlock-api-kem/src/routes/account.rs):
// the body carries a fresh proof, the one turning a second step off takes, instead of the
// password.
import type { Api } from './client';

type Http = Pick<Api, 'send'>;

export function createEraseAccountApi(http: Http) {
  return {
    /** Erases the account, its vault, files, Sends and devices. Refused while it is the only owner of a space with others in it. */
    erase: (proof: string) => http.send({ method: 'DELETE', path: '/kem/v1/account', body: { proof } }),
    /** Mails the one-time code that proves the owner. */
    proofRequest: () => http.send({ method: 'POST', path: '/kem/v1/account/two-factor/proof' }),
  };
}

export type EraseAccountApi = ReturnType<typeof createEraseAccountApi>;
