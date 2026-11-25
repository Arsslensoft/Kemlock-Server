// Deleting the account (`DELETE /kem/v1/account`, crates/kemlock-api-kem/src/routes/account.rs):
// the body carries a fresh OPAQUE login (the password again) and, when the account has a second
// step on, a fresh proof beside it, the one turning a second step off takes.
import type { Api } from './client';

type Http = Pick<Api, 'send'>;

/** The last two messages of a fresh OPAQUE login. */
export interface PasswordProof {
  loginState: string;
  finalization: string;
}

export function createEraseAccountApi(http: Http) {
  return {
    /**
     * Erases the account, its vault, files, Sends and devices. Refused while it is the only owner
     * of a space with others in it, and when a second step is on and `proof` is missing.
     */
    erase: (password: PasswordProof, proof?: string) =>
      http.send({
        method: 'DELETE',
        path: '/kem/v1/account',
        body: proof === undefined ? { ...password } : { ...password, proof },
      }),
    /** Mails the one-time code that proves the owner. */
    proofRequest: () => http.send({ method: 'POST', path: '/kem/v1/account/two-factor/proof' }),
  };
}

export type EraseAccountApi = ReturnType<typeof createEraseAccountApi>;
