// The signed-only flag of an owner (docs/crypto.md, "The signed-only flag";
// crates/kemlock-api-kem/src/routes/items.rs): once on, the server and every server holding the
// owner refuse an unsigned `kem1` write. The account turns it on for its own vault with a request,
// and off again with the password (a fresh login, and a fresh proof beside it when a second step
// is on), as erasing the account does.
import type { Api } from './client';
import type { PasswordProof } from './eraseAccount';

type Http = Pick<Api, 'request' | 'send'>;

export function createOwnerSigningApi(http: Http) {
  const path = (owner: string) => `/kem/v1/owners/${encodeURIComponent(owner)}/signed-writes`;
  return {
    /** Whether `owner` takes signed writes only. */
    required: async (owner: string): Promise<boolean> =>
      (await http.request<{ required: boolean }>({ method: 'GET', path: path(owner) })).required,
    /** Asks that `owner` take signed writes only. Idempotent. */
    require: (owner: string) => http.send({ method: 'PUT', path: path(owner) }),
    /** Takes the flag off, with the password again and, when a second step is on, a fresh proof. */
    clear: (owner: string, password: PasswordProof, proof?: string) =>
      http.send({
        method: 'DELETE',
        path: path(owner),
        body: proof === undefined ? { ...password } : { ...password, proof },
      }),
  };
}

export type OwnerSigningApi = ReturnType<typeof createOwnerSigningApi>;
