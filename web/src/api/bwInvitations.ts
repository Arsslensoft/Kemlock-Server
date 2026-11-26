// The Bitwarden API's accept routes, called with the signed token of a mailed link and no sign-in:
// an account made in a Bitwarden app has no way into this web vault, and the token is the proof.
// The answers are Vaultwarden-shaped (`{ message }`), not problem documents, so this reads them
// itself rather than through the Kemlock client.

export type Accepted = { ok: true } | { ok: false; message: string };

async function post(path: string, token: string): Promise<Accepted> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    });
  } catch {
    return { ok: false, message: '' };
  }
  if (response.ok) return { ok: true };
  let message = '';
  try {
    const body = (await response.json()) as { message?: unknown; Message?: unknown };
    const text = body.message ?? body.Message;
    if (typeof text === 'string') message = text;
  } catch {
    // An answer with no body: the status says enough.
  }
  return { ok: false, message };
}

const part = encodeURIComponent;

export const bwInvitations = {
  /** `POST /api/organizations/{org}/users/{member}/accept` */
  acceptOrganization: (organization: string, member: string, token: string) =>
    post(`/api/organizations/${part(organization)}/users/${part(member)}/accept`, token),
  /** `POST /api/emergency-access/{id}/accept` */
  acceptEmergency: (id: string, token: string) => post(`/api/emergency-access/${part(id)}/accept`, token),
};
