// Bitwarden writes the links of its mails with the route in the hash (`/#/accept-organization/?…`).
// The routes of this app are paths, so the three links the server mails (an invitation to an
// organization, an invitation as an emergency contact and the end of a sign-up) are moved from the
// hash into the path before the router starts. What follows the `?` stays in the fragment
// (`/accept-organization#token=…`), never in the query string: a fragment is not sent to the server
// on a reload and is not written in its logs, and the page reads it once and then removes it from
// the address (see `features/invitations/linkParams.ts`).
const HASH_LINK = /^#\/(accept-organization|accept-emergency|finish-signup)\/?(?:\?(.*))?$/;

/**
 * The path (with the link's values as a fragment) a Bitwarden hash link stands for, or `undefined`
 * for any other hash.
 */
export function hashLinkToPath(location: { hash: string }): string | undefined {
  const match = HASH_LINK.exec(location.hash);
  if (!match) return undefined;
  const values = match[2] ?? '';
  return `/${match[1] ?? ''}${values ? `#${values}` : ''}`;
}
