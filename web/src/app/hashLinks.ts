// Bitwarden writes the links of its mails with the route in the hash (`/#/accept-organization/?…`).
// The routes of this app are paths, so the three links the server mails (an invitation to an
// organization, an invitation as an emergency contact and the end of a sign-up) are moved from the
// hash into the path before the router starts.
const HASH_LINK = /^#\/(accept-organization|accept-emergency|finish-signup)\/?(\?.*)?$/;

/** The path (with its query) a Bitwarden hash link stands for, or `undefined` for any other hash. */
export function hashLinkToPath(location: { hash: string }): string | undefined {
  const match = HASH_LINK.exec(location.hash);
  if (!match) return undefined;
  return `/${match[1] ?? ''}${match[2] ?? ''}`;
}
