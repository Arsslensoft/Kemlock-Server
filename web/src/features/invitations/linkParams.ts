import { useEffect, useState } from 'react';

/** What a mailed link carries in its fragment; every value is optional so a short link still opens. */
export interface LinkParams {
  organizationId?: string;
  organizationUserId?: string;
  organizationName?: string;
  id?: string;
  name?: string;
  email?: string;
  token?: string;
}

const KEYS = ['organizationId', 'organizationUserId', 'organizationName', 'id', 'name', 'email', 'token'] as const;

/** The values in an address fragment (`#a=b&c=d`). Only the keys a link uses are read. */
export function readLinkParams(hash: string): LinkParams {
  const values = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const params: LinkParams = {};
  for (const key of KEYS) {
    const value = values.get(key);
    if (value) params[key] = value;
  }
  return params;
}

/**
 * The claims in the payload of a link's token, for showing who invited you. Nothing here is
 * verified (the server does that when the token is spent), so it is only ever text on the screen,
 * never a reason to trust the link.
 */
export function tokenClaims(token: string | undefined): Record<string, unknown> {
  const payload = token?.split('.')[1];
  if (!payload) return {};
  try {
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const bytes = Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
    const claims: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return claims && typeof claims === 'object' && !Array.isArray(claims) ? (claims as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** A claim as text, or `undefined` when it is missing or not a short string. */
export function claimText(claims: Record<string, unknown>, key: string): string | undefined {
  const value = claims[key];
  return typeof value === 'string' && value.length > 0 && value.length <= 200 ? value : undefined;
}

/** Takes the values and the token out of the address bar and out of the history entry. */
export function scrubAddress(): void {
  try {
    const { pathname } = window.location;
    // The state object stays: the router keeps its history index in it.
    window.history.replaceState(window.history.state, '', pathname);
  } catch {
    // A frame or an old browser that refuses: the address keeps what it had.
  }
}

// React may run the initializer of a state twice (StrictMode). The first run cleans the address, so
// it leaves what it read here for the second.
let held: LinkParams | undefined;

/**
 * The values of this page's link, read once from the fragment. The address is cleaned in the same
 * step, so the token is in the page's memory only: it is not in the history, in a bookmark or in a
 * reload. The page that spends the token does so on a button press, never on load.
 */
export function useLinkParams(): LinkParams {
  const [params] = useState<LinkParams>(() => {
    if (window.location.hash) {
      held = readLinkParams(window.location.hash);
      scrubAddress();
    }
    return held ?? {};
  });
  useEffect(
    () => () => {
      held = undefined;
    },
    [],
  );
  return params;
}
