// The session's seal over the crypto worker: text in, a base64url blob out, under the tab's own key.
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
import type { TabSealer } from './session';

export function createTabSealer(crypto: Pick<CryptoPort, 'tabSeal' | 'tabOpen' | 'deviceCopyReset'>): TabSealer {
  return {
    async seal(tabId, accountId, deviceId, text) {
      return encodeB64(await crypto.tabSeal(tabId, accountId, deviceId, utf8(text)));
    },
    async open(tabId, accountId, deviceId, sealed) {
      return fromUtf8(await crypto.tabOpen(tabId, accountId, deviceId, decodeB64(sealed)));
    },
    reset: (tabId) => crypto.deviceCopyReset(tabId),
  };
}
