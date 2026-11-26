import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeB64 } from '@/lib/b64url';
import { absorbSendLinkFromAddress, forgetSendLink, heldSendLink, subscribeSendLink } from './sendLink';

const ACCESS_ID = encodeB64(new Uint8Array(16).fill(7));
const KEY = 'A'.repeat(43);

beforeEach(() => {
  window.history.replaceState(null, '', '/');
  forgetSendLink();
});
afterEach(() => {
  window.history.replaceState(null, '', '/');
  forgetSendLink();
});

function open(address: string) {
  window.history.replaceState(null, '', address);
}

describe('a Send link in the address', () => {
  it('is taken out of the address bar and held in memory', () => {
    open(`/?x=1#/send/${ACCESS_ID}/${KEY}`);
    absorbSendLinkFromAddress();
    expect(heldSendLink()).toEqual({ link: { accessId: ACCESS_ID, key: KEY } });
    expect(window.location.hash).toBe('');
    expect(window.location.href).not.toContain(KEY);
    expect(window.location.href).not.toContain(ACCESS_ID);
    // The page's own address is kept, query and all.
    expect(window.location.pathname + window.location.search).toBe('/?x=1');
  });

  it('is still held when read again, which a re-render does', () => {
    open(`/#/send/${ACCESS_ID}/${KEY}`);
    absorbSendLinkFromAddress();
    absorbSendLinkFromAddress();
    expect(heldSendLink()?.link?.key).toBe(KEY);
    expect(heldSendLink()).toBe(heldSendLink());
  });

  it('is taken out of the address even when it is not a good link, and opens nothing', () => {
    open(`/#/send/${ACCESS_ID}/short`);
    expect(heldSendLink()).toEqual({ link: null });
    expect(window.location.hash).toBe('');
  });

  it('is let go of when the person goes to a fragment of the app', () => {
    open(`/#/send/${ACCESS_ID}/${KEY}`);
    expect(heldSendLink()).toBeDefined();
    open('/#/something');
    expect(heldSendLink()).toBeUndefined();
  });

  it('holds nothing for an address with no fragment', () => {
    open('/');
    expect(heldSendLink()).toBeUndefined();
  });

  it('does not put the key into the history: the entry is replaced, not added', () => {
    const before = window.history.length;
    open(`/#/send/${ACCESS_ID}/${KEY}`);
    absorbSendLinkFromAddress();
    expect(window.history.length).toBe(before);
  });

  it('survives a browser that refuses to change the address', () => {
    open(`/#/send/${ACCESS_ID}/${KEY}`);
    const spy = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {
      throw new Error('refused');
    });
    expect(() => absorbSendLinkFromAddress()).not.toThrow();
    spy.mockRestore();
    expect(heldSendLink()?.link?.key).toBe(KEY);
  });
});

describe('following the address', () => {
  it('tells a listener when another link is opened in the same page, and takes that one out too', () => {
    const changed = vi.fn();
    const stop = subscribeSendLink(changed);
    const other = encodeB64(new Uint8Array(16).fill(9));
    open(`/#/send/${other}/${KEY}`);
    window.dispatchEvent(new Event('hashchange'));
    expect(changed).toHaveBeenCalledTimes(1);
    expect(heldSendLink()?.link?.accessId).toBe(other);
    expect(window.location.hash).toBe('');
    stop();
    window.dispatchEvent(new Event('hashchange'));
    expect(changed).toHaveBeenCalledTimes(1);
  });
});
