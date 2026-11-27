import { describe, expect, it, vi } from 'vitest';
import type { BundleAtDto } from '@/api/bundles';
import { encodeB64, utf8 } from '@/lib/b64url';
import { memoryBundlePinStore } from '@/spaces/anchors';
import { crypto, fakeBundleOf } from '@/test/fake-crypto';
import { createBundleHistory } from './bundleHistory';

const ACCOUNT = '99999999-9999-4999-8999-999999999999';
const WRITER = '55555555-5555-4555-8555-555555555555';

/** What the server serves for a bundle: its bytes and a signature the fake worker accepts. */
const served = (bundle: Uint8Array): BundleAtDto => ({
  keyVersion: 1,
  publicBundle: encodeB64(bundle),
  bundleSignature: encodeB64(utf8('sig')),
});

function setup(answer: (account: string, version: number) => BundleAtDto | null) {
  const pins = memoryBundlePinStore();
  const at = vi.fn(async (account: string, version: number) => answer(account, version));
  const history = createBundleHistory({
    api: { at },
    crypto,
    accountId: () => ACCOUNT,
    pins,
  });
  return { history, pins, at };
}

describe('the bundles an account had before its current key version', () => {
  it('serves the bundle it pinned while that was the current one', async () => {
    const v1 = fakeBundleOf(WRITER, 1);
    const { history, at } = setup((_, version) => (version === 1 ? served(v1) : null));
    await history.pin(v1);
    expect(await history.past(WRITER, 1)).toEqual(v1);
    expect(at).toHaveBeenCalledWith(WRITER, 1);
  });

  it('takes no bundle for a version it never saw vouched, and does not even ask', async () => {
    const { history, at } = setup(() => served(fakeBundleOf(WRITER, 1)));
    expect(await history.past(WRITER, 1)).toBeNull();
    expect(at).not.toHaveBeenCalled();
  });

  it('refuses a bundle the server made up for a pinned version', async () => {
    const real = fakeBundleOf(WRITER, 1);
    // Another account's bundle, another version's, and one whose signature fails.
    const other = fakeBundleOf('66666666-6666-4666-8666-666666666666', 1);
    const wrongVersion = fakeBundleOf(WRITER, 2);
    for (const made of [served(other), served(wrongVersion), { ...served(real), bundleSignature: encodeB64(utf8('forged')) }]) {
      const { history } = setup(() => made);
      await history.pin(real);
      expect(await history.past(WRITER, 1)).toBeNull();
    }
  });

  it('refuses a bundle that is not the pinned one even when it is well formed and signed', async () => {
    const third = fakeBundleOf(WRITER, 3);
    const wrong = setup(() => served(third));
    await wrong.pins.save(ACCOUNT, WRITER, 3, 'not-the-fingerprint');
    expect(await wrong.history.past(WRITER, 3)).toBeNull();

    const right = setup(() => served(third));
    await right.history.pin(third);
    expect(await right.history.past(WRITER, 3)).toEqual(third);
  });

  it('keeps the first pin for a version', async () => {
    const pins = memoryBundlePinStore();
    await pins.save(ACCOUNT, WRITER, 1, 'first');
    await pins.save(ACCOUNT, WRITER, 1, 'second');
    expect(await pins.load(ACCOUNT, WRITER, 1)).toBe('first');
    expect(await pins.load(ACCOUNT, WRITER, 2)).toBeUndefined();
    expect(await pins.load('someone-else', WRITER, 1)).toBeUndefined();
  });

  it('pins once per session when told which versions it already did', async () => {
    const v1 = fakeBundleOf(WRITER, 1);
    const { history, pins } = setup(() => null);
    const save = vi.spyOn(pins, 'save');
    const done = new Set<string>();
    await history.pin(v1, done);
    await history.pin(v1, done);
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('says nothing when nothing can be pinned or read', async () => {
    const { history } = setup(() => null);
    await expect(history.pin(utf8('not a bundle'))).resolves.toBeUndefined();
    expect(await history.past(WRITER, 1)).toBeNull();
    const broken = createBundleHistory({
      api: { at: async () => null },
      crypto,
      accountId: () => ACCOUNT,
      pins: {
        load: async () => {
          throw new Error('unreadable');
        },
        save: async () => {
          throw new Error('unwritable');
        },
      },
    });
    await expect(broken.pin(fakeBundleOf(WRITER, 1))).resolves.toBeUndefined();
    expect(await broken.past(WRITER, 1)).toBeNull();
  });
});
