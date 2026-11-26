import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import type { ManifestDto, PutManifestBody } from '@/api/manifests';
import type { ItemDto } from '@/api/types';
import { CryptoError } from '@/crypto/types';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
import { TOMBSTONE_HASH, type Manifest, ciphertextHash, decodeManifest, encodeManifest } from './format';
import { NO_WARNING, VERIFY_EVERY_MS, createManifestKeeper } from './keeper';
import { memoryRecordStore } from './records';

const ACCOUNT = '99999999-9999-4999-8999-999999999999';
const OWN = `user:${ACCOUNT}`;
const SPACE = 'space:44444444-4444-4444-8444-444444444444';
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const MEMBER = '55555555-5555-4555-8555-555555555555';

/** A kem1 item as the server serves it; the ciphertext is `text`, so its hash is known. */
function item(id: string, revision: number, text = `text-${id}-${revision}`, owner = OWN): ItemDto {
  return {
    id,
    owner,
    kind: 'login',
    format: 'kem1',
    revision,
    keyVersion: 1,
    ciphertext: encodeB64(utf8(text)),
    itemKey: 'a2V5',
    deleted: false,
    ...(owner === SPACE ? { collectionId: C } : {}),
  };
}

const tombstone = (id: string, revision: number, owner = OWN): ItemDto => ({
  id,
  owner,
  kind: 'login',
  format: 'kem1',
  revision,
  keyVersion: 1,
  deleted: true,
});

const hash = (text: string) => ciphertextHash(utf8(text));

beforeEach(() => {
  vi.clearAllMocks();
});

async function listed(id: string, revision: number, text = `text-${id}-${revision}`) {
  return { id, revision, hash: await hash(text), deleted: false };
}
const tomb = (id: string, revision: number) => ({ id, revision, hash: TOMBSTONE_HASH, deleted: true });

/** What the fake worker signs: the signer and the exact bytes, so only that signer's check passes. */
const crypto = {
  manifestSign: vi.fn(async (manifest: Uint8Array) => utf8(`sig:${ACCOUNT}:${encodeB64(manifest)}`)),
  manifestVerifyOwn: vi.fn(
    async (manifest: Uint8Array, signature: Uint8Array) =>
      fromUtf8(signature) === `sig:${ACCOUNT}:${encodeB64(manifest)}`,
  ),
  manifestVerify: vi.fn(
    async (bundle: Uint8Array, manifest: Uint8Array, signature: Uint8Array) =>
      fromUtf8(signature) === `sig:${fromUtf8(bundle)}:${encodeB64(manifest)}`,
  ),
};

/** A manifest as the server serves it, signed by `signer` (the account unless said). */
function served(manifest: Manifest, signer = ACCOUNT, forged = false): ManifestDto {
  const bytes = encodeManifest(manifest);
  return {
    owner: manifest.owner,
    counter: manifest.counter,
    manifest: encodeB64(bytes),
    signature: encodeB64(utf8(forged ? 'forged' : `sig:${signer}:${encodeB64(bytes)}`)),
    signer,
    storedAt: '2026-11-26T10:00:00Z',
  };
}

function setup(
  options: {
    spaceSigner?: (space: string, signer: string) => Promise<Uint8Array | null>;
    spaces?: () => Promise<string[]>;
    maxBytes?: number;
  } = {},
) {
  const stored = new Map<string, ManifestDto>();
  const api = {
    get: vi.fn(async (owner: string): Promise<ManifestDto | null> => stored.get(owner) ?? null),
    put: vi.fn(async (owner: string, body: PutManifestBody): Promise<ManifestDto> => {
      const manifest = decodeManifest(decodeB64(body.manifest));
      const current = stored.get(owner);
      if (!manifest) throw new ApiError(400, { type: 'urn:kemlock:problem:invalid', title: 'invalid', status: 400 });
      if (current && manifest.counter <= current.counter) {
        throw new ApiError(409, {
          type: 'urn:kemlock:problem:stale-manifest',
          title: 'stale',
          status: 409,
          currentCounter: current.counter,
        });
      }
      const dto: ManifestDto = {
        owner,
        counter: manifest.counter,
        manifest: body.manifest,
        signature: body.signature,
        signer: ACCOUNT,
        storedAt: '',
      };
      stored.set(owner, dto);
      return dto;
    }),
  };
  const records = memoryRecordStore();
  const timers: Array<() => void> = [];
  let clock = 1_000_000;
  const keeper = createManifestKeeper({
    api,
    crypto,
    records,
    accountId: () => ACCOUNT,
    spaceSigner: options.spaceSigner ?? (async () => null),
    ...(options.spaces ? { spaces: options.spaces } : {}),
    ...(options.maxBytes ? { maxBytes: options.maxBytes } : {}),
    now: () => clock,
    schedule: (run) => {
      timers.push(run);
      return () => undefined;
    },
  });
  return {
    keeper,
    api,
    stored,
    records,
    timers,
    advance: (ms: number) => {
      clock += ms;
    },
    /** A first sync: what the server serves, then the check. */
    async sync(items: ItemDto[], force = true, opened = true) {
      for (const dto of items) keeper.served(dto, opened);
      keeper.markComplete();
      await keeper.verify(force);
    },
  };
}

const putBody = (api: ReturnType<typeof setup>['api'], call = 0) => {
  const [owner, body] = api.put.mock.calls[call] ?? [];
  return { owner, manifest: decodeManifest(decodeB64((body as PutManifestBody).manifest)) };
};

describe('checking what the server serves against the manifest', () => {
  it('has nothing to say when it matches, and when the server has newer or unlisted items', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 2), await listed(B, 1)] }));
    await run.sync([item(A, 2), item(B, 3), item(C, 1)]);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
    // What was accepted is kept, for the next time.
    expect((await run.records.get(`${ACCOUNT}|${OWN}`))?.counter).toBe(3);
  });

  it('flags an older copy, a missing item and a deleted item that came back', async () => {
    const run = setup();
    run.stored.set(
      OWN,
      served({ owner: OWN, counter: 3, entries: [await listed(A, 3), await listed(B, 2), tomb(C, 4)] }),
    );
    await run.sync([item(A, 2), item(C, 3)]);
    const { manifests, items } = run.keeper.getWarning();
    expect(manifests).toEqual([]);
    expect(items.map(({ id, verdict }) => [id, verdict])).toEqual([
      [A, 'rolled-back'],
      [B, 'missing'],
      [C, 'resurrected'],
    ]);
    expect(items.every((entry) => entry.owner === OWN)).toBe(true);
  });

  it('refuses a lower counter than it has seen, and compares against what it saw', async () => {
    const run = setup();
    await run.records.put(`${ACCOUNT}|${OWN}`, {
      manifest: encodeB64(encodeManifest({ owner: OWN, counter: 5, entries: [await listed(A, 3)] })),
      counter: 5,
      deleted: {},
    });
    // The server serves a genuine but older manifest, which lists nothing newer.
    run.stored.set(OWN, served({ owner: OWN, counter: 4, entries: [await listed(A, 1)] }));
    await run.sync([item(A, 1)]);
    expect(run.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'rolled-back' }]);
    expect(run.keeper.getWarning().items.map(({ id, verdict }) => [id, verdict])).toEqual([[A, 'rolled-back']]);
    expect((await run.records.get(`${ACCOUNT}|${OWN}`))?.counter).toBe(5);
  });

  it('refuses another manifest at the counter it has seen', async () => {
    const run = setup();
    const mine = await listed(A, 3);
    await run.records.put(`${ACCOUNT}|${OWN}`, {
      manifest: encodeB64(encodeManifest({ owner: OWN, counter: 5, entries: [mine] })),
      counter: 5,
      deleted: {},
    });
    run.stored.set(OWN, served({ owner: OWN, counter: 5, entries: [await listed(A, 3, 'another')] }));
    await run.sync([item(A, 3)]);
    expect(run.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'rolled-back' }]);
  });

  it('refuses a manifest the account’s own key did not sign, and one made for another owner', async () => {
    const forged = setup();
    forged.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [] }, ACCOUNT, true));
    await forged.sync([item(A, 1)]);
    expect(forged.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'invalid' }]);
    expect(await forged.records.get(`${ACCOUNT}|${OWN}`)).toBeUndefined();

    const other = setup();
    other.stored.set(OWN, { ...served({ owner: SPACE, counter: 3, entries: [] }), owner: OWN });
    await other.sync([item(A, 1)]);
    expect(other.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'invalid' }]);
    // The account's own key is the only one asked about its own manifest.
    expect(crypto.manifestVerify).not.toHaveBeenCalled();
  });

  it("gives no verdict when the vault has no keys to check with, instead of calling the manifest unverified", async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 3)] }));
    crypto.manifestVerifyOwn.mockRejectedValueOnce(new CryptoError('locked'));
    await run.sync([item(A, 1)]);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
    expect(await run.records.get(`${ACCOUNT}|${OWN}`)).toBeUndefined();
    // And nothing is signed on such a check either.
    crypto.manifestVerifyOwn.mockRejectedValueOnce(new CryptoError('locked'));
    await run.keeper.wrote([item(B, 1)]);
    await run.keeper.flush();
    expect(run.api.put).not.toHaveBeenCalled();
  });

  it('refuses a manifest whose counter is not the one it was served under', async () => {
    const run = setup();
    run.stored.set(OWN, { ...served({ owner: OWN, counter: 3, entries: [] }), counter: 9 });
    await run.sync([]);
    expect(run.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'invalid' }]);
  });

  it('says so when the server has no manifest where it had one', async () => {
    const run = setup();
    await run.records.put(`${ACCOUNT}|${OWN}`, {
      manifest: encodeB64(encodeManifest({ owner: OWN, counter: 2, entries: [await listed(A, 1)] })),
      counter: 2,
      deleted: {},
    });
    await run.sync([item(A, 1)]);
    expect(run.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'dropped' }]);
  });

  it('has nothing to say where there never was a manifest', async () => {
    const run = setup();
    await run.sync([item(A, 1)]);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
  });

  it('remembers ids it saw deleted, so a later answer that brings one back is caught without the manifest saying so', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [tomb(A, 4)] }));
    await run.sync([tombstone(A, 4)]);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
    expect((await run.records.get(`${ACCOUNT}|${OWN}`))?.deleted).toEqual({ [A]: { revision: 4, seenAt: 1_000_000 } });

    // Later the manifest is gone from the list (the server drops the tombstone) and the item is back.
    run.stored.set(OWN, served({ owner: OWN, counter: 4, entries: [] }));
    run.keeper.reset();
    await run.sync([item(A, 3)]);
    expect(run.keeper.getWarning().items.map(({ id, verdict }) => [id, verdict])).toEqual([[A, 'resurrected']]);
  });

  it('flags what the server serves lower than it already served, and tells whoever is watching', async () => {
    const run = setup();
    const heard = vi.fn();
    run.keeper.subscribe(heard);
    for (const dto of [item(A, 3), tombstone(B, 5), item(A, 2), item(B, 4)]) run.keeper.served(dto, true);
    await run.keeper.settled();
    expect(heard).toHaveBeenCalled();
    expect(run.keeper.getWarning().items.map(({ id, verdict }) => [id, verdict])).toEqual([
      [A, 'rolled-back'],
      [B, 'resurrected'],
    ]);
  });

  it('leaves items of another format alone', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 1, entries: [] }));
    await run.sync([{ ...item(A, 1), format: 'bw' }]);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
  });

  it('keeps its last answer when the server can not be reached, and checks again only after a change or a while', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 3)] }));
    await run.sync([item(A, 2)]);
    const found = run.keeper.getWarning();
    expect(found.items).toHaveLength(1);

    // Nothing changed and little time has passed: no new request.
    run.api.get.mockClear();
    await run.keeper.verify();
    expect(run.api.get).not.toHaveBeenCalled();

    // A while later it asks again, and an unreachable server leaves what was found.
    run.advance(VERIFY_EVERY_MS + 1);
    run.api.get.mockRejectedValueOnce(new Error('offline'));
    await run.keeper.verify();
    expect(run.api.get).toHaveBeenCalledTimes(1);
    expect(run.keeper.getWarning()).toEqual(found);
  });

  it('forgets everything on reset', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 3)] }));
    await run.sync([item(A, 2)]);
    expect(run.keeper.getWarning()).not.toBe(NO_WARNING);
    run.keeper.reset();
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
    // And a check before the next sync is whole does nothing.
    run.api.get.mockClear();
    await run.keeper.verify(true);
    expect(run.api.get).not.toHaveBeenCalled();
  });
});

describe('a space’s manifest', () => {
  const SPACE_ID = SPACE.slice('space:'.length);

  it('is checked with the bundle of a signer the space vouches for, and only then', async () => {
    const vouched = vi.fn(async () => utf8(MEMBER));
    const run = setup({ spaceSigner: vouched });
    run.stored.set(SPACE, served({ owner: SPACE, counter: 2, entries: [await listed(A, 2, 'one')] }, MEMBER));
    await run.sync([item(A, 2, 'one', SPACE), item(B, 1, 'other', SPACE)]);
    expect(vouched).toHaveBeenCalledWith(SPACE_ID, MEMBER);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);

    const unvouched = setup({ spaceSigner: async () => null });
    unvouched.stored.set(SPACE, served({ owner: SPACE, counter: 2, entries: [] }, MEMBER));
    await unvouched.sync([item(B, 1, 'other', SPACE)]);
    expect(unvouched.keeper.getWarning().manifests).toEqual([{ owner: SPACE, problem: 'invalid' }]);
  });

  it('flags an item served older than the space manifest lists', async () => {
    const run = setup({ spaceSigner: async () => utf8(MEMBER) });
    run.stored.set(SPACE, served({ owner: SPACE, counter: 2, entries: [await listed(A, 4)] }, MEMBER));
    await run.sync([item(A, 3, 'older', SPACE)]);
    expect(run.keeper.getWarning().items.map(({ owner, id, verdict }) => [owner, id, verdict])).toEqual([
      [SPACE, A, 'rolled-back'],
    ]);
  });

  it('flags an item it lists that the server did not serve, as a space member is sent every envelope', async () => {
    const run = setup({ spaceSigner: async () => utf8(MEMBER) });
    run.stored.set(SPACE, served({ owner: SPACE, counter: 2, entries: [await listed(A, 2, 'one')] }, MEMBER));
    await run.sync([item(B, 1, 'other', SPACE)]);
    expect(run.keeper.getWarning().items.map(({ owner, id, verdict }) => [owner, id, verdict])).toEqual([
      [SPACE, A, 'missing'],
    ]);
  });

  it("is checked for a space whose items the server withheld altogether, from the account's space list", async () => {
    const run = setup({ spaceSigner: async () => utf8(MEMBER), spaces: async () => [SPACE_ID] });
    run.stored.set(SPACE, served({ owner: SPACE, counter: 2, entries: [await listed(A, 2, 'one')] }, MEMBER));
    await run.sync([]);
    expect(run.keeper.getWarning().items.map(({ owner, id, verdict }) => [owner, id, verdict])).toEqual([
      [SPACE, A, 'missing'],
    ]);
    // Without the list, a space that served nothing is not looked at.
    const blind = setup({ spaceSigner: async () => utf8(MEMBER) });
    blind.stored.set(SPACE, served({ owner: SPACE, counter: 2, entries: [await listed(A, 2, 'one')] }, MEMBER));
    await blind.sync([]);
    expect(blind.keeper.getWarning()).toBe(NO_WARNING);
  });

  it('is no manifest dropped when the account has left the space, and one dropped when it has not', async () => {
    const entries = [await listed(A, 2, 'one')];
    const record = {
      manifest: encodeB64(encodeManifest({ owner: SPACE, counter: 2, entries })),
      counter: 2,
      deleted: {},
    };
    // Left: the space is not on the list any more, and the server answers 404 for it.
    const left = setup({ spaceSigner: async () => utf8(MEMBER), spaces: async () => [] });
    await left.records.put(`${ACCOUNT}|${SPACE}`, record);
    await left.sync([item(A, 2, 'one', SPACE)]);
    expect(left.keeper.getWarning()).toBe(NO_WARNING);

    const member = setup({ spaceSigner: async () => utf8(MEMBER), spaces: async () => [SPACE_ID] });
    await member.records.put(`${ACCOUNT}|${SPACE}`, record);
    await member.sync([item(A, 2, 'one', SPACE)]);
    expect(member.keeper.getWarning().manifests).toEqual([{ owner: SPACE, problem: 'dropped' }]);

    // The list could not be read: a 404 says nothing then.
    const blind = setup({
      spaceSigner: async () => utf8(MEMBER),
      spaces: async () => {
        throw new Error('offline');
      },
    });
    await blind.records.put(`${ACCOUNT}|${SPACE}`, record);
    await blind.sync([item(A, 2, 'one', SPACE)]);
    expect(blind.keeper.getWarning()).toBe(NO_WARNING);
  });
});

describe('counters far above what was seen', () => {
  it('are not accepted, whether this browser has a record or not', async () => {
    const fresh = setup();
    fresh.stored.set(OWN, served({ owner: OWN, counter: 2 ** 40, entries: [] }));
    await fresh.sync([]);
    expect(fresh.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'invalid' }]);
    expect(await fresh.records.get(`${ACCOUNT}|${OWN}`)).toBeUndefined();

    const known = setup();
    await known.records.put(`${ACCOUNT}|${OWN}`, {
      manifest: encodeB64(encodeManifest({ owner: OWN, counter: 5, entries: [] })),
      counter: 5,
      deleted: {},
    });
    known.stored.set(OWN, served({ owner: OWN, counter: 5 + 2 ** 32 + 1, entries: [] }));
    await known.sync([]);
    expect(known.keeper.getWarning().manifests).toEqual([{ owner: OWN, problem: 'invalid' }]);
    // One within reach is taken.
    known.stored.set(OWN, served({ owner: OWN, counter: 5 + 2 ** 32, entries: [] }));
    await known.sync([]);
    expect(known.keeper.getWarning()).toBe(NO_WARNING);
  });

  it('are not adopted from a 409 either: nothing is signed above a made-up counter', async () => {
    const run = setup();
    run.api.put.mockRejectedValue(
      new ApiError(409, {
        type: 'urn:kemlock:problem:stale-manifest',
        title: 'stale',
        status: 409,
        currentCounter: 2 ** 50,
      }),
    );
    await run.sync([]);
    await run.keeper.wrote([item(A, 1)]);
    await run.keeper.flush();
    expect(run.api.put).toHaveBeenCalledTimes(1);
  });
});

describe('signing the next manifest after this browser writes', () => {
  it('takes in what was written, one counter above the highest known, and keeps the record', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 1, 'old')] }));
    await run.sync([item(A, 1, 'old')]);

    await run.keeper.wrote([item(A, 2, 'new'), item(B, 1, 'fresh')]);
    expect(run.timers).toHaveLength(1);
    await run.keeper.flush();

    expect(run.api.put).toHaveBeenCalledTimes(1);
    const { owner, manifest } = putBody(run.api);
    expect(owner).toBe(OWN);
    expect(manifest?.counter).toBe(4);
    expect(manifest?.owner).toBe(OWN);
    expect(manifest?.entries).toEqual([
      { id: A, revision: 2, hash: await hash('new'), deleted: false },
      { id: B, revision: 1, hash: await hash('fresh'), deleted: false },
    ]);
    expect(crypto.manifestSign).toHaveBeenCalled();
    expect((await run.records.get(`${ACCOUNT}|${OWN}`))?.counter).toBe(4);

    // Written again, the counter goes up by one more.
    await run.keeper.wrote([tombstone(B, 2)]);
    await run.keeper.flush();
    expect(putBody(run.api, 1).manifest?.counter).toBe(5);
    expect(putBody(run.api, 1).manifest?.entries.find((entry) => entry.id === B)).toEqual(tomb(B, 2));
  });

  it('signs a first manifest at counter 1', async () => {
    const run = setup();
    await run.sync([]);
    await run.keeper.wrote([item(A, 1)]);
    await run.keeper.flush();
    expect(putBody(run.api).manifest?.counter).toBe(1);
  });

  it('never signs in a rollback, a hidden item or a resurrection', async () => {
    const run = setup();
    run.stored.set(
      OWN,
      served({
        owner: OWN,
        counter: 6,
        entries: [await listed(A, 3), await listed(B, 2), tomb(C, 4)],
      }),
    );
    // A served older, B not served, C served live again: three things wrong; then a write of D.
    await run.sync([item(A, 2), item(C, 3)]);
    expect(run.keeper.getWarning().items).toHaveLength(3);
    await run.keeper.wrote([item('44444444-4444-4444-8444-444444444444', 1)]);
    await run.keeper.flush();

    const entries = putBody(run.api).manifest?.entries ?? [];
    expect(entries.find((entry) => entry.id === A)).toEqual(await listed(A, 3));
    expect(entries.find((entry) => entry.id === B)).toEqual(await listed(B, 2));
    expect(entries.find((entry) => entry.id === C)).toEqual(tomb(C, 4));
    expect(entries).toHaveLength(4);
  });

  it('goes above the counter the server says it holds when it answers 409', async () => {
    const run = setup();
    // The server holds a manifest this browser can not verify, at a high counter.
    run.stored.set(OWN, served({ owner: OWN, counter: 9, entries: [] }, ACCOUNT, true));
    await run.sync([]);
    await run.keeper.wrote([item(A, 1)]);
    await run.keeper.flush();
    expect(run.api.put).toHaveBeenCalledTimes(2);
    expect(putBody(run.api, 0).manifest?.counter).toBe(1);
    expect(putBody(run.api, 1).manifest?.counter).toBe(10);
    expect(run.stored.get(OWN)?.counter).toBe(10);
  });

  it("never signs by itself after a sync, however much it found the manifest lacked", async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 1)] }));
    await run.sync([item(A, 1), item(B, 2)]);
    expect(run.timers).toHaveLength(0);
    await run.keeper.flush();
    expect(run.api.put).not.toHaveBeenCalled();
    // Only a write of this browser's own does, and it takes the other item in with it.
    await run.keeper.wrote([item(C, 1)]);
    await run.keeper.flush();
    expect(putBody(run.api).manifest?.counter).toBe(4);
    expect(putBody(run.api).manifest?.entries.map((entry) => entry.id)).toEqual([A, B, C]);
  });

  it("takes in only items whose envelope opened, so junk at a huge revision is not signed", async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 1)] }));
    run.keeper.served(item(A, 1), true);
    run.keeper.served(item(B, 9_000_000_000), false);
    run.keeper.served(item(C, 2), true);
    run.keeper.markComplete();
    await run.keeper.verify(true);
    await run.keeper.wrote([item('44444444-4444-4444-8444-444444444444', 1)]);
    await run.keeper.flush();
    const ids = putBody(run.api).manifest?.entries.map((entry) => entry.id);
    expect(ids).toEqual([A, C, '44444444-4444-4444-8444-444444444444']);
  });

  it("flags a tombstone the server served for an item the manifest lists live, and never signs it in", async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 2), await listed(B, 1)] }));
    // A fake deletion one revision above the entry, which looks like any other device's.
    await run.sync([tombstone(A, 3), item(B, 1)]);
    expect(run.keeper.getWarning().items.map(({ id, verdict }) => [id, verdict])).toEqual([[A, 'deleted']]);
    await run.keeper.wrote([item(C, 1)]);
    await run.keeper.flush();
    const entries = putBody(run.api).manifest?.entries ?? [];
    expect(entries.find((entry) => entry.id === A)).toEqual(await listed(A, 2));
  });

  it("signs in a deletion this browser wrote, and does not flag it", async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 2)] }));
    await run.sync([item(A, 2)]);
    await run.keeper.wrote([tombstone(A, 3)]);
    await run.keeper.flush();
    expect(putBody(run.api).manifest?.entries).toEqual([tomb(A, 3)]);
    // The server serves that tombstone back on the next sync; the manifest now lists it.
    await run.sync([tombstone(A, 3)]);
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
  });

  it("does not sign in a tombstone for an item it never saw, which only bloats the manifest", async () => {
    const run = setup();
    await run.sync([tombstone(A, 7)]);
    await run.keeper.wrote([item(B, 1)]);
    await run.keeper.flush();
    expect(putBody(run.api).manifest?.entries.map((entry) => entry.id)).toEqual([B]);
  });

  it("flags a revision no run of writes could have reached, and does not sign it", async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 2)] }));
    await run.sync([tombstone(A, 2 ** 33)]);
    expect(run.keeper.getWarning().items.map(({ id, verdict }) => [id, verdict])).toEqual([[A, 'implausible']]);
    await run.keeper.wrote([item(C, 1)]);
    await run.keeper.flush();
    expect(putBody(run.api).manifest?.entries.find((entry) => entry.id === A)).toEqual(await listed(A, 2));
  });

  it("does not let the person's own write sign in a resurrection", async () => {
    const run = setup();
    // This browser saw A deleted at revision 4; the manifest has since dropped the tombstone.
    await run.records.put(`${ACCOUNT}|${OWN}`, {
      manifest: encodeB64(encodeManifest({ owner: OWN, counter: 5, entries: [await listed(B, 1)] })),
      counter: 5,
      deleted: { [A]: { revision: 4, seenAt: 1_000_000 } },
    });
    run.stored.set(OWN, served({ owner: OWN, counter: 5, entries: [await listed(B, 1)] }));
    // The server serves A live again at revision 3, and the person edits it, writing revision 4.
    await run.sync([item(A, 3), item(B, 1)]);
    expect(run.keeper.getWarning().items.map(({ id, verdict }) => [id, verdict])).toEqual([[A, 'resurrected']]);
    await run.keeper.wrote([item(A, 4)]);
    await run.keeper.flush();
    expect(run.api.put).not.toHaveBeenCalled();
    // And an unrelated write does not take it in either.
    await run.keeper.wrote([item(C, 1)]);
    await run.keeper.flush();
    expect(putBody(run.api).manifest?.entries.map((entry) => entry.id)).toEqual([B, C]);
  });

  it('signs nothing when there is nothing new', async () => {
    const run = setup();
    run.stored.set(OWN, served({ owner: OWN, counter: 3, entries: [await listed(A, 2)] }));
    await run.sync([item(A, 2)]);
    await run.keeper.wrote([item(A, 2)]);
    await run.keeper.flush();
    expect(run.api.put).not.toHaveBeenCalled();
  });

  it('writes a space manifest too, and stops asking once the server says this account may not', async () => {
    const run = setup({ spaceSigner: async () => utf8(MEMBER) });
    run.api.put.mockImplementation(async () => {
      throw new ApiError(403, { type: 'urn:kemlock:problem:forbidden', title: 'no', status: 403 });
    });
    await run.sync([]);
    await run.keeper.wrote([item(A, 1, 'x', SPACE)]);
    await run.keeper.flush();
    expect(run.api.put).toHaveBeenCalledTimes(1);
    expect(putBody(run.api).owner).toBe(SPACE);
    // Not being allowed to write a space's manifest is no failure to show.
    expect(run.keeper.getWarning().publishFailed).toBe(false);
    await run.keeper.wrote([item(A, 2, 'y', SPACE)]);
    await run.keeper.flush();
    expect(run.api.put).toHaveBeenCalledTimes(1);
  });

  it("shows a manifest it could not store, and stops showing it once one is", async () => {
    const run = setup();
    await run.sync([]);
    run.api.put.mockRejectedValueOnce(new Error('offline'));
    await run.keeper.wrote([item(A, 1)]);
    await run.keeper.flush();
    expect(run.keeper.getWarning()).toEqual({ manifests: [], items: [], publishFailed: true });
    await run.keeper.wrote([item(B, 1)]);
    await run.keeper.flush();
    expect(run.keeper.getWarning()).toBe(NO_WARNING);
  });

  it("shows a manifest too big for the server, and sends nothing", async () => {
    const run = setup({ maxBytes: 100 });
    await run.sync([]);
    await run.keeper.wrote([item(A, 1)]);
    await run.keeper.flush();
    expect(run.api.put).not.toHaveBeenCalled();
    expect(run.keeper.getWarning().publishFailed).toBe(true);
  });

  it('drops what it planned when the vault locks', async () => {
    const run = setup();
    await run.sync([]);
    await run.keeper.wrote([item(A, 1)]);
    run.keeper.reset();
    await run.keeper.flush();
    expect(run.api.put).not.toHaveBeenCalled();
  });
});

describe('the last manifest that is good', () => {
  it('is the one the server serves when it verifies', async () => {
    const run = setup({ spaceSigner: async () => utf8(MEMBER) });
    const manifest = { owner: SPACE, counter: 4, entries: [await listed(A, 2)] };
    run.stored.set(SPACE, served(manifest, MEMBER));
    expect(await run.keeper.acceptedManifest(SPACE)).toEqual(manifest);
  });

  it('is none when the server serves none, a forged one or a lower counter than this browser has seen', async () => {
    const run = setup({ spaceSigner: async () => utf8(MEMBER) });
    expect(await run.keeper.acceptedManifest(SPACE)).toBeNull();
    run.stored.set(SPACE, served({ owner: SPACE, counter: 4, entries: [] }, MEMBER, true));
    expect(await run.keeper.acceptedManifest(SPACE)).toBeNull();
    run.stored.set(SPACE, served({ owner: SPACE, counter: 4, entries: [] }, MEMBER));
    expect(await run.keeper.acceptedManifest(SPACE)).not.toBeNull();
    // Seen at 4, now served at 3: rolled back.
    await run.records.put(`${ACCOUNT}|${SPACE}`, {
      manifest: encodeB64(encodeManifest({ owner: SPACE, counter: 4, entries: [] })),
      counter: 4,
      deleted: {},
    });
    run.stored.set(SPACE, served({ owner: SPACE, counter: 3, entries: [] }, MEMBER));
    expect(await run.keeper.acceptedManifest(SPACE)).toBeNull();
  });

  it('is none for a signer the space does not vouch for', async () => {
    const run = setup({ spaceSigner: async () => null });
    run.stored.set(SPACE, served({ owner: SPACE, counter: 4, entries: [] }, MEMBER));
    expect(await run.keeper.acceptedManifest(SPACE)).toBeNull();
  });
});

describe('after the account rotated its keys', () => {
  it('signs the next manifest with the new key, listing the re-encrypted items, and the check then passes', async () => {
    const run = setup();
    // The manifest the server holds was signed by the key the account had before the rotation: this
    // browser accepted it then, but the new key does not verify it.
    const old = { owner: OWN, counter: 3, entries: [await listed(A, 1, 'old-a'), await listed(B, 3, 'old-b')] };
    run.stored.set(OWN, served(old, 'the-old-key'));
    await run.records.put(`${ACCOUNT}|${OWN}`, {
      manifest: encodeB64(encodeManifest(old)),
      counter: 3,
      deleted: {},
    });

    // The rotation re-encrypted both items at the next revision; the page tells the keeper.
    const moved = [item(A, 2, 'new-a'), item(B, 4, 'new-b')];
    await run.keeper.wrote(moved);
    await run.keeper.flush();

    expect(run.api.put).toHaveBeenCalledTimes(1);
    const { manifest } = putBody(run.api);
    expect(manifest?.counter).toBe(4);
    expect(manifest?.entries).toEqual([
      { id: A, revision: 2, hash: await hash('new-a'), deleted: false },
      { id: B, revision: 4, hash: await hash('new-b'), deleted: false },
    ]);

    // The next sync serves the re-encrypted items, and the manifest the new key signed matches.
    await run.sync(moved);
    expect(run.keeper.getWarning()).toEqual(NO_WARNING);
  });
});
