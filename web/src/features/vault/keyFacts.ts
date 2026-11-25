// What a list can say about a key item without opening it: its fingerprint, and a line to tell it
// apart. Keys keep their halves, not their fingerprint, so it is worked out here (WebCrypto, in this
// browser) from the stored public half, once per item revision. Nothing is logged or sent.
import { useEffect, useMemo, useState } from 'react';
import { certInfo, pgpInfo, sshInfo } from './details/keyInfo';
import type { ItemData, VaultItem } from './vault';

/** The kinds that have a fingerprint. */
export const KEY_KINDS: readonly string[] = ['ssh-key', 'pgp-key', 'certificate'];

export interface KeyFacts {
  /** As the kind prints it: `SHA256:…`, hex in groups of four, or colon-separated hex. */
  fingerprint: string;
  /** An SSH key's algorithm (`ed25519`). */
  algorithm?: string;
  /** A certificate's subject. */
  subject?: string;
  /** When a certificate stops being valid. */
  notAfter?: Date;
  /** A PGP key's first user id. */
  userId?: string;
}

function text(data: ItemData, key: string): string {
  const value = data[key];
  return typeof value === 'string' ? value : '';
}

/** The facts of a key item, or undefined when its halves can't be read. */
export async function keyFactsOf(item: Pick<VaultItem, 'kind' | 'data'>): Promise<KeyFacts | undefined> {
  const data = item.data;
  if (!data) return undefined;
  // An app that keeps the fingerprint itself is believed; the others are worked out.
  const stored = text(data, 'fingerprint');
  if (item.kind === 'ssh-key') {
    const algorithm = text(data, 'algorithm');
    const info = stored === '' ? await sshInfo(algorithm, text(data, 'public')) : undefined;
    const fingerprint = stored || info?.fingerprint;
    return fingerprint ? { fingerprint, ...(algorithm ? { algorithm } : {}) } : undefined;
  }
  if (item.kind === 'pgp-key') {
    const source = text(data, 'public') || text(data, 'private');
    const info = source === '' ? undefined : await pgpInfo(source);
    const fingerprint = stored || info?.fingerprint;
    const userId = info?.userIds[0];
    return fingerprint ? { fingerprint, ...(userId ? { userId } : {}) } : undefined;
  }
  if (item.kind === 'certificate') {
    const info = await certInfo(text(data, 'certificate'));
    const fingerprint = stored || info?.fingerprint;
    if (!fingerprint) return undefined;
    return {
      fingerprint,
      ...(info?.subject ? { subject: info.subject } : {}),
      ...(info?.notAfter ? { notAfter: info.notAfter } : {}),
    };
  }
  return undefined;
}

const cache = new Map<string, Promise<KeyFacts | undefined>>();

function factsFor(item: VaultItem): Promise<KeyFacts | undefined> {
  const key = `${item.id}:${item.revision}`;
  let facts = cache.get(key);
  if (!facts) {
    facts = keyFactsOf(item).catch(() => undefined);
    cache.set(key, facts);
  }
  return facts;
}

/** Forgets the worked-out facts (on lock and sign-out, so no key outlives the session in memory). */
export function forgetKeyFacts(): void {
  cache.clear();
}

/** The facts of every key item in `items`, by item id; keys that aren't read yet are missing. */
export function useKeyFacts(items: readonly VaultItem[]): ReadonlyMap<string, KeyFacts> {
  const keys = useMemo(() => items.filter((item) => KEY_KINDS.includes(item.kind) && item.data !== null), [items]);
  const [facts, setFacts] = useState<ReadonlyMap<string, KeyFacts>>(() => new Map());
  useEffect(() => {
    let live = true;
    void Promise.all(keys.map(async (item) => [item.id, await factsFor(item)] as const)).then((pairs) => {
      if (!live) return;
      const found = new Map<string, KeyFacts>();
      for (const [id, fact] of pairs) if (fact) found.set(id, fact);
      setFacts(found);
    });
    return () => {
      live = false;
    };
  }, [keys]);
  return facts;
}
