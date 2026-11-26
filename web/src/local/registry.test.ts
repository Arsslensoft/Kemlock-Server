import { afterEach, describe, expect, it, vi } from 'vitest';
import { type LocalStore, registerLocalStore, registeredLocalStores, resealLocalStores } from './registry';

const removers: Array<() => void> = [];
afterEach(() => {
  for (const remove of removers.splice(0)) remove();
});

function register(store: LocalStore): void {
  removers.push(registerLocalStore(store));
}

describe('the stores that keep sealed values', () => {
  it('are all asked to seal their values again, for the account', async () => {
    const seen: string[] = [];
    register({ name: 'one', resealAll: async (account) => void seen.push(`one:${account}`) });
    register({ name: 'two', resealAll: async (account) => void seen.push(`two:${account}`) });
    expect(registeredLocalStores()).toEqual(expect.arrayContaining(['one', 'two']));
    expect(await resealLocalStores('acct', async (_label, sealed) => sealed)).toEqual([]);
    expect(seen).toEqual(expect.arrayContaining(['one:acct', 'two:acct']));
  });

  it('are given the reseal function, so the worker does the sealing', async () => {
    const reseal = vi.fn(async (_label: string, sealed: string) => `new-${sealed}`);
    let answer = '';
    register({ name: 'one', resealAll: async (_account, again) => void (answer = await again('l', 'v')) });
    await resealLocalStores('acct', reseal);
    expect(reseal).toHaveBeenCalledWith('l', 'v');
    expect(answer).toBe('new-v');
  });

  it('do not stop each other when one fails, and the failure is named', async () => {
    const ran = vi.fn();
    register({
      name: 'broken',
      resealAll: async () => {
        throw new Error('indexeddb');
      },
    });
    register({ name: 'fine', resealAll: async () => void ran() });
    expect(await resealLocalStores('acct', async (_l, s) => s)).toEqual(['broken']);
    expect(ran).toHaveBeenCalled();
  });

  it('can be taken out again, and a store of the same name replaces the old one', async () => {
    const first = vi.fn(async () => undefined);
    const second = vi.fn(async () => undefined);
    register({ name: 'same', resealAll: first });
    register({ name: 'same', resealAll: second });
    await resealLocalStores('acct', async (_l, s) => s);
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalled();
    for (const remove of removers.splice(0)) remove();
    expect(registeredLocalStores()).not.toContain('same');
  });
});
