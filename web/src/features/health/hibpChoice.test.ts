import { describe, expect, it } from 'vitest';
import { readHibpChoice, writeHibpChoice, type ChoiceStorage } from './hibpChoice';

function memory(): ChoiceStorage & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => void items.set(key, value),
  };
}

describe('the Pwned Passwords choice', () => {
  it('is undecided until the account answers, so nothing is looked up by default', () => {
    expect(readHibpChoice('account-a', memory())).toBeUndefined();
  });

  it('keeps the answer per account', () => {
    const storage = memory();
    writeHibpChoice('account-a', true, storage);
    writeHibpChoice('account-b', false, storage);
    expect(readHibpChoice('account-a', storage)).toBe(true);
    expect(readHibpChoice('account-b', storage)).toBe(false);
    expect(readHibpChoice('account-c', storage)).toBeUndefined();
  });

  it('does not carry over the old switch, which was on unless turned off', () => {
    const storage = memory();
    storage.setItem('kemlock.health.hibp', 'on');
    expect(readHibpChoice('account-a', storage)).toBeUndefined();
  });

  it('treats an unreadable or unwritable store as undecided and never throws', () => {
    const broken: ChoiceStorage = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
    };
    expect(readHibpChoice('account-a', broken)).toBeUndefined();
    expect(() => writeHibpChoice('account-a', true, broken)).not.toThrow();
    expect(readHibpChoice('account-a', undefined)).toBeUndefined();
  });

  it('reads anything but on and off as undecided', () => {
    const storage = memory();
    storage.setItem('kemlock.health.hibp.account-a', 'yes');
    expect(readHibpChoice('account-a', storage)).toBeUndefined();
  });
});
