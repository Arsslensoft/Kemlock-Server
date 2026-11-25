import { describe, expect, it } from 'vitest';
import { createViewStore } from './viewState';

function memory(initial?: string) {
  const data = new Map<string, string>();
  if (initial !== undefined) data.set('kemlock.duplicates.view', initial);
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
  };
}

describe('the duplicates view store', () => {
  it('starts from all, with nothing selected', () => {
    expect(createViewStore(memory()).load()).toEqual({ filter: 'all', selectedId: undefined });
  });

  it('gives back what was saved, so going into a group and back keeps the list', () => {
    const storage = memory();
    createViewStore(storage).save({ filter: 'login', selectedId: 'g2' });
    expect(createViewStore(storage).load()).toEqual({ filter: 'login', selectedId: 'g2' });
  });

  it('ignores a filter it does not know and damaged text', () => {
    expect(createViewStore(memory('{"filter":"nope","selectedId":3}')).load()).toEqual({
      filter: 'all',
      selectedId: undefined,
    });
    expect(createViewStore(memory('{not json')).load().filter).toBe('all');
  });

  it('works without storage, or with storage that throws', () => {
    expect(createViewStore(undefined).load().filter).toBe('all');
    const blocked = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
    };
    const store = createViewStore(blocked);
    expect(() => store.save({ filter: 'otp', selectedId: undefined })).not.toThrow();
    expect(store.load().filter).toBe('all');
  });
});
