import { describe, expect, it, vi } from 'vitest';
import { createSession } from './session';

function storage() {
  const data = new Map<string, string>();
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
    removeItem: (key: string) => void data.delete(key),
  };
}

const IN = { email: 'sam@example.org', userId: 'u1', deviceId: 'd1', admin: false, name: 'Sam Rivera' } as const;

describe('renaming', () => {
  it('changes the name the avatar shows and tells the listeners', () => {
    const session = createSession();
    session.signedIn(IN);
    session.unlocked();
    const listener = vi.fn();
    session.subscribe(listener);
    session.renamed('Alex Chen');
    expect(session.getState()).toMatchObject({ name: 'Alex Chen', status: 'unlocked', email: 'sam@example.org' });
    expect(listener).toHaveBeenCalledOnce();
  });

  it('clears the name when it was cleared', () => {
    const session = createSession();
    session.signedIn(IN);
    session.renamed(null);
    expect(session.getState().name).toBeNull();
  });

  it('is kept in the tab for a reload', () => {
    const tab = storage();
    const session = createSession({ storage: tab });
    session.signedIn(IN);
    session.renamed('Alex Chen');
    expect(JSON.parse(tab.getItem('kemlock.session.info') ?? '{}')).toMatchObject({ name: 'Alex Chen' });
  });

  it('does nothing while signed out', () => {
    const session = createSession();
    const listener = vi.fn();
    session.subscribe(listener);
    session.renamed('Alex Chen');
    expect(session.getState().name).toBeNull();
    expect(listener).not.toHaveBeenCalled();
  });
});
