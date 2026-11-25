// The address of a list page: `/vault?kind=<kind id>`, with the search, the page and the favourites
// filter beside it. The sidebar links to these, and so do the type chips of All items.
import { QueryClient } from '@tanstack/react-query';
import { createMemoryHistory } from '@tanstack/react-router';
import { describe, expect, it } from 'vitest';
import { KIND_ORDER } from '@/features/vault/kindList';
import { createAppRouter } from './router';
import { createSession } from './session';

/** A router over a memory history with the vault open, at `entry`. */
async function visit(entry: string) {
  const session = createSession();
  session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false });
  session.unlocked();
  const queryClient = new QueryClient();
  queryClient.setQueryData(['config'], { setup: 'complete' });
  const router = createAppRouter({ queryClient, session }, createMemoryHistory({ initialEntries: [entry] }));
  await router.load();
  const { pathname, search } = router.state.location;
  return { pathname, search: search as Record<string, unknown>, router };
}

describe('the list pages\' address', () => {
  it('is /vault for All items, with no type', async () => {
    const at = await visit('/vault');
    expect(at.pathname).toBe('/vault');
    expect(at.search['kind']).toBeUndefined();
  });

  it.each(KIND_ORDER)('is /vault?kind=%s for that type, kept as it is', async (kind) => {
    const at = await visit(`/vault?kind=${kind}`);
    expect(at.pathname).toBe('/vault');
    expect(at.search['kind']).toBe(kind);
  });

  it('keeps the search, the page and the favourites filter beside the type', async () => {
    const at = await visit('/vault?kind=backup-codes&q=github&page=2&fav=true');
    expect(at.search).toMatchObject({ kind: 'backup-codes', q: 'github', page: 2, fav: true });
  });

  it('drops a page that is not a whole number from one, and a favourites flag that is not one', async () => {
    const at = await visit('/vault?kind=otp&page=0&fav=maybe');
    expect(at.search['kind']).toBe('otp');
    expect(at.search['page']).toBeUndefined();
    expect(at.search['fav']).toBeUndefined();
  });

  it('builds the address of a type from the router, as the sidebar links do', async () => {
    const { router } = await visit('/vault');
    expect(router.buildLocation({ to: '/vault', search: { kind: 'ssh-key' } }).href).toBe('/vault?kind=ssh-key');
    expect(router.buildLocation({ to: '/vault', search: {} }).href).toBe('/vault');
  });

  it('has Trash and Duplicates beside it, each with its own page', async () => {
    expect((await visit('/trash')).pathname).toBe('/trash');
    expect((await visit('/duplicates')).pathname).toBe('/duplicates');
  });
});
