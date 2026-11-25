import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api, queryClient } from '@/app/services';
import { afterSignIn } from './afterSignIn';

function fakeRouter() {
  return {
    navigate: vi.fn(async () => undefined),
    history: { push: vi.fn(), replace: vi.fn() },
  };
}
const signedIn = { status: 'signed-in', admin: false } as const;

beforeEach(() => {
  queryClient.clear();
  vi.spyOn(api, 'config').mockResolvedValue({ setup: 'complete' } as never);
});

describe('afterSignIn', () => {
  it('replaces the sign-in with the page asked for, so Back does not return to it', async () => {
    const router = fakeRouter();
    await afterSignIn(router as never, signedIn, '/vault/abc?x=1');
    expect(router.history.replace).toHaveBeenCalledWith('/vault/abc?x=1');
    expect(router.history.push).not.toHaveBeenCalled();
  });

  it('replaces the sign-in with the vault when nothing was asked for, or the address is not ours', async () => {
    for (const next of [undefined, '//evil.example', 'https://evil.example', '/\\evil']) {
      const router = fakeRouter();
      await afterSignIn(router as never, signedIn, next);
      expect(router.navigate).toHaveBeenCalledWith({ to: '/vault', replace: true });
      expect(router.history.replace).not.toHaveBeenCalled();
    }
  });

  it('replaces the sign-in with the unfinished setup step', async () => {
    vi.spyOn(api, 'config').mockResolvedValue({ setup: 'pending' } as never);
    const router = fakeRouter();
    await afterSignIn(router as never, { status: 'signed-in', admin: true }, '/vault');
    expect(router.navigate).toHaveBeenCalledWith({ to: '/setup/two-step', replace: true });
  });
});
