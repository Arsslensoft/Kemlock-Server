import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({
  canGoBack: true,
  back: vi.fn(),
  navigate: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  useCanGoBack: () => state.canGoBack,
  useRouter: () => ({ history: { back: state.back } }),
  useNavigate: () => state.navigate,
}));

import { useBackToList } from './backNav';

describe('useBackToList', () => {
  beforeEach(() => {
    state.back.mockReset();
    state.navigate.mockReset();
  });

  it('steps back in the history when it can, keeping the list as it was', () => {
    state.canGoBack = true;
    renderHook(() => useBackToList()).result.current();
    expect(state.back).toHaveBeenCalledOnce();
    expect(state.navigate).not.toHaveBeenCalled();
  });

  it('goes to the vault when the item was opened with no history', () => {
    state.canGoBack = false;
    renderHook(() => useBackToList()).result.current();
    expect(state.back).not.toHaveBeenCalled();
    expect(state.navigate).toHaveBeenCalledWith({ to: '/vault' });
  });
});
