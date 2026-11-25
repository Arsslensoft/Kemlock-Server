import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';
import { USERS } from './fixtures';

const users = vi.hoisted(() => vi.fn());
vi.mock('./client', () => ({
  admin: {
    users,
    spaces: () => Promise.resolve({ spaces: [] }),
    invitations: () => Promise.resolve([]),
    stepUpTotp: vi.fn(),
  },
}));

import Users from './Users';

describe('the Users page', () => {
  it('keeps the search box mounted while a new search loads', async () => {
    users.mockImplementation(({ search }: { search?: string }) =>
      search === undefined
        ? Promise.resolve({ users: USERS, total: USERS.length })
        : new Promise((resolve) => setTimeout(() => resolve({ users: [], total: 0 }), 50)),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <I18nProvider>
          <Users />
        </I18nProvider>
      </QueryClientProvider>,
    );
    const box = await screen.findByRole('searchbox');
    const user = userEvent.setup();
    await user.type(box, 'ri');
    expect(screen.getByRole('searchbox')).toBe(box);
    expect(box).toHaveFocus();
    expect(box).toHaveValue('ri');
  });
});
