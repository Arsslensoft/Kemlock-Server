import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { Root } from './Root';
import type { createAppRouter } from './router';

const router = {} as ReturnType<typeof createAppRouter>;

afterEach(() => {
  window.location.hash = '';
});

describe('Root', () => {
  it('shows a spinner, not a blank page, while the session is being restored', () => {
    renderWithIntl(<Root router={router} restored={new Promise(() => undefined)} />);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});
