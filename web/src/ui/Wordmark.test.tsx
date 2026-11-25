import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Wordmark } from './Icon';

describe('Wordmark', () => {
  it('is one image named Kemlock', () => {
    render(<Wordmark />);
    expect(screen.getByRole('img', { name: 'Kemlock' })).toBeInTheDocument();
  });

  it('is 28px tall by default and takes a height', () => {
    const { container, rerender } = render(<Wordmark />);
    expect(container.querySelector('svg')).toHaveAttribute('height', '28');
    rerender(<Wordmark height={40} />);
    expect(container.querySelector('svg')).toHaveAttribute('height', '40');
  });

  it('draws both theme variants with gradient ids no other wordmark shares', () => {
    const { container } = render(
      <>
        <Wordmark />
        <Wordmark />
      </>,
    );
    const ids = [...container.querySelectorAll('linearGradient')].map((g) => g.id);
    expect(ids).toHaveLength(4);
    expect(new Set(ids).size).toBe(4);
    for (const id of ids) {
      expect(container.querySelector(`path[fill="url(#${id})"]`)).not.toBeNull();
    }
  });
});
