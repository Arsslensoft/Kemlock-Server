import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';
import { TypeLastGroup, lastGroup, typedLastGroup } from './TypeLastGroup';

const FINGERPRINT = '12345 67890 11111 22222 33333 44444 55555 66666 77777 88888 99999 00000';

describe('the last group of a fingerprint', () => {
  it('is the last block of digits', () => {
    expect(lastGroup(FINGERPRINT)).toBe('00000');
    expect(lastGroup('  67890 ')).toBe('67890');
    expect(lastGroup('')).toBe('');
  });

  it('is matched with the spaces left out, and never by an empty fingerprint', () => {
    expect(typedLastGroup(FINGERPRINT, '00000')).toBe(true);
    expect(typedLastGroup(FINGERPRINT, ' 000 00 ')).toBe(true);
    expect(typedLastGroup(FINGERPRINT, '99999')).toBe(false);
    expect(typedLastGroup(FINGERPRINT, '')).toBe(false);
    expect(typedLastGroup('', '')).toBe(false);
  });
});

describe('typing the last group', () => {
  it('reports whether what was typed is right, starting from not', async () => {
    const onMatch = vi.fn();
    render(
      <I18nProvider>
        <TypeLastGroup fingerprint={FINGERPRINT} onMatch={onMatch} />
      </I18nProvider>,
    );
    expect(onMatch).toHaveBeenLastCalledWith(false);
    const box = screen.getByLabelText(/Type the last group of digits/);
    await userEvent.setup().type(box, '00000');
    expect(onMatch).toHaveBeenLastCalledWith(true);
    await userEvent.setup().type(box, '1');
    expect(onMatch).toHaveBeenLastCalledWith(false);
  });
});
