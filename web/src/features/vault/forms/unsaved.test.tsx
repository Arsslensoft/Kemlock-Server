import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { hasUnsavedItemForm, useUnsavedMark } from './unsaved';

function Form() {
  const mark = useUnsavedMark();
  return (
    <div onInput={mark} onChange={mark}>
      <label>
        Name
        <input />
      </label>
    </div>
  );
}

describe('unsaved item forms', () => {
  it('start clean, count as unsaved once the person types, and are clean again when they go', async () => {
    const view = render(<Form />);
    expect(hasUnsavedItemForm()).toBe(false);
    await userEvent.setup().type(screen.getByLabelText('Name'), 'x');
    expect(hasUnsavedItemForm()).toBe(true);
    view.unmount();
    expect(hasUnsavedItemForm()).toBe(false);
  });

  it('hold while any of two forms has input', async () => {
    const user = userEvent.setup();
    const a = render(<Form />);
    const b = render(<Form />);
    await user.type(a.getAllByLabelText('Name')[0] as HTMLElement, 'x');
    await user.type(b.getAllByLabelText('Name')[0] as HTMLElement, 'y');
    a.unmount();
    expect(hasUnsavedItemForm()).toBe(true);
    b.unmount();
    expect(hasUnsavedItemForm()).toBe(false);
  });
});
