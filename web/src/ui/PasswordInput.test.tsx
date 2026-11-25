import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useForm } from 'react-hook-form';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { PasswordInput } from './PasswordInput';
import { Field } from './fields';

function Wrapped({ disabled }: { disabled?: boolean }) {
  const { control } = useForm<{ password: string }>({ defaultValues: { password: 'hunter2' } });
  return <Field control={control} name="password" label="Master password" type="password" disabled={disabled} />;
}

describe('PasswordInput', () => {
  it('hides the password and shows it again from the eye', async () => {
    renderWithIntl(
      <div className="field">
        <label htmlFor="pw">Secret</label>
        <PasswordInput id="pw" defaultValue="hunter2" />
      </div>,
    );
    const user = userEvent.setup({ delay: null });
    const input = screen.getByLabelText('Secret');
    expect(input).toHaveAttribute('type', 'password');

    await user.click(screen.getByRole('button', { name: 'Show the password' }));
    expect(input).toHaveAttribute('type', 'text');
    expect(input).toHaveValue('hunter2');

    await user.click(screen.getByRole('button', { name: 'Hide the password' }));
    expect(input).toHaveAttribute('type', 'password');
    expect(input).toHaveValue('hunter2');
  });

  it('puts the eye inside the box, not beside it', () => {
    renderWithIntl(<PasswordInput aria-label="Secret" />);
    const input = screen.getByLabelText('Secret');
    const eye = screen.getByRole('button', { name: 'Show the password' });
    expect(input.parentElement).toBe(eye.parentElement);
    expect(input.parentElement).toHaveClass('pw');
  });

  it('does not submit a form when the eye is pressed', async () => {
    const onSubmit = vi.fn((event: { preventDefault: () => void }) => event.preventDefault());
    renderWithIntl(
      <form onSubmit={onSubmit}>
        <PasswordInput aria-label="Secret" />
      </form>,
    );
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Show the password' }));
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('keeps the eye off when the box is disabled', () => {
    renderWithIntl(<PasswordInput aria-label="Secret" disabled />);
    expect(screen.getByRole('button', { name: 'Show the password' })).toBeDisabled();
  });

  it('keeps the eye off when the box is isDisabled, as React Aria spells it', () => {
    renderWithIntl(<PasswordInput aria-label="Secret" isDisabled />);
    expect(screen.getByLabelText('Secret')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Show the password' })).toBeDisabled();
  });

  it('is as disabled as the field it sits in', () => {
    renderWithIntl(<Wrapped disabled />);
    expect(screen.getByLabelText('Master password')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Show the password' })).toBeDisabled();
  });

  it('is what a password field of the form controls draws', async () => {
    renderWithIntl(<Wrapped />);
    const user = userEvent.setup({ delay: null });
    const input = screen.getByLabelText('Master password');
    expect(input).toHaveAttribute('type', 'password');
    expect(input.parentElement).toHaveClass('pw');
    await user.click(screen.getByRole('button', { name: 'Show the password' }));
    expect(input).toHaveAttribute('type', 'text');
  });
});
