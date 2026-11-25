// A password box with its show and hide eye inside it, at the right edge. Every password-type
// input in the app is this one, so the eye is never beside the field. It is a React Aria `Input`:
// inside a `TextField` (see `Field` in fields.tsx) it takes the field's label, hint and error as
// they are, and on its own it is a plain input.
import { type InputHTMLAttributes, type Ref, useContext, useState } from 'react';
import { Input, InputContext } from 'react-aria-components';
import { useT } from '@/i18n';
import { Icon } from './Icon';

export interface PasswordInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  ref?: Ref<HTMLInputElement>;
  /** The same as `disabled`, as a React Aria field spells it. */
  isDisabled?: boolean;
}

export function PasswordInput({ ref, isDisabled, ...rest }: PasswordInputProps) {
  const t = useT();
  const [shown, setShown] = useState(false);
  // A disabled field (`isDisabled` on its TextField) tells its input through this context, so the
  // eye is as disabled as the box it sits in.
  const field = useContext(InputContext) as { disabled?: boolean } | null;
  const disabled = rest.disabled === true || isDisabled === true || field?.disabled === true;
  return (
    <span className="pw">
      <Input {...rest} ref={ref} type={shown ? 'text' : 'password'} disabled={disabled || undefined} />
      <button
        type="button"
        className="pw-eye"
        aria-label={shown ? t('item.hidePassword') : t('item.showPassword')}
        disabled={disabled}
        onClick={() => setShown((value) => !value)}
      >
        <Icon name={shown ? 'eyeOff' : 'eye'} />
      </button>
    </span>
  );
}
