// Form controls: React Aria Components for behaviour and accessibility, wired to React Hook Form
// and styled with the canvas tokens in src/styles. Every error is a message id from the Zod
// schemas (src/lib/schemas.ts), translated here.
import type { ReactNode } from 'react';
import {
  Checkbox,
  FieldError,
  Input,
  Label,
  Radio,
  RadioGroup,
  Switch,
  Text,
  TextArea,
  TextField,
} from 'react-aria-components';
import {
  type Control,
  type FieldPath,
  type FieldValues,
  useController,
} from 'react-hook-form';
import { type MessageId, useT } from '@/i18n';
import { Icon } from './Icon';
import { PasswordInput } from './PasswordInput';

interface FieldProps<T extends FieldValues> {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  hint?: ReactNode;
  type?: 'text' | 'email' | 'password' | 'url' | 'number' | 'search' | 'tel' | 'date';
  multiline?: boolean;
  autoComplete?: string;
  inputMode?: 'text' | 'numeric' | 'email' | 'url';
  placeholder?: string;
  /** The longest value the box takes. */
  maxLength?: number;
  mono?: boolean;
  /** 48 px tall, as on the sign-in and setup cards. */
  large?: boolean;
  /** The big monospaced box for one-time codes. */
  code?: boolean;
  readOnly?: boolean;
  disabled?: boolean;
  autoFocus?: boolean;
  /** A control beside the input, such as a Generate button. */
  action?: ReactNode;
  /** Shown under the input, after the hint: a strength meter, say. */
  below?: ReactNode;
}

export function Field<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  type = 'text',
  multiline,
  autoComplete,
  inputMode,
  placeholder,
  maxLength,
  mono,
  large,
  code,
  readOnly,
  disabled,
  autoFocus,
  action,
  below,
}: FieldProps<T>) {
  const t = useT();
  const { field, fieldState } = useController({ control, name });
  const message = fieldState.error?.message;
  const classes = ['field', large ? 'lg' : '', code ? 'code' : '', mono || code ? 'mono' : '']
    .filter(Boolean)
    .join(' ');
  const input = multiline ? (
    <TextArea
      ref={field.ref}
      placeholder={placeholder}
      spellCheck={false}
      autoCorrect="off"
      autoCapitalize="off"
    />
  ) : type === 'password' ? (
    // The eye is inside the box, here and in every other password field (PasswordInput).
    <PasswordInput ref={field.ref} placeholder={placeholder} spellCheck={false} />
  ) : (
    <Input ref={field.ref} placeholder={placeholder} spellCheck={false} />
  );
  return (
    <TextField
      className={classes}
      name={field.name}
      value={typeof field.value === 'string' ? field.value : ''}
      onChange={field.onChange}
      onBlur={field.onBlur}
      type={type}
      autoComplete={autoComplete}
      inputMode={inputMode}
      maxLength={maxLength}
      isInvalid={Boolean(fieldState.error)}
      isReadOnly={readOnly}
      isDisabled={disabled}
      autoFocus={autoFocus}
    >
      <Label>{label}</Label>
      {action ? (
        <div className="with-action">
          {input}
          {action}
        </div>
      ) : (
        input
      )}
      {below}
      {hint ? (
        <Text slot="description" className="hint">
          {hint}
        </Text>
      ) : null}
      {message ? <FieldError className="error">{t(message as MessageId)}</FieldError> : null}
    </TextField>
  );
}

/** A native select, which the canvas uses and which every screen reader already handles. */
export function SelectField<T extends FieldValues>({
  control,
  name,
  label,
  options,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  options: Array<{ value: string; label: string }>;
}) {
  const { field } = useController({ control, name });
  const id = `select-${field.name}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        name={field.name}
        ref={field.ref}
        value={typeof field.value === 'string' ? field.value : ''}
        onChange={field.onChange}
        onBlur={field.onBlur}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function CheckField<T extends FieldValues>({
  control,
  name,
  children,
  hint,
  disabled,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  children: ReactNode;
  hint?: ReactNode;
  disabled?: boolean;
}) {
  const t = useT();
  const { field, fieldState } = useController({ control, name });
  const message = fieldState.error?.message;
  return (
    <>
      <Checkbox
        className="check"
        isSelected={Boolean(field.value)}
        onChange={field.onChange}
        onBlur={field.onBlur}
        isDisabled={disabled}
        name={field.name}
      >
        <span className="box">
          <Icon name="check" />
        </span>
        <span>
          <span className="t">{children}</span>
          {hint ? <span className="hint">{hint}</span> : null}
        </span>
      </Checkbox>
      {message ? (
        <span className="field-error" role="alert">
          {t(message as MessageId)}
        </span>
      ) : null}
    </>
  );
}

export function SwitchField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  hint?: ReactNode;
}) {
  const { field } = useController({ control, name });
  return (
    <Switch
      className="switch"
      isSelected={Boolean(field.value)}
      onChange={field.onChange}
      onBlur={field.onBlur}
    >
      <span className="text">
        <span className="t">{label}</span>
        {hint ? <span className="hint">{hint}</span> : null}
      </span>
      <span className="track" />
    </Switch>
  );
}

export interface ChoiceOption {
  value: string;
  title: ReactNode;
  hint?: ReactNode;
  disabled?: boolean;
}

/** Radios drawn as the canvas's option cards. */
export function RadioCards<T extends FieldValues>({
  control,
  name,
  legend,
  options,
  columns,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  legend: string;
  options: ChoiceOption[];
  columns?: boolean;
}) {
  const { field } = useController({ control, name });
  return (
    <RadioGroup
      aria-label={legend}
      value={typeof field.value === 'string' ? field.value : ''}
      onChange={field.onChange}
      className={columns ? 'grid' : 'opts'}
    >
      {options.map((option) => (
        <Radio key={option.value} value={option.value} isDisabled={option.disabled} className="opt">
          <span className="box">
            <Icon name="check" />
          </span>
          <span>
            <span className="t">{option.title}</span>
            {option.hint ? <span className="hint">{option.hint}</span> : null}
          </span>
        </Radio>
      ))}
    </RadioGroup>
  );
}
