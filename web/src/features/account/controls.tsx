// Plain labelled controls for the account screens: a native input or select under the canvas's
// `.field` styling, which every screen reader already handles.
import { type ChangeEvent, type ReactNode, useId } from 'react';
import { PasswordInput } from '@/ui/PasswordInput';

export function TextInput({
  label,
  value,
  onChange,
  type = 'text',
  hint,
  mono,
  required,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: 'text' | 'email' | 'number' | 'password';
  hint?: ReactNode;
  mono?: boolean;
  required?: boolean;
}) {
  const id = useId();
  const input = {
    id,
    className: mono ? 'mono' : undefined,
    value,
    required,
    autoComplete: 'off',
    spellCheck: false,
    onChange: (event: ChangeEvent<HTMLInputElement>) => onChange(event.target.value),
  };
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {type === 'password' ? <PasswordInput {...input} /> : <input type={type} {...input} />}
      {hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

export function SelectInput({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

/** A group of checkboxes: the toggled value is added to or removed from `selected`. */
export function CheckList({
  legend,
  options,
  selected,
  onChange,
}: {
  legend: string;
  options: Array<{ value: string; label: string }>;
  selected: string[];
  onChange: (selected: string[]) => void;
}) {
  return (
    <fieldset className="stack">
      <legend className="lbl">{legend}</legend>
      <div className="perm-list">
        {options.map((option) => (
          <label key={option.value}>
            <input
              type="checkbox"
              checked={selected.includes(option.value)}
              onChange={(event) =>
                onChange(
                  event.target.checked
                    ? [...selected, option.value]
                    : selected.filter((value) => value !== option.value),
                )
              }
            />
            {option.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
