// Controls and frames the admin screens share. Plain controlled inputs (the screens keep their
// forms in state and check them with Zod before saving), styled by the same classes as src/ui/fields.
import { type ReactNode, useId } from 'react';
import { Checkbox, Radio, RadioGroup, Switch } from 'react-aria-components';
import '@/styles/admin.css';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';

export function PageHead({
  title,
  lede,
  actions,
}: {
  title: string;
  lede?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {lede ? <p className="lede">{lede}</p> : null}
      </div>
      {actions ? <div className="actions">{actions}</div> : null}
    </div>
  );
}

export function Loading() {
  const t = useT();
  return (
    <p className="empty" role="status">
      {t('state.loading')}
    </p>
  );
}

/** A failed call, worded by `describeError`. */
export function ErrorNotice({ error }: { error: unknown }) {
  const t = useT();
  // Backing out of the re-authentication dialog is not a failure to report.
  if (error instanceof Error && error.name === 'ReauthCancelled') return null;
  const described = describeError(error);
  return (
    <Notice tone="error" live>
      <p>{t(described.id, described.values)}</p>
    </Notice>
  );
}

export function TextBox({
  label,
  value,
  onChange,
  type = 'text',
  mono,
  hint,
  placeholder,
  error,
  errorValues,
  autoComplete,
  disabled,
  readOnly,
  inputMode,
  required,
  min,
  max,
  step,
  pattern,
  maxLength,
  suffix,
}: {
  label: string;
  value: string;
  onChange?: (value: string) => void;
  type?: 'text' | 'email' | 'password' | 'url' | 'number' | 'search';
  mono?: boolean;
  hint?: ReactNode;
  placeholder?: string;
  error?: MessageId | undefined;
  /** The values the error's words take, such as a range. */
  errorValues?: Record<string, string | number>;
  autoComplete?: string;
  disabled?: boolean;
  readOnly?: boolean;
  inputMode?: 'text' | 'numeric' | 'email' | 'url';
  required?: boolean;
  min?: number;
  max?: number;
  step?: number;
  pattern?: string;
  maxLength?: number;
  /** A unit shown beside the input, such as KiB. */
  suffix?: string;
}) {
  const t = useT();
  const id = useId();
  const described = [hint ? `${id}-h` : '', error ? `${id}-e` : ''].filter((x) => x !== '').join(' ');
  return (
    <div className="field" data-invalid={error ? true : undefined}>
      <label htmlFor={id}>{label}</label>
      {hint ? (
        <span className="hint" id={`${id}-h`}>
          {hint}
        </span>
      ) : null}
      <div className={suffix ? 'with-suffix' : 'contents'}>
        <input
          id={id}
          className={mono ? 'mono' : undefined}
          type={type}
          value={value}
          placeholder={placeholder}
          autoComplete={autoComplete ?? 'off'}
          spellCheck={false}
          disabled={disabled}
          readOnly={readOnly ?? onChange === undefined}
          inputMode={inputMode}
          required={required}
          min={min}
          max={max}
          step={step}
          pattern={pattern}
          maxLength={maxLength}
          aria-invalid={error ? true : undefined}
          aria-describedby={described || undefined}
          onChange={(event) => onChange?.(event.target.value)}
        />
        {suffix ? <span className="unit">{suffix}</span> : null}
      </div>
      {error ? (
        <span className="field-error" id={`${id}-e`}>
          {t(error, errorValues)}
        </span>
      ) : null}
    </div>
  );
}

export function SelectBox({
  label,
  value,
  onChange,
  options,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  hint?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {hint ? (
        <span className="hint" id={`${id}-h`}>
          {hint}
        </span>
      ) : null}
      <select
        id={id}
        value={value}
        aria-describedby={hint ? `${id}-h` : undefined}
        onChange={(event) => onChange(event.target.value)}
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

export function Toggle({
  label,
  hint,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  hint?: ReactNode;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <Switch className="switch lead" isSelected={checked} onChange={onChange} isDisabled={disabled}>
      <span className="text">
        <span className="t">{label}</span>
        {hint ? <span className="hint">{hint}</span> : null}
      </span>
      <span className="track" />
    </Switch>
  );
}

export function CheckBox({
  label,
  hint,
  checked,
  onChange,
  disabled,
}: {
  label: ReactNode;
  hint?: ReactNode;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <Checkbox className="check" isSelected={checked} onChange={onChange} isDisabled={disabled}>
      <span className="box">
        <Icon name="check" />
      </span>
      <span>
        <span className="t">{label}</span>
        {hint ? <span className="hint">{hint}</span> : null}
      </span>
    </Checkbox>
  );
}

export interface Choice {
  value: string;
  title: ReactNode;
  hint?: ReactNode;
  disabled?: boolean;
}

export function ChoiceGroup({
  legend,
  value,
  onChange,
  options,
}: {
  legend: string;
  value: string;
  onChange: (value: string) => void;
  options: Choice[];
}) {
  return (
    <RadioGroup aria-label={legend} value={value} onChange={onChange} className="opts">
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

/** A switch on its own row inside a card. */
export function SwitchRow(props: Parameters<typeof Toggle>[0]) {
  return (
    <div className="adm-switchrow">
      <Toggle {...props} />
    </div>
  );
}

/** A `<dt>`/`<dd>` row of the security cards. */
export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}
