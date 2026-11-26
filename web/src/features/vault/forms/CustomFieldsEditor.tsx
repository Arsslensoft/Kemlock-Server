// The "Custom fields" card: rows of fields and the "Add a field" menu. "From your admin" lists the
// fields an admin defined (a fixed name and type, an Admin badge; the person fills in the value),
// "Your own field" makes one with a name, a type and a value. Every field is optional.
import { useEffect, useId, useRef, useState } from 'react';
import type { CustomFieldDefinitions, CustomFieldType } from '@/api/customFields';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { PasswordInput } from '@/ui/PasswordInput';
import {
  type FieldValue,
  addAdminField,
  addOwnField,
  adminChoices,
  changeField,
  fieldProblem,
  removeField,
} from './extras';

const TYPE_LABELS: Record<CustomFieldType, MessageId> = {
  text: 'itemForm.fields.type.text',
  hidden: 'itemForm.fields.type.hidden',
  checkbox: 'itemForm.fields.type.checkbox',
};
const TYPES: CustomFieldType[] = ['text', 'hidden', 'checkbox'];

interface Props {
  /** The kind of the item, which decides which admin fields are offered. */
  kind: string;
  value: FieldValue[];
  onChange: (next: FieldValue[]) => void;
  definitions: CustomFieldDefinitions;
  /** Show what each row needs fixed (after a Save that was refused). */
  showProblems?: boolean;
}

export function CustomFieldsEditor({ kind, value, onChange, definitions, showProblems }: Props) {
  const t = useT();
  const id = useId();
  const choices = adminChoices(definitions.fields, kind, value);
  const canAdd = choices.length > 0 || definitions.allowOwn;
  return (
    <section className="card pad" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`}>{t('itemForm.fields.title')}</h2>
      <div className="cf-list">
        {value.length === 0 ? <p className="hint">{t('itemForm.fields.none')}</p> : null}
        {value.map((field, index) => (
          <FieldRow
            key={field.key}
            field={field}
            n={index + 1}
            problem={showProblems ? fieldProblem(field) : undefined}
            onChange={(patch) => onChange(changeField(value, field.key, patch))}
            onRemove={() => onChange(removeField(value, field.key))}
          />
        ))}
        {canAdd ? (
          <div>
            <AddFieldMenu
              choices={choices}
              allowOwn={definitions.allowOwn}
              onAdmin={(def) => onChange(addAdminField(value, def))}
              onOwn={() => onChange(addOwnField(value))}
            />
          </div>
        ) : null}
      </div>
      <p className="hint">{t(definitions.allowOwn ? 'itemForm.fields.hint' : 'itemForm.fields.hintAdminOnly')}</p>
    </section>
  );
}

function FieldRow({
  field,
  n,
  problem,
  onChange,
  onRemove,
}: {
  field: FieldValue;
  n: number;
  problem: MessageId | undefined;
  onChange: (patch: Partial<Pick<FieldValue, 'name' | 'type' | 'value'>>) => void;
  onRemove: () => void;
}) {
  const t = useT();
  const id = useId();
  const admin = field.adminField !== undefined;
  const control = (label: string) => {
    if (field.type === 'checkbox') {
      return (
        <span className="check-row cf-value">
          <input
            id={`${id}-v`}
            type="checkbox"
            aria-label={label}
            checked={field.value === 'true'}
            onChange={(event) => onChange({ value: event.target.checked ? 'true' : 'false' })}
          />
        </span>
      );
    }
    const common = {
      id: `${id}-v`,
      'aria-label': label,
      className: 'cf-value',
      autoComplete: 'off',
      value: field.value,
      placeholder: t('itemForm.fields.placeholderValue'),
      onChange: (event: { target: { value: string } }) => onChange({ value: event.target.value }),
    };
    return field.type === 'hidden' ? <PasswordInput {...common} /> : <input type="text" spellCheck={false} {...common} />;
  };
  if (admin) {
    return (
      <div className="field">
        <div className="cf-row">
          <label htmlFor={`${id}-v`} className="cf-label">
            {field.name}
            <span className="cf-tag">{t('itemForm.fields.admin')}</span>
            <span className="cf-type">{t(TYPE_LABELS[field.type])}</span>
          </label>
          {control(field.name)}
          <button
            type="button"
            className="btn rm"
            aria-label={t('itemForm.fields.remove', { name: field.name })}
            onClick={onRemove}
          >
            <Icon name="close" />
          </button>
        </div>
      </div>
    );
  }
  return (
    <div className="field">
      <div className="cf-row">
        <input
          type="text"
          className="cf-name"
          aria-label={t('itemForm.fields.name', { n })}
          placeholder={t('itemForm.fields.placeholderName')}
          autoComplete="off"
          spellCheck={false}
          value={field.name}
          aria-invalid={problem ? true : undefined}
          onChange={(event) => onChange({ name: event.target.value })}
        />
        <select
          className="cf-kind"
          aria-label={t('itemForm.fields.typeOf', { n })}
          value={field.type}
          onChange={(event) => onChange({ type: event.target.value as CustomFieldType })}
        >
          {TYPES.map((type) => (
            <option key={type} value={type}>
              {t(TYPE_LABELS[type])}
            </option>
          ))}
        </select>
        {control(t('itemForm.fields.value', { n }))}
        <button
          type="button"
          className="btn rm"
          aria-label={t('itemForm.fields.removeN', { n })}
          onClick={onRemove}
        >
          <Icon name="close" />
        </button>
      </div>
      {problem ? (
        <span className="error" role="alert">
          {t(problem)}
        </span>
      ) : null}
    </div>
  );
}

function AddFieldMenu({
  choices,
  allowOwn,
  onAdmin,
  onOwn,
}: {
  choices: ReturnType<typeof adminChoices>;
  allowOwn: boolean;
  onAdmin: (def: ReturnType<typeof adminChoices>[number]) => void;
  onOwn: () => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return undefined;
    const away = (event: MouseEvent) => {
      if (!wrap.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', away);
    return () => document.removeEventListener('mousedown', away);
  }, [open]);
  const pick = (action: () => void) => () => {
    action();
    setOpen(false);
  };
  return (
    <div
      className="af"
      ref={wrap}
      // The panel closes when focus leaves it (a Tab past its end, a click elsewhere).
      onBlur={(event) => {
        if (open && !event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.stopPropagation();
          setOpen(false);
          wrap.current?.querySelector<HTMLButtonElement>('button[aria-haspopup]')?.focus();
        }
      }}
    >
      <Button size="small" aria-expanded={open} aria-haspopup="dialog" onPress={() => setOpen((was) => !was)}>
        <Icon name="plus" />
        {t('itemForm.fields.add')}
      </Button>
      {open ? (
        <div className="af-menu" role="dialog" aria-label={t('itemForm.fields.add')} tabIndex={-1}>
          {choices.length > 0 ? (
            <>
              <h3>{t('itemForm.fields.fromAdmin')}</h3>
              {choices.map((def) => (
                <button key={def.id} type="button" className="af-item" onClick={pick(() => onAdmin(def))}>
                  {def.name}
                  <span className="ty">{t(TYPE_LABELS[def.type])}</span>
                </button>
              ))}
            </>
          ) : null}
          {choices.length > 0 && allowOwn ? <div className="af-rule" /> : null}
          {allowOwn ? (
            <button type="button" className="af-item" onClick={pick(onOwn)}>
              <Icon name="plus" />
              {t('itemForm.fields.own')}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
