// The compact "Strength" panel under a login's password: the heading and the length on one line,
// the slider on its own line, then the characters the password may use. It sets how the Generate
// button makes the password; nothing here touches the password itself.
import { useId } from 'react';
import { useT } from '@/i18n';
import type { GeneratorOptions } from '@/lib/password';

interface Props {
  options: GeneratorOptions;
  onChange: (next: GeneratorOptions) => void;
}

const SETS: Array<{ key: 'upper' | 'lower' | 'digits' | 'symbols'; label: string }> = [
  { key: 'upper', label: 'A to Z' },
  { key: 'lower', label: 'a to z' },
  { key: 'digits', label: '0 to 9' },
  { key: 'symbols', label: '!@#$%^&*' },
];

export function GeneratorPanel({ options, onChange }: Props) {
  const t = useT();
  const id = useId();
  return (
    <div role="group" aria-labelledby={`${id}-h`} className="gen">
      <div className="gen-top">
        <span id={`${id}-h`} className="gen-title">
          {t('itemForm.generator.title')}
        </span>
        <label htmlFor={`${id}-len`} className="gen-length">
          {t('itemForm.generator.length', { length: options.length })}
        </label>
      </div>
      <input
        id={`${id}-len`}
        type="range"
        min={8}
        max={64}
        value={options.length}
        onChange={(event) => onChange({ ...options, length: Number(event.target.value) })}
      />
      <div className="gen-sets">
        {SETS.map(({ key, label }) => (
          <div key={key} className="check-row">
            <input
              id={`${id}-${key}`}
              type="checkbox"
              checked={options[key]}
              onChange={(event) => onChange({ ...options, [key]: event.target.checked })}
            />
            <label htmlFor={`${id}-${key}`}>{label}</label>
          </div>
        ))}
      </div>
    </div>
  );
}
