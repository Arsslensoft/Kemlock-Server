// The compact "Strength" panel under a login's password: the heading and the length on one line,
// the slider on its own line, then the characters the password may use. It sets how the Generate
// button makes the password; nothing here touches the password itself.
import { useId } from 'react';
import { type MessageId, useT } from '@/i18n';
import type { GeneratorOptions } from '@/lib/password';

interface Props {
  options: GeneratorOptions;
  onChange: (next: GeneratorOptions) => void;
}

const SETS: Array<{ key: 'upper' | 'lower' | 'digits' | 'symbols'; label: MessageId }> = [
  { key: 'upper', label: 'itemForm.generator.upper' },
  { key: 'lower', label: 'itemForm.generator.lower' },
  { key: 'digits', label: 'itemForm.generator.digits' },
  { key: 'symbols', label: 'itemForm.generator.symbols' },
];

export function GeneratorPanel({ options, onChange }: Props) {
  const t = useT();
  const id = useId();
  // At least one kind of character stays chosen: the last one can't be turned off.
  const chosen = SETS.filter(({ key }) => options[key]).length;
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
              disabled={options[key] && chosen === 1}
              onChange={(event) => onChange({ ...options, [key]: event.target.checked })}
            />
            <label htmlFor={`${id}-${key}`}>{t(label)}</label>
          </div>
        ))}
      </div>
    </div>
  );
}
