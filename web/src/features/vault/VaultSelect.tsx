// The "Vault" filter above a list: All vaults, Personal or one space. A native select, so it works
// by keyboard and with a screen reader without more.
import { useId } from 'react';
import { useT } from '@/i18n';
import { Icon } from '@/ui/Icon';
import '@/styles/lists.css';
import { ALL_VAULTS } from './listFilters';
import type { VaultOption } from './vaults';

export function VaultSelect({
  value,
  options,
  onChange,
}: {
  value: string;
  options: readonly VaultOption[];
  onChange: (vault: string) => void;
}) {
  const t = useT();
  const id = useId();
  return (
    <div className="filter-row">
      <label htmlFor={id}>{t('lists.vault.label')}</label>
      <select id={id} className="vault-select" value={value} onChange={(event) => onChange(event.target.value)}>
        <option value={ALL_VAULTS}>{t('lists.vault.all')}</option>
        {options.map((option) => (
          <option key={option.id} value={option.id}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

/** The pill that names the vault an item is in. */
export function VaultPill({ label }: { label: string }) {
  return (
    <span className="vault-pill">
      <Icon name="building" />
      {label}
    </span>
  );
}
