// The picker of the Send form's item kinds: lists the vault's items of one kind, to choose one.
import { useT } from '@/i18n';
import { type EditableKind } from '@/features/vault/kinds';
import { type VaultItem, itemName } from '@/features/vault/vault';

/** The active items of a kind that can be sent, by name. */
export function itemsOfKind(items: VaultItem[], kind: EditableKind): VaultItem[] {
  return items
    .filter((item) => item.kind === kind && item.data !== null)
    .sort((a, b) => itemName(a).localeCompare(itemName(b)));
}

export function SendItemPicker({
  items,
  kind,
  selectedId,
  onSelect,
}: {
  items: VaultItem[];
  kind: EditableKind;
  selectedId: string | undefined;
  onSelect: (item: VaultItem | undefined) => void;
}) {
  const t = useT();
  const own = itemsOfKind(items, kind);
  return (
    <div className="field">
      <label htmlFor="s-item">{t('sendItem.choose')}</label>
      <select
        id="s-item"
        value={selectedId ?? ''}
        disabled={own.length === 0}
        onChange={(event) => onSelect(own.find((item) => item.id === event.target.value))}
      >
        <option value="">{own.length === 0 ? t('sendItem.none') : t('sendItem.pick')}</option>
        {own.map((item) => (
          <option key={item.id} value={item.id}>
            {itemName(item)}
          </option>
        ))}
      </select>
      <span className="hint">{t('sendItem.hint')}</span>
    </div>
  );
}
