// What the otp, backup-codes, card and identity forms share. Their items are the Kemlock app's
// own entries (kemlock-core `OtpAccount`, `BackupService`, `PaymentCard`, `Identity`): the item's
// plaintext is the entry's JSON, so the keys here are the app's (`note`, `pinned`, `addedAt`),
// not the login's. Keys the form doesn't own stay, because `saveItem` merges over `existing.data`.
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import type { VaultItem } from '../vault';

export type Described = { id: MessageId; values?: Record<string, string | number> } | undefined;

export interface FormProps<T> {
  initial: T;
  onSubmit: (values: T) => void;
  onCancel: () => void;
  pending?: boolean | undefined;
  error?: Described;
  submitLabel: string;
}

export function Actions({
  pending,
  onCancel,
  submitLabel,
  error,
}: Pick<FormProps<unknown>, 'pending' | 'onCancel' | 'submitLabel' | 'error'>) {
  const t = useT();
  return (
    <>
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <div className="actions">
        <Button onPress={onCancel}>{t('action.cancel')}</Button>
        <Button type="submit" variant="primary" isDisabled={pending}>
          {submitLabel}
        </Button>
      </div>
    </>
  );
}

/** The `addedAt` (epoch ms) a new entry carries; an edit keeps its own. The entry `id` is the item's, set by `saveItem`. */
export function entryBase(existing?: VaultItem): { addedAt?: number } {
  if (existing) return {};
  return { addedAt: Date.now() };
}

export function str(data: VaultItem['data'] | undefined, key: string): string {
  const value = data?.[key];
  return typeof value === 'string' ? value : '';
}

export function num(data: VaultItem['data'] | undefined, key: string): string {
  const value = data?.[key];
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

/** An empty string becomes `undefined`, which `saveItem` drops, so a cleared field is removed. */
export function orUndefined(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

export function isPinned(item?: VaultItem): boolean {
  return item?.data?.['pinned'] === true;
}
