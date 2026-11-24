// What the key forms share: the error notice and the Cancel and Save buttons.
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';

export type Described = { id: MessageId; values?: Record<string, string | number> } | undefined;

export interface KeyFormProps<T> {
  initial: T;
  /** An existing item is being edited: only its name and note change. */
  editing?: boolean;
  onSubmit: (values: T) => void;
  onCancel: () => void;
  pending?: boolean;
  error?: Described;
  submitLabel: string;
}

export function FormActions({
  pending,
  onCancel,
  submitLabel,
  error,
}: Pick<KeyFormProps<unknown>, 'pending' | 'onCancel' | 'submitLabel' | 'error'>) {
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
