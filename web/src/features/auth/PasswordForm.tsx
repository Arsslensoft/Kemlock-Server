import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { type MessageId, useT } from '@/i18n';
import { type PasswordValues, passwordSchema } from '@/lib/schemas';
import { Button } from '@/ui/Button';
import { Field } from '@/ui/fields';
import { Notice } from '@/ui/Notice';

/** The master-password box and its button. The password goes to `onSubmit` and nowhere else. */
export function PasswordForm({
  onSubmit,
  submitLabel,
  pending,
  error,
}: {
  onSubmit: (password: string) => void;
  submitLabel: string;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
}) {
  const t = useT();
  const { control, handleSubmit } = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { password: '' },
  });
  return (
    <form className="stack" noValidate onSubmit={handleSubmit((values) => onSubmit(values.password))}>
      <Field
        control={control}
        name="password"
        label={t('field.masterPassword')}
        type="password"
        autoComplete="current-password"
        large
        autoFocus
      />
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <Button type="submit" variant="primary" size="large" block isDisabled={pending}>
        {pending ? t('signIn.opening') : submitLabel}
      </Button>
    </form>
  );
}
