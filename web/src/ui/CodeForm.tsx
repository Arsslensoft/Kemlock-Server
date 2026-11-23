import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { type MessageId, useT } from '@/i18n';
import { type CodeValues, codeSchema, normaliseCode } from '@/lib/schemas';
import { Button } from './Button';
import { Field } from './fields';
import { Notice } from './Notice';

/** One six-digit code and a button: the second step of sign-in, and TOTP enrolment. */
export function CodeForm({
  label,
  submitLabel,
  onSubmit,
  pending,
  error,
  hint,
}: {
  label: string;
  submitLabel: string;
  onSubmit: (code: string) => void;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
  hint?: string;
}) {
  const t = useT();
  const { control, handleSubmit } = useForm<CodeValues>({
    resolver: zodResolver(codeSchema),
    defaultValues: { code: '' },
  });
  return (
    <form
      className="stack"
      noValidate
      onSubmit={handleSubmit((values) => onSubmit(normaliseCode(values.code)))}
    >
      <Field
        control={control}
        name="code"
        label={label}
        hint={hint}
        code
        inputMode="numeric"
        autoComplete="one-time-code"
        autoFocus
      />
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <Button type="submit" variant="primary" size="large" block isDisabled={pending}>
        {submitLabel}
      </Button>
    </form>
  );
}
