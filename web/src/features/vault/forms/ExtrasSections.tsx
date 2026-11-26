// The "Linked items" and "Custom fields" cards of a form, wired to its values. A form puts
// `extrasShape` in its schema and `ExtrasValues` in its defaults, and draws `ExtrasSections`; a
// form with no custom fields (the File) draws `LinkedSection` alone.
import { type Control, useController } from 'react-hook-form';
import { CustomFieldsEditor } from './CustomFieldsEditor';
import { LinkedItemsEditor } from './LinkedItemsEditor';
import { useFormEnv } from './env';
import type { ExtrasValues } from './extras';

/** The linked items card. The form's own values hold more than `links`; the card only touches that. */
export function LinkedSection<T extends Pick<ExtrasValues, 'links'>>({ control }: { control: Control<T> }) {
  const env = useFormEnv();
  const { field } = useController({ control: control as unknown as Control<Pick<ExtrasValues, 'links'>>, name: 'links' });
  return (
    <LinkedItemsEditor
      value={field.value}
      onChange={field.onChange}
      items={env.items}
      selfId={env.selfId}
      canWrite={env.canWrite}
    />
  );
}

/** The custom fields card: the admin's fields are offered by the `kind` of the item. */
export function FieldsSection<T extends Pick<ExtrasValues, 'fields'>>({
  control,
  kind,
}: {
  control: Control<T>;
  kind: string;
}) {
  const env = useFormEnv();
  const { field, fieldState } = useController({
    control: control as unknown as Control<Pick<ExtrasValues, 'fields'>>,
    name: 'fields',
  });
  return (
    <CustomFieldsEditor
      kind={kind}
      value={field.value}
      onChange={field.onChange}
      definitions={env.definitions}
      showProblems={Boolean(fieldState.error)}
    />
  );
}

export function ExtrasSections<T extends ExtrasValues>({ control, kind }: { control: Control<T>; kind: string }) {
  return (
    <>
      <LinkedSection control={control} />
      <FieldsSection control={control} kind={kind} />
    </>
  );
}
