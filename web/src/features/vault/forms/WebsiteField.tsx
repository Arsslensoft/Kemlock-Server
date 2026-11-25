// The Website field of an MFA code and of backup codes. Unlinked, it is a normal field. Linked to
// an item that has websites, it shows those, read-only, and says where to change them: only the
// original item edits them.
import { Children, type ReactNode, useId } from 'react';
import { type Control, type FieldPath, type FieldValues, useWatch } from 'react-hook-form';
import { useIntl } from 'react-intl';
import { useT } from '@/i18n';
import { Field } from '@/ui/fields';
import { Icon } from '@/ui/Icon';
import { type LinkedWebsites, linkedWebsites } from '../linkedSites';
import { itemName } from '../vault';
import { useFormEnv } from './env';

/** What the items linked in the form lend as websites, or undefined when they lend none. */
export function useLinkedWebsites<T extends { links: string[] }>(control: Control<T>): LinkedWebsites | undefined {
  const env = useFormEnv();
  const links = useWatch({ control: control as unknown as Control<{ links: string[] }>, name: 'links' });
  return linkedWebsites(links, env.items);
}

export function WebsiteField<T extends FieldValues>({
  control,
  linked,
}: {
  control: Control<T>;
  linked: LinkedWebsites | undefined;
}) {
  const t = useT();
  const intl = useIntl();
  const env = useFormEnv();
  const id = useId();
  if (!linked) {
    return (
      <Field
        control={control}
        name={'website' as FieldPath<T>}
        label={t('itemForm.website.label')}
        hint={t('itemForm.website.hint')}
        autoComplete="off"
        inputMode="url"
      />
    );
  }
  const [first] = linked.sources;
  const hint = Children.toArray(
    linked.sources.length === 1 && first
      ? intl.formatMessage(
          { id: first.kind === 'login' ? 'itemForm.website.fromLogin' : 'itemForm.website.fromItem' },
          { name: itemName(first), b: (chunks: ReactNode[]) => env.renderItem(first, chunks) },
        )
      : intl.formatMessage(
          { id: 'itemForm.website.fromItems' },
          {
            names: linked.sources.map((item) => itemName(item)).join(', '),
            b: (chunks: ReactNode[]) => <b>{chunks}</b>,
          },
        ),
  );
  return (
    <div className="field">
      <label htmlFor={`${id}-w`}>{t('itemForm.website.label')}</label>
      <div className="ro-box">
        <input
          id={`${id}-w`}
          type="text"
          readOnly
          aria-readonly="true"
          aria-describedby={`${id}-hint`}
          value={linked.hosts.join(', ')}
        />
        <span className="ro-lock" aria-hidden="true">
          <Icon name="lock" />
        </span>
      </div>
      <span className="hint" id={`${id}-hint`}>
        {hint}
      </span>
    </div>
  );
}
