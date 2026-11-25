// An item's custom fields as read-only rows, for the end of its first card: text with a copy
// button, a hidden field masked with Show and Copy, a checkbox as Yes or No. A field the admin
// defined carries an "Admin" tag. Nothing here edits a field: the form does.
import { useT } from '@/i18n';
import type { CustomField } from '../customFields';
import { AdminTag, Row, SecretRow } from './rows';

export function CustomFieldRows({ fields }: { fields: CustomField[] }) {
  const t = useT();
  return (
    <>
      {fields.map((field, index) => {
        const key = `${index}-${field.name}`;
        const tag = field.admin ? <AdminTag /> : undefined;
        if (field.kind === 'hidden') {
          return <SecretRow key={key} label={field.name} value={field.value} tag={tag} />;
        }
        if (field.kind === 'checkbox') {
          return (
            <Row key={key} label={field.name} tag={tag}>
              <div>{t(field.value === 'true' ? 'detail.custom.yes' : 'detail.custom.no')}</div>
            </Row>
          );
        }
        return (
          <Row
            key={key}
            label={field.name}
            tag={tag}
            copy={field.value}
            copyLabel={t('detail.copy', { field: field.name.toLowerCase() })}
          >
            <div className="wrap pre-wrap">{field.value}</div>
          </Row>
        );
      })}
    </>
  );
}
