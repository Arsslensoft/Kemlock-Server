import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import type { CustomField, CustomFieldInput, CustomFields } from '@/api/admin';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { ConfirmDialog } from '@/ui/ConfirmDialog';
import { Icon } from '@/ui/Icon';
import { RowMenu } from '@/ui/RowMenu';
import '@/styles/admin.css';
import { admin } from './client';
import {
  FIELD_KINDS,
  FIELD_TYPES,
  type FieldDraft,
  KIND_LABELS,
  TYPE_LABELS,
  appliesTo,
  checkDraft,
  draftOf,
} from './fieldsModel';
import { useReauth } from './reauth';
import { ChoiceGroup, CheckBox, ErrorNotice, Loading, PageHead, SelectBox, TextBox, Toggle } from './ui';

/** The form of one field, in a dialog. It starts over each time the dialog opens. */
function FieldForm({
  field,
  pending,
  error,
  onSave,
  onCancel,
}: {
  /** The field being changed; none for a new one. */
  field: CustomField | null;
  pending?: boolean | undefined;
  error?: unknown;
  onSave: (input: CustomFieldInput) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [draft, setDraft] = useState<FieldDraft>(() => draftOf(field ?? undefined));
  const [tried, setTried] = useState(false);
  const checked = checkDraft(draft);
  // Errors show once Save was tried, then follow every key.
  const errors = tried && !checked.ok ? checked.errors : {};
  const set = <K extends keyof FieldDraft>(key: K, value: FieldDraft[K]) =>
    setDraft((previous) => ({ ...previous, [key]: value }));
  return (
    <form
      noValidate
      className="adm-form"
      onSubmit={(event) => {
        event.preventDefault();
        setTried(true);
        if (checked.ok) onSave(checked.input);
      }}
    >
      <Heading slot="title">
        {field ? t('admin.fields.dialog.edit', { name: field.name }) : t('admin.fields.dialog.add')}
      </Heading>
      <TextBox
        label={t('admin.fields.name')}
        hint={t('admin.fields.nameHint')}
        value={draft.name}
        onChange={(value) => set('name', value)}
        error={errors.name}
        autoComplete="off"
      />
      <SelectBox
        label={t('admin.fields.type')}
        value={draft.type}
        onChange={(value) => {
          const type = FIELD_TYPES.find((candidate) => candidate === value);
          if (type) set('type', type);
        }}
        options={FIELD_TYPES.map((type) => ({ value: type, label: t(TYPE_LABELS[type]) }))}
      />
      <ChoiceGroup
        legend={t('admin.fields.scope')}
        value={draft.scope}
        onChange={(value) => set('scope', value === 'only' ? 'only' : 'all')}
        options={[
          { value: 'all', title: t('admin.fields.scope.all'), hint: t('admin.fields.scope.allHint') },
          { value: 'only', title: t('admin.fields.scope.only') },
        ]}
      />
      {draft.scope === 'only' ? (
        <fieldset className="adm-kinds" aria-describedby={errors.kinds ? 'fields-kinds-error' : undefined}>
          <legend>{t('admin.fields.kinds')}</legend>
          <div className="perm-list">
            {FIELD_KINDS.map((kind) => (
              <CheckBox
                key={kind}
                label={t(KIND_LABELS[kind])}
                checked={draft.kinds.includes(kind)}
                onChange={(on) =>
                  set('kinds', on ? [...draft.kinds, kind] : draft.kinds.filter((other) => other !== kind))
                }
              />
            ))}
          </div>
          {errors.kinds ? (
            <span className="field-error" id="fields-kinds-error" role="alert">
              {t(errors.kinds)}
            </span>
          ) : null}
        </fieldset>
      ) : null}
      {error ? <ErrorNotice error={error} /> : null}
      <div className="actions">
        <Button isDisabled={pending} onPress={onCancel}>
          {t('action.cancel')}
        </Button>
        <Button type="submit" variant="primary" isDisabled={pending}>
          {t('action.save')}
        </Button>
      </div>
    </form>
  );
}

export interface FieldsViewProps {
  definitions: CustomFields;
  /** Adds the field (`id` null) or changes it. Answers false when the request failed: the form then stays open. */
  onSave: (id: string | null, input: CustomFieldInput) => Promise<boolean> | void;
  /** Answers false when the request failed: the question then stays open. */
  onDelete: (field: CustomField) => Promise<boolean> | void;
  onAllowOwn: (allow: boolean) => void;
  /**
   * A form or a question opened, or was put away without saving: the last failure it showed is
   * not the next one's to see.
   */
  onReset?: () => void;
  busy?: boolean;
  error?: unknown;
}

/** The fields an admin offers, and the switch for people's own. Takes data and callbacks, no network. */
export function FieldsView({ definitions, onSave, onDelete, onAllowOwn, onReset, busy, error }: FieldsViewProps) {
  const t = useT();
  // `null`: closed; `'new'`: the form of a new field; a field: its form.
  const [editing, setEditing] = useState<CustomField | 'new' | null>(null);
  const [deleting, setDeleting] = useState<CustomField | null>(null);
  const open = editing !== null || deleting !== null;
  const opening = (next: CustomField | 'new') => {
    onReset?.();
    setEditing(next);
  };
  const closing = () => {
    onReset?.();
    setEditing(null);
    setDeleting(null);
  };
  return (
    <>
      <PageHead
        title={t('admin.fields')}
        lede={t('admin.fields.lede')}
        actions={
          <Button size="small" variant="primary" onPress={() => opening('new')}>
            <Icon name="plus" />
            {t('admin.fields.add')}
          </Button>
        }
      />
      {error && !open ? <ErrorNotice error={error} /> : null}

      <section className="card" aria-label={t('admin.fields')}>
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th scope="col">{t('admin.fields.col.field')}</th>
                <th scope="col">{t('admin.fields.col.type')}</th>
                <th scope="col">{t('admin.fields.col.on')}</th>
                <th scope="col">
                  <span className="sr">{t('table.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {definitions.fields.length === 0 ? (
                <tr>
                  <td colSpan={4} className="adm-cell-sub">
                    {t('admin.fields.none')}
                  </td>
                </tr>
              ) : (
                definitions.fields.map((field) => {
                  const on = appliesTo(field);
                  return (
                    <tr key={field.id}>
                      <th scope="row" className="adm-field-name">
                        {field.name}
                      </th>
                      <td>{t(TYPE_LABELS[field.type])}</td>
                      <td>{on === 'all' ? t('admin.fields.on.all') : on.map((id) => t(id)).join(', ')}</td>
                      <td>
                        <div className="adm-row-actions">
                          <RowMenu
                            label={t('admin.fields.actionsFor', { name: field.name })}
                            items={[
                              {
                                id: 'edit',
                                label: t('admin.fields.edit'),
                                icon: <Icon name="edit" />,
                                onAction: () => opening(field),
                              },
                              {
                                id: 'delete',
                                label: t('admin.fields.delete'),
                                icon: <Icon name="trash" />,
                                danger: true,
                                onAction: () => {
                                  onReset?.();
                                  setDeleting(field);
                                },
                              },
                            ]}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card adm-pad">
        <Toggle
          label={t('admin.fields.own')}
          hint={t('admin.fields.ownHint')}
          checked={definitions.allowOwn}
          disabled={busy}
          onChange={onAllowOwn}
        />
      </section>

      <p className="hint">{t('admin.fields.note')}</p>

      <ModalOverlay
        isOpen={editing !== null}
        onOpenChange={(next) => {
          if (!next) closing();
        }}
        isDismissable={!busy}
        isKeyboardDismissDisabled={busy}
        className="overlay"
      >
        <Modal>
          <Dialog className="dialog">
            {editing !== null ? (
              <FieldForm
                field={editing === 'new' ? null : editing}
                pending={busy}
                error={error}
                onCancel={closing}
                onSave={async (input) => {
                  const done = await onSave(editing === 'new' ? null : editing.id, input);
                  if (done === false) return;
                  setEditing(null);
                }}
              />
            ) : null}
          </Dialog>
        </Modal>
      </ModalOverlay>

      <ConfirmDialog
        isOpen={deleting !== null}
        onOpenChange={(next) => {
          if (!next) closing();
        }}
        title={t('admin.fields.deleteTitle', { name: deleting?.name ?? '' })}
        confirmLabel={t('admin.fields.delete')}
        pending={busy}
        onConfirm={async () => {
          if (deleting && (await onDelete(deleting)) === false) return;
          setDeleting(null);
        }}
      >
        <p>{t('admin.fields.deleteBody')}</p>
        {error ? <ErrorNotice error={error} /> : null}
      </ConfirmDialog>
    </>
  );
}

export default function Fields() {
  const queryClient = useQueryClient();
  const { guard, dialog } = useReauth(admin);
  const fields = useQuery({ queryKey: ['admin', 'custom-fields'], queryFn: () => admin.customFields() });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['admin', 'custom-fields'] });
  const save = useMutation({
    mutationFn: ({ id, input }: { id: string | null; input: CustomFieldInput }) =>
      guard((token) => (id === null ? admin.addCustomField(input, token) : admin.updateCustomField(id, input, token))),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: (field: CustomField) => guard((token) => admin.deleteCustomField(field.id, token)),
    onSuccess: refresh,
  });
  const own = useMutation({
    mutationFn: (allow: boolean) => guard((token) => admin.allowOwnFields(allow, token)),
    onSuccess: refresh,
  });
  if (fields.isPending) return <Loading />;
  if (!fields.data) return <ErrorNotice error={fields.error} />;
  const busy = save.isPending || remove.isPending || own.isPending;
  return (
    <>
      <FieldsView
        definitions={fields.data}
        busy={busy}
        error={save.error ?? remove.error ?? own.error}
        onSave={(id, input) => {
          remove.reset();
          own.reset();
          return save.mutateAsync({ id, input }).then(
            () => true,
            () => false,
          );
        }}
        onDelete={(field) => {
          save.reset();
          own.reset();
          return remove.mutateAsync(field).then(
            () => true,
            () => false,
          );
        }}
        onReset={() => {
          save.reset();
          remove.reset();
          own.reset();
        }}
        onAllowOwn={(allow) => {
          save.reset();
          remove.reset();
          own.mutate(allow);
        }}
      />
      {dialog}
    </>
  );
}
