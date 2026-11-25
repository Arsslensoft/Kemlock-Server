import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import type { CustomFieldDefinitions } from '@/api/customFields';
import { renderWithIntl } from '@/test/render';
import type { ItemData, VaultItem } from '../vault';
import { CustomFieldsEditor } from './CustomFieldsEditor';
import { LinkedItemsEditor } from './LinkedItemsEditor';
import { FormEnvContext } from './env';
import { type FieldValue, writeFieldValues } from './extras';
import { NoteForm, type NoteFormValues, noteDefaults } from './note';

const DEFINITIONS: CustomFieldDefinitions = {
  allowOwn: true,
  fields: [
    { id: 'f-emp', name: 'Employee ID', type: 'text', kinds: 'all' },
    { id: 'f-q', name: 'Security question', type: 'hidden', kinds: ['login'] },
    { id: 'f-ok', name: 'Reviewed', type: 'checkbox', kinds: ['login', 'note'] },
  ],
};

function Fields({
  definitions = DEFINITIONS,
  kind = 'login',
  initial = [],
  seen,
}: {
  definitions?: CustomFieldDefinitions;
  kind?: string;
  initial?: FieldValue[];
  seen?: (value: FieldValue[]) => void;
}) {
  const [value, setValue] = useState<FieldValue[]>(initial);
  return (
    <CustomFieldsEditor
      kind={kind}
      value={value}
      onChange={(next) => {
        setValue(next);
        seen?.(next);
      }}
      definitions={definitions}
    />
  );
}

describe('the custom fields card', () => {
  it('starts empty, with the Add a field menu and no Required anywhere', async () => {
    renderWithIntl(<Fields />);
    expect(screen.getByText('No custom fields on this item.')).toBeInTheDocument();
    expect(screen.queryByText(/required/i)).not.toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Add a field' }));
    expect(screen.getByText('From your admin')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Your own field/ })).toBeInTheDocument();
  });

  it('lists the admin fields for the kind, with their type, and leaves out the others', async () => {
    renderWithIntl(<Fields kind="note" />);
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Add a field' }));
    const menu = screen.getByRole('dialog', { name: 'Add a field' });
    expect(within(menu).getByRole('button', { name: /Employee ID/ })).toHaveTextContent('Text');
    expect(within(menu).getByRole('button', { name: /Reviewed/ })).toHaveTextContent('Checkbox');
    expect(within(menu).queryByRole('button', { name: /Security question/ })).not.toBeInTheDocument();
  });

  it('adds an admin field with its fixed name and type and an Admin badge, and the person fills in the value', async () => {
    const seen = vi.fn();
    renderWithIntl(<Fields seen={seen} />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    await user.click(screen.getByRole('button', { name: /Employee ID/ }));
    expect(screen.getByText('Admin')).toBeInTheDocument();
    expect(screen.queryByLabelText('Field 1 name')).not.toBeInTheDocument();
    await user.type(screen.getByLabelText('Employee ID'), 'E-42');
    const last = seen.mock.calls.at(-1)?.[0] as FieldValue[];
    expect(writeFieldValues(last, null)).toEqual({
      fields: [{ name: 'Employee ID', value: 'E-42', kind: 'text', adminField: 'f-emp' }],
    });
    // Once added, it is not offered again.
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    expect(screen.queryByRole('button', { name: /^Employee ID/ })).not.toBeInTheDocument();
  });

  it('shows a hidden admin field with the eye inside its box', async () => {
    renderWithIntl(<Fields />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    await user.click(screen.getByRole('button', { name: /Security question/ }));
    const box = screen.getByLabelText('Security question');
    expect(box).toHaveAttribute('type', 'password');
    await user.click(screen.getByRole('button', { name: 'Show the password' }));
    expect(box).toHaveAttribute('type', 'text');
  });

  it('adds a field of their own with a name, a type and a value, and removes it', async () => {
    const seen = vi.fn();
    renderWithIntl(<Fields seen={seen} />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    await user.click(screen.getByRole('button', { name: /Your own field/ }));
    await user.type(screen.getByLabelText('Field 1 name'), 'Recovery email');
    await user.type(screen.getByLabelText('Field 1 value'), 'sam.backup@example.org');
    expect(writeFieldValues(seen.mock.calls.at(-1)?.[0] as FieldValue[], null)).toEqual({
      fields: [{ name: 'Recovery email', value: 'sam.backup@example.org', kind: 'text' }],
    });
    await user.selectOptions(screen.getByLabelText('Field 1 type'), 'Checkbox');
    await user.click(screen.getByLabelText('Field 1 value'));
    expect(writeFieldValues(seen.mock.calls.at(-1)?.[0] as FieldValue[], null)).toEqual({
      fields: [{ name: 'Recovery email', value: 'true', kind: 'boolean' }],
    });
    await user.click(screen.getByRole('button', { name: 'Remove field 1' }));
    expect(screen.getByText('No custom fields on this item.')).toBeInTheDocument();
  });

  it('offers no field of their own when the admin turned that off, and says so', async () => {
    renderWithIntl(<Fields definitions={{ ...DEFINITIONS, allowOwn: false }} />);
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Add a field' }));
    expect(screen.queryByRole('button', { name: /Your own field/ })).not.toBeInTheDocument();
    expect(screen.getByText(/^Pick a field your admin set up\. /)).toBeInTheDocument();
  });

  it('has no Add button when there is nothing to add', () => {
    renderWithIntl(<Fields definitions={{ fields: [], allowOwn: false }} />);
    expect(screen.queryByRole('button', { name: 'Add a field' })).not.toBeInTheDocument();
  });

  it('says it opens a dialog, and closes it when focus leaves', async () => {
    renderWithIntl(
      <>
        <Fields />
        <button type="button">Outside</button>
      </>,
    );
    const user = userEvent.setup({ delay: null });
    const opener = screen.getByRole('button', { name: 'Add a field' });
    expect(opener).toHaveAttribute('aria-haspopup', 'dialog');
    expect(opener).toHaveAttribute('aria-expanded', 'false');
    await user.click(opener);
    expect(opener).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('dialog', { name: 'Add a field' })).toBeInTheDocument();
    // Focus moving inside the panel does not close it.
    act(() => screen.getByRole('dialog', { name: 'Add a field' }).focus());
    expect(screen.getByRole('dialog', { name: 'Add a field' })).toBeInTheDocument();
    // Focus leaving it does.
    act(() => screen.getByRole('button', { name: 'Outside' }).focus());
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveAttribute('aria-expanded', 'false');
  });

  it('closes the menu with Escape', async () => {
    renderWithIntl(<Fields />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    await user.keyboard('{Escape}');
    expect(screen.queryByText('From your admin')).not.toBeInTheDocument();
  });
});

function item(id: string, kind: string, data: ItemData): VaultItem {
  return { id, owner: 'user:u', kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const D = '44444444-4444-4444-8444-444444444444';

const ITEMS = [
  item(A, 'login', { name: 'GitHub' }),
  item(B, 'otp', { issuer: 'GitHub code' }),
  item(C, 'backup-codes', { serviceName: 'GitHub recovery codes' }),
  item(D, 'note', { name: 'Old note', trashedAt: '2026-11-01T00:00:00Z' }),
];

function Links({ initial = [], selfId, seen }: { initial?: string[]; selfId?: string; seen?: (v: string[]) => void }) {
  const [value, setValue] = useState(initial);
  return (
    <LinkedItemsEditor
      value={value}
      onChange={(next) => {
        setValue(next);
        seen?.(next);
      }}
      items={ITEMS.filter((other) => other.data?.['trashedAt'] === undefined)}
      selfId={selfId}
    />
  );
}

describe('the linked items card', () => {
  it('says nothing is linked yet', () => {
    renderWithIntl(<Links />);
    expect(screen.getByText('Nothing linked yet.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Link an item' })).toBeInTheDocument();
  });

  it('shows a chip with the item name and kind, and unlinks it', async () => {
    const seen = vi.fn();
    renderWithIntl(<Links initial={[B, C]} seen={seen} />);
    const chip = screen.getByText('GitHub code').closest('li');
    expect(chip).toHaveTextContent('MFA code');
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Unlink GitHub code (MFA code)' }));
    expect(screen.queryByText('GitHub code')).not.toBeInTheDocument();
    expect(seen).toHaveBeenLastCalledWith([C]);
  });

  it('links an item found in the picker, not itself, not one already linked and not one in the Trash', async () => {
    const seen = vi.fn();
    renderWithIntl(<Links selfId={A} initial={[B]} seen={seen} />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Link an item' }));
    const picker = screen.getByRole('dialog', { name: 'Link an item' });
    expect(within(picker).getAllByRole('button').map((button) => button.textContent)).toEqual([
      expect.stringContaining('GitHub recovery codes'),
    ]);
    await user.type(within(picker).getByRole('searchbox', { name: 'Search your items' }), 'zzz');
    expect(within(picker).getByText('No other item to link.')).toBeInTheDocument();
    await user.clear(within(picker).getByRole('searchbox', { name: 'Search your items' }));
    await user.click(within(picker).getByRole('button', { name: /GitHub recovery codes/ }));
    expect(seen).toHaveBeenLastCalledWith([B, C]);
    expect(screen.getByRole('button', { name: 'Unlink GitHub recovery codes (Backup codes)' })).toBeInTheDocument();
    // The picker closed.
    expect(screen.queryByRole('dialog', { name: 'Link an item' })).not.toBeInTheDocument();
  });

  it('says it opens a dialog, and closes it when focus leaves', async () => {
    renderWithIntl(
      <>
        <Links selfId={A} />
        <button type="button">Outside</button>
      </>,
    );
    const user = userEvent.setup({ delay: null });
    const opener = screen.getByRole('button', { name: 'Link an item' });
    expect(opener).toHaveAttribute('aria-haspopup', 'dialog');
    await user.click(opener);
    expect(screen.getByRole('dialog', { name: 'Link an item' })).toBeInTheDocument();
    act(() => screen.getByRole('button', { name: 'Outside' }).focus());
    expect(screen.queryByRole('dialog', { name: 'Link an item' })).not.toBeInTheDocument();
  });

  it('shows a link to an item that is not there, and lets it be unlinked', async () => {
    const seen = vi.fn();
    renderWithIntl(<Links initial={[D]} seen={seen} />);
    expect(screen.getByText('Item not available')).toBeInTheDocument();
    await userEvent
      .setup({ delay: null })
      .click(screen.getByRole('button', { name: 'Unlink an item that is not available' }));
    expect(seen).toHaveBeenLastCalledWith([]);
  });
});

describe('the cards in a form', () => {
  it('put the links and custom fields chosen into what the form submits', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <FormEnvContext.Provider
        value={{ definitions: DEFINITIONS, items: ITEMS, canWrite: () => true, selfId: undefined, renderItem: (_i, l) => l }}
      >
        <NoteForm initial={noteDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />
      </FormEnvContext.Provider>,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Recovery plan');
    await user.click(screen.getByRole('button', { name: 'Link an item' }));
    await user.click(screen.getByRole('button', { name: /GitHub code/ }));
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    await user.click(screen.getByRole('button', { name: /Employee ID/ }));
    await user.type(screen.getByLabelText('Employee ID'), 'E-42');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const values = onSubmit.mock.calls[0]?.[0] as NoteFormValues;
    expect(values.links).toEqual([B]);
    expect(values.fields).toMatchObject([{ name: 'Employee ID', value: 'E-42', adminField: 'f-emp' }]);
  });

  it('refuse an own field that has a value and no name', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<NoteForm initial={noteDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Note');
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    await user.click(screen.getByRole('button', { name: /Your own field/ }));
    await user.type(screen.getByLabelText('Field 1 value'), 'orphan');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Give the field a name, or clear its value.')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
