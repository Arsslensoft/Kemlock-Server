import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { CustomFields } from '@/api/admin';
import { renderWithIntl } from '@/test/render';
import { FieldsView, type FieldsViewProps } from './Fields';

const DEFINITIONS: CustomFields = {
  fields: [
    { id: 'f1', name: 'Employee ID', type: 'text', kinds: 'all' },
    { id: 'f2', name: 'Cost center', type: 'text', kinds: ['card'] },
    { id: 'f3', name: 'Security question', type: 'hidden', kinds: ['login'] },
    { id: 'f4', name: 'Account owner', type: 'checkbox', kinds: ['login', 'card'] },
  ],
  allowOwn: true,
};

function view(over: Partial<FieldsViewProps> = {}) {
  const props: FieldsViewProps = {
    definitions: DEFINITIONS,
    onSave: vi.fn(),
    onDelete: vi.fn(),
    onAllowOwn: vi.fn(),
    ...over,
  };
  renderWithIntl(<FieldsView {...props} />);
  return props;
}

/** Opens the menu of a field's row and picks an item. */
async function pick(user: ReturnType<typeof userEvent.setup>, field: string, item: string) {
  await user.click(screen.getByRole('button', { name: `Actions for ${field}` }));
  await user.click(await screen.findByRole('menuitem', { name: item }));
}

describe('the Custom fields page', () => {
  it('has its title, its lede and the Add a field button', () => {
    view();
    expect(screen.getByRole('heading', { name: 'Custom fields', level: 1 })).toBeInTheDocument();
    expect(
      screen.getByText(
        'Fields people can add to their items. They pick from this list, or make their own if you allow it.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add a field' })).toBeInTheDocument();
  });

  it('lists each field with its type and the types it is on, and no Required column', () => {
    view();
    const table = screen.getByRole('table');
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual([
      'Field',
      'Type',
      'On',
      'Actions',
    ]);
    const rows = within(table).getAllByRole('row').slice(1);
    const cells = rows.map((row) => Array.from(row.children).map((cell) => cell.textContent));
    expect(cells).toEqual([
      ['Employee ID', 'Text', 'All types', ''],
      ['Cost center', 'Text', 'Cards', ''],
      ['Security question', 'Hidden', 'Logins', ''],
      ['Account owner', 'Checkbox', 'Logins, Cards', ''],
    ]);
    expect(screen.queryByText(/required/i)).toBeNull();
  });

  it('says how it is with no fields', () => {
    view({ definitions: { fields: [], allowOwn: true } });
    expect(screen.getByText(/No fields yet/)).toBeInTheDocument();
  });

  it('says every field is optional and that the values never reach the server', () => {
    view();
    expect(screen.getByText(/Every field is optional/)).toHaveTextContent(/the server never sees them/);
  });
});

describe('the switch for people adding their own fields', () => {
  it('shows what the server says, with its hint', () => {
    view();
    const on = screen.getByRole('switch', { name: 'People may add their own fields' });
    expect(on).toBeChecked();
    expect(on).toHaveAccessibleDescription('When off, items can only carry the fields above.');
  });

  it('asks to turn it on when it is off', async () => {
    const props = view({ definitions: { ...DEFINITIONS, allowOwn: false } });
    const sw = screen.getByRole('switch', { name: 'People may add their own fields' });
    expect(sw).not.toBeChecked();
    await userEvent.setup().click(sw);
    expect(props.onAllowOwn).toHaveBeenCalledWith(true);
  });

  it('asks to turn it off when it is on', async () => {
    const props = view();
    await userEvent.setup().click(screen.getByRole('switch', { name: 'People may add their own fields' }));
    expect(props.onAllowOwn).toHaveBeenCalledWith(false);
  });

  it('is disabled while a change is on its way', () => {
    view({ busy: true });
    expect(screen.getByRole('switch', { name: 'People may add their own fields' })).toBeDisabled();
  });
});

describe('adding a field', () => {
  it('opens a form, and sends the cleaned name, the type and all types', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a field' });
    await user.type(within(dialog).getByLabelText('Name'), '  Badge   number ');
    await user.selectOptions(within(dialog).getByLabelText('Type'), 'checkbox');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(props.onSave).toHaveBeenCalledWith(null, { name: 'Badge number', type: 'checkbox', kinds: 'all' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('offers the ten types, and not a file or a passkey, when it is only some of them', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a field' });
    expect(within(dialog).queryByRole('checkbox')).toBeNull();
    await user.click(within(dialog).getByRole('radio', { name: /Only these types/ }));
    const labels = within(dialog)
      .getAllByRole('checkbox')
      .map((box) => box.closest('label')?.textContent);
    expect(labels).toEqual([
      'Logins',
      'Notes',
      'MFA codes',
      'Backup codes',
      'Cards',
      'Identities',
      'Contacts',
      'Certificates',
      'SSH keys',
      'PGP keys',
    ]);
    await user.type(within(dialog).getByLabelText('Name'), 'Pin');
    await user.click(within(dialog).getByRole('checkbox', { name: 'Cards' }));
    await user.click(within(dialog).getByRole('checkbox', { name: 'Logins' }));
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    // In the apps' order, not the order they were ticked in.
    expect(props.onSave).toHaveBeenCalledWith(null, { name: 'Pin', type: 'text', kinds: ['login', 'card'] });
  });

  it('refuses an empty name and no types, and sends nothing', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a field' });
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText(/Enter a name of 1 to 64 characters/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true');
    await user.click(within(dialog).getByRole('radio', { name: /Only these types/ }));
    await user.type(within(dialog).getByLabelText('Name'), 'Pin');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText('Pick at least one type.')).toBeInTheDocument();
    expect(props.onSave).not.toHaveBeenCalled();
  });

  it('has no Required anywhere in the form', async () => {
    view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a field' });
    expect(within(dialog).queryByText(/required/i)).toBeNull();
    expect(within(dialog).getByLabelText('Name')).not.toBeRequired();
  });

  it('keeps the form open, with what was typed, when the save failed', async () => {
    const props = view({ onSave: vi.fn(async () => false) });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a field' });
    await user.type(within(dialog).getByLabelText('Name'), 'Pin');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(props.onSave).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('dialog', { name: 'Add a field' })).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Name')).toHaveValue('Pin');
  });

  it('closes on Cancel without sending anything', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a field' });
    await user.type(within(dialog).getByLabelText('Name'), 'Pin');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(props.onSave).not.toHaveBeenCalled();
  });
});

describe('changing a field', () => {
  it('opens the form with the field in it and sends the change by its id', async () => {
    const props = view();
    const user = userEvent.setup();
    await pick(user, 'Account owner', 'Edit');
    const dialog = await screen.findByRole('dialog', { name: 'Change Account owner' });
    expect(within(dialog).getByLabelText('Name')).toHaveValue('Account owner');
    expect(within(dialog).getByLabelText('Type')).toHaveValue('checkbox');
    expect(within(dialog).getByRole('radio', { name: /Only these types/ })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: 'Logins' })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: 'Cards' })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: 'Notes' })).not.toBeChecked();
    await user.click(within(dialog).getByRole('checkbox', { name: 'Cards' }));
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(props.onSave).toHaveBeenCalledWith('f4', { name: 'Account owner', type: 'checkbox', kinds: ['login'] });
  });

  it('starts a field that is on all types with the all types choice', async () => {
    view();
    const user = userEvent.setup();
    await pick(user, 'Employee ID', 'Edit');
    const dialog = await screen.findByRole('dialog', { name: 'Change Employee ID' });
    expect(within(dialog).getByRole('radio', { name: /All types/ })).toBeChecked();
    expect(within(dialog).queryByRole('checkbox')).toBeNull();
  });
});

describe('deleting a field', () => {
  it('asks first, and says what happens to the values already on items', async () => {
    const props = view();
    const user = userEvent.setup();
    await pick(user, 'Cost center', 'Delete');
    const dialog = await screen.findByRole('dialog', { name: 'Delete Cost center?' });
    expect(within(dialog).getByText(/Items that already have a value for it keep that value/)).toBeInTheDocument();
    expect(props.onDelete).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
    expect(props.onDelete).toHaveBeenCalledWith(DEFINITIONS.fields[1]);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('changes nothing on Cancel', async () => {
    const props = view();
    const user = userEvent.setup();
    await pick(user, 'Cost center', 'Delete');
    const dialog = await screen.findByRole('dialog', { name: 'Delete Cost center?' });
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(props.onDelete).not.toHaveBeenCalled();
  });

  it('keeps the question open when the delete failed', async () => {
    view({ onDelete: vi.fn(async () => false) });
    const user = userEvent.setup();
    await pick(user, 'Cost center', 'Delete');
    const dialog = await screen.findByRole('dialog', { name: 'Delete Cost center?' });
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
    expect(screen.getByRole('dialog', { name: 'Delete Cost center?' })).toBeInTheDocument();
  });
});

describe('a row menu', () => {
  it('is named for its field and offers Edit and Delete', async () => {
    view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Actions for Employee ID' }));
    const menu = await screen.findByRole('menu', { name: 'Actions for Employee ID' });
    expect(within(menu).getAllByRole('menuitem').map((item) => item.textContent)).toEqual(['Edit', 'Delete']);
  });
});

describe('what an earlier failure left behind', () => {
  it('is cleared when a form opens, when it is cancelled and when a question is put away', async () => {
    const onReset = vi.fn();
    view({ onReset });
    const user = userEvent.setup();
    expect(onReset).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const form = await screen.findByRole('dialog', { name: 'Add a field' });
    expect(onReset).toHaveBeenCalledTimes(1);
    await user.click(within(form).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(onReset).toHaveBeenCalledTimes(2);

    await pick(user, 'Cost center', 'Edit');
    await screen.findByRole('dialog', { name: 'Change Cost center' });
    expect(onReset).toHaveBeenCalledTimes(3);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(onReset).toHaveBeenCalledTimes(4);

    await pick(user, 'Cost center', 'Delete');
    const ask = await screen.findByRole('dialog', { name: 'Delete Cost center?' });
    expect(onReset).toHaveBeenCalledTimes(5);
    await user.click(within(ask).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(onReset).toHaveBeenCalledTimes(6);
  });

  it('is left alone by a save that worked: the form closes without a reset of its own', async () => {
    const onReset = vi.fn();
    view({ onReset });
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a field' }));
    const form = await screen.findByRole('dialog', { name: 'Add a field' });
    await user.type(within(form).getByLabelText('Name'), 'Pin');
    await user.click(within(form).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(onReset).toHaveBeenCalledTimes(1);
  });
});
