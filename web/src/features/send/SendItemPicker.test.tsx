import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { VaultItem } from '@/features/vault/vault';
import { renderWithIntl } from '@/test/render';
import { SendView } from './Send';
import { SendItemPicker, itemsOfKind } from './SendItemPicker';

function item(id: string, kind: string, data: Record<string, unknown> | null): VaultItem {
  return { id, owner: 'me', kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

const ITEMS = [
  item('1', 'card', { name: 'Visa', number: '4111111111111111', expMonth: 5, expYear: 2029, history: ['x'] }),
  item('2', 'card', { name: 'Amex' }),
  item('3', 'login', { name: 'GitHub', username: 'sam', password: 'pw' }),
  item('4', 'card', null),
];

describe('itemsOfKind', () => {
  it('keeps the readable items of the kind, by name', () => {
    expect(itemsOfKind(ITEMS, 'card').map((i) => i.id)).toEqual(['2', '1']);
  });
});

describe('SendItemPicker', () => {
  it('offers the items of the kind and reports the choice', async () => {
    const onSelect = vi.fn();
    renderWithIntl(<SendItemPicker items={ITEMS} kind="card" selectedId={undefined} onSelect={onSelect} />);
    expect(screen.queryByRole('option', { name: 'GitHub' })).not.toBeInTheDocument();
    await userEvent.setup().selectOptions(screen.getByLabelText('Item to send'), 'Visa');
    expect(onSelect).toHaveBeenCalledWith(ITEMS[0]);
  });

  it('says so when the vault has none of the kind', () => {
    renderWithIntl(<SendItemPicker items={ITEMS} kind="contact" selectedId={undefined} onSelect={vi.fn()} />);
    expect(screen.getByLabelText('Item to send')).toBeDisabled();
    expect(screen.getByText('No items of this kind in your vault')).toBeInTheDocument();
  });
});

describe('SendView with an item', () => {
  it('shows an error and sends nothing when the item is too large', async () => {
    const onCreate = vi.fn();
    const big = [item('9', 'note', { name: 'Huge', text: 'x'.repeat(70_000) })];
    renderWithIntl(
      <SendView rows={[]} now={new Date()} items={big} onCreate={onCreate} onCopy={vi.fn()} onDelete={vi.fn()} />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Note' }));
    await user.selectOptions(screen.getByLabelText('Item to send'), 'Huge');
    await user.click(screen.getByRole('button', { name: 'Create link' }));
    expect(onCreate).not.toHaveBeenCalled();
    expect(screen.getByText(/could not be turned into a Send/)).toBeInTheDocument();
  });

  it('creates a text Send whose text is the item envelope', async () => {
    const onCreate = vi.fn();
    renderWithIntl(
      <SendView rows={[]} now={new Date()} items={ITEMS} onCreate={onCreate} onCopy={vi.fn()} onDelete={vi.fn()} />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Card' }));
    expect(screen.getByRole('button', { name: 'Create link' })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText('Item to send'), 'Visa');
    expect(screen.getByLabelText('Name')).toHaveValue('Visa');
    await user.click(screen.getByRole('button', { name: 'Create link' }));
    const values = onCreate.mock.calls[0]?.[0] as { kind: string; text: string };
    expect(values.kind).toBe('text');
    expect(JSON.parse(values.text)).toEqual({
      kemlockSend: 1,
      kind: 'card',
      name: 'Visa',
      fields: { number: '4111111111111111', expiry: '05/2029' },
    });
  });
});
