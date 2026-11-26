import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { IntlMessageFormat } from 'intl-messageformat';
import { describe, expect, it, vi } from 'vitest';
import { type MessageId, messages } from '@/i18n';
import { renderWithIntl } from '@/test/render';
import { ServerHolds, serverRecord } from './ServerHolds';
import type { VaultItem } from './vault';

const item: VaultItem = {
  id: '3f6a0c2e-4b1d-4e7a-9c52-6d0f8a91b4e3',
  owner: 'user:7b2e1c90-5a3f-4d68-8e14-c3a9f0d2b657',
  kind: 'login',
  revision: 14,
  keyVersion: 3,
  data: { name: 'GitHub', password: 'hunter2' },
  sizes: { ciphertext: 1214, itemKey: 1648 },
};

// The words come from the messages, so the test says them the way the page does.
const t = (id: MessageId, values?: Record<string, string | number>) =>
  String(new IntlMessageFormat(messages[id] ?? id, 'en').format(values));

describe('serverRecord', () => {
  it('lists the id, kind, owner, revision, key version, wrapped key size and body cipher and size', () => {
    expect(serverRecord(item, t)).toBe(
      [
        'item     3f6a0c2e-4b1d-4e7a-9c52-6d0f8a91b4e3   login',
        'owner    user:7b2e1c90-5a3f-4d68-8e14-c3a9f0d2b657',
        'revision 14 · key version 3',
        'key      1648 B wrapped',
        'body     AES-256-GCM, 1214 B',
      ].join('\n'),
    );
  });

  it('adds the collection when the item sits in one, and lines the words up again', () => {
    const inSpace: VaultItem = { ...item, owner: 'space:5a1b', collectionId: 'c0ffee00-0000-4000-8000-000000000001' };
    expect(serverRecord(inSpace, t).split('\n')).toEqual([
      'item       3f6a0c2e-4b1d-4e7a-9c52-6d0f8a91b4e3   login',
      'owner      space:5a1b',
      'collection c0ffee00-0000-4000-8000-000000000001',
      'revision   14 · key version 3',
      'key        1648 B wrapped',
      'body       AES-256-GCM, 1214 B',
    ]);
  });

  it('says its words through the messages, in any language', () => {
    const shout = (id: MessageId, values?: Record<string, string | number>) => t(id, values).toUpperCase();
    expect(serverRecord(item, shout)).toContain('REVISION 14 · KEY VERSION 3');
  });

  it('holds no name, password or note: those are inside the ciphertext', () => {
    const record = serverRecord(item, t);
    expect(record).not.toContain('GitHub');
    expect(record).not.toContain('hunter2');
  });
});

describe('ServerHolds', () => {
  function open() {
    const onClose = vi.fn();
    renderWithIntl(<ServerHolds item={item} name="GitHub" onClose={onClose} />);
    return onClose;
  }

  it('is a modal dialog named by its heading, with the record and what it leaves out', () => {
    open();
    const dialog = screen.getByRole('dialog', { name: 'What the server holds' });
    expect(dialog).toHaveTextContent('This is everything the server stores for GitHub.');
    expect(screen.getByTestId('server-record')).toHaveTextContent('revision 14 · key version 3');
    expect(dialog).toHaveTextContent('Ciphertext, its kind, sizes and revision. No name, address, password or note.');
  });

  it('closes with the Close button, in the footer or in the corner', async () => {
    const onClose = open();
    const user = userEvent.setup();
    const buttons = screen.getAllByRole('button', { name: 'Close' });
    expect(buttons).toHaveLength(2);
    await user.click(buttons[1] as HTMLElement);
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.click(buttons[0] as HTMLElement);
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it('closes on Escape', async () => {
    const onClose = open();
    await userEvent.setup().keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('keeps focus inside while it is open', async () => {
    open();
    const user = userEvent.setup();
    const dialog = screen.getByRole('dialog');
    expect(dialog.contains(document.activeElement)).toBe(true);
    for (let i = 0; i < 5; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 3; i += 1) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });
});
