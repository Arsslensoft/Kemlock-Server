import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useT } from '@/i18n';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { renderWithIntl } from '@/test/render';
import { saveBatch } from './batch';
import { LinkedItems, sublineOf } from './LinkedItems';
import { linkInputs, readLinks, unlinkInputs } from './links';
import { type VaultDeps, VaultStore, type VaultItem } from './vault';

// The card only needs its links to be anchors to the item.
vi.mock('@tanstack/react-router', async () => {
  const { createElement } = await import('react');
  return {
    Link: ({ to, params, children, className }: { to: string; params?: { itemId: string }; children: unknown; className?: string }) =>
      createElement('a', { href: to.replace('$itemId', params?.itemId ?? ''), className }, children as never),
  };
});

let counter = 0;
function vaultItem(kind: string, data: Record<string, unknown>, extra: { id?: string } = {}): VaultItem {
  counter += 1;
  return {
    id: extra.id ?? `00000000-0000-4000-8000-${String(counter).padStart(12, '0')}`,
    owner: 'user:00000000-0000-4000-8000-0000000000aa',
    kind,
    revision: 1,
    keyVersion: 1,
    data,
    sizes: { ciphertext: 10, itemKey: 10 },
  };
}

const LOGIN = '00000000-0000-4000-8000-0000000000a1';
const CODE = '00000000-0000-4000-8000-0000000000a2';
const BACKUP = '00000000-0000-4000-8000-0000000000a3';
const PASSKEY = '00000000-0000-4000-8000-0000000000a4';
const OLD = '00000000-0000-4000-8000-0000000000a5';

function vault(): VaultItem[] {
  return [
    vaultItem('login', { name: 'GitHub', username: 'sam@example.org', urls: ['https://github.com'] }, { id: LOGIN }),
    vaultItem('otp', { name: 'GitHub code', issuer: 'GitHub', period: 30, urls: ['https://github.com'] }, { id: CODE }),
    vaultItem(
      'backup-codes',
      {
        name: 'GitHub recovery codes',
        codes: [{ code: 'aaaa' }, { code: 'bbbb', used: true }, { code: 'cccc' }],
      },
      { id: BACKUP },
    ),
    vaultItem('passkey', { name: 'GitHub passkey', rpId: 'github.com' }, { id: PASSKEY }),
    vaultItem('login', { name: 'Old login', trashedAt: '2026-11-01T00:00:00.000Z' }, { id: OLD }),
  ];
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

/**
 * The card as the item page wires it: a link or an unlink writes both items through saveBatch, and
 * the card is shown again with what was written. Two buttons stand in for opening the other item.
 */
function Page({
  items,
  start,
  canWrite = () => true,
  failUnlink = false,
}: {
  items: VaultItem[];
  start: string;
  canWrite?: (item: VaultItem) => boolean;
  failUnlink?: boolean;
}) {
  const [store] = useState(() => {
    const s = new VaultStore();
    for (const item of items) s.items.set(item.id, item);
    return s;
  });
  const [all, setAll] = useState<VaultItem[]>(items);
  const [openId, setOpenId] = useState(start);
  const deps: VaultDeps = {
    api: {
      putItem: async (dto) => ({ item: dto, etag: null }),
      putBatch: async (request) => request.writes.map((w) => w.item),
      sync: async () => ({ notModified: true }) as never,
    },
    crypto,
    now: () => new Date('2026-11-25T12:00:00Z'),
  };
  const open = all.find((item) => item.id === openId) as VaultItem;
  return (
    <>
      <button type="button" onClick={() => setOpenId(LOGIN)}>
        open the login
      </button>
      <button type="button" onClick={() => setOpenId(CODE)}>
        open the code
      </button>
      <LinkedItems
        item={open}
        all={all}
        canWrite={canWrite}
        onLink={async (other) => {
          await saveBatch(deps, store, linkInputs(open, other));
          setAll([...store.items.values()]);
        }}
        onUnlink={async (other) => {
          if (failUnlink) throw new Error('refused');
          await saveBatch(deps, store, unlinkInputs(open, other));
          setAll([...store.items.values()]);
        }}
      />
      <output data-testid="stored">{JSON.stringify([...store.items.values()].map((i) => [i.id, readLinks(i.data)]))}</output>
    </>
  );
}

const stored = () => JSON.parse(screen.getByTestId('stored').textContent ?? '[]') as Array<[string, string[]]>;
const linksOf = (id: string) => stored().find(([key]) => key === id)?.[1] ?? [];

describe('sublineOf', () => {
  function Sub({ item }: { item: VaultItem }) {
    const t = useT();
    return <p data-testid="sub">{sublineOf(item, t)}</p>;
  }
  const line = (item: VaultItem) => {
    const { unmount } = renderWithIntl(<Sub item={item} />);
    const text = screen.getByTestId('sub').textContent;
    unmount();
    return text;
  };

  it('says the type and one fact about the item', () => {
    const [login, code, backup, passkey, old] = vault() as [VaultItem, VaultItem, VaultItem, VaultItem, VaultItem];
    expect(line(login)).toBe('Login · sam@example.org');
    expect(line(code)).toBe('MFA code · github.com · every 30 s');
    expect(line(backup)).toBe('Backup codes · 3 codes, 2 unused');
    expect(line(passkey)).toBe('Passkey · github.com');
    expect(line(old)).toBe('Login · In the Trash');
    expect(line(vaultItem('card', { name: 'Visa', brand: 'Visa', number: '4111111111111111' }))).toBe('Card · Visa · •••• 1111');
    expect(line(vaultItem('contact', { name: 'Ada', company: 'Analytical Engines' }))).toBe('Contact · Analytical Engines');
    expect(line(vaultItem('file', { name: 'Lease', file: { name: 'a.pdf', size: 2_400_000, key: 'k' } }))).toBe('File · 2.4 MB');
    expect(line(vaultItem('ssh-key', { name: 'k' }))).toBe('SSH key');
  });
});

describe('the Linked items card', () => {
  it('says nothing is linked yet', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} />);
    const card = screen.getByRole('region', { name: 'Linked items' });
    expect(card).toHaveTextContent('Nothing linked yet.');
    expect(within(card).getByRole('button', { name: 'Link an item' })).toBeInTheDocument();
  });

  it('lists each linked item with its name, type and a line, as a link to that item', async () => {
    const items = vault();
    items[0] = vaultItem('login', { name: 'GitHub', links: [{ id: CODE }, { id: BACKUP }, { id: PASSKEY }] }, { id: LOGIN });
    renderWithIntl(<Page items={items} start={LOGIN} />);
    const card = screen.getByRole('region', { name: 'Linked items' });
    const links = within(card).getAllByRole('link');
    expect(links.map((link) => link.textContent)).toEqual([
      'GitHub codeMFA code · github.com · every 30 s',
      'GitHub passkeyPasskey · github.com',
      'GitHub recovery codesBackup codes · 3 codes, 2 unused',
    ]);
    expect(links.map((link) => link.getAttribute('href'))).toEqual([`/vault/${CODE}`, `/vault/${PASSKEY}`, `/vault/${BACKUP}`]);
  });

  it('shows an item that links here even when this item does not name it', async () => {
    const items = vault();
    items[1] = vaultItem('otp', { name: 'GitHub code', links: [{ id: LOGIN }] }, { id: CODE });
    renderWithIntl(<Page items={items} start={LOGIN} />);
    expect(within(screen.getByRole('region', { name: 'Linked items' })).getByRole('link')).toHaveTextContent('GitHub code');
  });

  it('is read-only for an item in the Trash: it lists its links and offers no change', async () => {
    const items = vault();
    items[0] = vaultItem('login', { name: 'GitHub', links: [{ id: CODE }] }, { id: LOGIN });
    function Fixed() {
      return (
        <LinkedItems item={items[0] as VaultItem} all={items} canWrite={() => true} readOnly onLink={vi.fn()} onUnlink={vi.fn()} />
      );
    }
    renderWithIntl(<Fixed />);
    expect(screen.getByRole('link', { name: /GitHub code/ })).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});

describe('Link an item', () => {
  async function openPicker() {
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Link an item' }));
    const dialog = await screen.findByRole('dialog', { name: 'Link an item' });
    return { user, dialog };
  }

  it('opens a picker that searches the vault, with the search box focused', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} />);
    const { user, dialog } = await openPicker();
    const search = within(dialog).getByRole('searchbox', { name: 'Search the vault' });
    expect(search).toHaveFocus();
    // Everything that can be linked, by name: not the login itself and not what is in the Trash.
    expect(within(dialog).getAllByRole('button', { name: /^Link / }).map((b) => b.getAttribute('aria-label'))).toEqual([
      'Link GitHub code',
      'Link GitHub passkey',
      'Link GitHub recovery codes',
    ]);
    await user.type(search, 'recovery');
    expect(within(dialog).getAllByRole('button', { name: /^Link / })).toHaveLength(1);
    await user.clear(search);
    await user.type(search, 'zzz');
    expect(within(dialog).getByRole('status')).toHaveTextContent('No item to link');
  });

  it('leaves out what this person may not change', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} canWrite={(item) => item.id !== PASSKEY} />);
    const { dialog } = await openPicker();
    expect(within(dialog).queryByRole('button', { name: 'Link GitHub passkey' })).not.toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Link GitHub code' })).toBeInTheDocument();
  });

  it('links the picked item, closes, and shows it', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} />);
    const { user, dialog } = await openPicker();
    await user.click(within(dialog).getByRole('button', { name: 'Link GitHub code' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    const card = screen.getByRole('region', { name: 'Linked items' });
    expect(within(card).getByRole('link')).toHaveTextContent('GitHub code');
    // The picked item is no longer offered.
    await user.click(within(card).getByRole('button', { name: 'Link an item' }));
    expect(within(await screen.findByRole('dialog')).queryByRole('button', { name: 'Link GitHub code' })).not.toBeInTheDocument();
  });

  it('saves the link on both items', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} />);
    const { user, dialog } = await openPicker();
    await user.click(within(dialog).getByRole('button', { name: 'Link GitHub code' }));
    await waitFor(() => expect(linksOf(LOGIN)).toEqual([CODE]));
    expect(linksOf(CODE)).toEqual([LOGIN]);
    // And the other item's card shows this one.
    await user.click(screen.getByRole('button', { name: 'open the code' }));
    expect(within(screen.getByRole('region', { name: 'Linked items' })).getByRole('link')).toHaveTextContent('GitHub');
  });

  it('closes on Escape or Cancel and changes nothing', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} />);
    const { user } = await openPicker();
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Link an item' }));
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(stored().every(([, links]) => links.length === 0)).toBe(true);
  });

  it('keeps focus inside the picker', async () => {
    renderWithIntl(<Page items={vault()} start={LOGIN} />);
    const { user, dialog } = await openPicker();
    for (let i = 0; i < 8; i += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });
});

describe('Unlink', () => {
  it('removes both ends, whichever item it is done from', async () => {
    const items = vault();
    items[0] = vaultItem('login', { name: 'GitHub', links: [{ id: CODE }, { id: PASSKEY }] }, { id: LOGIN });
    items[1] = vaultItem('otp', { name: 'GitHub code', links: [{ id: LOGIN }] }, { id: CODE });
    items[3] = vaultItem('passkey', { name: 'GitHub passkey', rpId: 'github.com', links: [{ id: LOGIN }] }, { id: PASSKEY });
    renderWithIntl(<Page items={items} start={CODE} />);
    const user = userEvent.setup();

    // From the code's card: the login drops the code too.
    await user.click(screen.getByRole('button', { name: 'Unlink GitHub' }));
    await waitFor(() => expect(linksOf(CODE)).toEqual([]));
    expect(linksOf(LOGIN)).toEqual([PASSKEY]);
    expect(screen.getByText('Nothing linked yet.')).toBeInTheDocument();

    // The login's card no longer lists the code, and does list the passkey.
    await user.click(screen.getByRole('button', { name: 'open the login' }));
    const card = screen.getByRole('region', { name: 'Linked items' });
    expect(within(card).queryByText('GitHub code')).not.toBeInTheDocument();
    expect(within(card).getByRole('link')).toHaveTextContent('GitHub passkey');

    // From the login's card: the passkey drops the login too, and the login has no links left.
    await user.click(within(card).getByRole('button', { name: 'Unlink GitHub passkey' }));
    await waitFor(() => expect(linksOf(LOGIN)).toEqual([]));
    expect(linksOf(PASSKEY)).toEqual([]);
    expect(stored().every(([, links]) => links.length === 0)).toBe(true);
  });

  it('says so when the unlink did not go through, and keeps the link listed', async () => {
    const items = vault();
    items[0] = vaultItem('login', { name: 'GitHub', links: [{ id: CODE }] }, { id: LOGIN });
    renderWithIntl(<Page items={items} start={LOGIN} failUnlink />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Unlink GitHub code' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link')).toHaveTextContent('GitHub code');
  });
});
