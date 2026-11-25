import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { SendDto } from '@/api/sends';
import { encodeB64, utf8 } from '@/lib/b64url';
import { I18nProvider } from '@/i18n';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { renderWithIntl } from '@/test/render';
import { type SendRow, SendView, formatSize, isSpent, rowsFrom } from './Send';
import { serializeEnvelope } from './itemEnvelope';
import { makeSend } from './sendCrypto';

const NOW = new Date('2026-11-22T10:00:00Z');

const ROWS: SendRow[] = [
  {
    id: 'a',
    name: 'Guest Wi-Fi',
    kind: 'text',
    viewCount: 3,
    maxViews: 10,
    size: null,
    hasPassword: false,
    expiresAt: '2026-11-24T10:00:00Z',
    link: 'https://vault.example.org/#/send/a/KEY',
  },
  {
    id: 'b',
    name: 'Lease contract.pdf',
    kind: 'file',
    viewCount: 1,
    maxViews: null,
    size: 2_200_000,
    hasPassword: true,
    expiresAt: '2026-11-28T10:00:00Z',
    link: 'https://vault.example.org/#/send/b/KEY',
  },
  {
    id: 'c',
    name: 'Router admin password',
    kind: 'text',
    viewCount: 1,
    maxViews: 1,
    size: null,
    hasPassword: false,
    expiresAt: '2026-11-30T10:00:00Z',
    link: 'https://vault.example.org/#/send/c/KEY',
  },
];

function view(over: Partial<Parameters<typeof SendView>[0]> = {}) {
  const onCreate = vi.fn();
  const onCopy = vi.fn();
  const onDelete = vi.fn();
  renderWithIntl(
    <SendView rows={ROWS} now={NOW} onCreate={onCreate} onCopy={onCopy} onDelete={onDelete} {...over} />,
  );
  return { onCreate, onCopy, onDelete };
}

describe('SendView', () => {
  it('lists the Sends with what is left of each', () => {
    view();
    expect(screen.getByText('Text · 3 of 10 views · deletes in 2 days')).toBeInTheDocument();
    expect(screen.getByText('File, 2.1 MB · 1 view · password · deletes in 6 days')).toBeInTheDocument();
    // A Send that reached its view limit offers Delete but no link.
    expect(screen.getByText('Expired')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Copy the link of Router admin password' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete Router admin password' })).toBeInTheDocument();
  });

  it('copies a link and deletes a Send', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Copy the link of Guest Wi-Fi' }));
    expect(props.onCopy).toHaveBeenCalledWith(ROWS[0]);
    await user.click(screen.getByRole('button', { name: 'Delete Guest Wi-Fi' }));
    expect(props.onDelete).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    expect(props.onDelete).toHaveBeenCalledWith(ROWS[0]);
  });

  it('says so when there is nothing yet', () => {
    view({ rows: [] });
    expect(screen.getByText(/No Sends yet/)).toBeInTheDocument();
  });

  it('creates a text Send with the options typed', async () => {
    const props = view();
    const user = userEvent.setup();
    const create = screen.getByRole('button', { name: 'Create link' });
    expect(create).toBeDisabled();
    await user.type(screen.getByLabelText('Name'), 'Door code');
    await user.type(screen.getByLabelText('Text'), '4 7 1 9');
    await user.selectOptions(screen.getByLabelText('Delete after'), '30');
    await user.type(screen.getByLabelText('Most views'), '3');
    await user.type(screen.getByLabelText('Password, optional'), 'hunter2');
    await user.click(screen.getByLabelText('Hide my email from whoever opens it'));
    expect(create).toBeEnabled();
    await user.click(create);
    expect(props.onCreate).toHaveBeenCalledWith({
      kind: 'text',
      name: 'Door code',
      text: '4 7 1 9',
      file: undefined,
      deleteAfterDays: 30,
      maxViews: 3,
      password: 'hunter2',
      hideEmail: false,
    });
  });

  it('refuses a most-views value that is not a whole number of 1 or more', async () => {
    view();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Name'), 'x');
    await user.type(screen.getByLabelText('Text'), 'y');
    await user.type(screen.getByLabelText('Most views'), '0');
    expect(screen.getByRole('alert')).toHaveTextContent(/whole number of 1 or more/);
    expect(screen.getByRole('button', { name: 'Create link' })).toBeDisabled();
  });

  it('takes a file, and refuses one over the limit', async () => {
    const props = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'File' }));
    await user.type(screen.getByLabelText('Name'), 'Lease');
    const input = screen.getByLabelText('File');
    await user.upload(input, new File(['hello'], 'lease.txt', { type: 'text/plain' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create link' })).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'Create link' }));
    const values = props.onCreate.mock.calls[0]?.[0] as { kind: string; file?: { name: string; mime: string; bytes: Uint8Array } };
    expect(values.kind).toBe('file');
    expect(values.file?.name).toBe('lease.txt');
    expect(values.file?.mime).toBe('text/plain');
    expect(new TextDecoder().decode(values.file?.bytes)).toBe('hello');

    const big = new File([new Uint8Array(1024 * 1024 + 1)], 'big.bin');
    await user.upload(input, big);
    expect(await screen.findByRole('alert')).toHaveTextContent(/over 1\.0 MB/);
  });

  it('shows the link it made, with the key after the #', () => {
    view({ createdLink: 'https://vault.example.org/#/send/x/KEY' });
    const status = screen.getByRole('status');
    expect(within(status).getByText('https://vault.example.org/#/send/x/KEY')).toBeInTheDocument();
  });
});

describe('Send helpers', () => {
  it('knows when a Send is spent', () => {
    expect(isSpent(ROWS[0] as SendRow, NOW)).toBe(false);
    expect(isSpent(ROWS[2] as SendRow, NOW)).toBe(true);
    expect(isSpent({ ...(ROWS[0] as SendRow), expiresAt: '2026-11-21T00:00:00Z' }, NOW)).toBe(true);
  });

  it('formats sizes', () => {
    expect(formatSize(512)).toBe('512 B');
    expect(formatSize(2048)).toBe('2.0 KB');
    expect(formatSize(3 * 1024 * 1024)).toBe('3.0 MB');
  });
});

describe('rowsFrom', () => {
  it('opens the owner\'s copy of each key and builds the link, and survives one it cannot open', async () => {
    resetFakeCrypto();
    await crypto.unlock('u', utf8('wrapped:u'), new Uint8Array(), new Uint8Array());
    const made = await makeSend(
      { kind: 'text', name: 'Door code', text: 'x', deleteAfterDays: 1, maxViews: null, hideEmail: false },
      { crypto },
      NOW,
    );
    const base = {
      kind: 'text' as const,
      payload: '',
      file: null,
      accessCount: 2,
      maxAccess: null,
      hideEmail: true,
      disabled: false,
      expiresAt: null,
      deletionAt: 1_795_000_000,
      createdAt: 1_794_000_000,
      revisedAt: 1_794_000_000,
      hasPassword: false,
    };
    const sends: SendDto[] = [
      {
        ...base,
        id: made.id,
        accessId: 'ACCESS1',
        meta: made.request.meta,
        sealedKey: made.request.sealedKey,
      },
      {
        ...base,
        id: 'send-2',
        accessId: 'ACCESS2',
        file: { size: 2_200_000, ready: true },
        meta: encodeB64(utf8('garbage')),
        sealedKey: encodeB64(utf8('x')),
      },
    ];
    const rows = await rowsFrom(sends, 'https://vault.example.org', crypto);
    expect(rows[0]).toMatchObject({
      name: 'Door code',
      viewCount: 2,
      expiresAt: '2026-11-18T11:06:40.000Z',
      link: `https://vault.example.org/#/send/ACCESS1/${made.key}`,
    });
    expect(rows[1]).toMatchObject({ name: 'send-2', link: null, size: 2_200_000 });
  });

  it('marks an item Send with the kind of its item, and leaves a text Send alone', async () => {
    resetFakeCrypto();
    await crypto.unlock('u', utf8('wrapped:u'), new Uint8Array(), new Uint8Array());
    const input = { kind: 'text' as const, deleteAfterDays: 1, maxViews: null, hideEmail: false };
    const item = await makeSend(
      {
        ...input,
        name: 'Visa',
        text: serializeEnvelope({ kemlockSend: 1, kind: 'card', name: 'Visa', fields: { number: '4111' } }),
      },
      { crypto },
      NOW,
    );
    const plain = await makeSend({ ...input, name: 'Note', text: '{"kemlockSend":1,"kind":"card"}' }, { crypto }, NOW);
    const dto = (made: typeof item, accessId: string): SendDto => ({
      kind: 'text',
      id: made.id,
      accessId,
      meta: made.request.meta,
      sealedKey: made.request.sealedKey,
      payload: made.request.payload,
      file: null,
      accessCount: 0,
      maxAccess: null,
      hideEmail: false,
      disabled: false,
      expiresAt: null,
      deletionAt: 1_795_000_000,
      createdAt: 1_794_000_000,
      revisedAt: 1_794_000_000,
      hasPassword: false,
    });
    const rows = await rowsFrom([dto(item, 'A1'), dto(plain, 'A2')], 'https://vault.example.org', crypto);
    expect(rows[0]?.itemKind).toBe('card');
    expect(rows[1]?.itemKind).toBeUndefined();
  });
});

describe('SendView after a Send is made', () => {
  it('empties the form so a second press cannot make it twice', async () => {
    const onCreate = vi.fn();
    const ui = (createdLink?: string) => (
      <I18nProvider>
        <SendView rows={[]} now={NOW} onCreate={onCreate} onCopy={vi.fn()} onDelete={vi.fn()} createdLink={createdLink} />
      </I18nProvider>
    );
    const { rerender } = render(ui());
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Name'), 'Door code');
    await user.type(screen.getByLabelText('Text'), '4 7 1 9');
    expect(screen.getByRole('button', { name: 'Create link' })).toBeEnabled();
    rerender(ui('https://vault.example.org/#/send/z/KEY'));
    await waitFor(() => expect(screen.getByLabelText('Name')).toHaveValue(''));
    expect(screen.getByLabelText('Text')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Create link' })).toBeDisabled();
  });

  it('keeps the Delete buttons still while a delete is in flight', () => {
    view({ deleting: true });
    expect(screen.getByRole('button', { name: 'Delete Guest Wi-Fi' })).toBeDisabled();
  });
});
