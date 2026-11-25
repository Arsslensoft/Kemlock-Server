import { screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { copySeed } from '../copyDraft';
import type { FormResult } from '../saveFlow';
import type { ItemData, VaultItem } from '../vault';
import { KindForm } from './index';
import { FormEnvContext } from './env';

const LOGIN = '11111111-1111-4111-8111-111111111111';
const CODE = '22222222-2222-4222-8222-222222222222';

function item(id: string, kind: string, data: ItemData): VaultItem {
  return { id, owner: 'user:u', kind, revision: 3, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

function setup(props: Partial<Parameters<typeof KindForm>[0]> & { kind: Parameters<typeof KindForm>[0]['kind'] }) {
  const onSubmit = vi.fn<(result: FormResult) => void>();
  renderWithIntl(<KindForm submitLabel="Save" onCancel={vi.fn()} onSubmit={onSubmit} {...props} />);
  return { onSubmit, user: userEvent.setup({ delay: null }) };
}

describe('a form opened from a copy', () => {
  const source = item(LOGIN, 'login', {
    id: LOGIN,
    name: 'GitHub',
    username: 'sam@example.org',
    password: 'hunter2',
    urls: ['https://github.com'],
    links: [{ id: CODE }],
    passwordHistory: [{ password: 'old', replacedAt: 'then' }],
    vendorKey: 'kept',
  });

  it('is filled from the original, without its links, and saves a new item', async () => {
    const { onSubmit, user } = setup({ kind: 'login', seed: copySeed(source) });
    expect(screen.getByLabelText('Name')).toHaveValue('GitHub');
    expect(screen.getByLabelText('Username')).toHaveValue('sam@example.org');
    expect(screen.getByLabelText('Website 1')).toHaveValue('https://github.com');
    expect(screen.getByText('Nothing linked yet.')).toBeInTheDocument();
    await user.clear(screen.getByLabelText('Name'));
    await user.type(screen.getByLabelText('Name'), 'GitHub (work)');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const result = onSubmit.mock.calls[0]?.[0] as FormResult;
    expect(result.fields).toMatchObject({ name: 'GitHub (work)', username: 'sam@example.org', password: 'hunter2' });
    expect(result.links).toEqual([]);
    expect(result.entry).toBe(false);
  });

  it('keeps a key pair it is copying instead of asking for the key again', async () => {
    const key = item(LOGIN, 'ssh-key', { name: 'Deploy', kind: 'ssh', private: 'p', public: 'q', algorithm: 'ed25519' });
    const { onSubmit, user } = setup({ kind: 'ssh-key', seed: copySeed(key) });
    expect(screen.queryByLabelText('Private key')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    // The key is not in what the form wrote: the copy takes it from the original's body.
    expect((onSubmit.mock.calls[0]?.[0] as FormResult).fields['private']).toBeUndefined();
  });
});

describe('a form opened on a login that codes name', () => {
  it('shows each code that names it in linkedLoginId as linked, and hands them back as its links', async () => {
    const login = item(LOGIN, 'login', { name: 'GitHub', urls: ['https://github.com'] });
    const code = item(CODE, 'otp', { issuer: 'GitHub', linkedLoginId: LOGIN });
    const env = {
      definitions: { fields: [], allowOwn: true },
      items: [login, code],
      canWrite: () => true,
      selfId: LOGIN,
      renderItem: (_item: VaultItem, label: ReactNode) => label,
    };
    const onSubmit = vi.fn<(result: FormResult) => void>();
    renderWithIntl(
      <FormEnvContext.Provider value={env}>
        <KindForm
          kind="login"
          item={login}
          existing={login}
          incoming={[CODE]}
          submitLabel="Save"
          onCancel={vi.fn()}
          onSubmit={onSubmit}
        />
      </FormEnvContext.Provider>,
    );
    expect(screen.getByRole('button', { name: 'Unlink GitHub (MFA code)' })).toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect((onSubmit.mock.calls[0]?.[0] as FormResult).links).toEqual([CODE]);
  });
});

describe('what a form hands over for its files', () => {
  it('lists the files a note holds, and those still to send, with nothing named for them yet', async () => {
    const stored = { id: 'old', name: 'old.txt', size: 1, key: 'k', addedAt: 1, kemlockFile: 'server-1' };
    const note = item(LOGIN, 'note', { name: 'Plan', text: 't', attachments: [stored] });
    const { onSubmit, user } = setup({ kind: 'note', item: note, existing: note });
    await user.upload(screen.getByLabelText('Add a file'), new File(['hello'], 'hello.txt', { type: 'text/plain' }));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const result = onSubmit.mock.calls[0]?.[0] as FormResult;
    expect(result.files.map((entry) => entry.name)).toEqual(['old.txt', 'hello.txt']);
    expect(result.uploads.map((entry) => entry.name)).toEqual(['hello.txt']);
    // The first save keeps the stored file and names none of the new ones.
    expect(result.fields['attachments']).toEqual([stored]);
    const sent = { ...(result.uploads[0] as NonNullable<(typeof result.uploads)[number]>), kemlockFile: 'server-2' };
    const { file: _bytes, ...named } = sent;
    expect(result.withUploaded([named])['attachments']).toEqual([stored, expect.objectContaining({ name: 'hello.txt', kemlockFile: 'server-2' })]);
  });

  it('keeps a new File item only if its file goes up, and never rolls back an edit', async () => {
    const file = new File(['lease'], 'Lease.pdf', { type: 'application/pdf' });
    const fresh = setup({ kind: 'file' });
    await fresh.user.upload(screen.getByLabelText('Choose a file'), file);
    await fresh.user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(fresh.onSubmit).toHaveBeenCalledOnce());
    expect((fresh.onSubmit.mock.calls[0]?.[0] as FormResult).rollbackOnFailure).toBe(true);
  });

  it('writes against the item an earlier try saved, so its addedAt stays and no key is made again', async () => {
    const saved = item(LOGIN, 'otp', { id: LOGIN, issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', addedAt: 5000 });
    const { onSubmit, user } = setup({ kind: 'otp', existing: saved });
    await user.type(screen.getByLabelText('Issuer'), 'GitHub');
    await user.type(screen.getByLabelText('Secret key'), 'JBSWY3DPEHPK3PXP');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const fields = (onSubmit.mock.calls[0]?.[0] as FormResult).fields;
    expect('addedAt' in fields).toBe(false);
    expect((onSubmit.mock.calls[0]?.[0] as FormResult).entry).toBe(true);
  });
});
