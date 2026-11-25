import { screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { hostsText, linkedWebsites, parseHosts, websiteFields } from '../linkedSites';
import type { ItemData, VaultItem } from '../vault';
import { BackupCodesForm, type BackupCodesValues, backupCodesDefaults, backupCodesFields } from './backupCodes';
import { FormEnvContext } from './env';
import { OtpForm, type OtpValues, otpDefaults, otpFields } from './otp';

const LOGIN = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';

function item(id: string, kind: string, data: ItemData): VaultItem {
  return { id, owner: 'user:u', kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

const GITHUB = item(LOGIN, 'login', {
  name: 'GitHub',
  uris: [{ uri: 'https://github.com' }, { uri: 'https://gist.github.com', match: 1 }, { uri: '^x$', match: 4 }],
});
const PLAIN = item(OTHER, 'note', { name: 'A note' });

function env(items: VaultItem[]) {
  return {
    definitions: { fields: [], allowOwn: true },
    items,
    canWrite: () => true,
    selfId: undefined,
    renderItem: (linked: VaultItem, label: ReactNode) => <a href={`/vault/${linked.id}`}>{label}</a>,
  };
}

const VALID_SECRET = 'JBSWY3DPEHPK3PXP';

describe('the Website field of an MFA code', () => {
  it('is a normal field when nothing is linked', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<OtpForm initial={otpDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    const website = screen.getByLabelText('Website');
    expect(website).not.toHaveAttribute('readonly');
    await user.type(screen.getByLabelText('Issuer'), 'GitHub');
    await user.type(website, 'github.com, https://gist.github.com/x');
    await user.type(screen.getByLabelText('Secret key'), VALID_SECRET);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const values = onSubmit.mock.calls[0]?.[0] as OtpValues;
    expect(values.website).toBe('github.com, https://gist.github.com/x');
    expect(otpFields(values)['websites']).toEqual(['github.com', 'gist.github.com']);
  });

  it('is read-only and shows the websites of a linked login, with where to change them', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <FormEnvContext.Provider value={env([GITHUB, PLAIN])}>
        <OtpForm
          initial={{ ...otpDefaults(), links: [LOGIN], website: 'old.example' }}
          onSubmit={onSubmit}
          onCancel={vi.fn()}
          submitLabel="Save"
        />
      </FormEnvContext.Provider>,
    );
    const website = screen.getByLabelText('Website');
    expect(website).toHaveAttribute('readonly');
    expect(website).toHaveValue('github.com, gist.github.com');
    expect(screen.getByText(/From the linked login/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'GitHub' })).toHaveAttribute('href', `/vault/${LOGIN}`);
    expect(screen.getByText(/Change it there; this updates with it\./)).toBeInTheDocument();

    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Issuer'), 'GitHub');
    await user.type(screen.getByLabelText('Secret key'), VALID_SECRET);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    // What the login lends is not the code's to write.
    const values = onSubmit.mock.calls[0]?.[0] as OtpValues;
    expect(values.website).toBeUndefined();
    expect('websites' in otpFields(values)).toBe(false);
  });

  it('stays an ordinary field when it is linked to an item with no website', () => {
    renderWithIntl(
      <FormEnvContext.Provider value={env([GITHUB, PLAIN])}>
        <OtpForm initial={{ ...otpDefaults(), links: [OTHER] }} onSubmit={vi.fn()} onCancel={vi.fn()} submitLabel="Save" />
      </FormEnvContext.Provider>,
    );
    expect(screen.getByLabelText('Website')).not.toHaveAttribute('readonly');
  });

  it('turns editable again once the link is removed', async () => {
    renderWithIntl(
      <FormEnvContext.Provider value={env([GITHUB])}>
        <OtpForm initial={{ ...otpDefaults(), links: [LOGIN] }} onSubmit={vi.fn()} onCancel={vi.fn()} submitLabel="Save" />
      </FormEnvContext.Provider>,
    );
    expect(screen.getByLabelText('Website')).toHaveAttribute('readonly');
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Unlink GitHub (Login)' }));
    expect(screen.getByLabelText('Website')).not.toHaveAttribute('readonly');
  });
});

describe('the Website field of backup codes', () => {
  it('shows a linked login\'s websites read-only, and writes none of its own', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <FormEnvContext.Provider value={env([GITHUB])}>
        <BackupCodesForm
          initial={{ ...backupCodesDefaults(), links: [LOGIN] }}
          onSubmit={onSubmit}
          onCancel={vi.fn()}
          submitLabel="Save"
        />
      </FormEnvContext.Provider>,
    );
    expect(screen.getByLabelText('Website')).toHaveAttribute('readonly');
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Service'), 'GitHub');
    await user.type(screen.getByLabelText('Codes'), 'aaaa-1111');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const values = onSubmit.mock.calls[0]?.[0] as BackupCodesValues;
    expect(values.website).toBeUndefined();
    expect('websites' in backupCodesFields(values)).toBe(false);
  });

  it('is a normal, editable field when unlinked, written as the websites of the item', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <BackupCodesForm initial={backupCodesDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Service'), 'GitHub');
    await user.type(screen.getByLabelText('Website'), 'github.com');
    await user.type(screen.getByLabelText('Codes'), 'aaaa-1111');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(backupCodesFields(onSubmit.mock.calls[0]?.[0] as BackupCodesValues)['websites']).toEqual(['github.com']);
  });
});

describe('what a linked item lends', () => {
  it('is the hosts of its websites that fill on a host, each once, from the items linked', () => {
    const lent = linkedWebsites([LOGIN, OTHER], [GITHUB, PLAIN]);
    expect(lent?.hosts).toEqual(['github.com', 'gist.github.com']);
    expect(lent?.sources.map((source) => source.id)).toEqual([LOGIN]);
    expect(linkedWebsites([OTHER], [GITHUB, PLAIN])).toBeUndefined();
    expect(linkedWebsites([], [GITHUB])).toBeUndefined();
    expect(linkedWebsites(['33333333-3333-4333-8333-333333333333'], [GITHUB])).toBeUndefined();
  });

  it('reads hosts typed with commas, spaces and lines', () => {
    expect(parseHosts('github.com, https://Gist.GitHub.com/x;  github.com\nexample.org:8443')).toEqual([
      'github.com',
      'gist.github.com',
      'example.org',
    ]);
    expect(parseHosts('  ')).toEqual([]);
    expect(hostsText(GITHUB.data)).toBe('github.com, gist.github.com');
  });

  it('writes websites, and keeps the rules an item had for the hosts that stay', () => {
    expect(websiteFields('a.example, b.example', {})).toEqual({ websites: ['a.example', 'b.example'] });
    expect(websiteFields('', {})).toEqual({ websites: undefined });
    const existing = { uris: [{ uri: 'https://a.example', match: 1 }, { uri: '^x$', match: 4 }] };
    expect(websiteFields('a.example, c.example', existing)).toEqual({
      websites: ['a.example', 'c.example'],
      uris: [{ uri: 'https://a.example', match: 1 }, { uri: 'c.example' }, { uri: '^x$', match: 4 }],
    });
  });
});
