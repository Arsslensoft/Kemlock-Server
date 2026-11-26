import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { copyText } from '@/lib/clipboard';
import { renderWithIntl } from '@/test/render';
import { readCustomFields } from '../customFields';
import { toB64 } from '../forms/keyMaterial';
import type { VaultItem } from '../vault';
import { CustomFieldRows } from './CustomFieldRows';
import { AttachmentsCard } from './FileDetails';
import { KindDetails } from './KindDetails';

vi.mock('@/lib/clipboard', () => ({ copyText: vi.fn(() => Promise.resolve(true)) }));

function item(kind: string, data: Record<string, unknown>): VaultItem {
  return { id: 'i1', owner: 'user:u1', kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

const user = () => userEvent.setup({ delay: null });

describe('custom fields in the first card', () => {
  const data = {
    number: '4111111111111111',
    brand: 'Visa',
    fields: [
      { name: 'Recovery email', value: 'sam.backup@example.org', kind: 'text' },
      { name: 'Security question', value: 'blue', kind: 'hidden', adminField: 'f-1' },
      { name: 'Paid', value: 'true', kind: 'boolean' },
      { name: 'Unpaid', value: 'false', kind: 'boolean' },
    ],
  };

  function render() {
    renderWithIntl(
      <KindDetails item={item('card', data)} extra={<CustomFieldRows fields={readCustomFields(data)} />} />,
    );
    return screen.getByRole('region', { name: 'Card' });
  }

  it('ends the first card with them, after the kind\'s own rows', () => {
    const card = render();
    const labels = within(card)
      .getAllByText(/^(Brand|Card number|Recovery email|Security question|Paid|Unpaid)/)
      .map((node) => node.textContent?.replace('Admin', ''));
    expect(labels).toEqual(['Brand', 'Card number', 'Recovery email', 'Security question', 'Paid', 'Unpaid']);
  });

  it('shows a text field with a copy button', async () => {
    render();
    expect(screen.getByText('sam.backup@example.org')).toBeInTheDocument();
    await user().click(screen.getByRole('button', { name: 'Copy the Recovery email' }));
    expect(copyText).toHaveBeenCalledWith('sam.backup@example.org', { secret: false });
  });

  it('masks a hidden field until it is shown, and copies it as a secret', async () => {
    render();
    expect(screen.queryByText('blue')).not.toBeInTheDocument();
    const u = user();
    await u.click(screen.getByRole('button', { name: 'Show the Security question' }));
    expect(screen.getByText('blue')).toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Hide the Security question' }));
    expect(screen.queryByText('blue')).not.toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Copy the Security question' }));
    expect(copyText).toHaveBeenCalledWith('blue', { secret: true });
  });

  it('tags only the fields the admin defined', () => {
    const card = render();
    const tags = within(card).getAllByText('Admin');
    expect(tags).toHaveLength(1);
    expect(tags[0]?.parentElement).toHaveTextContent('Security question');
  });

  it('shows a checkbox as Yes or No, and offers no way to change it', () => {
    const card = render();
    expect(within(card).getByText('Paid').closest('.row')).toHaveTextContent('Yes');
    expect(within(card).getByText('Unpaid').closest('.row')).toHaveTextContent('No');
    expect(within(card).queryByRole('checkbox')).not.toBeInTheDocument();
    expect(within(card).queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('names the buttons of a field with the name the person gave it, in its own case', async () => {
    renderWithIntl(
      <KindDetails
        item={item('card', { number: '4111111111111111' })}
        extra={
          <CustomFieldRows
            fields={readCustomFields({
              fields: [
                { name: 'SSH Key ID', value: 'abc', kind: 'text' },
                { name: 'API token', value: 'tok', kind: 'hidden' },
              ],
            })}
          />
        }
      />,
    );
    expect(screen.getByRole('button', { name: 'Copy the SSH Key ID' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Show the API token' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the API token' })).toBeInTheDocument();
  });

  it('adds nothing when the item has no custom fields', () => {
    renderWithIntl(<KindDetails item={item('card', { number: '4111111111111111' })} />);
    const card = screen.getByRole('region', { name: 'Card' });
    expect(card.querySelectorAll('.row')).toHaveLength(1);
  });
});

describe('the Website row of an MFA code and of backup codes', () => {
  const own = { urls: ['https://github.com', 'example.co'] };
  const note = 'From the linked login GitHub. Change it there.';

  it('shows the websites of an MFA code after its code, and before its custom fields', () => {
    renderWithIntl(
      <KindDetails
        item={item('otp', { name: 'GitHub code', secret: 'JBSWY3DPEHPK3PXP', ...own })}
        sites={{ urls: ['https://github.com', 'example.co'] }}
        extra={<CustomFieldRows fields={readCustomFields({ fields: [{ name: 'Seat', value: '12', kind: 'text' }] })} />}
      />,
    );
    const card = screen.getByRole('region', { name: 'MFA code' });
    const labels = Array.from(card.querySelectorAll('.lbl')).map((node) => node.textContent);
    expect(labels).toEqual(['Code', 'Website', 'Seat']);
    expect(within(card).getByRole('link', { name: 'github.com' })).toHaveAttribute('href', 'https://github.com');
    expect(within(card).getByText('example.co')).toBeInTheDocument();
    expect(card).not.toHaveTextContent(note);
  });

  it('says where the websites come from when they belong to the linked login, which alone changes them', () => {
    renderWithIntl(
      <KindDetails
        item={item('backup-codes', { name: 'Recovery', codes: [{ code: 'aaaa' }] })}
        sites={{ urls: ['https://github.com'], fromLogin: 'GitHub' }}
      />,
    );
    const card = screen.getByRole('region', { name: 'Backup codes' });
    expect(within(card).getByRole('link', { name: 'github.com' })).toBeInTheDocument();
    expect(card).toHaveTextContent(note);
    expect(within(card).queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('has no Website row without websites', () => {
    renderWithIntl(<KindDetails item={item('otp', { name: 'Code', secret: 'JBSWY3DPEHPK3PXP' })} sites={undefined} />);
    expect(screen.queryByText('Website')).not.toBeInTheDocument();
  });
});

describe('a File item', () => {
  const file = { name: 'Lease agreement.pdf', size: 2_400_000, type: 'application/pdf', key: 'k', kemlockFile: 'f1' };

  it('shows its name, type and size, and a Download button', () => {
    renderWithIntl(<KindDetails item={item('file', { name: 'Lease', file })} download={vi.fn()} />);
    const card = screen.getByRole('region', { name: 'File' });
    expect(card).toHaveTextContent('Lease agreement.pdf');
    expect(within(card).getByText('PDF')).toBeInTheDocument();
    expect(within(card).getByText('2.4 MB')).toBeInTheDocument();
    expect(within(card).getByRole('button', { name: 'Download Lease agreement.pdf' })).toBeEnabled();
  });

  it('downloads the file when asked, and says it is working until it is done', async () => {
    let finish: () => void = () => undefined;
    const download = vi.fn(() => new Promise<void>((resolve) => (finish = resolve)));
    renderWithIntl(<KindDetails item={item('file', { file })} download={download} />);
    await user().click(screen.getByRole('button', { name: 'Download Lease agreement.pdf' }));
    expect(download).toHaveBeenCalledWith(expect.objectContaining({ name: 'Lease agreement.pdf', serverId: 'f1', key: 'k' }));
    // Its name is what it says while it works, not the old one that no longer matches its words.
    const busy = screen.getByRole('button', { name: 'Preparing…' });
    expect(busy).toBeDisabled();
    expect(busy).toHaveTextContent('Preparing…');
    finish();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Download Lease agreement.pdf' })).toBeEnabled());
  });

  it('tells the person when the file could not be fetched or opened', async () => {
    renderWithIntl(<KindDetails item={item('file', { file })} download={vi.fn(() => Promise.reject(new Error('x')))} />);
    await user().click(screen.getByRole('button', { name: 'Download Lease agreement.pdf' }));
    expect(await screen.findByRole('alert')).toHaveTextContent("The file couldn't be downloaded or opened.");
    expect(screen.getByRole('button', { name: 'Download Lease agreement.pdf' })).toBeEnabled();
  });

  it('cannot download a file that was never uploaded, and says so', () => {
    renderWithIntl(
      <KindDetails item={item('file', { file: { ...file, kemlockFile: undefined } })} download={vi.fn()} />,
    );
    expect(screen.getByRole('button', { name: 'Download Lease agreement.pdf' })).toBeDisabled();
    expect(screen.getByText(/never uploaded/)).toBeInTheDocument();
  });

  it('says so when the item holds no file', () => {
    renderWithIntl(<KindDetails item={item('file', {})} download={vi.fn()} />);
    expect(screen.getByText('This item holds no file.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Download/ })).not.toBeInTheDocument();
  });
});

describe('the attachments of a note', () => {
  it('lists each with its type and size and a Download button, and nothing when there are none', async () => {
    const download = vi.fn(() => Promise.resolve());
    const data = {
      attachments: [
        { name: 'a.txt', size: 3, key: 'k', kemlockFile: 'f1' },
        { name: 'b.png', size: 1_500_000, type: 'image/png', key: 'k', kemlockFile: 'f2' },
      ],
    };
    const { unmount } = renderWithIntl(<AttachmentsCard data={data} download={download} />);
    const card = screen.getByRole('region', { name: 'Attachments' });
    expect(card).toHaveTextContent('Text · 3 B');
    expect(card).toHaveTextContent('Image · 1.5 MB');
    await user().click(screen.getByRole('button', { name: 'Download b.png' }));
    expect(download).toHaveBeenCalledWith(expect.objectContaining({ name: 'b.png', serverId: 'f2' }));
    unmount();
    const { container } = renderWithIntl(<AttachmentsCard data={{}} download={download} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('a contact as a person', () => {
  const person = {
    name: 'Ada Lovelace',
    company: 'Analytical Engines',
    email: 'ada@example.org',
    phone: '+44 20 7946 0000',
    address: '48 Pine Street\nPortland, OR 97205\nUnited States',
  };

  it('shows the name, company, email, phone and address, each copyable', async () => {
    renderWithIntl(<KindDetails item={item('contact', person)} />);
    const card = screen.getByRole('region', { name: 'Contact' });
    for (const text of ['Ada Lovelace', 'Analytical Engines', 'ada@example.org', '+44 20 7946 0000']) {
      expect(within(card).getByText(text)).toBeInTheDocument();
    }
    expect(within(card).getByText('48 Pine Street')).toBeInTheDocument();
    expect(within(card).getByText('Portland, OR 97205')).toBeInTheDocument();
    expect(within(card).getByText('United States')).toBeInTheDocument();
    await user().click(within(card).getByRole('button', { name: 'Copy the address' }));
    expect(copyText).toHaveBeenCalledWith('48 Pine Street\nPortland, OR 97205\nUnited States', { secret: false });
  });

  it('has no PGP rows without a key', () => {
    renderWithIntl(<KindDetails item={item('contact', person)} />);
    expect(screen.queryByText('Fingerprint')).not.toBeInTheDocument();
    expect(screen.queryByText('Public key')).not.toBeInTheDocument();
  });

  it('shows the optional PGP key with its fingerprint', async () => {
    // A v4 RSA public key packet: its fingerprint is the SHA-1 of the packet under 0x99.
    const body = Uint8Array.from([4, 0, 0, 0, 1, 1, 0, 8, 0xc3, 0, 8, 0x03]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', Uint8Array.from([0x99, 0, body.length, ...body])));
    const hex = Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
    // Shown in groups of four, in capitals.
    const fingerprint = hex.toUpperCase().replace(/(.{4})(?=.)/g, '$1 ');
    renderWithIntl(
      <KindDetails item={item('contact', { ...person, public: toB64(Uint8Array.from([0xc6, body.length, ...body])) })} />,
    );
    expect(await screen.findByText('Public key')).toBeInTheDocument();
    const card = screen.getByRole('region', { name: 'Contact' });
    expect(await within(card).findByText(fingerprint)).toBeInTheDocument();
    // The person's own rows are still there.
    expect(within(card).getByText('Ada Lovelace')).toBeInTheDocument();
  });

  it('reads an address kept as lines, as an identity keeps it', () => {
    renderWithIntl(
      <KindDetails item={item('contact', { name: 'Ada', address: { lines: ['1 Main St'], city: 'London', country: 'UK' } })} />,
    );
    expect(screen.getByText('1 Main St')).toBeInTheDocument();
    expect(screen.getByText('London')).toBeInTheDocument();
  });
});

describe('a passkey', () => {
  it('shows whose it is and explains that a website made it', () => {
    renderWithIntl(
      <KindDetails
        item={item('passkey', { rpId: 'github.com', rpName: 'GitHub', userName: 'sam@example.org', userDisplayName: 'Sam' })}
      />,
    );
    const card = screen.getByRole('region', { name: 'Passkey' });
    expect(within(card).getByText('github.com')).toBeInTheDocument();
    expect(within(card).getByText('sam@example.org')).toBeInTheDocument();
    expect(within(card).getByText(/A website made this passkey/)).toBeInTheDocument();
  });
});
