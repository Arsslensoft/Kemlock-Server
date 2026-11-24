import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { CertificateForm, certificateDefaults, certificateFields, certificatePem } from './CertificateForm';
import { ContactForm, contactDefaults, contactFields } from './ContactForm';
import { PgpKeyForm, pgpKeyDefaults, pgpKeyFields } from './PgpKeyForm';
import { SshKeyForm, sshKeyDefaults, sshKeyFields } from './SshKeyForm';
import { generateEd25519, readPastedSshKey } from './keyMaterial';
import { fromB64, pemBlocks, pgpHalves, sshAlgorithmOf, toB64 } from './keyMaterial';
import { type VaultItem, saveItem, VaultStore } from '../vault';
import { crypto as fakeCrypto } from '@/test/fake-crypto';

// Bytes that start like OpenPGP packets (top bit set), 12 bytes so the base64 has no padding.
const BODY = toB64(Uint8Array.from([0xc5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]));
const PUBLIC = `-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Test\n\n${BODY}\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----`;
const PRIVATE = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${BODY}\n=AbCd\n-----END PGP PRIVATE KEY BLOCK-----`;
const CERT = `-----BEGIN CERTIFICATE-----\n${BODY}\n-----END CERTIFICATE-----`;

describe('key material', () => {
  it('reads armor without its headers and checksum', () => {
    expect(pemBlocks(PUBLIC)).toEqual([{ label: 'PGP PUBLIC KEY BLOCK', body: BODY }]);
    expect(pgpHalves(`${PRIVATE}\n${PUBLIC}`)).toEqual({ private: BODY, public: BODY });
    expect(pgpHalves(PUBLIC)).toEqual({ public: BODY });
  });

  it('refuses text that is not an OpenPGP key', () => {
    expect(pgpHalves('hello')).toBeUndefined();
    expect(pgpHalves(CERT)).toBeUndefined();
    expect(pgpHalves(`${PUBLIC}\n${PUBLIC}`)).toBeUndefined();
  });

  it('round-trips base64 and names the algorithm of a PKCS#8 key', () => {
    expect(Array.from(fromB64(toB64(Uint8Array.from([1, 2, 250]))))).toEqual([1, 2, 250]);
    const ed = Uint8Array.from([0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22]);
    expect(sshAlgorithmOf(ed)).toBe('ed25519');
    expect(sshAlgorithmOf(Uint8Array.from([0x30, 3, 1, 2, 3]))).toBeUndefined();
  });
});

describe('field builders', () => {
  it('builds a contact from a public key and refuses a private one', () => {
    const values = { ...contactDefaults(), name: 'Sam', armor: PUBLIC };
    expect(contactFields(values, false)).toEqual({ name: 'Sam', note: undefined, public: BODY, source: 'paste' });
    expect(contactFields({ ...values, armor: PRIVATE }, false)).toBeUndefined();
    expect(contactFields({ ...values, armor: '' }, true)).toEqual({ name: 'Sam', note: undefined });
  });

  it('builds a pgp key whose halves are the binary keys', () => {
    const fields = pgpKeyFields({ ...pgpKeyDefaults(), name: 'Mine', armor: `${PRIVATE}\n${PUBLIC}` }, false);
    expect(fields).toMatchObject({ kind: 'pgp', algorithm: 'pgp', private: BODY, public: BODY, origin: 'imported' });
    expect(pgpKeyFields({ ...pgpKeyDefaults(), name: 'x', armor: PUBLIC }, false)).toBeUndefined();
  });

  it('builds a certificate, with or without its key', () => {
    expect(certificatePem(CERT)).toBe(`-----BEGIN CERTIFICATE-----\n${BODY}\n-----END CERTIFICATE-----\n`);
    const key = { algorithm: 'ed25519' as const, private: 'p', public: 'q' };
    const values = { ...certificateDefaults(), name: 'Site', certificate: CERT };
    expect(certificateFields(values, false, key)).toMatchObject({
      kind: 'signing',
      algorithm: 'ed25519',
      private: 'p',
      public: 'q',
      certificate: expect.stringContaining('BEGIN CERTIFICATE'),
    });
    expect(certificateFields(values, false)).toBeUndefined();
    expect(certificateFields({ ...values, certificate: 'nope' }, false, key)).toBeUndefined();
  });

  it('changes only the name and note of an ssh key that exists', () => {
    expect(sshKeyFields({ ...sshKeyDefaults(), name: 'Laptop', note: '' })).toEqual({
      name: 'Laptop',
      note: undefined,
    });
    expect(
      sshKeyFields(
        { ...sshKeyDefaults(), name: 'K', generatedPrivate: 'p' },
        { algorithm: 'ed25519', private: 'p', public: 'q' },
      ),
    ).toMatchObject({ kind: 'ssh', algorithm: 'ed25519', private: 'p', public: 'q', origin: 'generated' });
  });
});

describe('saving an entry', () => {
  it('stamps the item id and epoch milliseconds, and keeps the other fields on edit', async () => {
    const store = new VaultStore();
    const put = vi.fn().mockResolvedValue(undefined);
    const deps = {
      api: { sync: vi.fn(), putItem: put, putBatch: vi.fn() },
      crypto: fakeCrypto,
      now: () => new Date(5000),
      newId: () => 'item-1',
    };
    const first = await saveItem(deps as never, store, {
      kind: 'contact',
      owner: 'user:u',
      fields: { name: 'Sam', public: BODY, source: 'paste' },
      entry: true,
    });
    expect(first.data).toMatchObject({ id: 'item-1', name: 'Sam', addedAt: 5000, updatedAt: 5000 });
    const later = { ...deps, now: () => new Date(9000) };
    const edited: VaultItem = await saveItem(later as never, store, {
      existing: first,
      kind: 'contact',
      owner: 'user:u',
      fields: { name: 'Sam R' },
      entry: true,
    });
    expect(edited.data).toMatchObject({ id: 'item-1', name: 'Sam R', public: BODY, addedAt: 5000, updatedAt: 9000 });
  });
});

describe('the forms', () => {
  it('saves a contact from a pasted public key', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<ContactForm initial={contactDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Sam');
    await user.click(screen.getByLabelText('Public key'));
    await user.paste(PUBLIC);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
  });

  it('refuses a contact paste that is not a public key', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<ContactForm initial={contactDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Sam');
    await user.type(screen.getByLabelText('Public key'), 'hello');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/exactly one PGP public key/)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('asks for a pgp key and a certificate', async () => {
    const onPgp = vi.fn();
    const first = renderWithIntl(<PgpKeyForm initial={pgpKeyDefaults()} onSubmit={onPgp} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Mine');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('This is required.')).toBeInTheDocument();
    expect(onPgp).not.toHaveBeenCalled();
    first.unmount();
    const onCert = vi.fn();
    renderWithIntl(<CertificateForm initial={certificateDefaults()} onSubmit={onCert} onCancel={vi.fn()} submitLabel="Save" />);
    await user.type(screen.getByLabelText('Name'), 'Site');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('This is required.')).toBeInTheDocument();
    expect(onCert).not.toHaveBeenCalled();
  });

  it('shows only name and notes when an ssh key is edited', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <SshKeyForm initial={{ ...sshKeyDefaults(), name: 'Laptop' }} editing onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />,
    );
    expect(screen.queryByLabelText('Private key')).not.toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
  });
});

describe('key reading', () => {
  it('generates an Ed25519 key and reads it back when pasted', async () => {
    const made = await generateEd25519();
    expect(made.algorithm).toBe('ed25519');
    const pem = `-----BEGIN PRIVATE KEY-----\n${made.private}\n-----END PRIVATE KEY-----`;
    expect(await readPastedSshKey(pem)).toEqual(made);
    expect(await readPastedSshKey(made.private)).toEqual(made);
  });

  it('refuses what is not a PKCS#8 Ed25519 or P-256 key', async () => {
    expect(await readPastedSshKey('hello')).toBeUndefined();
    expect(await readPastedSshKey(PUBLIC)).toBeUndefined();
    expect(await readPastedSshKey(`-----BEGIN PRIVATE KEY-----\n${BODY}\n-----END PRIVATE KEY-----`)).toBeUndefined();
  });
});
