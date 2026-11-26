import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { createImportClient } from '@/import/client';
import { ME, SPACE, login, vaultItem } from '@/test/tools-fixtures';
import { createFakeImportWorker, FAKE_EXPORT_PASSWORD } from '@/test/fake-import-worker';
import { renderWithIntl } from '@/test/render';
import { ImportExportScreen, type ImportFlowDeps, type Scope, importThenPublish } from './ImportExport';

const BITWARDEN = JSON.stringify({
  items: [
    { type: 1, name: 'GitHub', login: { username: 'sam', password: 'pw', uris: [{ uri: 'https://github.com' }] } },
    { type: 1, name: 'Proton', login: { username: 'sam', password: 'pw2', uris: [{ uri: 'proton.me' }] } },
  ],
});

const SCOPES: Scope[] = [
  { id: 'me', label: 'My vault', owner: ME, count: 2 },
  { id: 'fam', label: 'Family', owner: SPACE, count: 1 },
  { id: 'co', label: 'Example Co', owner: 'space:00000000-0000-4000-8000-0000000000cc', count: 5, exportsOff: true },
];

function setup(over: Partial<ImportFlowDeps> = {}) {
  const importInto = vi.fn<ImportFlowDeps['importInto']>(async (conversion, _owner, onProgress) => {
    onProgress(conversion.items.length, conversion.items.length);
    return conversion.items.length;
  });
  const save = vi.fn<NonNullable<ImportFlowDeps['save']>>(() => true);
  const items = [
    login('GitHub', 'sam', 'pw', ['github.com']),
    vaultItem('note', { name: 'Wi-Fi', text: 'x' }),
    login('Family Netflix', 'sam', 'pw', ['netflix.com'], {}, { owner: SPACE }),
  ];
  const deps: ImportFlowDeps = {
    client: createImportClient(() => createFakeImportWorker()),
    items: () => items,
    scopes: SCOPES,
    importInto,
    save,
    now: () => new Date('2026-11-22T10:00:00Z'),
    ...over,
  };
  renderWithIntl(<ImportExportScreen deps={deps} />);
  return { importInto, save };
}

async function choose(content: string, name = 'export.json') {
  const user = userEvent.setup();
  await user.upload(screen.getByLabelText(/Drop a file here/), new File([content], name));
  return user;
}

describe('Import', () => {
  it('detects the file, reads it, shows a preview and imports into the chosen place', async () => {
    const { importInto } = setup();
    const user = await choose(BITWARDEN);
    expect(await screen.findByText(/export\.json · read as Bitwarden or Vaultwarden \(\.json\)/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Read the file' }));
    expect(await screen.findByText('2 items are ready to import.')).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText('Into'), 'fam');
    await user.click(screen.getByRole('button', { name: 'Import 2 items' }));
    await waitFor(() => expect(importInto).toHaveBeenCalledTimes(1));
    expect(importInto.mock.calls[0]?.[1]).toBe(SPACE);
    expect(importInto.mock.calls[0]?.[0].items.map((i) => i.kind)).toEqual(['login', 'login']);
    expect(await screen.findByText(/Imported 2 items\./)).toBeInTheDocument();
    // Once imported, the button can't import the same file twice.
    expect(screen.getByRole('button', { name: 'Import 2 items' })).toBeDisabled();
  });

  it('asks for the password of an encrypted export and says when it is wrong', async () => {
    setup();
    const user = await choose('{"passwordProtected":true}');
    expect(await screen.findByText(/This export is encrypted\. Type the password/)).toBeInTheDocument();

    await user.type(screen.getByLabelText('Export password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Read the file' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/doesn't open the export/);
  });

  it('says what is wrong with a file it cannot read', async () => {
    setup();
    await choose('just some text');
    expect(await screen.findByRole('alert')).toHaveTextContent(/isn't an export Kemlock can read/);
    expect(screen.getByRole('button', { name: 'Read the file' })).toBeDisabled();
  });

  it('says the importer cannot start when the worker is missing', async () => {
    setup({
      client: createImportClient(() => {
        throw new Error('no worker');
      }),
    });
    await choose(BITWARDEN);
    expect(await screen.findByRole('alert')).toHaveTextContent(/importer can't start in this build/);
  });
});

describe('Export', () => {
  it('lists the formats and turns a space\'s policy into a disabled box', () => {
    setup();
    expect(screen.getByRole('radio', { name: /Kemlock export, encrypted/ })).toBeChecked();
    expect(screen.getByRole('radio', { name: /Bitwarden JSON, encrypted/ })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /CSV, not encrypted/ })).toBeInTheDocument();
    expect(screen.getByLabelText('My vault, 2 items')).toBeChecked();
    const off = screen.getByLabelText('Example Co: its policy turns exports off');
    expect(off).toBeDisabled();
    expect(off).not.toBeChecked();
  });

  it('needs a password of 8 characters for an encrypted export, then saves what the worker wrote', async () => {
    const { save } = setup();
    const user = userEvent.setup();
    const button = screen.getByRole('button', { name: 'Export' });
    expect(button).toBeDisabled();
    await user.type(screen.getByLabelText('New export password'), FAKE_EXPORT_PASSWORD);
    expect(button).toBeEnabled();
    await user.click(button);
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const [bytes, name, mime] = save.mock.calls[0] ?? [];
    expect(name).toBe('kemlock-export.json');
    expect(mime).toBe('application/json');
    const written = JSON.parse(new TextDecoder().decode(bytes as Uint8Array)) as { items: Array<{ kind: string }> };
    // Only "My vault" was in the default selection with exports allowed, and "Family" too.
    expect(written.items).toHaveLength(3);
    expect(await screen.findByText('Saved kemlock-export.json to your downloads.')).toBeInTheDocument();
  });

  it('leaves a space out when its box is unticked', async () => {
    const { save } = setup();
    const user = userEvent.setup();
    await user.click(screen.getByLabelText('Family, 1 item'));
    await user.type(screen.getByLabelText('New export password'), FAKE_EXPORT_PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(save).toHaveBeenCalled());
    const written = JSON.parse(new TextDecoder().decode(save.mock.calls[0]?.[0] as Uint8Array)) as { items: unknown[] };
    expect(written.items).toHaveLength(2);
  });

  it('writes a CSV without a password and warns that it is not encrypted', async () => {
    const { save } = setup();
    const user = userEvent.setup();
    await user.click(screen.getByRole('radio', { name: /CSV, not encrypted/ }));
    expect(screen.getByText(/A CSV file isn't encrypted/)).toBeInTheDocument();
    expect(screen.getByText(/Spreadsheet apps may still treat some cells as formulas/)).toBeInTheDocument();
    expect(screen.queryByLabelText('New export password')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    const [csv, name, mime] = save.mock.calls[0] ?? [];
    expect(name).toBe('kemlock-export-2026-11-22.csv');
    expect(mime).toBe('text/csv');
    expect(String(csv)).toContain('login,GitHub');
    expect(String(csv)).toContain('login,Family Netflix');
  });

  describe('protecting a CSV against formulas', () => {
    const hostile = () => [login('=cmd|x', '+user', '=pw', ['github.com'], { totp: '+JBSWY3DP' })];

    it('is on by default, and says plainly that the password and code columns are left as they are', async () => {
      const { save } = setup({ items: hostile });
      const user = userEvent.setup();
      await user.click(screen.getByRole('radio', { name: /CSV, not encrypted/ }));
      expect(screen.getByRole('checkbox', { name: 'Protect against spreadsheet formulas' })).toBeChecked();
      expect(
        screen.getByText(/The password and one-time code columns are always written exactly as they are/),
      ).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Export' }));
      await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
      const csv = String(save.mock.calls[0]?.[0]);
      expect(csv).toContain("'=cmd|x");
      expect(csv).toContain("'+user");
      expect(csv).toContain(',=pw,+JBSWY3DP');
    });

    it('writes everything as saved when the person turns it off', async () => {
      const { save } = setup({ items: hostile });
      const user = userEvent.setup();
      await user.click(screen.getByRole('radio', { name: /CSV, not encrypted/ }));
      await user.click(screen.getByRole('checkbox', { name: 'Protect against spreadsheet formulas' }));
      await user.click(screen.getByRole('button', { name: 'Export' }));
      await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
      const csv = String(save.mock.calls[0]?.[0]);
      expect(csv).not.toContain("'");
      expect(csv).toContain('login,=cmd|x');
      expect(csv).toContain(',+user,=pw,+JBSWY3DP');
    });
  });
});

describe('importThenPublish', () => {
  it('publishes the vault after a success and returns the count', async () => {
    const publish = vi.fn();
    await expect(importThenPublish(async () => ({ imported: 3 }), publish)).resolves.toBe(3);
    expect(publish).toHaveBeenCalledOnce();
  });

  it('publishes the items saved before a failure, then lets the failure through', async () => {
    const publish = vi.fn();
    await expect(
      importThenPublish(async () => {
        throw new Error('the server went away');
      }, publish),
    ).rejects.toThrow('the server went away');
    expect(publish).toHaveBeenCalledOnce();
  });
});
