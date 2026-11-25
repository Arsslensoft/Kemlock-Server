import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import type { AttachmentEntry } from '../attachments';
import type { VaultItem } from '../vault';
import { FileForm, type FileFormValues, fileDefaults, fileFields } from './file';
import { NoteForm, type NoteFormValues, noteDefaults, noteFields } from './note';
import { PasskeyPage } from './passkey';

function item(kind: string, data: Record<string, unknown>): VaultItem {
  return { id: 'i1', owner: 'user:u', kind, revision: 2, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

const STORED = {
  id: 'abcdefghijklmnopqrstuv',
  name: 'recovery-codes.txt',
  size: 2048,
  type: 'text/plain',
  key: 'a2V5',
  addedAt: 5,
  kemlockFile: 'server-1',
  vendor: 'kept',
};

describe('NoteForm', () => {
  it('saves a note, whose text is labelled Note', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<NoteForm initial={noteDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Recovery plan');
    await user.type(screen.getByLabelText('Note'), 'line one');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({
      name: 'Recovery plan',
      text: 'line one',
      favorite: false,
      attachments: [],
      fields: [],
      links: [],
    });
  });

  it('attaches files, encrypted in this browser before upload, and removes one', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<NoteForm initial={noteDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    expect(screen.getByText(/encrypted in this browser before upload/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('Name'), 'With files');
    const input = screen.getByLabelText('Add a file');
    await user.upload(input, [
      new File(['hello'], 'hello.txt', { type: 'text/plain' }),
      new File(['%PDF'], 'lease.pdf', { type: 'application/pdf' }),
    ]);
    expect(screen.getByText('hello.txt')).toBeInTheDocument();
    expect(screen.getByText('TXT · 5 B · ready to encrypt and upload')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Remove lease.pdf' }));
    expect(screen.queryByText('lease.pdf')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const attachments = (onSubmit.mock.calls[0]?.[0] as NoteFormValues).attachments as AttachmentEntry[];
    expect(attachments).toHaveLength(1);
    expect(attachments[0]).toMatchObject({ name: 'hello.txt', size: 5, type: 'text/plain' });
    expect(attachments[0]?.file).toBeInstanceOf(Blob);
    expect(attachments[0]?.key).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(attachments[0]?.kemlockFile).toBeUndefined();
  });

  it('opens with the stored attachments, and writes only those that are on the server', () => {
    const existing = item('note', { name: 'Plan', text: 't', attachments: [STORED] });
    const values = noteDefaults(existing);
    expect(values.attachments).toHaveLength(1);
    const pending = {
      id: 'new',
      name: 'new.txt',
      size: 3,
      key: 'a2V5',
      addedAt: 9,
      file: new Blob(['abc']),
    } as AttachmentEntry;
    const fields = noteFields({ ...values, attachments: [...values.attachments, pending] }, existing);
    expect(fields['attachments']).toEqual([STORED]);
    expect(noteFields({ ...values, attachments: [] }, existing)['attachments']).toBeUndefined();
  });
});

describe('FileForm', () => {
  const file = () => new File(['lease'], 'Lease agreement.pdf', { type: 'application/pdf' });

  it('asks for a file and takes the name from it', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<FileForm initial={fileDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    expect(screen.getByText('Drop a file here')).toBeInTheDocument();
    expect(screen.getByText(/Counts toward the attachment space/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Choose a file.')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();

    await user.upload(screen.getByLabelText('Choose a file'), file());
    expect(screen.getByLabelText('Name')).toHaveValue('Lease agreement.pdf');
    expect(screen.getByText('PDF · 5 B · ready to encrypt and upload')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const values = onSubmit.mock.calls[0]?.[0] as FileFormValues;
    expect(values.name).toBe('Lease agreement.pdf');
    expect((values.file as AttachmentEntry).file).toBeInstanceOf(Blob);
  });

  it('takes a file dropped on the area, and lets it be removed', async () => {
    renderWithIntl(<FileForm initial={fileDefaults()} onSubmit={vi.fn()} onCancel={vi.fn()} submitLabel="Save" />);
    const zone = screen.getByText('Drop a file here').closest('.drop') as HTMLElement;
    fireEvent.drop(zone, { dataTransfer: { files: [file()] } });
    expect(await screen.findByText('PDF · 5 B · ready to encrypt and upload')).toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Remove Lease agreement.pdf' }));
    expect(screen.queryByText('PDF · 5 B · ready to encrypt and upload')).not.toBeInTheDocument();
  });

  it('keeps a name the person typed when another file is chosen', async () => {
    renderWithIntl(<FileForm initial={fileDefaults()} onSubmit={vi.fn()} onCancel={vi.fn()} submitLabel="Save" />);
    const user = userEvent.setup({ delay: null });
    await user.upload(screen.getByLabelText('Choose a file'), file());
    await user.clear(screen.getByLabelText('Name'));
    await user.type(screen.getByLabelText('Name'), 'My lease');
    await user.upload(screen.getByLabelText('Choose a file'), new File(['x'], 'other.pdf'));
    expect(screen.getByLabelText('Name')).toHaveValue('My lease');
  });

  it('has links and notes but no custom fields', () => {
    renderWithIntl(<FileForm initial={fileDefaults()} onSubmit={vi.fn()} onCancel={vi.fn()} submitLabel="Save" />);
    expect(screen.getByText('Linked items')).toBeInTheDocument();
    expect(screen.queryByText('Custom fields')).not.toBeInTheDocument();
    expect(screen.queryByText('Attachments')).not.toBeInTheDocument();
  });

  it('opens an existing file with its file, and writes it back untouched', () => {
    const existing = item('file', { name: 'Lease', notes: 'Signed', file: STORED, links: [] });
    const values = fileDefaults(existing);
    expect(values).toMatchObject({ name: 'Lease', notes: 'Signed' });
    expect((values.file as AttachmentEntry).kemlockFile).toBe('server-1');
    const fields = fileFields({ ...values, name: 'Lease 2027' }, existing);
    expect(fields).toMatchObject({ name: 'Lease 2027', notes: 'Signed', file: STORED });
  });

  it('does not write a file that is not on the server yet', () => {
    const chosen = {
      id: 'new',
      name: 'new.pdf',
      size: 3,
      key: 'a2V5',
      addedAt: 9,
      file: new Blob(['abc']),
    } as AttachmentEntry;
    const fields = fileFields({ ...fileDefaults(), name: 'New', file: chosen }, undefined);
    expect('file' in fields).toBe(false);
  });
});

describe('PasskeyPage', () => {
  it('has no field and says that websites make passkeys', async () => {
    const onDone = vi.fn();
    renderWithIntl(<PasskeyPage onDone={onDone} />);
    expect(screen.getByText('Passkeys come from websites')).toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(screen.getByText(/In a browser, use Kemlock for browsers/)).toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Done' }));
    expect(onDone).toHaveBeenCalledOnce();
  });
});
