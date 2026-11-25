import { describe, expect, it } from 'vitest';
import {
  type AttachmentEntry,
  entryBody,
  formatSize,
  newAttachment,
  noteAttachmentFields,
  pendingEntries,
  readAttachments,
  readFileEntry,
  removedServerFiles,
  storedEntries,
  typeLabel,
} from './attachments';

const STORED = {
  id: 'abcdefghijklmnopqrstuv',
  name: 'lease.pdf',
  size: 2400000,
  type: 'application/pdf',
  key: 'a2V5',
  addedAt: 5,
  sha256: 'ab'.repeat(32),
  kemlockFile: 'server-1',
  vendor: { kept: true },
};

describe('reading the files of a body', () => {
  it('reads the attachments of a note the way the Kemlock app writes them, keeping keys it does not know', () => {
    const [entry] = readAttachments({ attachments: [STORED, 'junk', null, { size: 3 }] });
    expect(entry).toEqual({
      id: 'abcdefghijklmnopqrstuv',
      name: 'lease.pdf',
      size: 2400000,
      type: 'application/pdf',
      key: 'a2V5',
      addedAt: 5,
      sha256: 'ab'.repeat(32),
      kemlockFile: 'server-1',
      extra: { vendor: { kept: true } },
    });
    expect(readAttachments({ attachments: [STORED, 'junk', null, { size: 3 }] })).toHaveLength(1);
    expect(readAttachments({})).toEqual([]);
    expect(readAttachments(null)).toEqual([]);
  });

  it('reads the one file of a File item', () => {
    expect(readFileEntry({ file: STORED })?.name).toBe('lease.pdf');
    expect(readFileEntry({})).toBeUndefined();
    expect(readFileEntry({ file: 'x' })).toBeUndefined();
  });
});

describe('writing the files of a body', () => {
  it('writes an entry back as it was read, with what it did not know', () => {
    const [entry] = readAttachments({ attachments: [STORED] });
    expect(entryBody(entry as AttachmentEntry)).toEqual(STORED);
  });

  it('makes an entry for a chosen file with its own id and key, and the bytes still to send', () => {
    const file = new File(['hello'], 'hello.txt', { type: 'text/plain' });
    const entry = newAttachment(file, 123);
    expect(entry).toMatchObject({ name: 'hello.txt', size: 5, type: 'text/plain', addedAt: 123 });
    expect(entry.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(entry.key).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(entry.file).toBe(file);
    expect(entry.kemlockFile).toBeUndefined();
    expect(newAttachment(file, 123).key).not.toBe(entry.key);
    // Its hash is taken from the bytes when they are sent (saveFlow), not when the file is chosen.
    expect(entry.sha256).toBeUndefined();
    // The bytes and the key never go in the body twice: the entry's body has no file.
    expect('file' in entryBody(entry)).toBe(false);
  });

  it('leaves out a type the picker did not know', () => {
    expect('type' in newAttachment(new File(['x'], 'x'), 1)).toBe(false);
  });

  it('splits stored entries from those still to send, and writes only the stored ones to a note', () => {
    const [stored] = readAttachments({ attachments: [STORED] });
    const chosen = newAttachment(new File(['x'], 'x.txt'), 1);
    const entries = [stored as AttachmentEntry, chosen];
    expect(storedEntries(entries)).toEqual([stored]);
    expect(pendingEntries(entries)).toEqual([chosen]);
    expect(noteAttachmentFields(entries)).toEqual({ attachments: [STORED] });
    expect(noteAttachmentFields([chosen])).toEqual({ attachments: undefined });
  });

  it('names the server files of the entries the person removed', () => {
    const before = readAttachments({
      attachments: [STORED, { ...STORED, id: 'second', kemlockFile: 'server-2' }, { ...STORED, id: 'third', kemlockFile: undefined }],
    });
    expect(removedServerFiles(before, [before[1] as AttachmentEntry])).toEqual(['server-1']);
    expect(removedServerFiles(before, before)).toEqual([]);
    expect(removedServerFiles([], before)).toEqual([]);
  });
});

describe('how a file is described', () => {
  it('writes sizes in decimal units', () => {
    expect(formatSize(5)).toBe('5 B');
    expect(formatSize(2048)).toBe('2 KB');
    expect(formatSize(2_400_000)).toBe('2.4 MB');
    expect(formatSize(1_500_000_000)).toBe('1.5 GB');
  });

  it('names the type from the extension, or the media type without one', () => {
    expect(typeLabel({ name: 'lease.pdf', type: 'application/pdf' })).toBe('PDF');
    expect(typeLabel({ name: 'README', type: 'text/plain' })).toBe('PLAIN');
    expect(typeLabel({ name: 'README' })).toBe('');
    expect(typeLabel({ name: 'archive.tar.verylongext', type: 'application/zip' })).toBe('ZIP');
  });
});
