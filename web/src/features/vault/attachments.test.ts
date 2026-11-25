import { describe, expect, it } from 'vitest';
import {
  type AttachmentEntry,
  copiedEntries,
  entryBody,
  formatSize,
  namedEntries,
  newAttachment,
  noteAttachmentFields,
  pendingEntries,
  readAttachments,
  readFileEntry,
  serverFileIds,
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
  it('reads the attachments of a note the way the Kemlock app writes them', () => {
    const [entry] = readAttachments({ attachments: [STORED, 'junk', null, { size: 3 }] });
    expect(entry).toMatchObject({
      id: 'abcdefghijklmnopqrstuv',
      name: 'lease.pdf',
      size: 2400000,
      type: 'application/pdf',
      key: 'a2V5',
      addedAt: 5,
      sha256: 'ab'.repeat(32),
      kemlockFile: 'server-1',
      origin: 0,
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

  it('names the entries the server holds a file for, and the ids of those files', () => {
    const data = {
      attachments: [STORED, { id: 'b', name: 'new.txt', size: 1, key: 'k', addedAt: 1 }],
      file: { id: 'c', name: 'lease.pdf', size: 1, key: 'k', addedAt: 1, kemlockFile: 'server-2' },
    };
    expect(namedEntries(data).map((entry) => entry.id)).toEqual(['abcdefghijklmnopqrstuv', 'c']);
    expect(serverFileIds(data)).toEqual(['server-1', 'server-2']);
    expect(serverFileIds({})).toEqual([]);
  });
});

describe('writing the files of a body', () => {
  it('writes a stored entry back exactly as it was: no key added, none moved, no value filled in', () => {
    const odd = { name: 'odd.bin', kemlockFile: 'server-3', key: 'k', extra: 1, size: 'unknown' };
    const [entry, other] = readAttachments({ attachments: [STORED, odd] });
    expect(entryBody(entry as AttachmentEntry)).toBe(STORED);
    expect(entryBody(other as AttachmentEntry)).toBe(odd);
    // What the form shows of the odd one is filled in; what is written is not.
    expect(other).toMatchObject({ id: '', size: 0, addedAt: 0 });
    expect(Object.keys(entryBody(other as AttachmentEntry))).toEqual(['name', 'kemlockFile', 'key', 'extra', 'size']);
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
    expect(Object.keys(entryBody(entry))).toEqual(['id', 'name', 'size', 'type', 'key', 'addedAt']);
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
    expect(noteAttachmentFields(entries, { attachments: [STORED] })).toEqual({ attachments: [STORED] });
    expect(noteAttachmentFields([chosen])).toEqual({ attachments: undefined });
  });

  it('keeps each stored entry where it was in the list, and what the form cannot show with it', () => {
    const second = { id: 'second', name: 'b.txt', size: 1, key: 'k', addedAt: 1, kemlockFile: 'server-2' };
    const unreadable = { surprise: true };
    const data = { attachments: [STORED, unreadable, second] };
    const entries = readAttachments(data);
    expect(entries.map((entry) => entry.origin)).toEqual([0, 2]);
    // Both stay: same list, same order, the unreadable entry between them.
    expect(noteAttachmentFields(entries, data)['attachments']).toEqual([STORED, unreadable, second]);
    // The first is removed: the others keep their order.
    expect(noteAttachmentFields(entries.slice(1), data)['attachments']).toEqual([unreadable, second]);
    // A new file goes after what was there.
    const chosen: AttachmentEntry = { id: 'new', name: 'x.txt', size: 1, key: 'k', addedAt: 1, kemlockFile: 'server-3' };
    expect((noteAttachmentFields([...entries, chosen], data)['attachments'] as unknown[]).slice(-1)).toEqual([
      entryBody(chosen),
    ]);
  });

  it('writes nothing for a note left with no file and no entry it could not read', () => {
    expect(noteAttachmentFields([], { attachments: [STORED] })).toEqual({ attachments: undefined });
    expect(noteAttachmentFields([], { attachments: ['odd'] })).toEqual({ attachments: ['odd'] });
  });
});

describe('how a file is described', () => {
  it('writes sizes in decimal units, the number as the locale writes it', () => {
    expect(formatSize(5)).toBe('5 B');
    expect(formatSize(2048)).toBe('2 KB');
    expect(formatSize(2_400_000)).toBe('2.4 MB');
    expect(formatSize(2_400_000, 'de')).toBe('2,4 MB');
    expect(formatSize(1_500_000_000)).toBe('1.5 GB');
  });

  it('names the kind of file in a word, as the mockup does', () => {
    expect(typeLabel({ name: 'recovery-codes.txt', type: 'text/plain' })).toBe('Text');
    expect(typeLabel({ name: 'README', type: 'text/plain' })).toBe('Text');
    expect(typeLabel({ name: 'notes.txt' })).toBe('Text');
    expect(typeLabel({ name: 'lease.pdf', type: 'application/pdf' })).toBe('PDF');
    expect(typeLabel({ name: 'photo.JPG', type: 'image/jpeg' })).toBe('Image');
    expect(typeLabel({ name: 'photo.png' })).toBe('Image');
    expect(typeLabel({ name: 'song.mp3', type: 'audio/mpeg' })).toBe('Audio');
    expect(typeLabel({ name: 'clip.mov' })).toBe('Video');
    expect(typeLabel({ name: 'backup.zip' })).toBe('ZIP');
    expect(typeLabel({ name: 'archive.tar.verylongext', type: 'application/zip' })).toBe('ZIP');
    expect(typeLabel({ name: 'README' })).toBe('');
  });
});

describe('the entries of a copy', () => {
  const held = [
    { id: 'a1', name: 'map.png', size: 3, key: 'k1', addedAt: 1, kemlockFile: 'old-1' },
    { id: 'a2', name: 'never.txt', size: 9, key: 'k2', addedAt: 2 },
  ];

  it('wait to have each uploaded file sent again, and name no file until then', () => {
    const [sent, never] = copiedEntries(readAttachments({ attachments: held }), 'source-item');
    expect(sent).toMatchObject({ id: 'a1', name: 'map.png', copyOf: { itemId: 'source-item', fileId: 'old-1' } });
    expect(sent?.kemlockFile).toBeUndefined();
    // An entry never uploaded has no file to send: it is kept as it is.
    expect(never?.copyOf).toBeUndefined();
  });

  it('are pending, not stored, so a save of the copy writes no name for them', () => {
    const entries = copiedEntries(readAttachments({ attachments: held }), 'source-item');
    expect(pendingEntries(entries).map((entry) => entry.id)).toEqual(['a1']);
    expect(storedEntries(entries).map((entry) => entry.id)).toEqual(['a2']);
    expect(noteAttachmentFields(entries, null)['attachments']).toEqual([entryBody(entries[1] as AttachmentEntry)]);
  });
});
