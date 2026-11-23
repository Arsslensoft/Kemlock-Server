import { describe, expect, it } from 'vitest';
import { ME, SPACE, login, vaultItem } from '@/test/tools-fixtures';
import { CSV_COLUMNS, exportFilename, exportItemsOf, toCsv } from './exporter';

describe('toCsv', () => {
  it('writes the header, then logins and notes with CRLF row ends', () => {
    const a = login('GitHub', 'sam', 'p"w,1', ['https://github.com', 'gist.github.com'], { folder: 'Work', favorite: true });
    const note = vaultItem('note', { name: 'Wi-Fi', text: 'line1\nline2' });
    const { csv, written, left } = toCsv([a, note]);
    const rows = csv.split('\r\n');
    expect(rows[0]).toBe(CSV_COLUMNS.join(','));
    expect(written).toBe(2);
    expect(left).toBe(0);
    expect(rows[1]).toBe('Work,1,login,GitHub,,,0,"https://github.com\ngist.github.com",sam,"p""w,1",');
    expect(rows[2]).toBe(',,note,Wi-Fi,"line1\nline2",,0,,,,');
    expect(csv.endsWith('\r\n')).toBe(true);
  });

  it('leaves a password as it is, even one a spreadsheet would read as a formula', () => {
    const { csv } = toCsv([login('X', 'u', '=1+1', ['x.example'])]);
    expect(csv).toContain(',=1+1,');
  });

  it('counts the kinds CSV has no column for, and unreadable items', () => {
    const { written, left } = toCsv([vaultItem('card', { name: 'Visa' }), vaultItem('login', null)]);
    expect(written).toBe(0);
    expect(left).toBe(2);
  });
});

describe('exportItemsOf', () => {
  it('takes the readable items of the chosen owners', () => {
    const mine = login('Mine', 'u', 'p', ['a.example']);
    const space = login('Space', 'u', 'p', ['b.example'], {}, { owner: SPACE });
    const unreadable = vaultItem('login', null);
    const out = exportItemsOf([mine, space, unreadable], new Set([ME]));
    expect(out).toEqual([{ id: mine.id, kind: 'login', data: mine.data }]);
  });
});

describe('exportFilename', () => {
  it('carries the date', () => {
    expect(exportFilename('kemlock-export', 'csv', new Date('2026-11-22T23:00:00Z'))).toBe(
      'kemlock-export-2026-11-22.csv',
    );
  });
});
