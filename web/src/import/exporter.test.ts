import { describe, expect, it } from 'vitest';
import { ME, SPACE, login, vaultItem } from '@/test/tools-fixtures';
import { CSV_COLUMNS, exportFilename, exportItemsOf, neutralise, toCsv } from './exporter';

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

describe('formula injection', () => {
  const row = (csv: string) => csv.split('\r\n')[1] ?? '';
  /** What a cell looks like in the file: quoted when it holds a quote, comma or line break. */
  const q = (value: string) => (/[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value);

  it('puts a quote in front of every text another member can write that a spreadsheet would run', () => {
    for (const start of ['=', '+', '-', '@', '\t', '\r']) {
      const hostile = `${start}cmd|x`;
      const { csv } = toCsv([login(hostile, hostile, 'pw', [hostile], { notes: hostile, folder: hostile })]);
      const safe = q(`'${hostile}`);
      expect(row(csv), JSON.stringify(start)).toBe(`${safe},,login,${safe},${safe},,0,${safe},${safe},pw,`);
    }
  });

  it('does the same for a note, and leaves ordinary text alone', () => {
    const { csv } = toCsv([
      vaultItem('note', { name: '=2+2', text: '@SUM(A1)' }),
      login('GitHub', 'sam', 'pw', ['https://github.com']),
    ]);
    const rows = csv.split('\r\n');
    expect(rows[1]).toBe(",,note,'=2+2,'@SUM(A1),,0,,,,");
    expect(rows[2]).toBe(',,login,GitHub,,,0,https://github.com,sam,pw,');
  });

  it('keeps the quoting a comma or a quote needs, after the prefix', () => {
    const { csv } = toCsv([login('=a,b', 'u', 'pw', [])]);
    expect(row(csv)).toBe(`,,login,"'=a,b",,,0,,u,pw,`);
  });

  it('never alters the password or the one-time code secret, which would change the secret', () => {
    const { csv } = toCsv([login('X', 'u', '=1+1', ['x.example'], { totp: '+JBSWY3DP' })]);
    expect(row(csv)).toBe(',,login,X,,,0,x.example,u,=1+1,+JBSWY3DP');
  });

  it('leaves a dash or an at sign in the middle of text alone', () => {
    expect(neutralise('Wi-Fi')).toBe('Wi-Fi');
    expect(neutralise('sam@example.co')).toBe('sam@example.co');
    expect(neutralise('')).toBe('');
    expect(neutralise('-1')).toBe("'-1");
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
