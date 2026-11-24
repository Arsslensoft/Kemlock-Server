import { describe, expect, it } from 'vitest';
import { displayPiece, isOneOf, normalizePiece } from './kitPiece';

const PIECE = `BMCKIT1-ABCDEFGH-231-${'ABCD'.repeat(13)}-WXYZ`;

describe('kit pieces as text', () => {
  it('groups the share in fours and leaves the rest alone', () => {
    const shown = displayPiece(PIECE);
    expect(shown.split('-')[3]).toBe(Array(13).fill('ABCD').join(' '));
    expect(shown.split('-')[0]).toBe('BMCKIT1');
    expect(shown.split('-')[4]).toBe('WXYZ');
  });

  it('shows text that is not a piece as it is', () => {
    expect(displayPiece('hello')).toBe('hello');
  });

  it('reads what was typed in any case with any spaces', () => {
    expect(normalizePiece(displayPiece(PIECE).toLowerCase())).toBe(PIECE);
  });

  it('matches a typed piece against the pieces shown', () => {
    const other = `BMCKIT1-ABCDEFGH-232-${'EFGH'.repeat(13)}-WXYZ`;
    expect(isOneOf(displayPiece(other).toLowerCase(), [PIECE, other])).toBe(true);
    expect(isOneOf(PIECE.slice(0, -1), [PIECE, other])).toBe(false);
    expect(isOneOf('   ', [PIECE])).toBe(false);
  });
});
