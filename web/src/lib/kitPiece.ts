// How a Recovery Kit piece is written for people (docs/crypto.md, "The Recovery Kit"). The worker
// reads and checks pieces; this only lays the text out and compares what was typed.

/** The piece's text however it was typed: upper case, no spaces. */
export function normalizePiece(text: string): string {
  return text.replace(/\s+/g, '').toUpperCase();
}

/** The piece with its long share in groups of four, for print and for reading aloud. */
export function displayPiece(text: string): string {
  const parts = text.split('-');
  if (parts.length !== 5) return text;
  parts[3] = (parts[3] ?? '').match(/.{1,4}/g)?.join(' ') ?? '';
  return parts.join('-');
}

/** Whether `typed` is one of `pieces`, ignoring case and spaces. */
export function isOneOf(typed: string, pieces: readonly string[]): boolean {
  const wanted = normalizePiece(typed);
  return wanted !== '' && pieces.some((piece) => normalizePiece(piece) === wanted);
}
