import { useMemo } from 'react';
import { encode } from 'uqr';

/**
 * A QR code drawn as SVG elements, not injected as markup: with Trusted Types on, nothing may
 * assign a string to innerHTML. One path with a rectangle per dark module.
 */
export function QrCode({ text, label, size = 184 }: { text: string; label: string; size?: number }) {
  const { path, modules } = useMemo(() => {
    const { data } = encode(text, { ecc: 'M', border: 0 });
    let d = '';
    data.forEach((row, y) => {
      row.forEach((dark, x) => {
        if (dark) d += `M${x} ${y}h1v1h-1z`;
      });
    });
    return { path: d, modules: data.length };
  }, [text]);
  const quiet = 3;
  const view = modules + quiet * 2;
  return (
    <svg
      className="qr"
      width={size}
      height={size}
      viewBox={`${-quiet} ${-quiet} ${view} ${view}`}
      role="img"
      aria-label={label}
      shapeRendering="crispEdges"
    >
      <rect x={-quiet} y={-quiet} width={view} height={view} fill="#ffffff" />
      <path d={path} fill="#0a0b0d" />
    </svg>
  );
}
