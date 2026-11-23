import { type ReactNode, useId } from 'react';

const ICONS = {
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V5a1 1 0 0 1 1-1h10" />
    </>
  ),
  check: <path d="m5 12 5 5 9-10" />,
  lock: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.8 12.2 8.7-8.7M17 6l2.5 2.5M14.5 8.5l2 2" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6" />
      <path d="m20 20-4.2-4.2" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  eye: (
    <>
      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M3 3l18 18" />
      <path d="M10.6 5.1A9.7 9.7 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.3 6.4C3.7 8.1 2 12 2 12s3.6 7 10 7a9.6 9.6 0 0 0 4-.9" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    </>
  ),
  trash: (
    <>
      <path d="M4 7h16M10 11v6M14 11v6" />
      <path d="M6 7l1 13h10l1-13M9 7V4h6v3" />
    </>
  ),
  restore: (
    <>
      <path d="M4 12a8 8 0 1 0 2.5-5.8" />
      <path d="M4 4v5h5" />
    </>
  ),
  shield: <path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6l-7-3Z" />,
  server: (
    <>
      <rect x="3" y="4" width="18" height="6" rx="2" />
      <rect x="3" y="14" width="18" height="6" rx="2" />
      <path d="M7 7h.01M7 17h.01" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </>
  ),
  alert: (
    <>
      <path d="M12 3 2 20h20L12 3Z" />
      <path d="M12 10v4M12 17h.01" />
    </>
  ),
  edit: <path d="M4 20h4L19 9l-4-4L4 16v4ZM13 7l4 4" />,
  note: (
    <>
      <path d="M6 3h9l4 4v14H6V3Z" />
      <path d="M14 3v5h5M9 13h6M9 17h6" />
    </>
  ),
  login: (
    <>
      <circle cx="9" cy="8" r="4" />
      <path d="M3 21v-1a6 6 0 0 1 9-5" />
      <path d="M16 17h5M18.5 14.5 21 17l-2.5 2.5" />
    </>
  ),
  items: (
    <>
      <rect x="4" y="4" width="16" height="16" rx="3" />
      <path d="M8 9h8M8 13h8M8 17h5" />
    </>
  ),
  device: (
    <>
      <rect x="7" y="3" width="10" height="18" rx="2" />
      <path d="M11 18h2" />
    </>
  ),
  user: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21a8 8 0 0 1 16 0" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2 20a7 7 0 0 1 14 0M16 5a3.5 3.5 0 0 1 0 7M18 20a7 7 0 0 0-3-5.7" />
    </>
  ),
  list: <path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" />,
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" />
    </>
  ),
  logout: (
    <>
      <path d="M10 4H5v16h5M15 8l4 4-4 4M19 12H9" />
    </>
  ),
  back: <path d="M19 12H5M11 6l-6 6 6 6" />,
  send: (
    <>
      <path d="M21 3 10 14" />
      <path d="M21 3 14 21l-4-7-7-4z" />
    </>
  ),
  pulse: <path d="M3 12h4l2-5 4 10 2-5h6" />,
  transfer: <path d="M7 4v13M3 13l4 4 4-4M17 20V7M13 11l4-4 4 4" />,
  building: <path d="M4 21V5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v16M15 9h4a1 1 0 0 1 1 1v11M3 21h18M8 8h3M8 12h3M8 16h3" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
    </>
  ),
  move: <path d="M4 12h14M14 6l6 6-6 6" />,
  signin: <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3" />,
  link: <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />,
  mail: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 7 9 6 9-6" />
    </>
  ),
  home: (
    <>
      <path d="M4 11 12 4l8 7v9a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z" />
      <path d="M10 21v-6h4v6" />
    </>
  ),
  cloudOff: (
    <>
      <path d="M3 3l18 18" />
      <path d="M9 5a6 6 0 0 1 10 4 4 4 0 0 1 2 6M6 8a5 5 0 0 0-1 10h11" />
    </>
  ),
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  grid: (
    <>
      <rect x="4" y="4" width="7" height="7" rx="1.5" />
      <rect x="13" y="4" width="7" height="7" rx="1.5" />
      <rect x="4" y="13" width="7" height="7" rx="1.5" />
      <rect x="13" y="13" width="7" height="7" rx="1.5" />
    </>
  ),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof ICONS;

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `i ${className}` : 'i'} viewBox="0 0 24 24" aria-hidden="true">
      {ICONS[name]}
    </svg>
  );
}

/** The Kemlock icon from the logo canvas (Keyhole K): the azure keyhole K on a gunmetal tile, in
 * the plain form the canvas uses at small sizes (no texture filters). */
export function Logo({ size = 36 }: { size?: number }) {
  // useId can hold characters url(#…) won't take, so only letters, digits, - and _ stay.
  const tile = `kl-tile${useId().replace(/[^A-Za-z0-9_-]/g, '')}`;
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <defs>
        <linearGradient id={tile} gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="0" y2="100">
          <stop offset="0" stopColor="#5E646E" />
          <stop offset="0.44" stopColor="#353A41" />
          <stop offset="0.5" stopColor="#15181C" />
          <stop offset="0.57" stopColor="#262A30" />
          <stop offset="0.85" stopColor="#1E2126" />
          <stop offset="1" stopColor="#16181C" />
        </linearGradient>
      </defs>
      <rect width="100" height="100" rx="22.5" fill={`url(#${tile})`} />
      <g transform="translate(-2 0)">
        <rect x="24" y="20" width="17" height="60" rx="4" fill="#5AA9FF" />
        <path
          d="M72 26L48 50l24 24"
          fill="none"
          stroke="#5AA9FF"
          strokeWidth="16"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx="32.5" cy="45" r="4.6" fill={`url(#${tile})`} />
        <path d="M30.4 47l-1.2 10h6.6l-1.2-10z" fill={`url(#${tile})`} />
      </g>
    </svg>
  );
}
