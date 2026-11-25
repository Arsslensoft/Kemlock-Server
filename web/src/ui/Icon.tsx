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
  // One icon per kind of item, as the New menu and the sidebar draw them (login, note and SSH
  // key use `login`, `note` and `key` above).
  file: <path d="m21 11-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7" />,
  mfa: (
    <>
      <circle cx="12" cy="13" r="8" />
      <path d="M12 9v4l2.5 2.5M9 2h6" />
    </>
  ),
  backupCodes: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4" />
      <path d="m5.6 5.6 3.6 3.6M14.8 14.8l3.6 3.6M18.4 5.6l-3.6 3.6M9.2 14.8l-3.6 3.6" />
    </>
  ),
  passkey: (
    <>
      <circle cx="9" cy="8" r="4" />
      <path d="M3 21v-1a6 6 0 0 1 8-5.6" />
      <circle cx="18" cy="14" r="2.5" />
      <path d="M18 16.5V22M18 19.5h2" />
    </>
  ),
  card: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="M3 10h18M7 15h3" />
    </>
  ),
  identity: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <circle cx="9" cy="11" r="2.5" />
      <path d="M5.5 17a3.5 3.5 0 0 1 7 0M15 10h3M15 14h3" />
    </>
  ),
  contact: (
    <>
      <path d="M6 3h12a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H6V3Z" />
      <circle cx="12.5" cy="10" r="2.5" />
      <path d="M9 16a3.5 3.5 0 0 1 7 0M4 7h2M4 12h2M4 17h2" />
    </>
  ),
  certificate: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M7 8h10M7 12h4" />
      <circle cx="16" cy="16" r="3" />
      <path d="m14.5 18.5-1 3.5 2.5-1.2 2.5 1.2-1-3.5" />
    </>
  ),
  pgpKey: (
    <>
      <rect x="4" y="11" width="11" height="10" rx="2" />
      <path d="M7 11V8a2.5 2.5 0 0 1 5 0v3" />
      <path d="M9.5 15v2M17 4h4M19 2v4" />
    </>
  ),
  close: <path d="M6 6l12 12M18 6 6 18" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof ICONS;

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `i ${className}` : 'i'} viewBox="0 0 24 24" aria-hidden="true">
      {ICONS[name]}
    </svg>
  );
}

const WORDMARK_PATH =
  'M107.886 81.032Q101.006 81.032 95.932 78.065Q90.858 75.098 88.106 69.68Q85.354 64.262 85.354 57.038Q85.354 49.814 88.106 44.396Q90.858 38.978 95.889 36.011Q100.92 33.044 107.628 33.044Q114.164 33.044 119.066 35.968Q123.968 38.892 126.677 44.396Q129.386 49.9 129.386 57.64L129.386 60.134L96.792 60.134Q97.05 66.154 100.06 69.207Q103.07 72.26 107.972 72.26Q115.454 72.26 117.518 65.896L128.784 66.584Q126.892 73.292 121.345 77.162Q115.798 81.032 107.886 81.032ZM96.792 52.738L118.034 52.738Q117.604 47.148 114.809 44.439Q112.014 41.73 107.628 41.73Q103.156 41.73 100.318 44.568Q97.48 47.406 96.792 52.738ZM135.379 80L135.379 34.076L145.355 34.076L145.613 41.73Q147.333 37.602 150.644 35.323Q153.955 33.044 158.255 33.044Q163.329 33.044 166.726 35.538Q170.123 38.032 171.585 42.504Q173.133 37.86 176.53 35.452Q179.927 33.044 184.743 33.044Q191.881 33.044 195.966 37.516Q200.051 41.988 200.051 50.502L200.051 80L189.043 80L189.043 53.34Q189.043 41.988 181.217 41.988Q177.261 41.988 175.025 45.041Q172.789 48.094 172.789 53.684L172.789 80L162.555 80L162.555 53.684Q162.555 48.094 160.835 45.041Q159.115 41.988 154.901 41.988Q150.945 41.988 148.666 45.084Q146.387 48.18 146.387 53.684L146.387 80L135.379 80ZM219.559 80Q214.485 80 211.518 77.42Q208.551 74.84 208.551 69.164L208.551 18.94L219.559 18.94L219.559 68.046Q219.559 71.486 222.999 71.486L226.353 71.486L226.353 80L219.559 80ZM250.753 81.032Q243.959 81.032 238.842 78.065Q233.725 75.098 230.93 69.723Q228.135 64.348 228.135 57.038Q228.135 49.728 230.93 44.353Q233.725 38.978 238.842 36.011Q243.959 33.044 250.753 33.044Q257.547 33.044 262.621 36.011Q267.695 38.978 270.49 44.353Q273.285 49.728 273.285 57.038Q273.285 64.348 270.49 69.723Q267.695 75.098 262.621 78.065Q257.547 81.032 250.753 81.032ZM250.753 72.088Q255.999 72.088 258.923 68.132Q261.847 64.176 261.847 57.038Q261.847 49.9 258.923 45.944Q255.999 41.988 250.753 41.988Q245.421 41.988 242.497 45.944Q239.573 49.9 239.573 57.038Q239.573 64.176 242.497 68.132Q245.421 72.088 250.753 72.088ZM299.144 81.032Q292.264 81.032 287.19 78.065Q282.116 75.098 279.321 69.68Q276.526 64.262 276.526 57.038Q276.526 49.814 279.321 44.396Q282.116 38.978 287.19 36.011Q292.264 33.044 299.144 33.044Q307.916 33.044 313.721 37.602Q319.526 42.16 320.558 50.33L309.206 50.932Q308.518 46.546 305.809 44.267Q303.1 41.988 299.144 41.988Q293.812 41.988 290.888 45.944Q287.964 49.9 287.964 57.038Q287.964 64.176 290.888 68.132Q293.812 72.088 299.144 72.088Q303.186 72.088 305.895 69.766Q308.604 67.444 309.206 62.542L320.558 63.058Q319.612 71.314 313.807 76.173Q308.002 81.032 299.144 81.032ZM325.614 80L325.614 18.94L336.622 18.94L336.622 54.802L355.456 34.076L369.044 34.076L351.07 53.168L369.646 80L357.262 80L343.846 59.704L336.622 67.358L336.622 80L325.614 80Z';
const WORDMARK_STOPS: Record<'dark' | 'light', Array<[number, string]>> = {
  dark: [
    [0, '#FAFBFD'],
    [0.28, '#DCE1E8'],
    [0.48, '#A4ACB8'],
    [0.52, '#5D6673'],
    [0.58, '#8F98A4'],
    [0.78, '#D3D8DF'],
    [0.92, '#EEF1F4'],
    [1, '#A9B0BA'],
  ],
  light: [
    [0, '#5A606A'],
    [0.45, '#3A3F47'],
    [0.5, '#16191D'],
    [0.58, '#2C3036'],
    [0.85, '#4A5059'],
    [1, '#2A2E34'],
  ],
};
const WORDMARK_KEY = { dark: '#5AA9FF', light: '#1F6FD1' };

/** The Kemlock wordmark: the keyhole K joined to "emlock". Both theme variants are drawn and CSS
 * (`.wordmark` in components.css) shows the one for the active theme. */
export function Wordmark({ height = 28 }: { height?: number }) {
  const uid = useId().replace(/[^A-Za-z0-9_-]/g, '');
  return (
    <span className="wordmark" role="img" aria-label="Kemlock">
      {(['dark', 'light'] as const).map((variant) => {
        const gradient = `kl-wm-${variant}${uid}`;
        return (
          <svg
            key={variant}
            className={`wm-${variant}`}
            height={height}
            width={(height * 354) / 76}
            viewBox="18 12 354 76"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id={gradient} gradientUnits="userSpaceOnUse" x1="0" y1="18" x2="0" y2="82">
                {WORDMARK_STOPS[variant].map(([offset, color]) => (
                  <stop key={offset} offset={offset} stopColor={color} />
                ))}
              </linearGradient>
            </defs>
            <g transform="translate(-2 0)">
              <path
                fill={WORDMARK_KEY[variant]}
                fillRule="evenodd"
                d="M28 20h9a4 4 0 0 1 4 4v52a4 4 0 0 1-4 4h-9a4 4 0 0 1-4-4V24a4 4 0 0 1 4-4zM29.2 57H35.8L34.836 48.963A4.6 4.6 0 1 0 30.164 48.963Z"
              />
              <path
                d="M72 26L48 50l24 24"
                fill="none"
                stroke={WORDMARK_KEY[variant]}
                strokeWidth="16"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </g>
            <path fill={`url(#${gradient})`} d={WORDMARK_PATH} />
          </svg>
        );
      })}
    </span>
  );
}
