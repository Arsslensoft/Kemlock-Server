// The avatar at the top right of both shells, and the menu it opens: who is signed in, then the
// entries each shell gives it. The vault's lists Profile, Security, Devices & apps, the admin
// console (admins only), About, and under a divider Lock the vault and Sign out. The admin
// console's lists My Vault, About, Sign out.
import type { ReactNode } from 'react';
import { useT } from '@/i18n';
import { Popup } from '@/ui/Popup';

export function AccountMenu({
  initials,
  name,
  subtitle,
  tone = 'accent',
  children,
}: {
  initials: string;
  /** What the person is called: their name, or the address when there is no name. */
  name: string;
  /** Under the name: the address, or "Admin · address" in the console. */
  subtitle: string;
  /** The console tints the avatar amber, as its badge is. */
  tone?: 'accent' | 'amber';
  /** The entries; `close` shuts the menu once one is chosen. */
  children: (close: () => void) => ReactNode;
}) {
  const t = useT();
  return (
    <Popup
      trigger={(props) => (
        <button type="button" className="avatar" {...props}>
          {/* The initials are a picture of the person, as a photo would be; the hidden text names
              the button, so no aria-label hides what it shows. */}
          <span aria-hidden="true">{initials}</span>
          <span className="sr">{t('shell.account', { name })}</span>
        </button>
      )}
    >
      {(close) => (
        <>
          <div className="popup-who">
            <span className={tone === 'amber' ? 'avatar-mark amber' : 'avatar-mark'} aria-hidden="true">
              {initials}
            </span>
            <span className="who-text">
              <span className="who-name">{name}</span>
              {subtitle ? <span className="who-sub">{subtitle}</span> : null}
            </span>
          </div>
          <nav aria-label={t('shell.menu.account')}>{children(close)}</nav>
        </>
      )}
    </Popup>
  );
}
