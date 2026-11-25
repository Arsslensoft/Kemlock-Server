import type { ReactNode } from 'react';
import { useT } from '@/i18n';
import { Wordmark } from './Icon';
import { LegalLinks } from './LegalLinks';

/** The centered card page of sign-in and setup, with the logo and the badge. */
export function AuthPage({
  badge,
  width,
  children,
  footnote,
  legal = true,
}: {
  badge?: 'setup' | 'admin';
  width?: 560 | 600 | 680 | 760;
  children: ReactNode;
  footnote?: ReactNode;
  /** Show the source and about links under the card; the about page itself leaves them out. */
  legal?: boolean;
}) {
  const t = useT();
  return (
    <div className="auth-page">
      <div className="brand">
        <Wordmark />
        {badge ? (
          <span className="tag-chip amber">{t(badge === 'setup' ? 'brand.setup' : 'brand.admin')}</span>
        ) : null}
      </div>
      <main className={width ? `auth-card w${width}` : 'auth-card'}>{children}</main>
      {footnote}
      {legal ? <LegalLinks /> : null}
    </div>
  );
}
