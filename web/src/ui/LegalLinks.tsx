import { Link } from '@tanstack/react-router';
import { useT } from '@/i18n';
import { SourceLink } from './SourceLink';
import '@/styles/about.css';

/** The source link and the about page, under the sign-in and setup cards. */
export function LegalLinks() {
  const t = useT();
  return (
    <nav className="legal-links" aria-label={t('about.nav')}>
      <SourceLink />
      <Link to="/about">{t('about.link')}</Link>
    </nav>
  );
}
