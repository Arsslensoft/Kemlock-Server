import { Link } from '@tanstack/react-router';
import { useT } from '@/i18n';
import '@/styles/about.css';

/** The about page (which says where the source is), under the sign-in and setup cards. */
export function LegalLinks() {
  const t = useT();
  return (
    <nav className="legal-links" aria-label={t('about.nav')}>
      <Link to="/about">{t('about.link')}</Link>
    </nav>
  );
}
