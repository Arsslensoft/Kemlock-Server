import { useQuery } from '@tanstack/react-query';
import { configQuery } from '@/app/services';
import { useT } from '@/i18n';
import { webAddress } from '@/lib/web-address';
import { Icon } from './Icon';

/**
 * "Source code": a link to the source of the version this server runs, which AGPL-3.0 section 13
 * offers to everyone who uses it, signed in or not. The address is the server's own (its config),
 * so a modified server points at its own source. Nothing shows until the server has said where.
 */
export function SourceLink({ icon, className }: { icon?: boolean; className?: string }) {
  const t = useT();
  const config = useQuery(configQuery);
  const href = webAddress(config.data?.sourceUrl);
  if (!href) return null;
  return (
    <a className={className} href={href} target="_blank" rel="noopener noreferrer">
      {icon ? <Icon name="link" /> : null}
      {t('about.source')}
    </a>
  );
}
