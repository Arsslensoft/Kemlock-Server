// The Website row of a detail card: a login's websites, or the ones an MFA code or backup codes show.
// Those take the websites of the login they are linked to, read-only: "From the linked login X.
// Change it there." Only the original item edits them.
import { useT } from '@/i18n';
import { hostOfUrl, isWebUrl } from '../kinds';
import type { SiteInfo } from '../itemLinks';
import { Row } from './rows';

export function WebsiteRow({ sites }: { sites: SiteInfo | undefined }) {
  const t = useT();
  if (!sites || sites.urls.length === 0) return null;
  return (
    <Row label={t('item.website')}>
      {sites.urls.map((url) => (
        <div key={url}>
          {isWebUrl(url) ? (
            <a href={url} target="_blank" rel="noreferrer noopener">
              {hostOfUrl(url)}
            </a>
          ) : (
            <span className="mono">{url}</span>
          )}
        </div>
      ))}
      {sites.fromLogin !== undefined ? (
        <div className="hint">{t('detail.website.fromLogin', { name: sites.fromLogin })}</div>
      ) : null}
    </Row>
  );
}
