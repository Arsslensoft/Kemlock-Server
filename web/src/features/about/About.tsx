import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { ConfigResponse } from '@/api/types';
import { configQuery } from '@/app/services';
import { useT } from '@/i18n';
import { webAddress } from '@/lib/web-address';
import { AuthPage } from '@/ui/AuthPage';
import '@/styles/about.css';

/** The part of the server's config this page reads. */
export type AboutConfig = Pick<ConfigResponse, 'version' | 'commit' | 'license' | 'sourceUrl'>;

/** How many characters of the commit are shown; the link has the rest. */
const SHORT_COMMIT = 12;

const CONTRIBUTORS_URL = 'https://github.com/Arsslensoft/Kemlock-Server/graphs/contributors';

const external = { target: '_blank', rel: 'noopener noreferrer' } as const;

/** What the page says: the licence, where the source of this version is, and who this is not. */
export function AboutView({ config }: { config: AboutConfig | undefined }) {
  const t = useT();
  const source = webAddress(config?.sourceUrl);
  return (
    <AuthPage width={600} legal={false}>
      <div>
        <h1>{t('about.title')}</h1>
        <p className="lede">{t('about.lede')}</p>
      </div>
      {config ? (
        <dl className="about-list">
          <dt>{t('about.version')}</dt>
          <dd>{config.version}</dd>
          {config.commit ? (
            <>
              <dt>{t('about.commit')}</dt>
              <dd>
                <code className="mono">{config.commit.slice(0, SHORT_COMMIT)}</code>
              </dd>
            </>
          ) : null}
          <dt>{t('about.licence')}</dt>
          <dd>
            <a href="/LICENSE.txt" {...external}>
              {t('about.license', { license: config.license })}
            </a>
          </dd>
          <dt>{t('about.sourceRow')}</dt>
          <dd>
            <div className="stack">
              {source ? (
                <a href={source} {...external}>
                  {t('about.source')}
                </a>
              ) : null}
              <span className="hint">{t('about.sourceHint')}</span>
            </div>
          </dd>
          <dt>{t('about.author')}</dt>
          <dd>{t('about.authorName')}</dd>
          <dt>{t('about.contributors')}</dt>
          <dd>
            <a href={CONTRIBUTORS_URL} {...external}>
              {t('about.contributorsLink')}
            </a>
          </dd>
          <dt>{t('about.documents')}</dt>
          <dd>
            <div className="stack">
              <a href="/THIRD-PARTY-NOTICES.txt" {...external}>
                {t('about.thirdParty')}
              </a>
              <a href="/NOTICE.txt" {...external}>
                {t('about.notices')}
              </a>
            </div>
          </dd>
        </dl>
      ) : (
        <p className="hint" role="status">
          {t('about.loading')}
        </p>
      )}
      <p className="hint">{t('about.notAffiliated')}</p>
      <Link to="/">{t('about.back')}</Link>
    </AuthPage>
  );
}

export default function About() {
  const config = useQuery(configQuery);
  return <AboutView config={config.data} />;
}
