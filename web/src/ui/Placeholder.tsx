import type { ReactNode } from 'react';
import { useT } from '@/i18n';
import { Icon, type IconName } from './Icon';

/**
 * A screen whose API doesn't exist yet. It says so plainly and names what will be here, so no
 * one mistakes an empty shell for an empty server.
 */
export function Placeholder({
  title,
  lede,
  icon,
  needs,
  children,
}: {
  title: string;
  lede: string;
  icon: IconName;
  /** The API the screen waits for, e.g. `kemlock-api-admin`. */
  needs: string;
  children?: ReactNode;
}) {
  const t = useT();
  return (
    <>
      <div>
        <h1 className="page-title">{title}</h1>
        <p className="lede">{lede}</p>
      </div>
      <section className="card">
        <div className="empty">
          <span className="tile big" aria-hidden="true">
            <Icon name={icon} />
          </span>
          <h2>{t('placeholder.title')}</h2>
          <p>{t('placeholder.body', { needs })}</p>
        </div>
      </section>
      {children}
    </>
  );
}
