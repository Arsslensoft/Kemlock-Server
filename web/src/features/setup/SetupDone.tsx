import { Link } from '@tanstack/react-router';
import type { ReactNode } from 'react';
import { useT } from '@/i18n';
import type { ServerBasicsValues } from '@/lib/schemas';
import { AuthPage } from '@/ui/AuthPage';
import { buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { SetupSteps } from '@/ui/SetupSteps';
import { setupMemory } from './memory';

function Row({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div>
      <dt>{term}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export default function SetupDone() {
  const t = useT();
  const memory = setupMemory.get();
  const basics: ServerBasicsValues | undefined = memory.basics;
  const admin = memory.adminName ? `${memory.adminName}, ${memory.adminEmail ?? ''}` : null;
  return (
    <AuthPage badge="admin" width={680}>
      <SetupSteps current={4} />
      <div className="page-head">
        <span className="tile big" aria-hidden="true">
          <Icon name="check" />
        </span>
        <div>
          <h1>{t('setup.done.title')}</h1>
          <p className="lede">
            {admin ? t('setup.done.lede', { name: memory.adminName ?? '' }) : t('setup.done.ledeBare')}
          </p>
        </div>
      </div>

      {basics ? (
        <section className="stack" aria-labelledby="h-sum">
          <h2 id="h-sum">{t('setup.done.summary')}</h2>
          <dl className="summary">
            <Row term={t('setup.done.address')}>
              <span className="mono">{basics.address}</span>
            </Row>
            {admin ? <Row term={t('setup.done.admin')}>{admin}</Row> : null}
            <Row term={t('setup.done.signsIn')}>{t('setup.done.signsInValue')}</Row>
            <Row term={t('setup.done.join')}>
              {basics.join === 'invite'
                ? t('setup.server.join.invite')
                : basics.join === 'domains'
                  ? `${t('setup.server.join.domains')}: ${basics.joinDomains}`
                  : t('setup.server.join.anyone')}
            </Row>
            <Row term={t('setup.done.email')}>
              {basics.mailHost ? basics.mailHost : t('setup.done.off')}
            </Row>
            <Row term={t('setup.done.push')}>{basics.push ? t('setup.done.on') : t('setup.done.off')}</Row>
            <Row term={t('setup.done.files')}>
              {basics.files === 'local' ? (
                <>
                  {t('setup.server.files.local')} <span className="mono">{basics.folder}</span>
                </>
              ) : (
                t('setup.server.files.s3')
              )}
            </Row>
            <Row term={t('setup.done.backups')}>
              {basics.backups
                ? t('setup.done.backupsOn', {
                    every:
                      basics.backupEvery === 'night'
                        ? t('setup.server.backupNight')
                        : t('setup.server.backupSixHours'),
                    keep: basics.backupKeep,
                  })
                : t('setup.done.off')}
            </Row>
          </dl>
          <p className="hint">{t('setup.done.configNote')}</p>
        </section>
      ) : null}

      <section className="notice" aria-labelledby="h-kit">
        <Icon name="key" />
        <div className="stack">
          <h2 id="h-kit">{t('setup.done.kit.title')}</h2>
          <p>{t('setup.done.kit.body')}</p>
          <div className="actions">
            <Link to="/security" className={buttonClass({ variant: 'primary' })}>
              {t('setup.done.kit.make')}
            </Link>
            <Link to="/vault">{t('setup.done.kit.later')}</Link>
          </div>
        </div>
      </section>

      <section className="stack" aria-labelledby="h-next">
        <h2 id="h-next">{t('setup.done.next')}</h2>
        <div className="grid">
          <Link to="/admin/users" className="way">
            <span className="ic" aria-hidden="true">
              <Icon name="users" />
            </span>
            <span>
              <span className="t">{t('setup.done.invite')}</span>
              <span className="d">{t('setup.done.inviteHint')}</span>
            </span>
          </Link>
          <Link to="/admin/settings" className="way">
            <span className="ic" aria-hidden="true">
              <Icon name="settings" />
            </span>
            <span>
              <span className="t">{t('setup.done.settings')}</span>
              <span className="d">{t('setup.done.settingsHint')}</span>
            </span>
          </Link>
        </div>
      </section>

      <div className="actions">
        <Link to="/vault" className={buttonClass({ size: 'large' })}>
          {t('setup.done.openVault')}
        </Link>
        <Link to="/admin" className={buttonClass({ size: 'large' })}>
          {t('setup.done.openAdmin')}
        </Link>
      </div>
    </AuthPage>
  );
}
