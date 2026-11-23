// Vault health (canvas: Health), worked out in this browser. The one network check is Pwned
// Passwords by k-anonymity, and it is a switch the person owns.
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useMemo, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import { buttonClass, Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import '@/styles/tools.css';
import { browserStorage, createDismissedStore } from '@/features/duplicates/dismissed';
import { useVault } from '@/features/vault/hooks';
import { loginOf } from '@/features/vault/vault';
import { type Analysis, type Issue, type IssueKind, analyse, countByKind } from './analyse';
import { pwnedCounts } from './hibp';

const SWITCH_KEY = 'kemlock.health.hibp';
const dealtWith = createDismissedStore(browserStorage(), 'kemlock.health.dealtWith');

function readSwitch(): boolean {
  try {
    return window.localStorage.getItem(SWITCH_KEY) !== 'off';
  } catch {
    return true;
  }
}

function writeSwitch(on: boolean): void {
  try {
    window.localStorage.setItem(SWITCH_KEY, on ? 'on' : 'off');
  } catch {
    // The choice holds for this page only.
  }
}

const TAGS: Record<IssueKind, { label: MessageId; bad: boolean }> = {
  exposed: { label: 'health.tag.exposed', bad: true },
  reused: { label: 'health.tag.reused', bad: false },
  weak: { label: 'health.tag.weak', bad: false },
  noCode: { label: 'health.tag.noCode', bad: false },
  expiring: { label: 'health.tag.expiring', bad: false },
};

const ACTIONS: Record<IssueKind, MessageId> = {
  exposed: 'health.action.change',
  reused: 'health.action.show',
  weak: 'health.action.generate',
  noCode: 'health.action.setup',
  expiring: 'health.action.extend',
};

const STAT_LABEL: Record<IssueKind, MessageId> = {
  exposed: 'health.stat.exposed',
  reused: 'health.stat.reused',
  weak: 'health.stat.weak',
  noCode: 'health.stat.noCode',
  expiring: 'health.stat.expiring',
};

export function HealthView({
  analysis,
  hibpOn,
  onHibp,
  checking,
  checkFailed,
  onDealtWith,
}: {
  analysis: Analysis;
  hibpOn: boolean;
  onHibp: (on: boolean) => void;
  checking?: boolean;
  checkFailed?: boolean;
  onDealtWith: (issue: Issue) => void;
}) {
  const t = useT();
  const counts = countByKind(analysis.issues);
  return (
    <>
      <div>
        <h1 className="page-title">{t('health.title')}</h1>
        <p className="lede">{t('health.lede')}</p>
      </div>

      <div className="stats">
        {(Object.keys(STAT_LABEL) as IssueKind[]).map((kind) => (
          <div className="stat" key={kind}>
            <b>{counts[kind]}</b>
            <span>{t(STAT_LABEL[kind])}</span>
          </div>
        ))}
      </div>

      {checkFailed ? (
        <Notice tone="warn" live>
          <p>{t('health.hibp.failed')}</p>
        </Notice>
      ) : null}

      <div className="two-col">
        <section className="card" aria-labelledby="h-fix">
          <div className="card-head">
            <h2 id="h-fix">{t('health.fix', { count: analysis.issues.length })}</h2>
            {checking ? <span className="hint" role="status">{t('health.checking')}</span> : null}
          </div>
          {analysis.issues.length === 0 ? (
            <p className="empty">{t('health.none')}</p>
          ) : (
            analysis.issues.map((issue) => {
              const tag = TAGS[issue.kind];
              const first = issue.itemIds[0];
              return (
                <div className="row" key={issue.id}>
                  <span className={tag.bad ? 'tag bad' : 'tag warn'}>{t(tag.label)}</span>
                  <div className="grow">
                    <div>{issue.title}</div>
                    <div className="hint">{t(issue.detail.id, issue.detail.values)}</div>
                  </div>
                  {first ? (
                    <Link
                      to="/vault/$itemId"
                      params={{ itemId: first }}
                      className={buttonClass({ size: 'small' })}
                    >
                      {t(ACTIONS[issue.kind])}
                    </Link>
                  ) : null}
                  <Button
                    size="small"
                    aria-label={t('health.dealtWithFor', { title: issue.title })}
                    onPress={() => onDealtWith(issue)}
                  >
                    {t('health.dealtWith')}
                  </Button>
                </div>
              );
            })
          )}
        </section>

        <div className="stack">
          <section className="card" aria-labelledby="h-good">
            <div className="card-head">
              <h2 id="h-good">{t('health.good')}</h2>
            </div>
            {analysis.good.map((entry) => (
              <div className="row" key={entry.id}>
                <span className="tag ok">{t('health.done')}</span>
                <span>{t(entry.id, entry.values)}</span>
              </div>
            ))}
          </section>

          <section className="card" aria-labelledby="h-checks">
            <div className="card-head">
              <h2 id="h-checks">{t('health.checks')}</h2>
            </div>
            <div className="switch-row pad-x">
              <div>
                <label htmlFor="sw-pwn">{t('health.hibp.label')}</label>
                <p className="hint">{t('health.hibp.hint')}</p>
              </div>
              <input
                id="sw-pwn"
                className="sw"
                type="checkbox"
                role="switch"
                checked={hibpOn}
                onChange={(event) => onHibp(event.target.checked)}
              />
            </div>
            <div className="switch-row pad-x">
              <div>
                <label htmlFor="sw-list">{t('health.list.label')}</label>
                <p className="hint">{t('health.list.hint')}</p>
              </div>
              <input id="sw-list" className="sw" type="checkbox" role="switch" checked={false} disabled readOnly />
            </div>
          </section>
        </div>
      </div>
    </>
  );
}

export default function Health() {
  const t = useT();
  const { active, isLoading } = useVault();
  const [hibpOn, setHibpOn] = useState(readSwitch);
  const [version, setVersion] = useState(0);

  const signature = useMemo(
    () => active.filter((item) => item.kind === 'login').map((item) => `${item.id}:${item.revision}`).join(','),
    [active],
  );
  const lookup = useQuery({
    queryKey: ['health', 'hibp', signature],
    enabled: hibpOn && signature !== '' && !isLoading,
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
    queryFn: async () => {
      const logins = active.filter((item) => item.kind === 'login');
      const counts = await pwnedCounts(
        logins.map((item) => loginOf(item).password).filter((p) => p !== ''),
        { fetch: (...args) => fetch(...args) },
      );
      // Keep ids and counts only: the passwords are not kept past this function.
      const byItem = new Map<string, number>();
      for (const item of logins) byItem.set(item.id, counts.get(loginOf(item).password) ?? 0);
      return byItem;
    },
  });

  const analysis = useMemo(() => {
    const found = analyse(active, hibpOn ? lookup.data : undefined, new Date());
    return { ...found, issues: found.issues.filter((issue) => !dealtWith.has(issue.id)) };
    // `version` re-reads the dealt-with set after a click.
  }, [active, hibpOn, lookup.data, version]);

  if (isLoading) {
    return (
      <p className="empty" role="status">
        {t('main.loading')}
      </p>
    );
  }
  return (
    <HealthView
      analysis={analysis}
      hibpOn={hibpOn}
      checking={hibpOn && lookup.isFetching}
      checkFailed={hibpOn && lookup.isError}
      onHibp={(on) => {
        writeSwitch(on);
        setHibpOn(on);
      }}
      onDealtWith={(issue) => {
        dealtWith.add(issue.id);
        setVersion((n) => n + 1);
      }}
    />
  );
}
