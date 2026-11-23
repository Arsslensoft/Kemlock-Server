import { useT } from '@/i18n';

/** The four-step bar at the top of every setup screen. */
export function SetupSteps({ current }: { current: 1 | 2 | 3 | 4 }) {
  const t = useT();
  const steps = [
    t('setup.step.code'),
    t('setup.step.admin'),
    t('setup.step.server'),
    t('setup.step.ready'),
  ];
  return (
    <ol className="steps" aria-label={t('setup.steps')}>
      {steps.map((label, index) => {
        const number = index + 1;
        const done = number < current;
        return (
          <li
            key={label}
            className={done ? 'step done' : 'step'}
            aria-current={number === current ? 'step' : undefined}
          >
            <span>
              <span className="n">{t('setup.stepNumber', { n: number })}</span>
              {label}
              {done ? <span className="sr"> {t('setup.stepDone')}</span> : null}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
