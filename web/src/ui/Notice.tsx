import type { ReactNode } from 'react';
import { Icon, type IconName } from './Icon';

const DEFAULT_ICON: Record<'info' | 'warn' | 'error', IconName> = {
  info: 'info',
  warn: 'alert',
  error: 'alert',
};

/** A boxed message: `info` for a fact, `warn` for something to do, `error` for a failure. */
export function Notice({
  tone = 'info',
  icon,
  children,
  live,
}: {
  tone?: 'info' | 'warn' | 'error';
  icon?: IconName;
  children: ReactNode;
  /** Announce it as soon as it appears (errors from a submit). */
  live?: boolean;
}) {
  return (
    <div
      className={tone === 'info' ? 'notice' : `notice ${tone}`}
      role={live ? (tone === 'error' ? 'alert' : 'status') : undefined}
    >
      <Icon name={icon ?? DEFAULT_ICON[tone]} />
      <div className="stack">{children}</div>
    </div>
  );
}
