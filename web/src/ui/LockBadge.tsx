// The round lock beside a page title. It says the page is end-to-end encrypted in a tooltip that
// shows on hover and on keyboard focus, stays while the pointer is over it, and goes with Escape
// (WCAG 1.4.13). The button holds the text through aria-describedby, so a screen reader reads it
// when the lock takes focus.
import { type KeyboardEvent, useId, useState } from 'react';
import { useT } from '@/i18n';
import '@/styles/lock-badge.css';
import { Icon } from './Icon';

export function LockBadge({ className }: { className?: string }) {
  const t = useT();
  const tipId = useId();
  const [hover, setHover] = useState(false);
  const [focus, setFocus] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const open = (hover || focus) && !dismissed;

  function onKeyDown(event: KeyboardEvent) {
    if (event.key !== 'Escape' || !open) return;
    // Only the tooltip closes: a dialog or menu around the title keeps its own Escape.
    event.stopPropagation();
    setDismissed(true);
  }

  return (
    <span
      className={className ? `enc ${className}` : 'enc'}
      data-open={open ? '' : undefined}
      onMouseEnter={() => {
        setDismissed(false);
        setHover(true);
      }}
      onMouseLeave={() => setHover(false)}
      onKeyDown={onKeyDown}
    >
      <button
        type="button"
        className="enc-b"
        aria-label={t('item.enc.title')}
        aria-describedby={tipId}
        onFocus={() => {
          setDismissed(false);
          setFocus(true);
        }}
        onBlur={() => setFocus(false)}
      >
        <Icon name="lock" />
      </button>
      <span id={tipId} role="tooltip" className="enc-tip">
        <span className="enc-tip-title">{t('item.enc.title')}</span>
        {t('item.enc.body')}
      </span>
    </span>
  );
}
