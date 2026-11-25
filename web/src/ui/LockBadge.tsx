// The round lock beside a page title. It says the page is end-to-end encrypted in a tooltip that
// shows on hover and on keyboard focus, stays while the pointer is over it, and goes with Escape
// (WCAG 1.4.13). A press toggles it too, which is how a touch screen, with no hover, opens it. The
// button holds the text through aria-describedby, so a screen reader reads it when the lock takes
// focus. A page that explains more says so with `body`; the title is always "End-to-end encrypted".
import { type KeyboardEvent, useId, useRef, useState } from 'react';
import { type MessageId, useT } from '@/i18n';
import '@/styles/lock-badge.css';
import { Icon } from './Icon';

export function LockBadge({
  className,
  body = 'item.enc.body',
}: {
  className?: string;
  /** The tooltip's text under its title. */
  body?: MessageId;
}) {
  const t = useT();
  const tipId = useId();
  const [hover, setHover] = useState(false);
  const [focus, setFocus] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  // A press moves focus to the button before it clicks: that focus must not open the tooltip, or
  // the click that follows would close it again.
  const pressing = useRef(false);
  const open = (hover || focus || pinned) && !dismissed;

  function onKeyDown(event: KeyboardEvent) {
    if (event.key !== 'Escape' || !open) return;
    // Only the tooltip closes: a dialog or menu around the title keeps its own Escape.
    event.stopPropagation();
    setDismissed(true);
    setPinned(false);
  }

  function toggle() {
    if (open) {
      setDismissed(true);
      setPinned(false);
    } else {
      setDismissed(false);
      setPinned(true);
    }
  }

  return (
    <span
      className={className ? `enc ${className}` : 'enc'}
      data-open={open ? '' : undefined}
      // A finger has no hover: a tap only presses.
      onPointerEnter={(event) => {
        if (event.pointerType === 'touch') return;
        setDismissed(false);
        setHover(true);
      }}
      onPointerLeave={() => setHover(false)}
      onKeyDown={onKeyDown}
    >
      <button
        type="button"
        className="enc-b"
        aria-label={t('item.enc.title')}
        aria-describedby={tipId}
        onPointerDown={() => {
          pressing.current = true;
        }}
        onPointerUp={() => {
          pressing.current = false;
        }}
        onPointerCancel={() => {
          pressing.current = false;
        }}
        onClick={toggle}
        onFocus={() => {
          if (pressing.current) return;
          setDismissed(false);
          setFocus(true);
        }}
        onBlur={() => {
          pressing.current = false;
          setFocus(false);
          setPinned(false);
        }}
      >
        <Icon name="lock" />
      </button>
      <span id={tipId} role="tooltip" className="enc-tip">
        <span className="enc-tip-title">{t('item.enc.title')}</span>
        {t(body)}
      </span>
    </span>
  );
}
