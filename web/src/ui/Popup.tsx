// A button that opens a panel under it: the avatar menu and the New menu. It is a disclosure, not an
// ARIA menu: the panel holds ordinary links and buttons that Tab reaches in order, which is what
// the canvas draws. The button says it opens something (`aria-haspopup`, `aria-expanded`,
// `aria-controls`); Escape shuts the panel and puts the focus back on the button; so do a click
// outside it and Tab leaving it. A choice inside the panel shuts it through `close`.
import { type FocusEvent, type KeyboardEvent, type ReactNode, type RefObject, useEffect, useId, useRef, useState } from 'react';
import '@/styles/popup.css';

/** What the trigger button needs spread on it. */
export interface PopupTrigger {
  ref: RefObject<HTMLButtonElement | null>;
  'aria-haspopup': 'true';
  'aria-expanded': boolean;
  'aria-controls': string;
  onClick: () => void;
}

export function Popup({
  trigger,
  panelClassName,
  panelLabel,
  children,
}: {
  trigger: (props: PopupTrigger) => ReactNode;
  /** Classes of the panel, beside `popup-panel`. */
  panelClassName?: string;
  /** Names the panel as a navigation landmark, for a panel that is only links. */
  panelLabel?: string;
  /** The panel's content. It is drawn only while the panel is open. */
  children: (close: () => void) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const Panel = panelLabel ? 'nav' : 'div';

  function close(returnFocus = false) {
    setOpen(false);
    if (returnFocus) button.current?.focus();
  }

  useEffect(() => {
    if (!open) return;
    function outside(event: PointerEvent) {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false);
    }
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [open]);

  function onKeyDown(event: KeyboardEvent) {
    if (event.key !== 'Escape' || !open) return;
    event.stopPropagation();
    close(true);
  }

  function onBlur(event: FocusEvent) {
    // Focus moving to somewhere else on the page (not into the panel, not to nothing) ends it.
    const next = event.relatedTarget;
    if (open && next instanceof Node && !root.current?.contains(next)) setOpen(false);
  }

  return (
    <div className="popup" ref={root} onKeyDown={onKeyDown} onBlur={onBlur}>
      {trigger({
        ref: button,
        'aria-haspopup': 'true',
        'aria-expanded': open,
        'aria-controls': id,
        onClick: () => setOpen((value) => !value),
      })}
      {open ? (
        <Panel
          id={id}
          className={panelClassName ? `popup-panel ${panelClassName}` : 'popup-panel'}
          aria-label={panelLabel}
        >
          {children(() => close())}
        </Panel>
      ) : null}
    </div>
  );
}
