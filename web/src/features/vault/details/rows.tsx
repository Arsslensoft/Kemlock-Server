// The pieces every detail card is made of: a card, a labelled row with a copy button, and a secret
// row masked until the person shows it. A secret is copied with the clipboard clearing it after 30
// seconds. Nothing here logs a secret.
import { type ReactNode, createContext, useContext, useState } from 'react';
import { useT } from '@/i18n';
import { IconButton } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';

export const MASK = '••••••••••••••••••••';

/**
 * Rows the page adds to the end of its first card: the item's custom fields. A card reads them
 * from here, so no kind's detail has to know about them.
 */
export const ExtraRows = createContext<ReactNode>(null);

/** The orange "Admin" tag beside the label of a field the admin defined. */
export function AdminTag() {
  const t = useT();
  return <span className="admin-tag">{t('detail.custom.admin')}</span>;
}

/** One labelled value, with an optional copy button. */
export function Row({
  label,
  children,
  copy,
  copyLabel,
  secret,
  tag,
}: {
  label: string;
  children: ReactNode;
  copy?: string;
  copyLabel?: string;
  secret?: boolean;
  /** Shown after the label, such as the Admin tag. */
  tag?: ReactNode;
}) {
  return (
    <div className="row">
      <div className="grow">
        <div className="lbl">
          {label}
          {tag}
        </div>
        {children}
      </div>
      {copy ? <CopyButton value={copy} label={copyLabel ?? label} secret={secret ?? false} /> : null}
    </div>
  );
}

/** A secret shown as dots until the person asks, with Show and Copy. */
export function SecretRow({
  label,
  value,
  masked = MASK,
  mono = true,
  copyValue,
  tag,
}: {
  label: string;
  value: string;
  masked?: string;
  mono?: boolean;
  /** What Copy puts on the clipboard, when it is not what is shown. */
  copyValue?: string;
  tag?: ReactNode;
}) {
  const t = useT();
  const [shown, setShown] = useState(false);
  const cls = mono ? 'mono' : undefined;
  return (
    <div className="row">
      <div className="grow">
        <div className="lbl">
          {label}
          {tag}
        </div>
        <div className={`${cls ?? ''} wrap`.trim()}>{shown ? value : masked}</div>
      </div>
      <IconButton
        aria-label={t(shown ? 'detail.hide' : 'detail.show', { field: label.toLowerCase() })}
        onPress={() => setShown((v) => !v)}
      >
        <Icon name={shown ? 'eyeOff' : 'eye'} />
      </IconButton>
      <CopyButton value={copyValue ?? value} secret label={t('detail.copy', { field: label.toLowerCase() })} />
    </div>
  );
}

/** A titled card. The first card of an item ends with its custom fields; `custom={false}` leaves them out. */
export function Card({
  id,
  title,
  children,
  custom = true,
}: {
  id: string;
  title: string;
  children: ReactNode;
  custom?: boolean;
}) {
  const extra = useContext(ExtraRows);
  return (
    <section className="card" aria-labelledby={id}>
      <div className="card-head">
        <h2 id={id}>{title}</h2>
      </div>
      {children}
      {custom ? extra : null}
    </section>
  );
}
