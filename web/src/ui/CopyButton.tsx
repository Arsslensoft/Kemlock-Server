import { useEffect, useRef, useState } from 'react';
import { copyText } from '@/lib/clipboard';
import { useT } from '@/i18n';
import { IconButton } from './Button';
import { Icon } from './Icon';

/** Copies `value` (a secret is cleared from the clipboard after 30 seconds). */
export function CopyButton({
  value,
  label,
  secret,
  big,
}: {
  value: string;
  label: string;
  secret?: boolean;
  big?: boolean;
}) {
  const t = useT();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <>
      <IconButton
        className={big ? 'big' : undefined}
        aria-label={label}
        onPress={() => {
          void copyText(value, { secret }).then((ok) => {
            setState(ok ? 'copied' : 'failed');
            clearTimeout(timer.current);
            timer.current = setTimeout(() => setState('idle'), 2000);
          });
        }}
      >
        <Icon name={state === 'copied' ? 'check' : 'copy'} />
      </IconButton>
      <span className="sr" role="status">
        {state === 'copied' ? t('copy.done') : state === 'failed' ? t('copy.failed') : ''}
      </span>
    </>
  );
}
