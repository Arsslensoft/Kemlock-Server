// The copy button at the end of a list row: a login's password, an MFA code's code right now.
// Both are secrets, so the clipboard is cleared 30 seconds later (lib/clipboard.ts).
import { useEffect, useRef, useState } from 'react';
import { useT } from '@/i18n';
import { copyText } from '@/lib/clipboard';
import { IconButton } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Icon } from '@/ui/Icon';
import { codeAt, otpParamsOf } from './details/otp';
import { type VaultItem, itemName, loginOf } from './vault';

/** Copies the code an MFA code item shows at the moment of the press, not one made earlier. */
function CopyCode({ item }: { item: VaultItem }) {
  const t = useT();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <>
      <IconButton
        aria-label={t(/code$/i.test(itemName(item).trim()) ? 'lists.copyCodeNamed' : 'lists.copyCode', { name: itemName(item) })}
        onPress={() => {
          const params = otpParamsOf(item.data);
          if (!params) return;
          void codeAt(params, Date.now())
            .then((code) => copyText(code, { secret: true }))
            .catch(() => false)
            .then((ok) => {
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

/** The row's copy button, or nothing for an item with no one value to copy. */
export function RowCopy({ item }: { item: VaultItem }) {
  const t = useT();
  if (item.kind === 'login') {
    const { password } = loginOf(item);
    return password ? (
      <CopyButton value={password} secret label={t('main.copyPassword', { name: itemName(item) })} />
    ) : null;
  }
  // A counter code has no code of the moment to copy: the counter moves when it is used.
  const params = item.kind === 'otp' ? otpParamsOf(item.data) : undefined;
  if (params && params.type !== 'hotp') return <CopyCode item={item} />;
  return null;
}
