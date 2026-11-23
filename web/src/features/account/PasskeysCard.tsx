import type { PasskeyDto } from '@/api/passkeys';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';

export interface PasskeysCardProps {
  /** undefined while loading */
  passkeys: PasskeyDto[] | undefined;
  busy: boolean;
  onAdd: () => void;
  onRemove: (id: string) => void;
}

/** The passkeys of the account, as rows of the two-step card: what is there, add one, remove one. */
export function PasskeysCard({ passkeys, busy, onAdd, onRemove }: PasskeysCardProps) {
  const t = useT();
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.passkeys.title')}</div>
          <div className="hint">{t('security.passkeys.hint')}</div>
        </div>
        {passkeys === undefined ? null : (
          <span className={passkeys.length > 0 ? 'tag ok' : 'tag off'}>
            {passkeys.length > 0 ? t('security.on') : t('security.off')}
          </span>
        )}
        <Button size="small" isDisabled={busy || passkeys === undefined} onPress={onAdd}>
          {t('security.passkeys.add')}
        </Button>
      </div>
      {passkeys?.map((passkey) => (
        <div className="row" key={passkey.id} data-testid="passkey">
          <div className="grow">{passkey.name}</div>
          {passkey.prf ? <span className="tag ok">{t('security.passkeys.opens')}</span> : null}
          <Button
            size="small"
            isDisabled={busy}
            aria-label={t('security.passkeys.remove', { name: passkey.name })}
            onPress={() => onRemove(passkey.id)}
          >
            {t('security.passkeys.removeLabel')}
          </Button>
        </div>
      ))}
    </>
  );
}
