// The passkey "form": there is nothing to type. A website makes a passkey when it asks for one,
// and Kemlock saves it to the vault. This page says so.
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';

export function PasskeyPage({ onDone }: { onDone: () => void }) {
  const t = useT();
  return (
    <div className="stack form-wide">
      <section className="card pad" aria-labelledby="h-passkey">
        <h2 id="h-passkey">{t('itemForm.passkey.title')}</h2>
        <p>{t('itemForm.passkey.body')}</p>
        <ul className="passkey-ways">
          <li>{t('itemForm.passkey.browser')}</li>
          <li>{t('itemForm.passkey.phone')}</li>
        </ul>
        <p className="hint">{t('itemForm.passkey.hint')}</p>
      </section>
      <div className="form-actions">
        <Button onPress={onDone}>{t('action.cancel')}</Button>
        <Button variant="primary" onPress={onDone}>
          {t('itemForm.passkey.done')}
        </Button>
      </div>
    </div>
  );
}
