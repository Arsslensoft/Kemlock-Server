// The `+` button in the vault's header and the "New" menu it opens: every type of item, in the
// owner's order, each one the address of that type's creation form (`/vault/new?kind=<kind id>`).
import { Link } from '@tanstack/react-router';
import { KIND_ORDER, kindIcon, kindLabel } from '@/features/vault/kinds';
import { useT } from '@/i18n';
import { buttonClass } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Popup } from '@/ui/Popup';

export function NewItemMenu() {
  const t = useT();
  return (
    <Popup
      panelClassName="types"
      panelLabel={t('action.newItem')}
      trigger={(props) => (
        <button
          type="button"
          className={buttonClass({ variant: 'primary', className: 'icon-only' })}
          aria-label={t('action.newItem')}
          {...props}
        >
          <Icon name="plus" />
        </button>
      )}
    >
      {(close) => (
        <>
          <h2>{t('shell.new')}</h2>
          {KIND_ORDER.map((kind) => (
            <Link key={kind} to="/vault/new" search={{ kind }} onClick={close}>
              <Icon name={kindIcon(kind)} />
              {t(kindLabel(kind))}
            </Link>
          ))}
        </>
      )}
    </Popup>
  );
}
