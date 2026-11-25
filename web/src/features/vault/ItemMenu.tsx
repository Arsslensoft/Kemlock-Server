// The `⋯` menu of the item page: Websites and rules (logins), Move to a space, Make a copy, What
// the server holds, then Move to Trash in red. An item in the Trash has only What the server
// holds. React Aria's menu gives it the keyboard (arrows,
// typeahead, Escape closing it with focus back on the button) and the menu roles.
//
// A choice is acted on once the menu has closed and focus is back on the button, so a dialog that
// opens from it takes focus from there and gives it back when it closes.
import { useRef } from 'react';
import { Menu, MenuItem, MenuTrigger, Popover, Separator, Text } from 'react-aria-components';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon, type IconName } from '@/ui/Icon';
import '@/styles/item.css';
import { TRASH_DAYS } from './vault';

export type ItemAction = 'websites' | 'move' | 'copy' | 'server' | 'trash';

export function ItemMenu({
  name,
  trashed,
  websites,
  copy,
  onAction,
}: {
  name: string;
  /** In the Trash: nothing to move, copy or trash. */
  trashed: boolean;
  /** Logins only. */
  websites: boolean;
  /** Not for a passkey or a file, which can't be copied. */
  copy: boolean;
  onAction: (action: ItemAction) => void;
}) {
  const t = useT();
  const picked = useRef<ItemAction | null>(null);

  function item(id: ItemAction, icon: IconName, label: string) {
    return (
      <MenuItem id={id} className="im-item" textValue={label}>
        <Icon name={icon} />
        <Text slot="label">{label}</Text>
      </MenuItem>
    );
  }

  return (
    <MenuTrigger
      onOpenChange={(open) => {
        const action = picked.current;
        if (open || action === null) return;
        picked.current = null;
        // After the menu has unmounted and given focus back to its button.
        window.setTimeout(() => onAction(action), 0);
      }}
    >
      <Button className="im-trigger" aria-label={t('detail.menu.label', { name })}>
        <Icon name="more" />
      </Button>
      <Popover placement="bottom end" className="im-popover">
        <Menu
          className="im-menu"
          aria-label={t('detail.menu.label', { name })}
          onAction={(key) => {
            picked.current = key as ItemAction;
          }}
        >
          {websites && !trashed ? item('websites', 'globe', t('sites.open')) : null}
          {trashed ? null : item('move', 'building', t('detail.menu.move'))}
          {copy && !trashed ? item('copy', 'copy', t('detail.menu.copy')) : null}
          {item('server', 'server', t('item.server.title'))}
          {trashed ? null : <Separator className="im-sep" />}
          {trashed ? null : (
            <MenuItem id="trash" className="im-item im-danger" textValue={t('item.moveToTrash')}>
              <Icon name="trash" />
              <span className="im-text">
                <Text slot="label" className="im-title">
                  {t('item.moveToTrash')}
                </Text>
                <Text slot="description" className="im-sub">
                  {t('detail.menu.trashNote', { days: TRASH_DAYS })}
                </Text>
              </span>
            </MenuItem>
          )}
        </Menu>
      </Popover>
    </MenuTrigger>
  );
}
