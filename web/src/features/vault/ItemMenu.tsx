// The `⋯` menu of the item page: Websites and rules (logins), Move to a space, Make a copy, What
// the server holds, then Move to Trash in red. The page says which of them this item and this
// person get: an item in the Trash, one that can't be read or one the person may not change has
// fewer, down to What the server holds alone. React Aria's menu gives it the keyboard (arrows,
// typeahead, Escape closing it with focus back on the button) and the menu roles.
//
// A choice is acted on once the menu has closed, with focus put back on the button first, so a
// dialog that opens from it remembers the button and gives focus back to it when it closes.
import { useId, useRef } from 'react';
import { Menu, MenuItem, MenuTrigger, Popover, Separator, Text } from 'react-aria-components';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Icon, type IconName } from '@/ui/Icon';
import '@/styles/item.css';
import { TRASH_DAYS } from './vault';

export type ItemAction = 'websites' | 'move' | 'copy' | 'server' | 'trash';

/** What the menu offers besides What the server holds, which is always there. */
export interface ItemMenuEntries {
  /** Logins only. */
  websites: boolean;
  move: boolean;
  /** Not for a passkey or a file, which can't be copied, nor an item that can't be read. */
  copy: boolean;
  trash: boolean;
}

export function ItemMenu({
  name,
  entries,
  trashing = false,
  onAction,
}: {
  name: string;
  entries: ItemMenuEntries;
  /** The item is being moved to the Trash: asking again would do it twice. */
  trashing?: boolean;
  onAction: (action: ItemAction) => void;
}) {
  const t = useT();
  const picked = useRef<ItemAction | null>(null);
  const triggerId = useId();

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
        // After the menu has unmounted: focus goes to the button now, not on a later frame, so
        // whatever the action opens finds it there.
        window.setTimeout(() => {
          document.getElementById(triggerId)?.focus();
          onAction(action);
        }, 0);
      }}
    >
      <Button id={triggerId} className="im-trigger" aria-label={t('detail.menu.label', { name })}>
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
          {entries.websites ? item('websites', 'globe', t('sites.open')) : null}
          {entries.move ? item('move', 'building', t('detail.menu.move')) : null}
          {entries.copy ? item('copy', 'copy', t('detail.menu.copy')) : null}
          {item('server', 'server', t('item.server.title'))}
          {entries.trash ? <Separator className="im-sep" /> : null}
          {entries.trash ? (
            <MenuItem
              id="trash"
              className="im-item im-danger"
              textValue={t('item.moveToTrash')}
              isDisabled={trashing}
            >
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
          ) : null}
        </Menu>
      </Popover>
    </MenuTrigger>
  );
}
