import { type ReactNode, useId } from 'react';
import { Button as AriaButton, Menu, MenuItem, MenuTrigger, Popover } from 'react-aria-components';
import '@/styles/rowmenu.css';
import { Icon } from './Icon';

export interface RowMenuItem {
  id: string;
  label: string;
  icon?: ReactNode;
  /** A red item, for what can't be undone. */
  danger?: boolean;
  disabled?: boolean;
  onAction: () => void;
}

/**
 * The three-dots button of a table row and the menu it opens. Arrow keys move, Enter picks, Escape
 * closes; the button's name says whose row it is. `note` is a line of small print under the items,
 * and the menu is described by it, so a screen reader reads why an item is off.
 */
export function RowMenu({
  label,
  items,
  note,
  isDisabled,
}: {
  label: string;
  items: RowMenuItem[];
  note?: string | undefined;
  isDisabled?: boolean | undefined;
}) {
  const noteId = useId();
  return (
    <MenuTrigger>
      <AriaButton className="btn s menu-btn" aria-label={label} isDisabled={isDisabled}>
        <Icon name="more" />
      </AriaButton>
      <Popover className="menu-pop" placement="bottom end">
        <Menu
          className="menu-list"
          aria-label={label}
          aria-describedby={note ? noteId : undefined}
          onAction={(key) => items.find((item) => item.id === key)?.onAction()}
        >
          {items.map((item) => (
            <MenuItem
              key={item.id}
              id={item.id}
              textValue={item.label}
              isDisabled={item.disabled}
              className={item.danger ? 'menu-item danger' : 'menu-item'}
            >
              {item.icon}
              {item.label}
            </MenuItem>
          ))}
        </Menu>
        {note ? (
          <p className="menu-note" id={noteId}>
            {note}
          </p>
        ) : null}
      </Popover>
    </MenuTrigger>
  );
}
