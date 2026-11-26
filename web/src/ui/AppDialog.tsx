// A modal with a title, a close button and room for content: the frame the item page's dialogs
// share. React Aria's modal traps focus, closes on Escape and gives focus back to what opened it;
// the dialog is named by its heading.
import type { ReactNode } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import { useT } from '@/i18n';
import '@/styles/app-dialog.css';
import { IconButton } from './Button';
import { Icon, type IconName } from './Icon';

export function AppDialog({
  isOpen,
  onOpenChange,
  title,
  icon,
  children,
  footer,
  isDismissable = true,
}: {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  icon?: IconName;
  children: ReactNode;
  /** Buttons under the content, right-aligned. */
  footer?: ReactNode;
  /** Whether a click outside or Escape closes it (not while it is saving). */
  isDismissable?: boolean;
}) {
  const t = useT();
  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      isDismissable={isDismissable}
      isKeyboardDismissDisabled={!isDismissable}
      className="overlay"
    >
      <Modal>
        <Dialog className="dialog app-dialog">
          {({ close }) => (
            <>
              <div className="app-dialog-head">
                {icon ? (
                  <span className="app-dialog-icon">
                    <Icon name={icon} />
                  </span>
                ) : null}
                <Heading slot="title">{title}</Heading>
                <IconButton aria-label={t('detail.close')} isDisabled={!isDismissable} onPress={close}>
                  <Icon name="close" />
                </IconButton>
              </div>
              {children}
              {footer ? <div className="app-dialog-foot">{footer}</div> : null}
            </>
          )}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}
