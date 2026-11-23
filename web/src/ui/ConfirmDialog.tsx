import type { ReactNode } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import { useT } from '@/i18n';
import { Button } from './Button';

/** A modal that asks before something that can't be undone. */
export function ConfirmDialog({
  isOpen,
  onOpenChange,
  title,
  children,
  confirmLabel,
  onConfirm,
  pending,
}: {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  pending?: boolean;
}) {
  const t = useT();
  return (
    <ModalOverlay isOpen={isOpen} onOpenChange={onOpenChange} isDismissable className="overlay">
      <Modal>
        <Dialog className="dialog">
          {({ close }) => (
            <>
              <Heading slot="title">{title}</Heading>
              <div className="muted">{children}</div>
              <div className="actions">
                <Button onPress={close}>{t('action.cancel')}</Button>
                <Button variant="danger" isDisabled={pending} onPress={onConfirm}>
                  {confirmLabel}
                </Button>
              </div>
            </>
          )}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}
