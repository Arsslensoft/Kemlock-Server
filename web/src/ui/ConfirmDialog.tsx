import type { ReactNode } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import { useT } from '@/i18n';
import { Button } from './Button';
import { Notice } from './Notice';

/** A modal that asks before something that can't be undone. */
export function ConfirmDialog({
  isOpen,
  onOpenChange,
  title,
  children,
  confirmLabel,
  onConfirm,
  pending,
  error,
}: {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  pending?: boolean;
  /** Why the last try failed, already worded. Shown inside the dialog, which stays open. */
  error?: ReactNode;
}) {
  const t = useT();
  return (
    <ModalOverlay
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      isDismissable={!pending}
      isKeyboardDismissDisabled={pending}
      className="overlay"
    >
      <Modal>
        <Dialog className="dialog">
          {({ close }) => (
            <>
              <Heading slot="title">{title}</Heading>
              <div className="muted">{children}</div>
              {error ? (
                <Notice tone="error" live>
                  <p>{error}</p>
                </Notice>
              ) : null}
              <div className="actions">
                <Button isDisabled={pending} onPress={close}>
                  {t('action.cancel')}
                </Button>
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
