// "What the server holds": the record the server keeps for an item, in a dialog. Ciphertext, its
// kind, its sizes and revision; no name, address, password or note. The sizes are of the sealed
// bytes the sync brought, so this is exactly what is on the server, not a guess.
import { useT } from '@/i18n';
import { AppDialog } from '@/ui/AppDialog';
import { Button } from '@/ui/Button';
import '@/styles/item.css';
import type { VaultItem } from './vault';

/** The record, one fact to a line, as the canvas shows it. */
export function serverRecord(item: VaultItem): string {
  return [
    `item     ${item.id}   ${item.kind}`,
    `owner    ${item.owner}`,
    `revision ${item.revision} · key version ${item.keyVersion}`,
    `key      ${item.sizes.itemKey} B wrapped`,
    `body     AES-256-GCM, ${item.sizes.ciphertext} B`,
  ].join('\n');
}

export function ServerHolds({
  item,
  name,
  onClose,
}: {
  item: VaultItem;
  name: string;
  onClose: () => void;
}) {
  const t = useT();
  return (
    <AppDialog
      isOpen
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t('item.server.title')}
      icon="server"
      footer={<Button onPress={onClose}>{t('detail.close')}</Button>}
    >
      <p className="muted">{t('detail.server.lede', { name })}</p>
      <pre className="server-record" data-testid="server-record">
        {serverRecord(item)}
      </pre>
      <p className="muted hint">{t('item.server.note')}</p>
    </AppDialog>
  );
}
