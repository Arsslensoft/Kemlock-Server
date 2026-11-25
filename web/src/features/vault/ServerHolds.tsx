// "What the server holds": the record the server keeps for an item, in a dialog. Ciphertext, its
// kind, its sizes and revision; no name, address, password or note. The sizes are of the sealed
// bytes the sync brought, so this is exactly what is on the server, not a guess.
import { type MessageId, useT } from '@/i18n';
import { AppDialog } from '@/ui/AppDialog';
import { Button } from '@/ui/Button';
import '@/styles/item.css';
import type { VaultItem } from './vault';

type T = (id: MessageId, values?: Record<string, string | number>) => string;

/**
 * The record, one fact to a line, as the canvas shows it. Its words come from the messages, and the
 * collection is there when the item sits in one.
 */
export function serverRecord(item: VaultItem, t: T): string {
  const rows: Array<[string, string]> = [
    [t('detail.server.rec.item'), `${item.id}   ${item.kind}`],
    [t('detail.server.rec.owner'), item.owner],
  ];
  if (item.collectionId) rows.push([t('detail.server.rec.collection'), item.collectionId]);
  rows.push(
    [
      t('detail.server.rec.revision'),
      t('detail.server.rec.revisionValue', { revision: item.revision, keyVersion: item.keyVersion }),
    ],
    [t('detail.server.rec.key'), t('detail.server.rec.keyValue', { size: item.sizes.itemKey })],
    [t('detail.server.rec.body'), t('detail.server.rec.bodyValue', { size: item.sizes.ciphertext })],
  );
  const width = Math.max(...rows.map(([label]) => label.length)) + 1;
  return rows.map(([label, value]) => `${label.padEnd(width)}${value}`).join('\n');
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
        {serverRecord(item, t)}
      </pre>
      <p className="muted hint">{t('item.server.note')}</p>
    </AppDialog>
  );
}
