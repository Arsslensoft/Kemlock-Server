// "Move to a space": pick where the item should live (the account's own vault, or a collection of a
// space this person may add items to) and move it. The move seals it again under the key of its
// new place and keeps its links; see move.ts. An item that holds files has them sent again, which
// takes a moment, and the dialog says so. A contact stays in the account's own vault.
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { Radio, RadioGroup } from 'react-aria-components';
import { session } from '@/app/services';
import { useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { AppDialog } from '@/ui/AppDialog';
import { Button } from '@/ui/Button';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import '@/styles/item.css';
import { useCanWrite, useVault, useVaultActions, useWritableCollections } from './hooks';
import { isLinked, linkedItems } from './links';
import { MAX_RELINKS, type MoveTarget, holdsFiles, isHere, moveRefusal } from './move';
import { type VaultItem, spaceOf } from './vault';

interface Place {
  value: string;
  label: string;
  target: MoveTarget;
}

export function MoveDialog({ item, name, onClose }: { item: VaultItem; name: string; onClose: () => void }) {
  const t = useT();
  const navigate = useNavigate();
  const collections = useWritableCollections();
  const { all } = useVault();
  const canWrite = useCanWrite();
  const { move } = useVaultActions();
  const userId = session.getState().userId;
  const writable = canWrite(item);

  const places: Place[] = [];
  if (spaceOf(item.owner) !== null && userId) {
    places.push({ value: 'vault', label: t('newItem.where.vault'), target: { owner: `user:${userId}` } });
  }
  // A contact is one person's own statement: it never goes into a space.
  for (const c of item.kind === 'contact' ? [] : (collections.data ?? [])) {
    const target: MoveTarget = { owner: `space:${c.spaceId}`, collectionId: c.collectionId };
    if (isHere(item, target)) continue;
    places.push({
      value: `${c.spaceId}/${c.collectionId}`,
      label: t('newItem.where.collection', { space: c.spaceName, collection: c.collectionName }),
      target,
    });
  }

  // The items that name this one and that this person may change: each names the new id after a move.
  const linked = linkedItems(item, all).filter((other) => other.data !== null && canWrite(other));
  const tooMany = linked.filter((other) => isLinked(other, item)).length > MAX_RELINKS;
  const refusal = moveRefusal(item, writable);
  const [chosen, setChosen] = useState<string | undefined>(undefined);
  const place = places.find((p) => p.value === (chosen ?? places[0]?.value));
  const failure = move.error ? describeError(move.error) : undefined;
  const blocked = refusal !== undefined || tooMany;

  async function submit() {
    if (!place) return;
    try {
      const moved = await move.mutateAsync({ item, target: place.target, linked, writable });
      // Where the item is now, then out of the dialog: closing first would leave a page for an id that is gone.
      await navigate({ to: '/vault/$itemId', params: { itemId: moved.id }, replace: true });
      onClose();
    } catch {
      // Why it failed is shown in the dialog, which stays open.
    }
  }

  return (
    <AppDialog
      isOpen
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      isDismissable={!move.isPending}
      title={t('detail.menu.move')}
      icon="building"
      footer={
        <>
          <Button isDisabled={move.isPending} onPress={onClose}>
            {t('action.cancel')}
          </Button>
          <Button variant="primary" isDisabled={!place || blocked || move.isPending} onPress={() => void submit()}>
            {t('detail.move.confirm')}
          </Button>
        </>
      }
    >
      <p className="muted">{t('detail.move.lede', { name })}</p>
      {refusal === 'read-only' ? (
        <Notice tone="warn">
          <p>{t('detail.move.readOnly')}</p>
        </Notice>
      ) : refusal !== undefined ? (
        <Notice tone="warn">
          <p>{t('detail.move.cant')}</p>
        </Notice>
      ) : tooMany ? (
        <Notice tone="warn">
          <p>{t('detail.move.tooMany')}</p>
        </Notice>
      ) : places.length === 0 ? (
        <Notice>
          <p>
            {collections.isPending
              ? t('main.loading')
              : item.kind === 'contact'
                ? t('detail.move.contact')
                : t('detail.move.none')}
          </p>
        </Notice>
      ) : (
        <RadioGroup
          aria-label={t('detail.move.where')}
          value={place?.value ?? ''}
          onChange={setChosen}
          isDisabled={move.isPending}
          className="opts"
        >
          {places.map((option) => (
            <Radio key={option.value} value={option.value} className="opt">
              <span className="box">
                <Icon name="check" />
              </span>
              <span>
                <span className="t">{option.label}</span>
                <span className="hint">
                  {t(option.value === 'vault' ? 'detail.move.vaultHint' : 'detail.move.spaceHint')}
                </span>
              </span>
            </Radio>
          ))}
        </RadioGroup>
      )}
      {move.isPending && holdsFiles(item) ? (
        <p className="muted" role="status">
          {t('detail.move.working')}
        </p>
      ) : null}
      {failure ? (
        <Notice tone="error" live>
          <p>{t(failure.id, failure.values)}</p>
        </Notice>
      ) : null}
    </AppDialog>
  );
}
