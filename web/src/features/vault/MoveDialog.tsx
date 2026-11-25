// "Move to a space": pick where the item should live (the account's own vault, or a collection of a
// space this person may add items to) and move it. The move seals it again under the key of its
// new place; see move.ts. An item that holds a file stays where it is, and the dialog says so.
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
import { linkedItems } from './links';
import { type MoveTarget, isHere, moveRefusal } from './move';
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

  const places: Place[] = [];
  if (spaceOf(item.owner) !== null && userId) {
    places.push({ value: 'vault', label: t('newItem.where.vault'), target: { owner: `user:${userId}` } });
  }
  for (const c of collections.data ?? []) {
    const target: MoveTarget = { owner: `space:${c.spaceId}`, collectionId: c.collectionId };
    if (isHere(item, target)) continue;
    places.push({
      value: `${c.spaceId}/${c.collectionId}`,
      label: t('newItem.where.collection', { space: c.spaceName, collection: c.collectionName }),
      target,
    });
  }

  const refusal = moveRefusal(item);
  const [chosen, setChosen] = useState<string | undefined>(undefined);
  const place = places.find((p) => p.value === (chosen ?? places[0]?.value));
  const failure = move.error ? describeError(move.error) : undefined;

  function submit() {
    if (!place) return;
    const linked = linkedItems(item, all).filter(canWrite);
    move.mutate(
      { item, target: place.target, linked },
      {
        onSuccess: (moved) => {
          onClose();
          void navigate({ to: '/vault/$itemId', params: { itemId: moved.id }, replace: true });
        },
      },
    );
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
          <Button variant="primary" isDisabled={!place || refusal !== undefined || move.isPending} onPress={submit}>
            {t('detail.move.confirm')}
          </Button>
        </>
      }
    >
      <p className="muted">{t('detail.move.lede', { name })}</p>
      {refusal === 'files' ? (
        <Notice tone="warn">
          <p>{t('detail.move.files')}</p>
        </Notice>
      ) : refusal !== undefined ? (
        <Notice tone="warn">
          <p>{t('detail.move.cant')}</p>
        </Notice>
      ) : places.length === 0 ? (
        <Notice>
          <p>{collections.isPending ? t('main.loading') : t('detail.move.none')}</p>
        </Notice>
      ) : (
        <RadioGroup
          aria-label={t('detail.move.where')}
          value={place?.value ?? ''}
          onChange={setChosen}
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
      {failure ? (
        <Notice tone="error" live>
          <p>{t(failure.id, failure.values)}</p>
        </Notice>
      ) : null}
    </AppDialog>
  );
}
