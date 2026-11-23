import { useEffect, useState } from 'react';
import { useT } from '@/i18n';
import { type KeyLabels, keyLabels } from './fingerprint';

export type LabelsOf = (identityKey: string) => Promise<KeyLabels>;

/** The words and short form of a key, once they are worked out. */
export function useKeyLabels(identityKey: string, labelsOf: LabelsOf = keyLabels): KeyLabels | undefined {
  const [labels, setLabels] = useState<KeyLabels | undefined>();
  useEffect(() => {
    // No key to work the words out from (the server did not send one): none are shown, rather
    // than the words of an empty key.
    if (identityKey === '') {
      setLabels(undefined);
      return;
    }
    let live = true;
    labelsOf(identityKey).then(
      (value) => {
        if (live) setLabels(value);
      },
      () => {
        if (live) setLabels(undefined);
      },
    );
    return () => {
      live = false;
    };
  }, [identityKey, labelsOf]);
  return labels;
}

/** The words and short form of an identity key, worked out here from the key's bytes. */
export function KeyBadge({
  identityKey,
  labelsOf = keyLabels,
}: {
  identityKey: string;
  labelsOf?: LabelsOf;
}) {
  const t = useT();
  const labels = useKeyLabels(identityKey, labelsOf);
  if (identityKey === '') return <span className="hint">—</span>;
  if (!labels) return <span className="hint">{t('state.loading')}</span>;
  return (
    <div>
      <div className="words">{labels.words}</div>
      <div className="fp">
        <span className="sr">{t('admin.fed.shortForm')} </span>
        {labels.short}
      </div>
    </div>
  );
}
