// `formatSize` for the language the page is in: the number as that language writes it, and the unit
// from the messages (`detail.size.*`).
import { useCallback } from 'react';
import { useIntl } from 'react-intl';
import { type MessageId, useT } from '@/i18n';
import { formatSize } from './files';

export function useFormatSize(): (bytes: number) => string {
  const intl = useIntl();
  const t = useT();
  return useCallback(
    (bytes) => formatSize(bytes, intl.locale, (unit, value) => t(`detail.size.${unit}` as MessageId, { value })),
    [intl.locale, t],
  );
}
