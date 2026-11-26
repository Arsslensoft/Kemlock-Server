// The warning for what the server serves of the vault against what this account's devices signed
// (src/manifest): older copies of items, items that are gone and deleted items that came back,
// or a signed list that is itself rolled back, forged or withheld. It shows nothing when all
// is as signed.
import { useSyncExternalStore } from 'react';
import { type MessageId, useT } from '@/i18n';
import { manifestKeeper } from '@/manifest/instance';
import type { ManifestProblem, ManifestWarning } from '@/manifest/keeper';
import { Notice } from '@/ui/Notice';

const PROBLEM: Record<ManifestProblem, MessageId> = {
  'rolled-back': 'manifest.notice.manifestRolledBack',
  invalid: 'manifest.notice.manifestInvalid',
  dropped: 'manifest.notice.manifestDropped',
};

/** The notice for a warning. Takes the warning, so it is shown and tested without the keeper. */
export function ManifestNoticeView({ warning }: { warning: ManifestWarning }) {
  const t = useT();
  if (warning.manifests.length === 0 && warning.items.length === 0 && !warning.publishFailed) return null;
  // The title and the advice are for a mismatch; a list that could not be saved says only that.
  const mismatch = warning.manifests.length > 0 || warning.items.length > 0;
  const count = (verdict: ManifestWarning['items'][number]['verdict']) =>
    warning.items.filter((item) => item.verdict === verdict).length;
  const problems = [...new Set(warning.manifests.map((entry) => entry.problem))];
  const rolledBack = count('rolled-back');
  const missing = count('missing');
  const resurrected = count('resurrected');
  const deleted = count('deleted');
  const implausible = count('implausible');
  const forged = count('forged');
  const unsigned = count('unsigned');
  return (
    <Notice tone="warn" live>
      {mismatch ? (
        <p>
          <b>{t('manifest.notice.title')}</b>
        </p>
      ) : null}
      {problems.map((problem) => (
        <p key={problem}>{t(PROBLEM[problem])}</p>
      ))}
      {warning.publishFailed ? <p>{t('manifest.notice.publishFailed')}</p> : null}
      {rolledBack > 0 ? <p>{t('manifest.notice.rolledBack', { count: rolledBack })}</p> : null}
      {missing > 0 ? <p>{t('manifest.notice.missing', { count: missing })}</p> : null}
      {resurrected > 0 ? <p>{t('manifest.notice.resurrected', { count: resurrected })}</p> : null}
      {deleted > 0 ? <p>{t('manifest.notice.deleted', { count: deleted })}</p> : null}
      {implausible > 0 ? <p>{t('manifest.notice.implausible', { count: implausible })}</p> : null}
      {forged > 0 ? <p>{t('manifest.notice.forged', { count: forged })}</p> : null}
      {unsigned > 0 ? <p>{t('manifest.notice.unsigned', { count: unsigned })}</p> : null}
      {mismatch ? <p className="hint">{t('manifest.notice.hint')}</p> : null}
    </Notice>
  );
}

export function ManifestNotice() {
  const warning = useSyncExternalStore(
    manifestKeeper.subscribe,
    manifestKeeper.getWarning,
    manifestKeeper.getWarning,
  );
  return <ManifestNoticeView warning={warning} />;
}
