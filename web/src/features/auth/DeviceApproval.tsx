import { Link, getRouteApi, useRouter } from '@tanstack/react-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createNewDeviceApi } from '@/api/devices';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { type MessageId, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { thisDevice } from '@/lib/device';
import { TextInput } from '@/features/account/controls';
import { lastGroup } from '@/ui/TypeLastGroup';
import { AuthPage } from '@/ui/AuthPage';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { afterSignIn } from './afterSignIn';
import {
  ApprovalRefused,
  type ApprovalOutcome,
  type ApprovalProgress,
  type DeviceApprovalDeps,
  signInWithAnotherDevice,
} from './approvalFlow';

const route = getRouteApi('/sign-in/device');

type Ended = Exclude<ApprovalOutcome, { status: 'signed-in' }>;

export { lastGroup };

/**
 * The answer to the comparison. "Same" is a deliberate act: it opens only when the person has
 * typed the last group of digits as the approving device shows it, so it is not pressed blindly.
 */
function FingerprintAnswer({
  fingerprint,
  onCompare,
}: {
  fingerprint: string;
  onCompare?: ((matches: boolean) => void) | undefined;
}) {
  const t = useT();
  const [typed, setTyped] = useState('');
  const typedRight = typed.replace(/\s+/g, '') === lastGroup(fingerprint);
  return (
    <>
      <TextInput
        label={t('deviceApproval.fingerprint.type')}
        value={typed}
        onChange={setTyped}
        mono
      />
      <Button variant="primary" size="large" block isDisabled={!typedRight} onPress={() => onCompare?.(true)}>
        {t('deviceApproval.fingerprint.match')}
      </Button>
      <Button block onPress={() => onCompare?.(false)}>
        {t('deviceApproval.fingerprint.differ')}
      </Button>
    </>
  );
}

function refusedMessage(error: ApprovalRefused): MessageId {
  if (error.reason === 'fingerprint') return 'deviceApproval.fingerprintRefused';
  if (error.reason === 'keys') return 'deviceApproval.keysRefused';
  return 'deviceApproval.refused';
}

/** What the screen shows for a progress or an ending. Takes no router or network. */
export function DeviceApprovalView({
  email,
  progress,
  ended,
  onCancel,
  onRetry,
  onCompare,
  next,
}: {
  email: string;
  progress: ApprovalProgress;
  ended?: Ended | undefined;
  onCancel: () => void;
  onRetry: () => void;
  /** The person's answer to the fingerprint comparison: `true` when the two were the same. */
  onCompare?: ((matches: boolean) => void) | undefined;
  /** The page the person was headed for, kept when they go back to sign in. */
  next?: string | undefined;
}) {
  const t = useT();
  let failure: MessageId | undefined;
  if (ended?.status === 'denied') failure = 'deviceApproval.denied';
  else if (ended?.status === 'expired') failure = 'deviceApproval.expired';
  else if (ended?.status === 'cancelled') failure = 'deviceApproval.cancelled';
  else if (ended?.status === 'failed') {
    failure =
      ended.error instanceof ApprovalRefused
        ? refusedMessage(ended.error)
        : describeError(ended.error).id;
    if (failure === 'error.generic') failure = 'deviceApproval.failed';
  }
  return (
    <AuthPage>
      <div>
        <h1>{t('deviceApproval.title')}</h1>
        <p className="lede">{t('deviceApproval.lede', { email })}</p>
      </div>
      {ended ? (
        <>
          <Notice tone={ended.status === 'cancelled' ? 'info' : 'error'} live>
            <p>{t(failure ?? 'deviceApproval.failed')}</p>
          </Notice>
          <Button variant="primary" size="large" block onPress={onRetry}>
            {t('deviceApproval.retry')}
          </Button>
          <Link to="/sign-in" search={{ next }} className="hint">
            {t('deviceApproval.back')}
          </Link>
        </>
      ) : progress.step === 'waiting' ? (
        <>
          <div className="stack">
            <p className="lbl" id="approval-phrase-label">
              {t('deviceApproval.phrase')}
            </p>
            <p
              className="mono phrase"
              aria-labelledby="approval-phrase-label"
              style={{ fontSize: '1.5rem', letterSpacing: '0.02em' }}
            >
              {progress.phrase}
            </p>
            <p className="hint">{t('deviceApproval.phrase.hint')}</p>
          </div>
          {progress.heldBack ? (
            <Notice tone="info">
              <p>{t('deviceApproval.heldBack')}</p>
            </Notice>
          ) : null}
          <p role="status">
            {t('deviceApproval.waiting', {
              time: new Date(progress.expiresAt).toLocaleTimeString(),
            })}
          </p>
          <Button block onPress={onCancel}>
            {t('deviceApproval.cancel')}
          </Button>
        </>
      ) : progress.step === 'compare' ? (
        <>
          <div className="stack">
            <p className="lbl" id="approval-fingerprint-label">
              {t('deviceApproval.fingerprint')}
            </p>
            <p
              className="mono phrase"
              aria-labelledby="approval-fingerprint-label"
              style={{ fontSize: '1.25rem', letterSpacing: '0.02em' }}
            >
              {progress.fingerprint}
            </p>
            <p className="hint">{t('deviceApproval.fingerprint.hint')}</p>
          </div>
          <FingerprintAnswer fingerprint={progress.fingerprint} onCompare={onCompare} />
        </>
      ) : (
        <p role="status">
          {t(progress.step === 'requesting' ? 'deviceApproval.requesting' : 'deviceApproval.signingIn')}
        </p>
      )}
    </AuthPage>
  );
}

/** What the screen supplies itself: the person's answer to the fingerprint comparison. */
type ScreenDeps = Omit<DeviceApprovalDeps, 'confirmFingerprint'>;

const realDeps: ScreenDeps = {
  approval: createNewDeviceApi(api),
  api,
  crypto: vaultCrypto,
  session,
  device: thisDevice,
};

export default function DeviceApproval({ deps = realDeps }: { deps?: ScreenDeps }) {
  const router = useRouter();
  const { email = '', next } = route.useSearch();
  const [progress, setProgress] = useState<ApprovalProgress>({ step: 'requesting' });
  const [ended, setEnded] = useState<Ended | undefined>();
  const [attempt, setAttempt] = useState(0);
  const controller = useRef<AbortController | undefined>(undefined);
  // Resolves the comparison the flow is waiting on; nothing waits for it outside the compare step.
  const answer = useRef<((matches: boolean) => void) | undefined>(undefined);
  const stable = useMemo<DeviceApprovalDeps>(
    () => ({
      ...deps,
      confirmFingerprint: (_fingerprint, signal) =>
        new Promise<boolean>((resolve) => {
          if (signal.aborted) {
            resolve(false);
            return;
          }
          answer.current = resolve;
          signal.addEventListener('abort', () => resolve(false), { once: true });
        }),
    }),
    [deps],
  );
  const compare = useCallback((matches: boolean) => {
    const resolve = answer.current;
    answer.current = undefined;
    resolve?.(matches);
  }, []);

  useEffect(() => {
    const abort = new AbortController();
    controller.current = abort;
    setEnded(undefined);
    setProgress({ step: 'requesting' });
    void signInWithAnotherDevice(stable, email, setProgress, abort.signal).then((outcome) => {
      if (outcome.status === 'signed-in') void afterSignIn(router, outcome, next);
      // Leaving the screen aborts the request; only a person's own cancel is worth saying.
      else if (!abort.signal.aborted || outcome.status === 'cancelled') setEnded(outcome);
    });
    return () => abort.abort();
  }, [stable, email, next, router, attempt]);

  const cancel = useCallback(() => controller.current?.abort(), []);
  return (
    <DeviceApprovalView
      email={email}
      progress={progress}
      ended={ended}
      onCancel={cancel}
      onRetry={() => setAttempt((n) => n + 1)}
      onCompare={compare}
      next={next}
    />
  );
}
