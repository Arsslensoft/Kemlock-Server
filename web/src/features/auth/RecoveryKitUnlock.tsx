import { useEffect, useRef, useState } from 'react';
import { createRecoveryKitApi } from '@/api/recoveryKit';
import { api, session } from '@/app/services';
import type { KitProblem } from '@/crypto/types';
import { vaultCrypto } from '@/crypto-port';
import { useT } from '@/i18n';
import { type Described, describeError } from '@/lib/errors';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { type PieceCheck, checkPieces, newestOnly, unlockWithKit } from './kitUnlock';
import { canScan, createQrReader } from './qrDetect';

const kitApi = createRecoveryKitApi(api);

/** Points the camera at a QR code until it reads one, and hands its text over. */
function Scanner({ onText, onStop }: { onText: (text: string) => void; onStop: () => void }) {
  const t = useT();
  const video = useRef<HTMLVideoElement>(null);
  // The latest callbacks, so the camera is not restarted when the parent renders.
  const latest = useRef({ onText, onStop });
  latest.current = { onText, onStop };
  useEffect(() => {
    let stopped = false;
    let stream: MediaStream | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    void (async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        const element = video.current;
        if (!element || stopped) return;
        element.srcObject = stream;
        await element.play();
        const read = await createQrReader();
        const look = async () => {
          if (stopped) return;
          const text = await read(element).catch(() => undefined);
          if (text) {
            latest.current.onText(text);
            return;
          }
          timer = setTimeout(() => void look(), 300);
        };
        void look();
      } catch {
        latest.current.onStop();
      }
    })();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, []);
  return (
    <div className="stack">
      <p className="hint">{t('unlock.kit.scanning')}</p>
      <video ref={video} muted playsInline aria-label={t('unlock.kit.scanning')} style={{ maxWidth: '100%' }} />
      <div className="actions">
        <Button onPress={onStop}>{t('unlock.kit.stopScan')}</Button>
      </div>
    </div>
  );
}

function problemMessage(problem: KitProblem): Described {
  switch (problem) {
    case 'checksum':
      return { id: 'unlock.kit.checksum' };
    case 'other-kit':
      return { id: 'unlock.kit.otherKit' };
    case 'duplicate':
      return { id: 'unlock.kit.duplicate' };
    default:
      return { id: 'unlock.kit.format' };
  }
}

/** The unlock screen's way in with 2 of the 3 pieces of a Recovery Kit. */
export function RecoveryKitUnlock({
  accountId,
  onUnlocked,
  onBack,
}: {
  accountId: string;
  onUnlocked: () => void;
  onBack: () => void;
}) {
  const t = useT();
  const [texts, setTexts] = useState(['', '']);
  const [checks, setChecks] = useState<PieceCheck[]>([{ status: 'empty' }, { status: 'empty' }]);
  const [together, setTogether] = useState<KitProblem | undefined>();
  const [scanning, setScanning] = useState<number | null>(null);
  const [pending, setPending] = useState(false);
  const [failure, setFailure] = useState<Described | undefined>();
  // One check at a time counts: the newest, so a slow answer about older text is dropped.
  const newest = useRef(newestOnly());
  // The text as typed, which a check that is still running must not be built on.
  const typed = useRef(texts);

  async function enter(index: number, text: string) {
    const next = typed.current.map((old, i) => (i === index ? text : old));
    typed.current = next;
    setTexts(next);
    setFailure(undefined);
    const result = await newest.current(() => checkPieces(vaultCrypto, next));
    if (!result) return;
    setChecks(result.each);
    setTogether(result.together);
  }

  const ready = checks.every((check) => check.status === 'ok') && together === undefined;

  async function open() {
    setPending(true);
    setFailure(undefined);
    try {
      const result = await unlockWithKit({ kit: kitApi, api, crypto: vaultCrypto, session }, accountId, texts);
      if (result.status === 'unlocked') onUnlocked();
      else if (result.status === 'no-kit') setFailure({ id: 'unlock.kit.noKit' });
      else if (result.status === 'stale') setFailure({ id: 'unlock.kit.stale' });
      else setFailure({ id: 'unlock.kit.wrong' });
    } catch (caught) {
      setFailure(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="stack" aria-labelledby="h-kit">
      <h2 id="h-kit">{t('unlock.kit.title')}</h2>
      <p className="hint">{t('unlock.kit.lede')}</p>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) void open();
        }}
      >
        {texts.map((text, i) => {
          const check = checks[i];
          const problem = check?.status === 'bad' ? check.problem : undefined;
          return (
            <div className="field" key={i}>
              <label htmlFor={`kit-piece-${i}`}>{t('unlock.kit.piece', { n: i + 1 })}</label>
              <textarea
                id={`kit-piece-${i}`}
                className="mono"
                rows={3}
                value={text}
                spellCheck={false}
                autoCapitalize="characters"
                autoComplete="off"
                aria-invalid={problem !== undefined}
                aria-describedby={`kit-piece-note-${i}`}
                placeholder={t('unlock.kit.pieceHint')}
                onChange={(event) => void enter(i, event.target.value)}
              />
              <div id={`kit-piece-note-${i}`} className="hint" role={problem ? 'alert' : undefined}>
                {problem ? (
                  (() => {
                    const message = problemMessage(problem);
                    return t(message.id, message.values);
                  })()
                ) : check?.status === 'ok' ? (
                  t('unlock.kit.ok', {
                    index: check.read.index,
                    shares: check.read.shares,
                    kitId: check.read.kitId,
                  })
                ) : null}
              </div>
              {canScan() && scanning === null ? (
                <div className="actions">
                  <Button size="small" onPress={() => setScanning(i)}>
                    {t('unlock.kit.scan')}
                  </Button>
                </div>
              ) : null}
              {scanning === i ? (
                <Scanner
                  onText={(scanned) => {
                    setScanning(null);
                    void enter(i, scanned);
                  }}
                  onStop={() => setScanning(null)}
                />
              ) : null}
            </div>
          );
        })}
        {together ? (
          <Notice tone="error" live>
            {t(problemMessage(together).id)}
          </Notice>
        ) : null}
        {failure ? (
          <Notice tone="error" live>
            {t(failure.id, failure.values)}
          </Notice>
        ) : null}
        <div className="actions">
          <Button type="submit" variant="primary" isDisabled={!ready || pending}>
            {t('unlock.kit.submit')}
          </Button>
          <Button onPress={onBack}>{t('unlock.kit.back')}</Button>
        </div>
      </form>
    </section>
  );
}
