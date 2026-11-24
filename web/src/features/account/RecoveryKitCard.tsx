import { useState } from 'react';
import type { RecoveryKitDto } from '@/api/recoveryKit';
import { useT } from '@/i18n';
import { displayPiece } from '@/lib/kitPiece';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { QrCode } from '@/ui/QrCode';
import { TextInput } from './controls';

export interface RecoveryKitProps {
  /** undefined while loading; null when the account has no kit */
  kit: RecoveryKitDto | null | undefined;
  /** A kit the key worker made that is not kept yet: its pieces are on screen. */
  making: { pieces: string[]; mismatch: boolean } | null;
  busy: boolean;
  actions: {
    /** Makes a kit in the key worker; true when its pieces are ready to show. */
    start: () => Promise<void>;
    cancel: () => void;
    /** Mails the one-time code that proves the owner, for replacing or removing a kit. */
    askProof: () => Promise<boolean>;
    /** Keeps the kit when `typed` is one of its pieces; `proof` when it replaces another. */
    confirm: (typed: string, proof?: string) => Promise<boolean>;
    remove: (proof: string) => Promise<boolean>;
  };
}

/** The Recovery Kit as rows of the two-step card: make, make again, remove. */
export function RecoveryKitCard({ kit, making, busy, actions }: RecoveryKitProps) {
  const t = useT();
  const [removing, setRemoving] = useState(false);
  const [proof, setProof] = useState('');
  const [typed, setTyped] = useState('');
  const replacing = kit != null;

  async function begin() {
    setTyped('');
    setProof('');
    if (replacing) void actions.askProof();
    await actions.start();
  }

  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.kit.title')}</div>
          <div className="hint">{t('security.kit.hint')}</div>
          {kit ? (
            <div className="hint">{t('security.kit.made', { when: new Date(kit.createdAt).toLocaleDateString() })}</div>
          ) : null}
        </div>
        {kit !== undefined ? (
          <span className={kit ? 'tag ok' : 'tag off'}>{kit ? t('security.on') : t('security.off')}</span>
        ) : null}
        {kit === null && !making ? (
          <Button size="small" isDisabled={busy} onPress={() => void begin()}>
            {t('security.kit.make')}
          </Button>
        ) : null}
        {kit && !making && !removing ? (
          <>
            <Button size="small" isDisabled={busy} onPress={() => void begin()}>
              {t('security.kit.regenerate')}
            </Button>
            <Button
              size="small"
              variant="danger"
              isDisabled={busy}
              onPress={() => {
                setProof('');
                setRemoving(true);
                void actions.askProof();
              }}
            >
              {t('security.kit.remove')}
            </Button>
          </>
        ) : null}
      </div>
      {kit && !kit.current ? <Notice tone="warn">{t('security.kit.stale')}</Notice> : null}

      {making ? (
        <form
          className="panel-body kit-sheet"
          onSubmit={(event) => {
            event.preventDefault();
            void actions.confirm(typed, replacing ? proof.trim() : undefined);
          }}
        >
          <Notice tone="warn">{t('security.kit.once')}</Notice>
          {replacing ? <p className="hint">{t('security.kit.replaces')}</p> : null}
          <ol className="kit-pieces">
            {making.pieces.map((piece, i) => (
              <li key={piece} className="kit-piece">
                <strong>{t('security.kit.piece', { n: i + 1 })}</strong>
                <QrCode text={piece} label={t('security.kit.qr', { n: i + 1 })} size={132} />
                <code className="mono kit-text" data-testid={`kit-piece-${i + 1}`}>
                  {displayPiece(piece)}
                </code>
                <CopyButton value={piece} label={t('security.kit.copy', { n: i + 1 })} secret />
              </li>
            ))}
          </ol>
          <p className="hint">{t('security.kit.apart')}</p>
          <div className="actions kit-noprint">
            <Button onPress={() => window.print()}>{t('security.kit.print')}</Button>
          </div>
          <div className="kit-noprint stack">
            <TextInput label={t('security.kit.confirm')} value={typed} onChange={setTyped} mono required />
            {making.mismatch ? <Notice tone="error" live>{t('security.kit.mismatch')}</Notice> : null}
            {replacing ? (
              <TextInput label={t('security.proof.code')} value={proof} onChange={setProof} mono required />
            ) : null}
            <div className="actions">
              <Button
                type="submit"
                variant="primary"
                isDisabled={busy || typed.trim() === '' || (replacing && proof.trim() === '')}
              >
                {replacing ? t('security.kit.keepNew') : t('security.kit.keep')}
              </Button>
              {replacing ? (
                <Button isDisabled={busy} onPress={() => void actions.askProof()}>
                  {t('security.proof.again')}
                </Button>
              ) : null}
              <Button onPress={actions.cancel}>{t('action.cancel')}</Button>
            </div>
          </div>
        </form>
      ) : null}

      {removing ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            void actions.remove(proof.trim()).then((done) => {
              if (done) setRemoving(false);
            });
          }}
        >
          <p className="hint">{t('security.kit.removeBody')}</p>
          <p className="hint">{t('security.kit.proofSent')}</p>
          <TextInput label={t('security.proof.code')} value={proof} onChange={setProof} mono required />
          <div className="actions">
            <Button type="submit" variant="danger" isDisabled={busy || proof.trim() === ''}>
              {t('security.kit.removeConfirm')}
            </Button>
            <Button isDisabled={busy} onPress={() => void actions.askProof()}>
              {t('security.proof.again')}
            </Button>
            <Button onPress={() => setRemoving(false)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
    </>
  );
}
