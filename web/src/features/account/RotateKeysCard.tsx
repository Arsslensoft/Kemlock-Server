import { useState } from 'react';
import type { Proof } from '@/api/twoStep';
import { useT } from '@/i18n';
import { displayPiece } from '@/lib/kitPiece';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { QrCode } from '@/ui/QrCode';
import { TextInput } from './controls';
import { type KeyProof, ProofInput, proofBlank, proofValue } from './ProofInput';
import type { RotationProgress } from './rotationModel';

/** What the page knows of the account before it rotates: what the rotation removes. */
export interface RotateContact {
  id: string;
  email: string;
  /** The contact's bundle as the server serves it now, base64url. */
  bundle: string;
  /** Its fingerprint, worked out here, for the person to compare with the contact's own screen. */
  fingerprint: string;
}

export interface RotateImpact {
  /** Emergency contacts the person may keep by comparing their fingerprint. */
  contacts: RotateContact[];
  passkeys: number;
  emergency: number;
  recovery: number;
  hasKit: boolean;
  hasPassword: boolean;
}

/** The outcome the person must see: the new kit to save, and what was removed. */
export interface RotateDone {
  fingerprint: string;
  kit: { kitId: string; pieces: string[] } | null;
  removed: { passkeys: Array<{ id: string; credentialId: string }>; emergency: number; recovery: number };
  /** The passkeys whose unlock was removed, to add back one by one. */
  passkeys: Array<{ id: string; name: string }>;
}

export interface RotateKeysProps {
  /** undefined while loading */
  impact: RotateImpact | undefined;
  /** The account is in a space or shared with Bitwarden apps: the page does not rotate it. */
  blocked: 'spaces' | 'compatible' | null;
  twoStep: boolean;
  keyProof?: KeyProof | undefined;
  busy: boolean;
  progress: RotationProgress | null;
  done: RotateDone | null;
  actions: {
    /** Rotates; true when it was installed. */
    start: (input: {
      password: string;
      makeKit: boolean;
      emergencyKeep: Record<string, string>;
      proof?: Proof;
    }) => Promise<boolean>;
    /** Mails the one-time code that proves the owner. */
    askProof: () => Promise<boolean>;
    /** Touches the passkey and keeps its unlock again; true when it was kept. */
    readdPasskey: (id: string) => Promise<boolean>;
    dismiss: () => void;
  };
}

/** "Rotate account keys": what it does, the password, progress, and the new Recovery Kit. */
export function RotateKeysCard({ impact, blocked, twoStep, keyProof, busy, progress, done, actions }: RotateKeysProps) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [makeKit, setMakeKit] = useState(true);
  const [proof, setProof] = useState<Proof>('');
  const [compared, setCompared] = useState<Set<string>>(new Set());
  const [readded, setReadded] = useState<Set<string>>(new Set());

  async function submit() {
    const emergencyKeep: Record<string, string> = {};
    for (const contact of impact?.contacts ?? []) {
      if (compared.has(contact.id)) emergencyKeep[contact.id] = contact.bundle;
    }
    const ok = await actions.start({
      password,
      makeKit,
      emergencyKeep,
      ...(twoStep && !proofBlank(proof) ? { proof: proofValue(proof) } : {}),
    });
    if (ok) {
      setPassword('');
      setProof('');
      setOpen(false);
    }
  }

  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.rotate.title')}</div>
          <div className="hint">{t('security.rotate.hint')}</div>
        </div>
        {!open && !done && impact && !blocked ? (
          <Button
            size="small"
            isDisabled={busy}
            onPress={() => {
              setOpen(true);
              if (twoStep) void actions.askProof();
            }}
          >
            {t('security.rotate.start')}
          </Button>
        ) : null}
      </div>
      {blocked ? <Notice tone="warn">{t(`security.rotate.blocked.${blocked}`)}</Notice> : null}

      {open && impact ? (
        <form
          className="panel-body stack"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <p>{t('security.rotate.what')}</p>
          <ul className="hint">
            <li>{t('security.rotate.others')}</li>
            {impact.passkeys > 0 ? <li>{t('security.rotate.passkeys', { n: impact.passkeys })}</li> : null}
            {impact.emergency > 0 ? <li>{t('security.rotate.emergency', { n: impact.emergency })}</li> : null}
            {impact.recovery > 0 ? <li>{t('security.rotate.recovery', { n: impact.recovery })}</li> : null}
            <li>{t('security.rotate.files')}</li>
          </ul>
          {impact.contacts.map((contact) => (
            <label className="check" key={contact.id}>
              <input
                type="checkbox"
                checked={compared.has(contact.id)}
                onChange={(event) =>
                  setCompared((held) => {
                    const next = new Set(held);
                    if (event.target.checked) next.add(contact.id);
                    else next.delete(contact.id);
                    return next;
                  })
                }
              />{' '}
              {t('security.rotate.contact', { email: contact.email })}
              <code className="mono" data-testid={`contact-fingerprint-${contact.id}`}>
                {contact.fingerprint}
              </code>
            </label>
          ))}
          <label className="check">
            <input type="checkbox" checked={makeKit} onChange={(event) => setMakeKit(event.target.checked)} />{' '}
            {impact.hasKit ? t('security.rotate.kitReplace') : t('security.rotate.kitMake')}
          </label>
          {impact.hasPassword ? (
            <TextInput
              label={t('security.rotate.password')}
              type="password"
              value={password}
              onChange={setPassword}
              required
            />
          ) : null}
          {twoStep ? <ProofInput value={proof} onChange={setProof} keyProof={keyProof} busy={busy} /> : null}
          {progress ? (
            <p role="status" className="hint">
              {t(`security.rotate.phase.${progress.phase}`, { done: progress.done, total: progress.total })}
            </p>
          ) : null}
          <div className="actions">
            <Button
              type="submit"
              variant="danger"
              isDisabled={busy || (impact.hasPassword && password === '') || (twoStep && proofBlank(proof) && !keyProof)}
            >
              {t('security.rotate.submit')}
            </Button>
            <Button isDisabled={busy} onPress={() => setOpen(false)}>
              {t('action.cancel')}
            </Button>
          </div>
        </form>
      ) : null}

      {done ? (
        <div className="panel-body kit-sheet" data-testid="rotated">
          <Notice tone="info">{t('security.rotate.done', { fingerprint: done.fingerprint })}</Notice>
          {done.removed.passkeys.length + done.removed.emergency + done.removed.recovery > 0 ? (
            <Notice tone="warn">
              {t('security.rotate.removed', {
                passkeys: done.removed.passkeys.length,
                emergency: done.removed.emergency,
                recovery: done.removed.recovery,
              })}
            </Notice>
          ) : null}
          {done.passkeys.map((passkey) => (
            <div className="row" key={passkey.id} data-testid="readd-passkey">
              <div className="grow">
                <div>{passkey.name}</div>
                <div className="hint">{t('security.rotate.readd.hint')}</div>
              </div>
              {readded.has(passkey.id) ? (
                <span className="tag ok">{t('security.passkeys.opens')}</span>
              ) : (
                <Button
                  size="small"
                  isDisabled={busy}
                  aria-label={t('security.rotate.readd', { name: passkey.name })}
                  onPress={() =>
                    void actions.readdPasskey(passkey.id).then((kept) => {
                      if (kept) setReadded((held) => new Set(held).add(passkey.id));
                    })
                  }
                >
                  {t('security.rotate.readd.button')}
                </Button>
              )}
            </div>
          ))}
          {done.kit ? (
            <>
              <Notice tone="warn">{t('security.kit.once')}</Notice>
              <ol className="kit-pieces">
                {done.kit.pieces.map((piece, i) => (
                  <li key={piece} className="kit-piece">
                    <strong>{t('security.kit.piece', { n: i + 1 })}</strong>
                    <QrCode text={piece} label={t('security.kit.qr', { n: i + 1 })} size={132} />
                    <code className="mono kit-text" data-testid={`rotated-kit-piece-${i + 1}`}>
                      {displayPiece(piece)}
                    </code>
                    <CopyButton value={piece} label={t('security.kit.copy', { n: i + 1 })} secret />
                  </li>
                ))}
              </ol>
              <div className="actions kit-noprint">
                <Button onPress={() => window.print()}>{t('security.kit.print')}</Button>
              </div>
            </>
          ) : null}
          <div className="actions kit-noprint">
            <Button onPress={actions.dismiss}>{t('security.rotate.dismiss')}</Button>
          </div>
        </div>
      ) : null}
    </>
  );
}
