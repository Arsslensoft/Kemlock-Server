import { useState } from 'react';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { TextInput } from './controls';

export interface SignedWritesProps {
  /** Whether the vault takes signed writes only; undefined while it is read. */
  required: boolean | undefined;
  /** A second step is on, so a fresh proof is asked beside the password to turn it off. */
  secondStep: boolean;
  busy: boolean;
  actions: {
    /** Turns it on; true when it is done. */
    turnOn: () => Promise<boolean>;
    /** Mails the one-time code that proves the owner. */
    askProof: () => Promise<boolean>;
    /** Turns it off with the password; true when it is done. `proof` only with a second step. */
    turnOff: (password: string, proof?: string) => Promise<boolean>;
  };
}

/**
 * Signed writes only: once it is on, the server and every server that holds the vault refuse an
 * item that is not signed by this account (docs/crypto.md, "The signed-only flag"). Turning it on
 * is one press; turning it off asks the password again, since it lets unsigned writes back in.
 */
export function SignedWritesCard({ required, secondStep, busy, actions }: SignedWritesProps) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [proof, setProof] = useState('');
  const ready = password !== '' && (!secondStep || proof.trim() !== '');

  return (
    <section className="card" aria-labelledby="h-signed">
      <div className="card-head">
        <div className="grow">
          <h2 id="h-signed">{t('security.signed.title')}</h2>
          <p className="hint">{t('security.signed.hint')}</p>
        </div>
        {required === undefined ? null : (
          <span className={required ? 'tag ok' : 'tag off'}>{required ? t('security.on') : t('security.off')}</span>
        )}
        {required === false ? (
          <Button size="small" isDisabled={busy} onPress={() => void actions.turnOn()}>
            {t('security.signed.turnOn')}
          </Button>
        ) : null}
        {required === true && !open ? (
          <Button
            size="small"
            isDisabled={busy}
            onPress={() => {
              setPassword('');
              setProof('');
              setOpen(true);
              if (secondStep) void actions.askProof();
            }}
          >
            {t('security.signed.turnOff')}
          </Button>
        ) : null}
      </div>
      {required === false ? <p className="hint">{t('security.signed.warnOn')}</p> : null}
      {required === true && open ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            if (!ready) return;
            void actions.turnOff(password, secondStep ? proof.trim() : undefined).then((done) => {
              if (done) setOpen(false);
            });
          }}
        >
          <Notice tone="warn">{t('security.signed.warnOff')}</Notice>
          <TextInput label={t('security.delete.password')} type="password" value={password} onChange={setPassword} required />
          {secondStep ? (
            <>
              <p className="hint">{t('security.kit.proofSent')}</p>
              <TextInput label={t('security.proof.code')} value={proof} onChange={setProof} mono required />
            </>
          ) : null}
          <div className="actions">
            <Button type="submit" isDisabled={busy || !ready}>
              {t('security.signed.confirmOff')}
            </Button>
            {secondStep ? (
              <Button isDisabled={busy} onPress={() => void actions.askProof()}>
                {t('security.proof.again')}
              </Button>
            ) : null}
            <Button isDisabled={busy} onPress={() => setOpen(false)}>
              {t('action.cancel')}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}
