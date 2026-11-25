import { useState } from 'react';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { TextInput } from './controls';
import { confirmsEmail } from './deleteAccountModel';

export interface DeleteAccountProps {
  email: string;
  /** A second step is on, so a fresh proof is asked beside the password. */
  secondStep: boolean;
  busy: boolean;
  actions: {
    /** Mails the one-time code that proves the owner. */
    askProof: () => Promise<boolean>;
    /** Erases the account and signs out; true when it is done. `proof` only with a second step. */
    erase: (typed: string, password: string, proof?: string) => Promise<boolean>;
  };
}

/** The danger zone: type your address, prove it is you, and the account and its data are erased. */
export function DeleteAccountCard({ email, secondStep, busy, actions }: DeleteAccountProps) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const [password, setPassword] = useState('');
  const [proof, setProof] = useState('');
  const ready = confirmsEmail(typed, email) && password !== '' && (!secondStep || proof.trim() !== '');

  return (
    <section className="card" aria-labelledby="h-delete">
      <div className="card-head">
        <div className="grow">
          <h2 id="h-delete">{t('security.delete.title')}</h2>
          <p className="hint">{t('security.delete.hint')}</p>
        </div>
        {!open ? (
          <Button
            size="small"
            variant="danger"
            isDisabled={busy}
            onPress={() => {
              setTyped('');
              setPassword('');
              setProof('');
              setOpen(true);
              if (secondStep) void actions.askProof();
            }}
          >
            {t('security.delete.start')}
          </Button>
        ) : null}
      </div>
      {open ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            if (ready) void actions.erase(typed, password, secondStep ? proof.trim() : undefined);
          }}
        >
          <Notice tone="warn">{t('security.delete.warn')}</Notice>
          <p className="hint">{t('security.delete.spaces')}</p>
          <TextInput label={t('security.delete.type', { email })} value={typed} onChange={setTyped} required />
          <TextInput label={t('security.delete.password')} type="password" value={password} onChange={setPassword} required />
          {secondStep ? (
            <>
              <p className="hint">{t('security.kit.proofSent')}</p>
              <TextInput label={t('security.proof.code')} value={proof} onChange={setProof} mono required />
            </>
          ) : null}
          <div className="actions">
            <Button type="submit" variant="danger" isDisabled={busy || !ready}>
              {t('security.delete.confirm')}
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
