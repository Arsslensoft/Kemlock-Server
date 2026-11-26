import { useState } from 'react';
import type { PasskeyDto } from '@/api/passkeys';
import type { Proof } from '@/api/twoStep';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { type KeyProof, ProofInput, proofBlank, proofValue } from './ProofInput';

export interface PasskeysCardProps {
  /** undefined while loading */
  passkeys: PasskeyDto[] | undefined;
  busy: boolean;
  /**
   * Whether a second step is on: a passkey signs in without the password or the second step, so
   * adding one then takes a fresh proof, as adding a security key does.
   */
  proofNeeded?: boolean;
  /** Answers the proof with a security key or passkey; undefined when the account has none. */
  keyProof?: KeyProof | undefined;
  /** Mails the one-time code the proof can be. */
  onAskProof?: () => void;
  /** Answers true when the passkey was added, so the proof panel can close. */
  onAdd: (proof?: Proof) => Promise<boolean> | void;
  onRemove: (id: string) => void;
}

/** The passkeys of the account, as rows of the two-step card: what is there, add one, remove one. */
export function PasskeysCard({
  passkeys,
  busy,
  proofNeeded = false,
  keyProof,
  onAskProof,
  onAdd,
  onRemove,
}: PasskeysCardProps) {
  const t = useT();
  const [asking, setAsking] = useState(false);
  const [proof, setProof] = useState<Proof>('');
  return (
    <>
      <div className="row">
        <div className="grow">
          <div>{t('security.passkeys.title')}</div>
          <div className="hint">{t('security.passkeys.hint')}</div>
        </div>
        {passkeys === undefined ? null : (
          <span className={passkeys.length > 0 ? 'tag ok' : 'tag off'}>
            {passkeys.length > 0 ? t('security.on') : t('security.off')}
          </span>
        )}
        {asking ? null : (
          <Button
            size="small"
            isDisabled={busy || passkeys === undefined}
            onPress={() => {
              if (!proofNeeded) {
                void onAdd();
                return;
              }
              setProof('');
              setAsking(true);
              onAskProof?.();
            }}
          >
            {t('security.passkeys.add')}
          </Button>
        )}
      </div>
      {asking ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            const given = proofValue(proof);
            void Promise.resolve(onAdd(proofBlank(given) ? undefined : given)).then((done) => {
              if (done) {
                setAsking(false);
                setProof('');
              }
            });
          }}
        >
          <p className="hint">{t('security.proofAdd.sent')}</p>
          <ProofInput value={proof} onChange={setProof} keyProof={keyProof} busy={busy} required={false} />
          <div className="actions">
            <Button type="submit" variant="primary" isDisabled={busy || proofBlank(proof)}>
              {t('security.passkeys.add')}
            </Button>
            <Button isDisabled={busy} onPress={() => onAskProof?.()}>
              {t('security.proof.again')}
            </Button>
            <Button onPress={() => setAsking(false)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
      {passkeys?.map((passkey) => (
        <div className="row" key={passkey.id} data-testid="passkey">
          <div className="grow">{passkey.name}</div>
          {passkey.prf ? <span className="tag ok">{t('security.passkeys.opens')}</span> : null}
          <Button
            size="small"
            isDisabled={busy}
            aria-label={t('security.passkeys.remove', { name: passkey.name })}
            onPress={() => onRemove(passkey.id)}
          >
            {t('security.passkeys.removeLabel')}
          </Button>
        </div>
      ))}
    </>
  );
}
