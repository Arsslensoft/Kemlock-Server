import type { Proof, WebauthnProof } from '@/api/twoStep';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { TextInput } from './controls';

/** Asks for a security key or passkey and returns its answer; undefined when it was not given. */
export type KeyProof = () => Promise<WebauthnProof | undefined>;

/** Whether a fresh proof has nothing in it yet. */
export function proofBlank(proof: Proof): boolean {
  return typeof proof === 'string' && proof.trim() === '';
}

/** The proof as it goes to the server: a typed code without its spaces at the ends, or the answer. */
export function proofValue(proof: Proof): Proof {
  return typeof proof === 'string' ? proof.trim() : proof;
}

/**
 * Where a fresh proof is entered: the code, or, when the account has a security key or passkey
 * (`keyProof` is given), the key's answer in its place.
 */
export function ProofInput({
  value,
  onChange,
  keyProof,
  busy = false,
  required = true,
  label,
}: {
  value: Proof;
  onChange: (next: Proof) => void;
  keyProof?: KeyProof | undefined;
  busy?: boolean;
  required?: boolean;
  /** Replaces the default label of the code field. */
  label?: string;
}) {
  const t = useT();
  if (typeof value !== 'string') {
    return (
      <div className="stack">
        <p className="hint" role="status">
          {t('security.proof.keyReady')}
        </p>
        <div className="actions">
          <Button isDisabled={busy} onPress={() => onChange('')}>
            {t('security.proof.useCode')}
          </Button>
        </div>
      </div>
    );
  }
  return (
    <>
      <TextInput label={label ?? t('security.proof.code')} value={value} onChange={onChange} mono required={required} />
      {keyProof ? (
        <div className="actions">
          <Button
            isDisabled={busy}
            onPress={() => {
              void keyProof().then((answer) => {
                if (answer) onChange(answer);
              });
            }}
          >
            {t('security.proof.useKey')}
          </Button>
        </div>
      ) : null}
    </>
  );
}
