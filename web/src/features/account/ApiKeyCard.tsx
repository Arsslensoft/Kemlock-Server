import { useState } from 'react';
import type { ApiKeyInfoDto } from '@/api/apiKey';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { TextInput } from './controls';

export interface ApiKeyProps {
  /** undefined while loading; null when the account has no Bitwarden sign-in, so no key */
  info: ApiKeyInfoDto | null | undefined;
  /** The secret, once a proof showed it; kept off the screen again by `hide`. */
  secret: string | null;
  /** What the last call did, for the notice. */
  changed: 'created' | 'rotated' | null;
  busy: boolean;
  actions: {
    /** Mails the one-time code that proves the owner. */
    askProof: () => Promise<boolean>;
    /** Shows the secret (made first when there is none); true when it worked. */
    reveal: (proof: string) => Promise<boolean>;
    /** Replaces the secret and shows the new one. */
    rotate: (proof: string) => Promise<boolean>;
    hide: () => void;
  };
}

/** The personal API key, for the Bitwarden CLI and scripts: its id, its secret after a proof, a new secret. */
export function ApiKeyCard({ info, secret, changed, busy, actions }: ApiKeyProps) {
  const t = useT();
  const [mode, setMode] = useState<'reveal' | 'rotate' | null>(null);
  const [proof, setProof] = useState('');

  function begin(next: 'reveal' | 'rotate') {
    setProof('');
    setMode(next);
    void actions.askProof();
  }

  return (
    <section className="card" aria-labelledby="h-apikey">
      <div className="card-head">
        <div className="grow">
          <h2 id="h-apikey">{t('security.apiKey.title')}</h2>
          <p className="hint">{t('security.apiKey.hint')}</p>
        </div>
      </div>
      {info === null ? <p className="hint panel-body">{t('security.apiKey.unavailable')}</p> : null}
      {info ? (
        <>
          <div className="row">
            <div className="grow">
              <div>{t('security.apiKey.clientId')}</div>
              <span className="cmd">
                <code>{info.clientId}</code>
                <CopyButton value={info.clientId} label={t('security.apiKey.copyId')} />
              </span>
            </div>
          </div>
          <div className="row">
            <div className="grow">
              <div>{t('security.apiKey.secret')}</div>
              {secret ? (
                <span className="cmd">
                  <code data-testid="api-secret">{secret}</code>
                  <CopyButton value={secret} label={t('security.apiKey.copySecret')} secret />
                </span>
              ) : (
                <div className="hint">{info.set ? t('security.apiKey.hidden') : t('security.apiKey.notMade')}</div>
              )}
            </div>
            {secret ? (
              <Button size="small" isDisabled={busy} onPress={actions.hide}>
                {t('security.apiKey.hide')}
              </Button>
            ) : mode === null ? (
              <Button size="small" isDisabled={busy} onPress={() => begin('reveal')}>
                {info.set ? t('security.apiKey.show') : t('security.apiKey.make')}
              </Button>
            ) : null}
            {mode === null && info.set ? (
              <Button size="small" variant="danger" isDisabled={busy} onPress={() => begin('rotate')}>
                {t('security.apiKey.rotate')}
              </Button>
            ) : null}
          </div>
          {changed === 'rotated' ? (
            <Notice tone="warn" live>
              {t('security.apiKey.rotated')}
            </Notice>
          ) : null}
          {changed === 'created' ? (
            <Notice tone="info" live>
              {t('security.apiKey.created')}
            </Notice>
          ) : null}
          {secret ? <p className="hint">{t('security.apiKey.keep')}</p> : null}
        </>
      ) : null}

      {mode ? (
        <form
          className="panel-body"
          onSubmit={(event) => {
            event.preventDefault();
            const run = mode === 'rotate' ? actions.rotate : actions.reveal;
            void run(proof.trim()).then((done) => {
              if (done) setMode(null);
            });
          }}
        >
          <p className="hint">{mode === 'rotate' ? t('security.apiKey.rotateBody') : t('security.apiKey.proofBody')}</p>
          <p className="hint">{t('security.kit.proofSent')}</p>
          <TextInput label={t('security.proof.code')} value={proof} onChange={setProof} mono required />
          <div className="actions">
            <Button
              type="submit"
              variant={mode === 'rotate' ? 'danger' : 'primary'}
              isDisabled={busy || proof.trim() === ''}
            >
              {mode === 'rotate' ? t('security.apiKey.rotateConfirm') : t('security.apiKey.showConfirm')}
            </Button>
            <Button isDisabled={busy} onPress={() => void actions.askProof()}>
              {t('security.proof.again')}
            </Button>
            <Button onPress={() => setMode(null)}>{t('action.cancel')}</Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}
