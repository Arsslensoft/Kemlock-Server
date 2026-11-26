import { useState } from 'react';
import type { Proof } from '@/api/twoStep';
import type { TotpEnrolResponse } from '@/api/types';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CodeForm } from '@/ui/CodeForm';
import { CopyButton } from '@/ui/CopyButton';
import { Notice } from '@/ui/Notice';
import { QrCode } from '@/ui/QrCode';
import '@/styles/account.css';
import { ApiKeyCard, type ApiKeyProps } from './ApiKeyCard';
import { DeleteAccountCard, type DeleteAccountProps } from './DeleteAccountCard';
import { EmergencyCard, type EmergencyCardProps } from './EmergencyCard';
import { groupSecret } from './emergencyModel';
import { PasskeysCard, type PasskeysCardProps } from './PasskeysCard';
import { SignedWritesCard, type SignedWritesProps } from './SignedWritesCard';
import { RecoveryKitCard, type RecoveryKitProps } from './RecoveryKitCard';
import { SecondStepsCard, type SecondStepsProps } from './SecondStepsCard';
import { ProofInput, proofBlank, proofValue } from './ProofInput';
import type { Described } from './errors';

export interface TotpState {
  /** The enrolment panel is open. */
  open: boolean;
  /** The secret and URI, once the server has made them. */
  enrol: TotpEnrolResponse | undefined;
}

export interface SecurityViewProps {
  email: string;
  host: string;
  /** The methods the server lists for this account; undefined while loading. */
  methods: string[] | undefined;
  totp: TotpState;
  busy: boolean;
  error?: Described | undefined;
  totpError?: Described | undefined;
  onStartTotp: () => void;
  onCancelTotp: () => void;
  /** `proof` is the recovery code, given when another second step is on already. */
  onConfirmTotp: (code: string, proof?: Proof) => void;
  emergency: EmergencyCardProps;
  /** The account's passkeys; omitted where passkeys are not offered. */
  passkeys?: PasskeysCardProps | undefined;
  /** The emailed code, YubiKeys, Duo, security keys and the recovery code; omitted, they read "Later". */
  secondSteps?: SecondStepsProps | undefined;
  /** The Recovery Kit: make, make again, remove. */
  recoveryKit?: RecoveryKitProps | undefined;
  /** The personal API key for the Bitwarden CLI: show, copy, replace. */
  apiKey?: ApiKeyProps | undefined;
  /** Signed writes only for the account's own vault: turn on, turn off with the password. */
  signedWrites?: SignedWritesProps | undefined;
  /** The danger zone: delete the account. */
  deleteAccount?: DeleteAccountProps | undefined;
}

/** The methods drawn as "Later" where the screen is given no way to set them up. */
const LATER = ['yubikey', 'duo', 'email', 'recovery'] as const;

export function SecurityView({
  email,
  host,
  methods,
  totp,
  busy,
  error,
  totpError,
  onStartTotp,
  onCancelTotp,
  onConfirmTotp,
  emergency,
  passkeys,
  secondSteps,
  recoveryKit,
  apiKey,
  signedWrites,
  deleteAccount,
}: SecurityViewProps) {
  const t = useT();
  const totpOn = methods?.includes('totp') ?? false;
  // Another second step that is on asks for the recovery code before an app is added beside it.
  const othersOn = methods?.some((m) => m !== 'totp') ?? false;
  const [recovery, setRecovery] = useState<Proof>('');
  const later: readonly (typeof LATER)[number][] = secondSteps ? [] : LATER;

  return (
    <>
      <div>
        <h1 className="page-title">{t('security.title')}</h1>
        <p className="lede">{t('security.signedInAs', { email })}</p>
      </div>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}

      <div className="acct-grid">
        <div className="acct-col">
          <section className="card" aria-labelledby="h-keys">
            <div className="card-head">
              <div className="grow">
                <h2 id="h-keys">{t('security.keys.title')}</h2>
                <p className="hint">{t('security.keys.lede')}</p>
              </div>
            </div>
            <div className="row">
              <div className="grow">
                <div>{t('security.keys.pair')}</div>
                <div className="hint">{t('security.keys.pairHint')}</div>
              </div>
            </div>
            <div className="row">
              <div className="grow">
                <div>{t('security.keys.password')}</div>
                <div className="hint">{t('security.keys.passwordHint')}</div>
              </div>
              <span className="tag off">{t('security.later')}</span>
            </div>
          </section>

          <section className="card" aria-labelledby="h-2fa">
            <div className="card-head">
              <div className="grow">
                <h2 id="h-2fa">{t('security.twoStep.title')}</h2>
                <p className="hint">{t('security.twoStep.lede')}</p>
              </div>
            </div>
            <div className="row">
              <div className="grow">
                <div>{t('security.twoStep.app')}</div>
                <div className="hint">{t('security.twoStep.appHint')}</div>
              </div>
              {methods === undefined ? null : (
                <span className={totpOn ? 'tag ok' : 'tag off'}>
                  {totpOn ? t('security.on') : t('security.off')}
                </span>
              )}
              {!totpOn && methods !== undefined && !totp.open ? (
                <Button size="small" isDisabled={busy} onPress={onStartTotp}>
                  {t('security.setUp')}
                </Button>
              ) : null}
            </div>
            {totp.open ? (
              <div className="panel-body">
                {totpError ? (
                  <Notice tone="error" live>
                    <p>{t(totpError.id, totpError.values)}</p>
                  </Notice>
                ) : null}
                {totp.enrol ? (
                  <section className="scan" aria-labelledby="h-scan">
                    <h3 id="h-scan" className="sr">
                      {t('twoStep.scanTitle')}
                    </h3>
                    <QrCode text={totp.enrol.uri} label={t('twoStep.qr', { host, email })} />
                    <ol>
                      <li>{t('twoStep.scan', { host, email })}</li>
                      <li className="stack">
                        {t('twoStep.typeKey')}
                        <span className="cmd">
                          <code>{groupSecret(totp.enrol.secret)}</code>
                          <CopyButton value={totp.enrol.secret} label={t('twoStep.copyKey')} secret big />
                        </span>
                      </li>
                      <li>{t('twoStep.typeCode')}</li>
                    </ol>
                  </section>
                ) : (
                  <p role="status" className="muted">
                    {t('state.loading')}
                  </p>
                )}
                <p className="hint">{t('twoStep.keepApp')}</p>
                {othersOn ? (
                  <>
                    <p className="hint">{t('security.totp.proof')}</p>
                    <ProofInput
                      label={t('security.totp.recovery')}
                      value={recovery}
                      onChange={setRecovery}
                      keyProof={secondSteps?.keyProof}
                      required={false}
                    />
                  </>
                ) : null}
                <CodeForm
                  label={t('twoStep.codeLabel')}
                  submitLabel={t('twoStep.submit')}
                  onSubmit={(code) => (proofBlank(recovery) ? onConfirmTotp(code) : onConfirmTotp(code, proofValue(recovery)))}
                  pending={busy || !totp.enrol}
                />
                <div className="actions">
                  <Button onPress={onCancelTotp}>{t('action.cancel')}</Button>
                </div>
              </div>
            ) : null}
            {passkeys ? <PasskeysCard {...passkeys} /> : null}
            {secondSteps ? <SecondStepsCard {...secondSteps} /> : null}
            {recoveryKit ? <RecoveryKitCard {...recoveryKit} /> : null}
            {later.map((method) => (
              <div className="row" key={method}>
                <div className="grow">
                  <div>{t(`security.method.${method}`)}</div>
                  <div className="hint">{t(`security.method.${method}.hint`)}</div>
                </div>
                <span className="tag off">{t('security.later')}</span>
              </div>
            ))}
          </section>
        </div>

        <div className="acct-col">
          <EmergencyCard {...emergency} />

          {apiKey ? <ApiKeyCard {...apiKey} /> : null}
          {signedWrites ? <SignedWritesCard {...signedWrites} /> : null}
          {deleteAccount ? <DeleteAccountCard {...deleteAccount} /> : null}
        </div>
      </div>
    </>
  );
}
