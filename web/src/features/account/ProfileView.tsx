// The Profile page: the name and the address, and the master password. The page holds no keys and
// calls nothing itself; the container (Profile.tsx) gives it the account and the actions.
import { type FormEvent, useEffect, useId, useState } from 'react';
import type { ProfileDto } from '@/api/profile';
import type { Proof } from '@/api/twoStep';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { PasswordInput } from '@/ui/PasswordInput';
import '@/styles/profile.css';
import type { Described } from './errors';
import { type KeyProof, ProofInput, proofBlank, proofValue } from './ProofInput';
import { type PasswordProblem, isEmail, passwordProblem, sameEmail } from './profileModel';

/** What the last save of the name and address did. */
export type IdentityNotice = { kind: 'saved' } | { kind: 'sent'; email: string } | { kind: 'cancelled' };
export type PasswordNotice = 'changed' | 'changedOthers';

export interface ProfileViewProps {
  profile: ProfileDto;
  busy: boolean;
  identityNotice?: IdentityNotice | undefined;
  identityError?: Described | undefined;
  passwordNotice?: PasswordNotice | undefined;
  passwordError?: Described | undefined;
  /** Answers a second step's proof with a security key or passkey, where there is one to use. */
  identityKeyProof?: KeyProof | undefined;
  passwordKeyProof?: KeyProof | undefined;
  actions: {
    /**
     * Saves what changed: `name` and `email` are given only when they differ, and `proof` is given
     * with a new address when a second step is on. True when it worked.
     */
    saveIdentity: (input: { name?: string; email?: string; password: string; proof?: Proof }) => Promise<boolean>;
    cancelEmailChange: () => Promise<boolean>;
    changePassword: (input: {
      current: string;
      next: string;
      signOutOthers: boolean;
      proof?: Proof;
    }) => Promise<boolean>;
    /** Mails the one-time code that proves the owner. */
    askProof: () => Promise<boolean>;
  };
}

/**
 * The second step's proof, asked beside the password when the account has a second step on, as
 * deleting the account asks it: a code from the authenticator app, the recovery code or one mailed
 * on request, or a security key's or passkey's answer. It works once.
 */
function SecondStepProof({
  value,
  onChange,
  keyProof,
  busy,
  askProof,
}: {
  value: Proof;
  onChange: (next: Proof) => void;
  keyProof: KeyProof | undefined;
  busy: boolean;
  askProof: () => Promise<boolean>;
}) {
  const t = useT();
  return (
    <div className="stack">
      <p className="hint">{t('profile.proof.hint')}</p>
      <ProofInput value={value} onChange={onChange} keyProof={keyProof} busy={busy} label={t('profile.proof.code')} />
      {typeof value === 'string' ? (
        <div className="actions">
          <Button size="small" isDisabled={busy} onPress={() => void askProof()}>
            {t('profile.proof.send')}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

const PROBLEMS: Record<PasswordProblem, MessageId> = {
  short: 'error.passwordShort',
  mismatch: 'error.passwordMismatch',
  same: 'profile.pw.same',
};

export function ProfileView(props: ProfileViewProps) {
  const t = useT();
  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t('profile.title')}</h1>
          <p className="lede">{t('profile.lede')}</p>
        </div>
      </div>
      <IdentityCard {...props} />
      <PasswordCard {...props} />
    </>
  );
}

function IdentityCard({ profile, busy, identityNotice, identityError, identityKeyProof, actions }: ProfileViewProps) {
  const t = useT();
  const ids = { name: useId(), email: useId(), password: useId() };
  const [name, setName] = useState(profile.name ?? '');
  const [email, setEmail] = useState(profile.email);
  const [password, setPassword] = useState('');
  const [proof, setProof] = useState<Proof>('');

  // What the server says is current replaces what was typed, once a save or a cancel went through.
  useEffect(() => {
    setName(profile.name ?? '');
    setEmail(profile.email);
    setPassword('');
    setProof('');
  }, [profile.name, profile.email, profile.pendingEmail]);

  const nameLocked = profile.sso;
  // A new address needs the master password (the sign-in record is made again under it), which an
  // account an identity provider owns, one shared with Bitwarden apps or one with no password lacks.
  const emailLocked = profile.sso || profile.compatible || !profile.hasPassword;
  const nameChanged = !nameLocked && name.trim() !== (profile.name ?? '');
  const emailChanged = !emailLocked && !sameEmail(email, profile.email);
  const emailInvalid = emailChanged && !isEmail(email);
  // A new address asks the second step's proof too, when the account has one on.
  const needsProof = emailChanged && profile.twoStep;
  const ready =
    (nameChanged || emailChanged) &&
    !emailInvalid &&
    (!emailChanged || password !== '') &&
    (!needsProof || !proofBlank(proof)) &&
    !busy;
  const lockedNote: MessageId | undefined = profile.sso
    ? 'profile.locked.sso'
    : profile.compatible
      ? 'profile.locked.compatible'
      : !profile.hasPassword
        ? 'profile.locked.noPassword'
        : undefined;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    await actions.saveIdentity({
      ...(nameChanged ? { name: name.trim() } : {}),
      ...(emailChanged ? { email: email.trim() } : {}),
      ...(needsProof ? { proof: proofValue(proof) } : {}),
      password,
    });
    // A proof works once, whether the save went through or not.
    setProof('');
  }

  return (
    <section className="card pad profile-card" aria-labelledby="h-me">
      <div>
        <h2 id="h-me">{t('profile.me.title')}</h2>
        <p className="hint">{t('profile.me.hint')}</p>
      </div>
      <form className="stack profile-form" onSubmit={(event) => void submit(event)} noValidate>
        <div className="profile-grid">
          <div className="field">
            <label htmlFor={ids.name}>{t('profile.name')}</label>
            <input
              id={ids.name}
              type="text"
              autoComplete="name"
              value={name}
              readOnly={nameLocked}
              onChange={(event) => setName(event.target.value)}
              aria-describedby={`${ids.name}-hint`}
            />
            <span className="hint" id={`${ids.name}-hint`}>
              {t(nameLocked ? 'profile.locked.sso' : 'profile.name.hint')}
            </span>
          </div>
          <div className="field">
            <label htmlFor={ids.email}>{t('profile.email')}</label>
            <input
              id={ids.email}
              type="email"
              autoComplete="email"
              value={email}
              readOnly={emailLocked}
              aria-invalid={emailInvalid || undefined}
              onChange={(event) => setEmail(event.target.value)}
              aria-describedby={`${ids.email}-hint`}
            />
            <span className="hint" id={`${ids.email}-hint`}>
              {emailInvalid ? (
                <span className="field-error" role="alert">
                  {t('profile.email.invalid')}
                </span>
              ) : (
                t(lockedNote ?? 'profile.email.hint')
              )}
            </span>
          </div>
        </div>

        {emailChanged ? (
          <div className="field">
            <label htmlFor={ids.password}>{t('profile.email.password')}</label>
            <PasswordInput
              id={ids.password}
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-describedby={`${ids.password}-hint`}
            />
            <span className="hint" id={`${ids.password}-hint`}>
              {t('profile.email.password.hint')}
            </span>
          </div>
        ) : null}
        {needsProof ? (
          <SecondStepProof
            value={proof}
            onChange={setProof}
            keyProof={identityKeyProof}
            busy={busy}
            askProof={actions.askProof}
          />
        ) : null}

        {profile.pendingEmail && !emailLocked ? (
          <Notice icon="mail">
            <p>{t('profile.pending', { email: profile.pendingEmail, current: profile.email })}</p>
            <div>
              <Button size="small" isDisabled={busy} onPress={() => void actions.cancelEmailChange()}>
                {t('profile.pending.cancel')}
              </Button>
            </div>
          </Notice>
        ) : null}

        {identityNotice ? (
          <Notice tone="info" icon="check" live>
            <p>
              {identityNotice.kind === 'sent'
                ? t('profile.emailSent', { email: identityNotice.email })
                : t(identityNotice.kind === 'cancelled' ? 'profile.pending.cancelled' : 'profile.saved')}
            </p>
          </Notice>
        ) : null}
        {identityError ? (
          <Notice tone="error" live>
            <p>{t(identityError.id, identityError.values)}</p>
          </Notice>
        ) : null}

        {nameLocked && emailLocked ? null : (
          <div className="profile-actions">
            <Button type="submit" variant="primary" isDisabled={!ready}>
              {t('profile.save')}
            </Button>
          </div>
        )}
      </form>
    </section>
  );
}

function PasswordCard({ profile, busy, passwordNotice, passwordError, passwordKeyProof, actions }: ProfileViewProps) {
  const t = useT();
  const ids = { current: useId(), next: useId(), again: useId(), out: useId() };
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [signOutOthers, setSignOutOthers] = useState(true);
  const [attempted, setAttempted] = useState(false);
  const [proof, setProof] = useState<Proof>('');

  const problem = passwordProblem(current, next, again);
  const shown = attempted ? problem : undefined;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || current === '' || (profile.twoStep && proofBlank(proof))) return;
    setAttempted(true);
    if (problem) return;
    const done = await actions.changePassword({
      current,
      next,
      signOutOthers,
      ...(profile.twoStep ? { proof: proofValue(proof) } : {}),
    });
    // A proof works once, whether the change went through or not.
    setProof('');
    if (done) {
      setCurrent('');
      setNext('');
      setAgain('');
      setAttempted(false);
    }
  }

  return (
    <section className="card pad profile-card" aria-labelledby="h-pw">
      <div>
        <h2 id="h-pw">{t('profile.pw.title')}</h2>
        <p className="hint">{t('profile.pw.hint')}</p>
      </div>
      {profile.compatible ? (
        <Notice>
          <p>{t('profile.pw.compatible')}</p>
        </Notice>
      ) : !profile.hasPassword ? (
        <Notice>
          <p>{t('profile.pw.none')}</p>
        </Notice>
      ) : (
        <form className="stack profile-form" onSubmit={(event) => void submit(event)} noValidate>
          <div className="field">
            <label htmlFor={ids.current}>{t('profile.pw.current')}</label>
            <PasswordInput
              id={ids.current}
              autoComplete="current-password"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
            />
          </div>
          <div className="profile-grid">
            <div className="field">
              <label htmlFor={ids.next}>{t('profile.pw.new')}</label>
              <PasswordInput
                id={ids.next}
                autoComplete="new-password"
                value={next}
                aria-invalid={shown === 'short' || shown === 'same' || undefined}
                aria-describedby={`${ids.next}-hint`}
                onChange={(event) => setNext(event.target.value)}
              />
              <span className="hint" id={`${ids.next}-hint`}>
                {shown === 'short' || shown === 'same' ? (
                  <span className="field-error" role="alert">
                    {t(PROBLEMS[shown])}
                  </span>
                ) : (
                  t('profile.pw.new.hint')
                )}
              </span>
            </div>
            <div className="field">
              <label htmlFor={ids.again}>{t('profile.pw.again')}</label>
              <PasswordInput
                id={ids.again}
                autoComplete="new-password"
                value={again}
                aria-invalid={shown === 'mismatch' || undefined}
                aria-describedby={shown === 'mismatch' ? `${ids.again}-error` : undefined}
                onChange={(event) => setAgain(event.target.value)}
              />
              {shown === 'mismatch' ? (
                <span className="field-error" id={`${ids.again}-error`} role="alert">
                  {t(PROBLEMS.mismatch)}
                </span>
              ) : null}
            </div>
          </div>
          <div className="check-row top">
            <input
              id={ids.out}
              type="checkbox"
              checked={signOutOthers}
              onChange={(event) => setSignOutOthers(event.target.checked)}
            />
            <label htmlFor={ids.out}>
              <span className="t">{t('profile.pw.signOut')}</span>
              <span className="hint">{t('profile.pw.signOut.hint')}</span>
            </label>
          </div>
          {profile.twoStep ? (
            <SecondStepProof
              value={proof}
              onChange={setProof}
              keyProof={passwordKeyProof}
              busy={busy}
              askProof={actions.askProof}
            />
          ) : null}
          <Notice tone="warn">
            <p>
              <b>{t('profile.pw.noReset')}</b> {t('profile.pw.noReset.body')}
            </p>
          </Notice>
          {passwordNotice ? (
            <Notice icon="check" live>
              <p>{t(passwordNotice === 'changedOthers' ? 'profile.pw.changedOthers' : 'profile.pw.changed')}</p>
            </Notice>
          ) : null}
          {passwordError ? (
            <Notice tone="error" live>
              <p>{t(passwordError.id, passwordError.values)}</p>
            </Notice>
          ) : null}
          <div className="profile-actions">
            <Button
              type="submit"
              variant="primary"
              isDisabled={busy || current === '' || (profile.twoStep && proofBlank(proof))}
            >
              {t('profile.pw.submit')}
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}
