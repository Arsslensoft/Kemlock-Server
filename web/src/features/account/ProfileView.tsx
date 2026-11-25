// The Profile page: the name and the address, and the master password. The page holds no keys and
// calls nothing itself; the container (Profile.tsx) gives it the account and the actions.
import { type FormEvent, useEffect, useId, useState } from 'react';
import type { ProfileDto } from '@/api/profile';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { PasswordInput } from '@/ui/PasswordInput';
import '@/styles/profile.css';
import type { Described } from './errors';
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
  actions: {
    /** Saves what changed: `name` and `email` are given only when they differ. True when it worked. */
    saveIdentity: (input: { name?: string; email?: string; password: string }) => Promise<boolean>;
    cancelEmailChange: () => Promise<boolean>;
    changePassword: (input: { current: string; next: string; signOutOthers: boolean }) => Promise<boolean>;
  };
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

function IdentityCard({ profile, busy, identityNotice, identityError, actions }: ProfileViewProps) {
  const t = useT();
  const ids = { name: useId(), email: useId(), password: useId() };
  const [name, setName] = useState(profile.name ?? '');
  const [email, setEmail] = useState(profile.email);
  const [password, setPassword] = useState('');

  // What the server says is current replaces what was typed, once a save or a cancel went through.
  useEffect(() => {
    setName(profile.name ?? '');
    setEmail(profile.email);
    setPassword('');
  }, [profile.name, profile.email, profile.pendingEmail]);

  const nameLocked = profile.sso;
  // A new address needs the master password (the sign-in record is made again under it), which an
  // account an identity provider owns, one shared with Bitwarden apps or one with no password lacks.
  const emailLocked = profile.sso || profile.compatible || !profile.hasPassword;
  const nameChanged = !nameLocked && name.trim() !== (profile.name ?? '');
  const emailChanged = !emailLocked && !sameEmail(email, profile.email);
  const emailInvalid = emailChanged && !isEmail(email);
  const ready = (nameChanged || emailChanged) && !emailInvalid && (!emailChanged || password !== '') && !busy;
  const lockedNote: MessageId | undefined = profile.sso
    ? 'profile.locked.sso'
    : profile.compatible
      ? 'profile.locked.compatible'
      : !profile.hasPassword
        ? 'profile.locked.noPassword'
        : undefined;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready) return;
    void actions.saveIdentity({
      ...(nameChanged ? { name: name.trim() } : {}),
      ...(emailChanged ? { email: email.trim() } : {}),
      password,
    });
  }

  return (
    <section className="card pad profile-card" aria-labelledby="h-me">
      <div>
        <h2 id="h-me">{t('profile.me.title')}</h2>
        <p className="hint">{t('profile.me.hint')}</p>
      </div>
      <form className="stack profile-form" onSubmit={submit} noValidate>
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

function PasswordCard({ profile, busy, passwordNotice, passwordError, actions }: ProfileViewProps) {
  const t = useT();
  const ids = { current: useId(), next: useId(), again: useId(), out: useId() };
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [signOutOthers, setSignOutOthers] = useState(true);
  const [attempted, setAttempted] = useState(false);

  const problem = passwordProblem(current, next, again);
  const shown = attempted ? problem : undefined;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || current === '') return;
    setAttempted(true);
    if (problem) return;
    const done = await actions.changePassword({ current, next, signOutOthers });
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
            <Button type="submit" variant="primary" isDisabled={busy || current === ''}>
              {t('profile.pw.submit')}
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}
